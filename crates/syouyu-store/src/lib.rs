mod cipher;
mod models;

use std::time::Duration;

use chrono::{DateTime, Utc};
use serde_json::Value;
use sqlx::{PgPool, Postgres, Transaction, postgres::PgPoolOptions};
use thiserror::Error;
use uuid::Uuid;

use cipher::ReceiptCipher;
pub use models::*;

static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("../../migrations");

#[derive(Clone)]
pub struct PgStore {
    pool: PgPool,
    receipt_cipher: ReceiptCipher,
    credential_limits: CredentialLimits,
}

impl PgStore {
    pub async fn connect(
        database_url: &str,
        max_connections: u32,
        receipt_encryption_key: &[u8],
        credential_limits: CredentialLimits,
    ) -> Result<Self, StoreError> {
        if database_url.is_empty() {
            return Err(StoreError::Configuration("DATABASE_URL is empty"));
        }
        let pool = PgPoolOptions::new()
            .max_connections(max_connections)
            .min_connections(1)
            .acquire_timeout(Duration::from_secs(5))
            .idle_timeout(Duration::from_secs(30))
            .max_lifetime(Duration::from_mins(5))
            .connect(database_url)
            .await?;
        Self::from_pool(pool, receipt_encryption_key, credential_limits)
    }

    pub fn from_pool(
        pool: PgPool,
        receipt_encryption_key: &[u8],
        credential_limits: CredentialLimits,
    ) -> Result<Self, StoreError> {
        Ok(Self {
            pool,
            receipt_cipher: ReceiptCipher::new(receipt_encryption_key)?,
            credential_limits: credential_limits.validate()?,
        })
    }

    #[must_use]
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    pub async fn migrate(&self) -> Result<(), StoreError> {
        MIGRATOR.run(&self.pool).await?;
        Ok(())
    }

    pub async fn health(&self) -> Result<(), StoreError> {
        sqlx::query("SELECT 1").execute(&self.pool).await?;
        Ok(())
    }

    pub async fn prepare_reconcile(
        &self,
        command: &ReconcileCommand,
    ) -> Result<Prepare<ReconcileContext>, StoreError> {
        command.validate()?;
        let mut transaction = self.pool.begin().await?;
        advisory_lock(
            &mut transaction,
            &format!("operation:{}", command.operation.idempotency_key),
        )
        .await?;
        if let Some(replay) = self
            .existing_receipt(&mut transaction, &command.operation)
            .await?
        {
            transaction.commit().await?;
            return Ok(replay.map_context());
        }

        lock_service(&mut transaction, command.operation.service_instance_id).await?;
        reject_parallel_operation(&mut transaction, command.operation.service_instance_id).await?;

        let existing = fetch_service_row(
            &mut transaction,
            command.operation.service_instance_id,
            true,
        )
        .await?;
        let mut previously_applied = false;
        let mut physical_bucket_id = None;
        if let Some(existing) = existing {
            ensure_scope(
                &command.operation,
                existing.organization_id,
                existing.project_id,
            )?;
            if existing.phase == "deleted" {
                return Err(StoreError::Conflict(
                    "service instance has already been deleted",
                ));
            }
            if command.generation < existing.desired_generation {
                return Err(StoreError::StaleGeneration {
                    current: existing.desired_generation,
                    requested: command.generation,
                });
            }
            let existing_bucket =
                fetch_bucket_row(&mut transaction, command.operation.service_instance_id)
                    .await?
                    .ok_or(StoreError::CorruptData("service bucket"))?;
            if existing_bucket.bucket_name != command.spec.bucket_name {
                return Err(StoreError::Conflict(
                    "bucket_name is immutable after service creation",
                ));
            }
            physical_bucket_id.clone_from(&existing_bucket.physical_bucket_id);
            if command.generation == existing.desired_generation {
                let current_spec: TargetSpec = serde_json::from_value(existing.desired_spec)
                    .map_err(|_| StoreError::CorruptData("service desired_spec"))?;
                if existing.name != command.name || current_spec != command.spec {
                    return Err(StoreError::Conflict(
                        "generation was reused with different desired state",
                    ));
                }
                if existing.phase != "ready" || existing.observed_generation != command.generation {
                    return Err(StoreError::OperationInProgress(
                        existing.current_operation_id,
                    ));
                }
                previously_applied = true;
            }
        }

        reserve_bucket_name(
            &mut transaction,
            &command.spec.bucket_name,
            command.operation.service_instance_id,
        )
        .await?;
        let operation_id = reserve_receipt(&mut transaction, &command.operation).await?;
        transaction.commit().await?;

        Ok(Prepare::Execute {
            operation_id,
            context: ReconcileContext {
                bucket: BucketRecord {
                    service_instance_id: command.operation.service_instance_id,
                    organization_id: command.operation.organization_id,
                    project_id: command.operation.project_id,
                    physical_bucket_id,
                    bucket_name: command.spec.bucket_name.clone(),
                    region: command.spec.region.clone(),
                    quota_bytes: command.spec.quota_bytes,
                    quota_objects: command.spec.quota_objects,
                    used_bytes: 0,
                    used_objects: 0,
                    usage_measured_at: None,
                },
                previously_applied,
            },
        })
    }

    pub async fn complete_reconcile(
        &self,
        command: &ReconcileCommand,
        operation_id: Uuid,
        physical_bucket_id: &str,
        response: &StoredHttpResponse,
        audit: &AuditEvent,
    ) -> Result<(), StoreError> {
        if physical_bucket_id.is_empty() || physical_bucket_id.len() > 256 {
            return Err(StoreError::Validation("physical bucket ID is invalid"));
        }
        let spec = serde_json::to_value(&command.spec)
            .map_err(|_| StoreError::CorruptData("service desired_spec serialization"))?;
        let quota_bytes = to_i64(command.spec.quota_bytes, "quota_bytes")?;
        let quota_objects = to_i64(command.spec.quota_objects, "quota_objects")?;
        let mut transaction = self.pool.begin().await?;
        lock_service(&mut transaction, command.operation.service_instance_id).await?;
        require_in_progress_receipt(&mut transaction, &command.operation, operation_id).await?;

        let service_update = sqlx::query(
            r"
            INSERT INTO syouyu_service_instances (
                id, organization_id, project_id, name, desired_generation,
                desired_spec, observed_generation, phase, current_operation_id
            )
            VALUES ($1, $2, $3, $4, $5, $6, $5, 'ready', $7)
            ON CONFLICT (id) DO UPDATE
            SET name = EXCLUDED.name,
                desired_generation = EXCLUDED.desired_generation,
                desired_spec = EXCLUDED.desired_spec,
                observed_generation = EXCLUDED.observed_generation,
                phase = 'ready',
                current_operation_id = EXCLUDED.current_operation_id,
                last_error = NULL,
                updated_at = now(),
                deleted_at = NULL
            WHERE syouyu_service_instances.organization_id = EXCLUDED.organization_id
              AND syouyu_service_instances.project_id = EXCLUDED.project_id
              AND syouyu_service_instances.desired_generation <= EXCLUDED.desired_generation
              AND syouyu_service_instances.phase <> 'deleted'
            ",
        )
        .bind(command.operation.service_instance_id)
        .bind(command.operation.organization_id)
        .bind(command.operation.project_id)
        .bind(&command.name)
        .bind(command.generation)
        .bind(spec)
        .bind(operation_id)
        .execute(&mut *transaction)
        .await
        .map_err(map_database_error)?;
        if service_update.rows_affected() != 1 {
            return Err(StoreError::Conflict(
                "service changed while reconciliation was in progress",
            ));
        }

        sqlx::query(
            r"
            INSERT INTO syouyu_buckets (
                service_instance_id, organization_id, project_id,
                physical_bucket_id, bucket_name, region, quota_bytes, quota_objects
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            ON CONFLICT (service_instance_id) DO UPDATE
            SET physical_bucket_id = EXCLUDED.physical_bucket_id,
                bucket_name = EXCLUDED.bucket_name,
                region = EXCLUDED.region,
                quota_bytes = EXCLUDED.quota_bytes,
                quota_objects = EXCLUDED.quota_objects,
                updated_at = now()
            ",
        )
        .bind(command.operation.service_instance_id)
        .bind(command.operation.organization_id)
        .bind(command.operation.project_id)
        .bind(physical_bucket_id)
        .bind(&command.spec.bucket_name)
        .bind(&command.spec.region)
        .bind(quota_bytes)
        .bind(quota_objects)
        .execute(&mut *transaction)
        .await
        .map_err(map_database_error)?;
        sqlx::query(
            r"
            DELETE FROM syouyu_bucket_name_reservations
            WHERE service_instance_id = $1 AND bucket_name <> $2
            ",
        )
        .bind(command.operation.service_instance_id)
        .bind(&command.spec.bucket_name)
        .execute(&mut *transaction)
        .await?;
        self.finish_receipt(&mut transaction, &command.operation, operation_id, response)
            .await?;
        insert_audit(&mut transaction, audit).await?;
        transaction.commit().await?;
        Ok(())
    }

    pub async fn prepare_delete(
        &self,
        command: &DeleteCommand,
    ) -> Result<Prepare<DeleteContext>, StoreError> {
        command.validate()?;
        let mut transaction = self.pool.begin().await?;
        advisory_lock(
            &mut transaction,
            &format!("operation:{}", command.operation.idempotency_key),
        )
        .await?;
        if let Some(replay) = self
            .existing_receipt(&mut transaction, &command.operation)
            .await?
        {
            transaction.commit().await?;
            return Ok(replay.map_context());
        }
        advisory_lock(
            &mut transaction,
            &format!(
                "organization:credentials:{}",
                command.operation.organization_id
            ),
        )
        .await?;
        lock_service(&mut transaction, command.operation.service_instance_id).await?;
        reject_parallel_operation(&mut transaction, command.operation.service_instance_id).await?;

        let service = fetch_service_row(
            &mut transaction,
            command.operation.service_instance_id,
            true,
        )
        .await?
        .ok_or(StoreError::NotFound)?;
        ensure_scope(
            &command.operation,
            service.organization_id,
            service.project_id,
        )?;
        if service.phase == "deleted" {
            return Err(StoreError::NotFound);
        }
        let expected_generation = service
            .desired_generation
            .checked_add(1)
            .ok_or(StoreError::Configuration("service generation overflow"))?;
        if command.generation < expected_generation {
            return Err(StoreError::StaleGeneration {
                current: service.desired_generation,
                requested: command.generation,
            });
        }
        if command.generation != expected_generation {
            return Err(StoreError::Conflict(
                "delete generation must immediately follow desired generation",
            ));
        }
        let bucket = fetch_bucket_row(&mut transaction, command.operation.service_instance_id)
            .await?
            .ok_or(StoreError::CorruptData("service bucket"))?;
        if bucket.physical_bucket_id.is_none() {
            return Err(StoreError::CorruptData("physical bucket ID"));
        }
        let garage_key_ids = sqlx::query_scalar::<_, String>(
            r"
            SELECT garage_key_id
            FROM syouyu_credentials
            WHERE service_instance_id = $1 AND status = 'active'
            ORDER BY created_at, id
            ",
        )
        .bind(command.operation.service_instance_id)
        .fetch_all(&mut *transaction)
        .await?;
        let operation_id = reserve_receipt(&mut transaction, &command.operation).await?;
        transaction.commit().await?;
        Ok(Prepare::Execute {
            operation_id,
            context: DeleteContext {
                bucket,
                garage_key_ids,
            },
        })
    }

    pub async fn complete_delete(
        &self,
        command: &DeleteCommand,
        operation_id: Uuid,
        response: &StoredHttpResponse,
        audit: &AuditEvent,
    ) -> Result<(), StoreError> {
        let mut transaction = self.pool.begin().await?;
        lock_service(&mut transaction, command.operation.service_instance_id).await?;
        require_in_progress_receipt(&mut transaction, &command.operation, operation_id).await?;
        sqlx::query(
            r"
            UPDATE syouyu_credentials
            SET status = 'revoked', revoked_at = COALESCE(revoked_at, now()),
                revoked_by = COALESCE(revoked_by, $2)
            WHERE service_instance_id = $1 AND status = 'active'
            ",
        )
        .bind(command.operation.service_instance_id)
        .bind(command.operation.principal_id)
        .execute(&mut *transaction)
        .await?;
        let updated = sqlx::query(
            r"
            UPDATE syouyu_service_instances
            SET desired_generation = $2,
                observed_generation = $2,
                phase = 'deleted',
                current_operation_id = $3,
                last_error = NULL,
                deleted_at = now(),
                updated_at = now()
            WHERE id = $1
              AND organization_id = $4
              AND project_id = $5
              AND phase <> 'deleted'
            ",
        )
        .bind(command.operation.service_instance_id)
        .bind(command.generation)
        .bind(operation_id)
        .bind(command.operation.organization_id)
        .bind(command.operation.project_id)
        .execute(&mut *transaction)
        .await?;
        if updated.rows_affected() != 1 {
            return Err(StoreError::Conflict(
                "service changed while deletion was in progress",
            ));
        }
        sqlx::query("DELETE FROM syouyu_bucket_name_reservations WHERE service_instance_id = $1")
            .bind(command.operation.service_instance_id)
            .execute(&mut *transaction)
            .await?;
        self.finish_receipt(&mut transaction, &command.operation, operation_id, response)
            .await?;
        insert_audit(&mut transaction, audit).await?;
        transaction.commit().await?;
        Ok(())
    }

    pub async fn prepare_create_credential(
        &self,
        command: &CreateCredentialCommand,
    ) -> Result<Prepare<CreateCredentialContext>, StoreError> {
        command.validate()?;
        let mut transaction = self.pool.begin().await?;
        advisory_lock(
            &mut transaction,
            &format!("operation:{}", command.operation.idempotency_key),
        )
        .await?;
        if let Some(replay) = self
            .existing_receipt(&mut transaction, &command.operation)
            .await?
        {
            transaction.commit().await?;
            return Ok(replay.map_context());
        }
        advisory_lock(
            &mut transaction,
            &format!(
                "organization:credentials:{}",
                command.operation.organization_id
            ),
        )
        .await?;
        lock_service(&mut transaction, command.operation.service_instance_id).await?;
        reject_parallel_operation(&mut transaction, command.operation.service_instance_id).await?;
        let bucket = self
            .ready_bucket_in_transaction(&mut transaction, &command.operation)
            .await?;
        let duplicate: bool = sqlx::query_scalar(
            r"
            SELECT EXISTS (
                SELECT 1 FROM syouyu_credentials
                WHERE service_instance_id = $1 AND name = $2
                UNION ALL
                SELECT 1 FROM syouyu_credential_reservations
                WHERE service_instance_id = $1 AND name = $2
            )
            ",
        )
        .bind(command.operation.service_instance_id)
        .bind(&command.name)
        .fetch_one(&mut *transaction)
        .await?;
        if duplicate {
            return Err(StoreError::Conflict(
                "credential name already exists for this service",
            ));
        }
        let per_bucket: i64 = sqlx::query_scalar(
            r"
            SELECT
                (SELECT count(*) FROM syouyu_credentials
                 WHERE service_instance_id = $1 AND status = 'active')
              + (SELECT count(*) FROM syouyu_credential_reservations
                 WHERE service_instance_id = $1)
            ",
        )
        .bind(command.operation.service_instance_id)
        .fetch_one(&mut *transaction)
        .await?;
        let max_credentials_per_bucket = command
            .credential_limits
            .max_credentials_per_bucket
            .min(self.credential_limits.max_credentials_per_bucket);
        if per_bucket >= i64::from(max_credentials_per_bucket) {
            return Err(StoreError::CredentialLimitExceeded {
                scope: "bucket",
                limit: max_credentials_per_bucket,
            });
        }
        let total: i64 = sqlx::query_scalar(
            r"
            SELECT
                (SELECT count(*) FROM syouyu_credentials
                 WHERE organization_id = $1 AND status = 'active')
              + (SELECT count(*) FROM syouyu_credential_reservations
                 WHERE organization_id = $1)
            ",
        )
        .bind(command.operation.organization_id)
        .fetch_one(&mut *transaction)
        .await?;
        let max_total_credentials = command
            .credential_limits
            .max_total_credentials
            .min(self.credential_limits.max_total_credentials);
        if total >= i64::from(max_total_credentials) {
            return Err(StoreError::CredentialLimitExceeded {
                scope: "organization",
                limit: max_total_credentials,
            });
        }
        let operation_id = reserve_receipt(&mut transaction, &command.operation).await?;
        let credential_id = Uuid::now_v7();
        let permissions = serde_json::to_value(command.permissions)
            .map_err(|_| StoreError::CorruptData("credential permissions serialization"))?;
        sqlx::query(
            r"
            INSERT INTO syouyu_credential_reservations (
                credential_id, operation_id, service_instance_id, organization_id,
                project_id, name, permissions
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            ",
        )
        .bind(credential_id)
        .bind(operation_id)
        .bind(command.operation.service_instance_id)
        .bind(command.operation.organization_id)
        .bind(command.operation.project_id)
        .bind(&command.name)
        .bind(permissions)
        .execute(&mut *transaction)
        .await
        .map_err(map_database_error)?;
        transaction.commit().await?;
        Ok(Prepare::Execute {
            operation_id,
            context: CreateCredentialContext {
                bucket,
                credential_id,
            },
        })
    }

    pub async fn complete_create_credential(
        &self,
        command: &CreateCredentialCommand,
        operation_id: Uuid,
        credential: &NewCredential,
        response: &StoredHttpResponse,
        audit: &AuditEvent,
    ) -> Result<(), StoreError> {
        if credential.id.is_nil()
            || credential.garage_key_id.is_empty()
            || credential.access_key_id.is_empty()
            || credential.name != command.name
            || credential.permissions != command.permissions
        {
            return Err(StoreError::Validation(
                "created credential metadata is invalid",
            ));
        }
        let permissions = serde_json::to_value(credential.permissions)
            .map_err(|_| StoreError::CorruptData("credential permissions serialization"))?;
        let mut transaction = self.pool.begin().await?;
        advisory_lock(
            &mut transaction,
            &format!(
                "organization:credentials:{}",
                command.operation.organization_id
            ),
        )
        .await?;
        lock_service(&mut transaction, command.operation.service_instance_id).await?;
        require_in_progress_receipt(&mut transaction, &command.operation, operation_id).await?;
        let reserved: bool = sqlx::query_scalar(
            r"
            SELECT EXISTS (
                SELECT 1 FROM syouyu_credential_reservations
                WHERE credential_id = $1 AND operation_id = $2
                  AND service_instance_id = $3 AND name = $4
            )
            ",
        )
        .bind(credential.id)
        .bind(operation_id)
        .bind(command.operation.service_instance_id)
        .bind(&command.name)
        .fetch_one(&mut *transaction)
        .await?;
        if !reserved {
            return Err(StoreError::CorruptData("credential reservation"));
        }
        sqlx::query(
            r"
            INSERT INTO syouyu_credentials (
                id, service_instance_id, organization_id, project_id, principal_id,
                name, garage_key_id, access_key_id, permissions,
                secret_key_fingerprint, status
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, 'active')
            ",
        )
        .bind(credential.id)
        .bind(command.operation.service_instance_id)
        .bind(command.operation.organization_id)
        .bind(command.operation.project_id)
        .bind(command.operation.principal_id)
        .bind(&credential.name)
        .bind(&credential.garage_key_id)
        .bind(&credential.access_key_id)
        .bind(permissions)
        .bind(credential.secret_key_fingerprint.as_slice())
        .execute(&mut *transaction)
        .await
        .map_err(map_database_error)?;
        sqlx::query(
            "DELETE FROM syouyu_credential_reservations WHERE credential_id = $1 AND operation_id = $2",
        )
        .bind(credential.id)
        .bind(operation_id)
        .execute(&mut *transaction)
        .await?;
        self.finish_receipt(&mut transaction, &command.operation, operation_id, response)
            .await?;
        insert_audit(&mut transaction, audit).await?;
        transaction.commit().await?;
        Ok(())
    }

    pub async fn prepare_revoke_credential(
        &self,
        command: &RevokeCredentialCommand,
    ) -> Result<Prepare<RevokeCredentialContext>, StoreError> {
        command.operation.validate()?;
        let mut transaction = self.pool.begin().await?;
        advisory_lock(
            &mut transaction,
            &format!("operation:{}", command.operation.idempotency_key),
        )
        .await?;
        if let Some(replay) = self
            .existing_receipt(&mut transaction, &command.operation)
            .await?
        {
            transaction.commit().await?;
            return Ok(replay.map_context());
        }
        lock_service(&mut transaction, command.operation.service_instance_id).await?;
        reject_parallel_operation(&mut transaction, command.operation.service_instance_id).await?;
        self.ready_bucket_in_transaction(&mut transaction, &command.operation)
            .await?;
        let row = sqlx::query_as::<_, CredentialStateRow>(
            r"
            SELECT garage_key_id, status
            FROM syouyu_credentials
            WHERE id = $1 AND service_instance_id = $2
            FOR UPDATE
            ",
        )
        .bind(command.credential_id)
        .bind(command.operation.service_instance_id)
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or(StoreError::NotFound)?;
        let operation_id = reserve_receipt(&mut transaction, &command.operation).await?;
        transaction.commit().await?;
        Ok(Prepare::Execute {
            operation_id,
            context: RevokeCredentialContext {
                garage_key_id: row.garage_key_id,
                already_revoked: row.status == "revoked",
            },
        })
    }

    pub async fn complete_revoke_credential(
        &self,
        command: &RevokeCredentialCommand,
        operation_id: Uuid,
        response: &StoredHttpResponse,
        audit: &AuditEvent,
    ) -> Result<(), StoreError> {
        let mut transaction = self.pool.begin().await?;
        lock_service(&mut transaction, command.operation.service_instance_id).await?;
        require_in_progress_receipt(&mut transaction, &command.operation, operation_id).await?;
        let updated = sqlx::query(
            r"
            UPDATE syouyu_credentials
            SET status = 'revoked',
                revoked_at = COALESCE(revoked_at, now()),
                revoked_by = COALESCE(revoked_by, $3)
            WHERE id = $1 AND service_instance_id = $2
            ",
        )
        .bind(command.credential_id)
        .bind(command.operation.service_instance_id)
        .bind(command.operation.principal_id)
        .execute(&mut *transaction)
        .await?;
        if updated.rows_affected() != 1 {
            return Err(StoreError::NotFound);
        }
        self.finish_receipt(&mut transaction, &command.operation, operation_id, response)
            .await?;
        insert_audit(&mut transaction, audit).await?;
        transaction.commit().await?;
        Ok(())
    }

    pub async fn fail_operation(
        &self,
        operation: &OperationRequest,
        operation_id: Uuid,
        response: &StoredHttpResponse,
        audit: &AuditEvent,
    ) -> Result<(), StoreError> {
        if !response.failed {
            return Err(StoreError::Validation(
                "failed operation response must be marked failed",
            ));
        }
        let mut transaction = self.pool.begin().await?;
        advisory_lock(
            &mut transaction,
            &format!("organization:credentials:{}", operation.organization_id),
        )
        .await?;
        lock_service(&mut transaction, operation.service_instance_id).await?;
        require_in_progress_receipt(&mut transaction, operation, operation_id).await?;
        self.finish_receipt(&mut transaction, operation, operation_id, response)
            .await?;
        sqlx::query("DELETE FROM syouyu_credential_reservations WHERE operation_id = $1")
            .bind(operation_id)
            .execute(&mut *transaction)
            .await?;
        sqlx::query(
            r"
            DELETE FROM syouyu_bucket_name_reservations reservation
            WHERE reservation.service_instance_id = $1
              AND NOT EXISTS (
                  SELECT 1 FROM syouyu_buckets bucket
                  WHERE bucket.service_instance_id = reservation.service_instance_id
                    AND bucket.bucket_name = reservation.bucket_name
              )
            ",
        )
        .bind(operation.service_instance_id)
        .execute(&mut *transaction)
        .await?;
        insert_audit(&mut transaction, audit).await?;
        transaction.commit().await?;
        Ok(())
    }

    pub async fn service_overview(
        &self,
        organization_id: Uuid,
        project_id: Uuid,
        service_instance_id: Uuid,
    ) -> Result<ServiceRecord, StoreError> {
        let mut transaction = self.pool.begin().await?;
        let service = fetch_service_row(&mut transaction, service_instance_id, false)
            .await?
            .ok_or(StoreError::NotFound)?;
        if service.organization_id != organization_id || service.project_id != project_id {
            return Err(StoreError::NotFound);
        }
        if service.phase == "deleted" {
            return Err(StoreError::NotFound);
        }
        let bucket = fetch_bucket_row(&mut transaction, service_instance_id)
            .await?
            .ok_or(StoreError::CorruptData("service bucket"))?;
        let record = service.try_into_record(bucket)?;
        transaction.commit().await?;
        Ok(record)
    }

    pub async fn list_credentials(
        &self,
        organization_id: Uuid,
        project_id: Uuid,
        service_instance_id: Uuid,
    ) -> Result<Vec<CredentialRecord>, StoreError> {
        let exists: bool = sqlx::query_scalar(
            r"
            SELECT EXISTS (
                SELECT 1 FROM syouyu_service_instances
                WHERE id = $1 AND organization_id = $2 AND project_id = $3
                  AND phase <> 'deleted'
            )
            ",
        )
        .bind(service_instance_id)
        .bind(organization_id)
        .bind(project_id)
        .fetch_one(&self.pool)
        .await?;
        if !exists {
            return Err(StoreError::NotFound);
        }
        let rows = sqlx::query_as::<_, CredentialRow>(
            r"
            SELECT id, service_instance_id, name, access_key_id, permissions,
                   status, created_at, revoked_at
            FROM syouyu_credentials
            WHERE service_instance_id = $1
            ORDER BY created_at DESC, id DESC
            ",
        )
        .bind(service_instance_id)
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter()
            .map(CredentialRow::try_into_record)
            .collect()
    }

    pub async fn record_usage(
        &self,
        organization_id: Uuid,
        project_id: Uuid,
        service_instance_id: Uuid,
        bytes_used: u64,
        objects_used: u64,
        measured_at: DateTime<Utc>,
    ) -> Result<UsageRecord, StoreError> {
        let bytes = to_i64(bytes_used, "bytes_used")?;
        let objects = to_i64(objects_used, "objects_used")?;
        let mut transaction = self.pool.begin().await?;
        let bucket = sqlx::query_as::<_, BucketRow>(
            r"
            SELECT * FROM syouyu_buckets
            WHERE service_instance_id = $1 AND organization_id = $2 AND project_id = $3
            FOR UPDATE
            ",
        )
        .bind(service_instance_id)
        .bind(organization_id)
        .bind(project_id)
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or(StoreError::NotFound)?;
        sqlx::query(
            r"
            UPDATE syouyu_buckets
            SET used_bytes = $2, used_objects = $3, usage_measured_at = $4, updated_at = now()
            WHERE service_instance_id = $1
            ",
        )
        .bind(service_instance_id)
        .bind(bytes)
        .bind(objects)
        .bind(measured_at)
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            r"
            INSERT INTO syouyu_usage_snapshots (
                service_instance_id, organization_id, project_id,
                bytes_used, objects_used, measured_at
            )
            VALUES ($1, $2, $3, $4, $5, $6)
            ON CONFLICT (service_instance_id) DO UPDATE
            SET bytes_used = EXCLUDED.bytes_used,
                objects_used = EXCLUDED.objects_used,
                measured_at = EXCLUDED.measured_at,
                recorded_at = now()
            WHERE syouyu_usage_snapshots.measured_at <= EXCLUDED.measured_at
            ",
        )
        .bind(service_instance_id)
        .bind(organization_id)
        .bind(project_id)
        .bind(bytes)
        .bind(objects)
        .bind(measured_at)
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(UsageRecord {
            service_instance_id,
            bytes_used,
            objects_used,
            quota_bytes: from_i64(bucket.quota_bytes, "bucket quota_bytes")?,
            quota_objects: from_i64(bucket.quota_objects, "bucket quota_objects")?,
            measured_at,
        })
    }

    pub async fn record_audit(&self, audit: &AuditEvent) -> Result<(), StoreError> {
        let mut transaction = self.pool.begin().await?;
        insert_audit(&mut transaction, audit).await?;
        transaction.commit().await?;
        Ok(())
    }

    async fn ready_bucket_in_transaction(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        operation: &OperationRequest,
    ) -> Result<BucketRecord, StoreError> {
        let service = fetch_service_row(transaction, operation.service_instance_id, true)
            .await?
            .ok_or(StoreError::NotFound)?;
        ensure_scope(operation, service.organization_id, service.project_id)?;
        if service.phase != "ready" || service.observed_generation != service.desired_generation {
            return Err(StoreError::ServiceNotReady);
        }
        let bucket = fetch_bucket_row(transaction, operation.service_instance_id)
            .await?
            .ok_or(StoreError::CorruptData("ready service bucket"))?;
        if bucket.physical_bucket_id.is_none() {
            return Err(StoreError::CorruptData("physical bucket ID"));
        }
        Ok(bucket)
    }

    async fn existing_receipt(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        operation: &OperationRequest,
    ) -> Result<Option<Prepare<()>>, StoreError> {
        let row = sqlx::query_as::<_, ReceiptRow>(
            "SELECT * FROM syouyu_operation_receipts WHERE idempotency_key = $1 FOR UPDATE",
        )
        .bind(operation.idempotency_key)
        .fetch_optional(&mut **transaction)
        .await?;
        let Some(row) = row else {
            return Ok(None);
        };
        if !row.matches(operation) {
            return Err(StoreError::IdempotencyConflict);
        }
        if row.state == "in_progress" {
            return Ok(Some(Prepare::InProgress {
                operation_id: row.operation_id,
            }));
        }
        Ok(Some(Prepare::Replay(self.decode_receipt(&row)?)))
    }

    async fn finish_receipt(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        operation: &OperationRequest,
        operation_id: Uuid,
        response: &StoredHttpResponse,
    ) -> Result<(), StoreError> {
        let row = sqlx::query_as::<_, ReceiptRow>(
            "SELECT * FROM syouyu_operation_receipts WHERE idempotency_key = $1 FOR UPDATE",
        )
        .bind(operation.idempotency_key)
        .fetch_optional(&mut **transaction)
        .await?
        .ok_or(StoreError::CorruptData("operation receipt"))?;
        if !row.matches(operation) || row.operation_id != operation_id {
            return Err(StoreError::IdempotencyConflict);
        }
        if row.state != "in_progress" {
            if self.decode_receipt(&row)? == *response {
                return Ok(());
            }
            return Err(StoreError::Conflict(
                "operation receipt already has a different result",
            ));
        }
        let plaintext = serde_json::to_vec(&response.body)
            .map_err(|_| StoreError::CorruptData("operation response serialization"))?;
        let (nonce, ciphertext) =
            self.receipt_cipher
                .encrypt(operation.idempotency_key, operation_id, &plaintext)?;
        let state = if response.failed {
            "failed"
        } else {
            "succeeded"
        };
        sqlx::query(
            r"
            UPDATE syouyu_operation_receipts
            SET state = $2,
                response_status = $3,
                response_nonce = $4,
                response_ciphertext = $5,
                completed_at = now(),
                updated_at = now()
            WHERE idempotency_key = $1 AND state = 'in_progress'
            ",
        )
        .bind(operation.idempotency_key)
        .bind(state)
        .bind(i32::from(response.status))
        .bind(nonce.as_slice())
        .bind(ciphertext)
        .execute(&mut **transaction)
        .await?;
        Ok(())
    }

    fn decode_receipt(&self, row: &ReceiptRow) -> Result<StoredHttpResponse, StoreError> {
        let status = row
            .response_status
            .and_then(|value| u16::try_from(value).ok())
            .ok_or(StoreError::CorruptData("operation response status"))?;
        let nonce = row
            .response_nonce
            .as_deref()
            .ok_or(StoreError::CorruptData("operation response nonce"))?;
        let ciphertext = row
            .response_ciphertext
            .as_deref()
            .ok_or(StoreError::CorruptData("operation response ciphertext"))?;
        let plaintext = self.receipt_cipher.decrypt(
            row.idempotency_key,
            row.operation_id,
            nonce,
            ciphertext,
        )?;
        let body = serde_json::from_slice(&plaintext)
            .map_err(|_| StoreError::CorruptData("operation response JSON"))?;
        Ok(StoredHttpResponse {
            status,
            body,
            failed: row.state == "failed",
        })
    }
}

impl<T> Prepare<T> {
    fn map_context<U>(self) -> Prepare<U> {
        match self {
            Self::Replay(response) => Prepare::Replay(response),
            Self::InProgress { operation_id } => Prepare::InProgress { operation_id },
            Self::Execute { .. } => unreachable!("existing receipt cannot request execution"),
        }
    }
}

async fn reserve_receipt(
    transaction: &mut Transaction<'_, Postgres>,
    operation: &OperationRequest,
) -> Result<Uuid, StoreError> {
    let operation_id = Uuid::now_v7();
    sqlx::query(
        r"
        INSERT INTO syouyu_operation_receipts (
            idempotency_key, operation_id, organization_id, project_id,
            service_instance_id, principal_id, action, generation, request_hash, state
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'in_progress')
        ",
    )
    .bind(operation.idempotency_key)
    .bind(operation_id)
    .bind(operation.organization_id)
    .bind(operation.project_id)
    .bind(operation.service_instance_id)
    .bind(operation.principal_id)
    .bind(&operation.action)
    .bind(operation.generation)
    .bind(operation.request_hash.as_slice())
    .execute(&mut **transaction)
    .await
    .map_err(map_database_error)?;
    Ok(operation_id)
}

async fn require_in_progress_receipt(
    transaction: &mut Transaction<'_, Postgres>,
    operation: &OperationRequest,
    operation_id: Uuid,
) -> Result<(), StoreError> {
    let row = sqlx::query_as::<_, ReceiptIdentityRow>(
        r"
        SELECT operation_id, organization_id, project_id, service_instance_id,
               principal_id, action, generation, request_hash, state
        FROM syouyu_operation_receipts
        WHERE idempotency_key = $1
        FOR UPDATE
        ",
    )
    .bind(operation.idempotency_key)
    .fetch_optional(&mut **transaction)
    .await?
    .ok_or(StoreError::CorruptData("operation receipt"))?;
    if row.operation_id != operation_id || !row.matches(operation) {
        return Err(StoreError::IdempotencyConflict);
    }
    if row.state != "in_progress" {
        return Err(StoreError::Conflict("operation is already complete"));
    }
    Ok(())
}

async fn reject_parallel_operation(
    transaction: &mut Transaction<'_, Postgres>,
    service_instance_id: Uuid,
) -> Result<(), StoreError> {
    let operation_id = sqlx::query_scalar::<_, Uuid>(
        r"
        SELECT operation_id
        FROM syouyu_operation_receipts
        WHERE service_instance_id = $1 AND state = 'in_progress'
        ORDER BY created_at
        LIMIT 1
        ",
    )
    .bind(service_instance_id)
    .fetch_optional(&mut **transaction)
    .await?;
    if let Some(operation_id) = operation_id {
        return Err(StoreError::OperationInProgress(operation_id));
    }
    Ok(())
}

async fn reserve_bucket_name(
    transaction: &mut Transaction<'_, Postgres>,
    bucket_name: &str,
    service_instance_id: Uuid,
) -> Result<(), StoreError> {
    let result = sqlx::query(
        r"
        INSERT INTO syouyu_bucket_name_reservations (bucket_name, service_instance_id)
        VALUES ($1, $2)
        ON CONFLICT (bucket_name) DO UPDATE
        SET bucket_name = EXCLUDED.bucket_name
        WHERE syouyu_bucket_name_reservations.service_instance_id = EXCLUDED.service_instance_id
        ",
    )
    .bind(bucket_name)
    .bind(service_instance_id)
    .execute(&mut **transaction)
    .await?;
    if result.rows_affected() != 1 {
        return Err(StoreError::BucketNameUnavailable);
    }
    Ok(())
}

async fn fetch_service_row(
    transaction: &mut Transaction<'_, Postgres>,
    service_instance_id: Uuid,
    for_update: bool,
) -> Result<Option<ServiceRow>, StoreError> {
    let query = if for_update {
        "SELECT * FROM syouyu_service_instances WHERE id = $1 FOR UPDATE"
    } else {
        "SELECT * FROM syouyu_service_instances WHERE id = $1"
    };
    Ok(sqlx::query_as::<_, ServiceRow>(query)
        .bind(service_instance_id)
        .fetch_optional(&mut **transaction)
        .await?)
}

async fn fetch_bucket_row(
    transaction: &mut Transaction<'_, Postgres>,
    service_instance_id: Uuid,
) -> Result<Option<BucketRecord>, StoreError> {
    sqlx::query_as::<_, BucketRow>("SELECT * FROM syouyu_buckets WHERE service_instance_id = $1")
        .bind(service_instance_id)
        .fetch_optional(&mut **transaction)
        .await?
        .map(BucketRow::try_into_record)
        .transpose()
}

async fn insert_audit(
    transaction: &mut Transaction<'_, Postgres>,
    audit: &AuditEvent,
) -> Result<(), StoreError> {
    if audit.request_id.is_empty()
        || audit.request_id.len() > 256
        || audit.action.is_empty()
        || audit.action.len() > 128
        || audit.resource_type.is_empty()
        || audit.resource_type.len() > 64
        || !matches!(audit.outcome.as_str(), "allowed" | "denied" | "failed")
        || !audit.details.is_object()
    {
        return Err(StoreError::Validation("audit event is invalid"));
    }
    sqlx::query(
        r"
        INSERT INTO syouyu_audit_events (
            id, organization_id, project_id, service_instance_id, principal_id,
            principal_context_id, request_id, action, resource_type,
            resource_id, outcome, details
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
        ",
    )
    .bind(Uuid::now_v7())
    .bind(audit.organization_id)
    .bind(audit.project_id)
    .bind(audit.service_instance_id)
    .bind(audit.principal_id)
    .bind(audit.principal_context_id)
    .bind(&audit.request_id)
    .bind(&audit.action)
    .bind(&audit.resource_type)
    .bind(&audit.resource_id)
    .bind(&audit.outcome)
    .bind(&audit.details)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

async fn advisory_lock(
    transaction: &mut Transaction<'_, Postgres>,
    key: &str,
) -> Result<(), StoreError> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(key)
        .execute(&mut **transaction)
        .await?;
    Ok(())
}

async fn lock_service(
    transaction: &mut Transaction<'_, Postgres>,
    service_instance_id: Uuid,
) -> Result<(), StoreError> {
    advisory_lock(
        transaction,
        &format!("service-instance:{service_instance_id}"),
    )
    .await
}

fn ensure_scope(
    operation: &OperationRequest,
    organization_id: Uuid,
    project_id: Uuid,
) -> Result<(), StoreError> {
    if operation.organization_id != organization_id || operation.project_id != project_id {
        return Err(StoreError::Conflict(
            "service instance scope does not match authenticated principal",
        ));
    }
    Ok(())
}

fn to_i64(value: u64, field: &'static str) -> Result<i64, StoreError> {
    i64::try_from(value).map_err(|_| StoreError::InvalidNumericValue(field))
}

fn from_i64(value: i64, field: &'static str) -> Result<u64, StoreError> {
    u64::try_from(value).map_err(|_| StoreError::CorruptData(field))
}

fn map_database_error(error: sqlx::Error) -> StoreError {
    if let Some(database_error) = error.as_database_error()
        && database_error.is_unique_violation()
    {
        return StoreError::Conflict("resource already exists");
    }
    StoreError::Database(error)
}

#[derive(sqlx::FromRow)]
struct ServiceRow {
    id: Uuid,
    organization_id: Uuid,
    project_id: Uuid,
    name: String,
    desired_generation: i64,
    desired_spec: Value,
    observed_generation: i64,
    phase: String,
    current_operation_id: Uuid,
    #[allow(dead_code)]
    last_error: Option<String>,
    #[allow(dead_code)]
    created_at: DateTime<Utc>,
    #[allow(dead_code)]
    updated_at: DateTime<Utc>,
    #[allow(dead_code)]
    deleted_at: Option<DateTime<Utc>>,
}

impl ServiceRow {
    fn try_into_record(self, bucket: BucketRecord) -> Result<ServiceRecord, StoreError> {
        Ok(ServiceRecord {
            id: self.id,
            organization_id: self.organization_id,
            project_id: self.project_id,
            name: self.name,
            desired_generation: self.desired_generation,
            observed_generation: self.observed_generation,
            phase: self.phase,
            operation_id: self.current_operation_id,
            spec: serde_json::from_value(self.desired_spec)
                .map_err(|_| StoreError::CorruptData("service desired_spec"))?,
            bucket,
        })
    }
}

#[derive(sqlx::FromRow)]
struct BucketRow {
    service_instance_id: Uuid,
    organization_id: Uuid,
    project_id: Uuid,
    physical_bucket_id: Option<String>,
    bucket_name: String,
    region: String,
    quota_bytes: i64,
    quota_objects: i64,
    used_bytes: i64,
    used_objects: i64,
    usage_measured_at: Option<DateTime<Utc>>,
    #[allow(dead_code)]
    created_at: DateTime<Utc>,
    #[allow(dead_code)]
    updated_at: DateTime<Utc>,
}

impl BucketRow {
    fn try_into_record(self) -> Result<BucketRecord, StoreError> {
        Ok(BucketRecord {
            service_instance_id: self.service_instance_id,
            organization_id: self.organization_id,
            project_id: self.project_id,
            physical_bucket_id: self.physical_bucket_id,
            bucket_name: self.bucket_name,
            region: self.region,
            quota_bytes: from_i64(self.quota_bytes, "bucket quota_bytes")?,
            quota_objects: from_i64(self.quota_objects, "bucket quota_objects")?,
            used_bytes: from_i64(self.used_bytes, "bucket used_bytes")?,
            used_objects: from_i64(self.used_objects, "bucket used_objects")?,
            usage_measured_at: self.usage_measured_at,
        })
    }
}

#[derive(sqlx::FromRow)]
struct ReceiptRow {
    idempotency_key: Uuid,
    operation_id: Uuid,
    organization_id: Uuid,
    project_id: Uuid,
    service_instance_id: Uuid,
    principal_id: Uuid,
    action: String,
    generation: Option<i64>,
    request_hash: Vec<u8>,
    state: String,
    response_status: Option<i32>,
    response_nonce: Option<Vec<u8>>,
    response_ciphertext: Option<Vec<u8>>,
    #[allow(dead_code)]
    created_at: DateTime<Utc>,
    #[allow(dead_code)]
    completed_at: Option<DateTime<Utc>>,
    #[allow(dead_code)]
    updated_at: DateTime<Utc>,
}

impl ReceiptRow {
    fn matches(&self, operation: &OperationRequest) -> bool {
        self.organization_id == operation.organization_id
            && self.project_id == operation.project_id
            && self.service_instance_id == operation.service_instance_id
            && self.principal_id == operation.principal_id
            && self.action == operation.action
            && self.generation == operation.generation
            && self.request_hash == operation.request_hash
    }
}

#[derive(sqlx::FromRow)]
struct ReceiptIdentityRow {
    operation_id: Uuid,
    organization_id: Uuid,
    project_id: Uuid,
    service_instance_id: Uuid,
    principal_id: Uuid,
    action: String,
    generation: Option<i64>,
    request_hash: Vec<u8>,
    state: String,
}

impl ReceiptIdentityRow {
    fn matches(&self, operation: &OperationRequest) -> bool {
        self.organization_id == operation.organization_id
            && self.project_id == operation.project_id
            && self.service_instance_id == operation.service_instance_id
            && self.principal_id == operation.principal_id
            && self.action == operation.action
            && self.generation == operation.generation
            && self.request_hash == operation.request_hash
    }
}

#[derive(sqlx::FromRow)]
struct CredentialStateRow {
    garage_key_id: String,
    status: String,
}

#[derive(sqlx::FromRow)]
struct CredentialRow {
    id: Uuid,
    service_instance_id: Uuid,
    name: String,
    access_key_id: String,
    permissions: Value,
    status: String,
    created_at: DateTime<Utc>,
    revoked_at: Option<DateTime<Utc>>,
}

impl CredentialRow {
    fn try_into_record(self) -> Result<CredentialRecord, StoreError> {
        Ok(CredentialRecord {
            id: self.id,
            service_instance_id: self.service_instance_id,
            name: self.name,
            access_key_id: self.access_key_id,
            permissions: serde_json::from_value::<syouyu_domain::BucketPermissions>(
                self.permissions,
            )
            .map_err(|_| StoreError::CorruptData("credential permissions"))?,
            status: self.status,
            created_at: self.created_at,
            revoked_at: self.revoked_at,
        })
    }
}

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),
    #[error("database migration error: {0}")]
    Migration(#[from] sqlx::migrate::MigrateError),
    #[error("invalid configuration: {0}")]
    Configuration(&'static str),
    #[error("validation failed: {0}")]
    Validation(&'static str),
    #[error("validation failed: {0}")]
    DomainValidation(#[source] syouyu_domain::ValidationError),
    #[error("resource was not found")]
    NotFound,
    #[error("conflict: {0}")]
    Conflict(&'static str),
    #[error("idempotency key was reused with a different operation")]
    IdempotencyConflict,
    #[error("bucket name is already reserved")]
    BucketNameUnavailable,
    #[error("generation {requested} is stale; current generation is {current}")]
    StaleGeneration { current: i64, requested: i64 },
    #[error("operation {0} is still in progress")]
    OperationInProgress(Uuid),
    #[error("service instance is not ready")]
    ServiceNotReady,
    #[error("{scope} active credential limit of {limit} has been reached")]
    CredentialLimitExceeded { scope: &'static str, limit: u32 },
    #[error("invalid numeric value for {0}")]
    InvalidNumericValue(&'static str),
    #[error("stored data is corrupt: {0}")]
    CorruptData(&'static str),
    #[error("receipt encryption failed: {0}")]
    Encryption(&'static str),
}
