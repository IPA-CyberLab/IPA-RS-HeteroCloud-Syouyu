use std::env;

use serde_json::json;
use syouyu_domain::BucketPermissions;
use syouyu_store::{
    AuditEvent, CreateCredentialCommand, CredentialLimits, DeleteCommand, NewCredential,
    OperationRequest, PgStore, Prepare, ReconcileCommand, RevokeCredentialCommand, StoreError,
    StoredHttpResponse, TargetSpec, request_hash,
};
use tokio::sync::Mutex;
use uuid::Uuid;

static DATABASE_TEST_LOCK: Mutex<()> = Mutex::const_new(());

#[derive(Clone, Copy)]
#[allow(clippy::struct_field_names)]
struct Scope {
    organization_id: Uuid,
    project_id: Uuid,
    service_instance_id: Uuid,
    principal_id: Uuid,
}

#[tokio::test]
async fn completed_receipt_replays_without_plaintext_secret() {
    let _guard = DATABASE_TEST_LOCK.lock().await;
    let Some(store) = test_store(CredentialLimits::default()).await else {
        return;
    };
    let scope = provision_service(&store).await;
    let request = json!({
        "name": "flash-workspace",
        "permissions": {"read": true, "write": true}
    });
    let command = CreateCredentialCommand {
        operation: operation(
            scope,
            "credential.create",
            request_hash("credential.create", &request).unwrap(),
        ),
        name: "flash-workspace".into(),
        permissions: BucketPermissions {
            read: true,
            write: true,
        },
        credential_limits: CredentialLimits::default(),
    };
    let Prepare::Execute {
        operation_id,
        context,
    } = store.prepare_create_credential(&command).await.unwrap()
    else {
        panic!("first request must execute");
    };
    let secret = "garage-secret-value-that-must-not-appear-in-postgres";
    let response = StoredHttpResponse {
        status: 201,
        body: json!({
            "credential": {"id": context.credential_id},
            "secret_access_key": secret
        }),
        failed: false,
    };
    let credential = NewCredential {
        id: context.credential_id,
        garage_key_id: "garage-key-1".into(),
        access_key_id: "access-key-1".into(),
        secret_key_fingerprint: sha256(secret),
        name: command.name.clone(),
        permissions: command.permissions,
    };
    store
        .complete_create_credential(
            &command,
            operation_id,
            &credential,
            &response,
            &audit(
                scope,
                "credential.create",
                context.credential_id.to_string(),
            ),
        )
        .await
        .unwrap();

    let replay = store.prepare_create_credential(&command).await.unwrap();
    assert_eq!(replay, Prepare::Replay(response));
    let ciphertext: Vec<u8> = sqlx::query_scalar(
        "SELECT response_ciphertext FROM syouyu_operation_receipts WHERE idempotency_key = $1",
    )
    .bind(command.operation.idempotency_key)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert!(
        !ciphertext
            .windows(secret.len())
            .any(|bytes| bytes == secret.as_bytes())
    );
    let persisted_secret_columns: i64 = sqlx::query_scalar(
        r"
        SELECT count(*)
        FROM information_schema.columns
        WHERE table_schema = current_schema()
          AND table_name = 'syouyu_credentials'
          AND column_name IN ('secret', 'secret_key', 'secret_access_key')
        ",
    )
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(persisted_secret_columns, 0);
}

#[tokio::test]
async fn pending_reservations_enforce_bucket_credential_limit() {
    let _guard = DATABASE_TEST_LOCK.lock().await;
    let Some(store) = test_store(CredentialLimits {
        max_credentials_per_bucket: 1,
        max_total_credentials: 10,
    })
    .await
    else {
        return;
    };
    let scope = provision_service(&store).await;
    let first = credential_command(scope, "first");
    assert!(matches!(
        store.prepare_create_credential(&first).await.unwrap(),
        Prepare::Execute { .. }
    ));

    let second = credential_command(scope, "second");
    assert!(matches!(
        store.prepare_create_credential(&second).await,
        Err(StoreError::CredentialLimitExceeded {
            scope: "bucket",
            limit: 1
        })
    ));
}

#[tokio::test]
async fn idempotency_key_reuse_with_different_body_is_rejected() {
    let _guard = DATABASE_TEST_LOCK.lock().await;
    let Some(store) = test_store(CredentialLimits::default()).await else {
        return;
    };
    let scope = provision_service(&store).await;
    let first = credential_command(scope, "first");
    store.prepare_create_credential(&first).await.unwrap();
    let mut replay = credential_command(scope, "other-name");
    replay.operation.idempotency_key = first.operation.idempotency_key;
    assert!(matches!(
        store.prepare_create_credential(&replay).await,
        Err(StoreError::IdempotencyConflict)
    ));
}

#[tokio::test]
async fn stale_credential_lease_has_one_takeover_and_keeps_its_reservation() {
    let _guard = DATABASE_TEST_LOCK.lock().await;
    let Some(store) = test_store(CredentialLimits::default()).await else {
        return;
    };
    let scope = provision_service(&store).await;
    let command = credential_command(scope, "takeover-key");
    let Prepare::Execute {
        operation_id: abandoned_operation_id,
        context: abandoned_context,
    } = store.prepare_create_credential(&command).await.unwrap()
    else {
        panic!("first credential request must execute");
    };
    expire_lease(&store, command.operation.idempotency_key).await;

    let first_store = store.clone();
    let first_command = command.clone();
    let second_store = store.clone();
    let second_command = command.clone();
    let (first, second) = tokio::join!(
        async move {
            first_store
                .prepare_create_credential(&first_command)
                .await
                .unwrap()
        },
        async move {
            second_store
                .prepare_create_credential(&second_command)
                .await
                .unwrap()
        }
    );
    let (operation_id, context, in_progress_id) = match (first, second) {
        (
            Prepare::Execute {
                operation_id,
                context,
            },
            Prepare::InProgress {
                operation_id: in_progress_id,
            },
        )
        | (
            Prepare::InProgress {
                operation_id: in_progress_id,
            },
            Prepare::Execute {
                operation_id,
                context,
            },
        ) => (operation_id, context, in_progress_id),
        other => panic!("exactly one caller must take over the stale lease: {other:?}"),
    };
    assert_eq!(operation_id, in_progress_id);
    assert_ne!(operation_id, abandoned_operation_id);
    assert_eq!(context.credential_id, abandoned_context.credential_id);
    let reservation_operation_id: Uuid = sqlx::query_scalar(
        "SELECT operation_id FROM syouyu_credential_reservations WHERE credential_id = $1",
    )
    .bind(context.credential_id)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(reservation_operation_id, operation_id);
    let failed_response = StoredHttpResponse {
        status: 502,
        body: json!({"error": "late failure"}),
        failed: true,
    };
    assert!(matches!(
        store
            .fail_operation(
                &command.operation,
                abandoned_operation_id,
                &failed_response,
                &audit(
                    scope,
                    "credential.create",
                    context.credential_id.to_string(),
                ),
            )
            .await,
        Err(StoreError::OperationLeaseLost {
            current_operation_id
        }) if current_operation_id == operation_id
    ));
    let reservations_after_late_failure: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM syouyu_credential_reservations WHERE credential_id = $1 AND operation_id = $2",
    )
    .bind(context.credential_id)
    .bind(operation_id)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(reservations_after_late_failure, 1);

    let response = StoredHttpResponse {
        status: 201,
        body: json!({"credential_id": context.credential_id}),
        failed: false,
    };
    let credential = NewCredential {
        id: context.credential_id,
        garage_key_id: "garage-key-takeover".into(),
        access_key_id: "access-key-takeover".into(),
        secret_key_fingerprint: sha256("takeover-secret"),
        name: command.name.clone(),
        permissions: command.permissions,
    };
    assert!(matches!(
        store
            .complete_create_credential(
                &command,
                abandoned_operation_id,
                &credential,
                &response,
                &audit(
                    scope,
                    "credential.create",
                    context.credential_id.to_string(),
                ),
            )
            .await,
        Err(StoreError::OperationLeaseLost {
            current_operation_id
        }) if current_operation_id == operation_id
    ));
    store
        .complete_create_credential(
            &command,
            operation_id,
            &credential,
            &response,
            &audit(
                scope,
                "credential.create",
                context.credential_id.to_string(),
            ),
        )
        .await
        .unwrap();

    let reservations: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM syouyu_credential_reservations WHERE service_instance_id = $1",
    )
    .bind(scope.service_instance_id)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(reservations, 0);
    let lease_attempt: i64 = sqlx::query_scalar(
        "SELECT lease_attempt FROM syouyu_operation_receipts WHERE idempotency_key = $1",
    )
    .bind(command.operation.idempotency_key)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(lease_attempt, 2);
    assert_eq!(
        store.prepare_create_credential(&command).await.unwrap(),
        Prepare::Replay(response)
    );
}

#[tokio::test]
async fn stale_reconcile_replays_external_partial_success_safely() {
    let _guard = DATABASE_TEST_LOCK.lock().await;
    let Some(store) = test_store(CredentialLimits::default()).await else {
        return;
    };
    let scope = new_scope();
    let command = reconcile_command(scope);
    let Prepare::Execute {
        operation_id: abandoned_operation_id,
        context: first_context,
    } = store.prepare_reconcile(&command).await.unwrap()
    else {
        panic!("first reconcile must execute");
    };
    assert!(first_context.bucket.physical_bucket_id.is_none());
    expire_lease(&store, command.operation.idempotency_key).await;

    let Prepare::Execute {
        operation_id,
        context,
    } = store.prepare_reconcile(&command).await.unwrap()
    else {
        panic!("stale reconcile must be taken over");
    };
    assert_ne!(operation_id, abandoned_operation_id);
    assert_eq!(context.bucket.bucket_name, command.spec.bucket_name);
    assert!(context.bucket.physical_bucket_id.is_none());
    let response = StoredHttpResponse {
        status: 202,
        body: json!({"status": "ready"}),
        failed: false,
    };
    assert!(matches!(
        store
            .complete_reconcile(
                &command,
                abandoned_operation_id,
                "garage-partial-bucket",
                &response,
                &audit(
                    scope,
                    "service-instance.reconcile",
                    scope.service_instance_id.to_string(),
                ),
            )
            .await,
        Err(StoreError::OperationLeaseLost { .. })
    ));
    store
        .complete_reconcile(
            &command,
            operation_id,
            "garage-partial-bucket",
            &response,
            &audit(
                scope,
                "service-instance.reconcile",
                scope.service_instance_id.to_string(),
            ),
        )
        .await
        .unwrap();
    assert_eq!(
        store.prepare_reconcile(&command).await.unwrap(),
        Prepare::Replay(response)
    );
}

#[tokio::test]
async fn stale_delete_can_repeat_key_and_bucket_removal() {
    let _guard = DATABASE_TEST_LOCK.lock().await;
    let Some(store) = test_store(CredentialLimits::default()).await else {
        return;
    };
    let scope = provision_service(&store).await;
    let (_, garage_key_id) = create_active_credential(&store, scope, "delete-key").await;
    let command = delete_command(scope, 2);
    let Prepare::Execute {
        operation_id: abandoned_operation_id,
        context: first_context,
    } = store.prepare_delete(&command).await.unwrap()
    else {
        panic!("first delete must execute");
    };
    assert_eq!(first_context.garage_key_ids, vec![garage_key_id.clone()]);
    expire_lease(&store, command.operation.idempotency_key).await;

    let Prepare::Execute {
        operation_id,
        context,
    } = store.prepare_delete(&command).await.unwrap()
    else {
        panic!("stale delete must be taken over");
    };
    assert_eq!(context.garage_key_ids, vec![garage_key_id]);
    assert_ne!(operation_id, abandoned_operation_id);
    let response = StoredHttpResponse {
        status: 200,
        body: json!({"status": "deleted"}),
        failed: false,
    };
    store
        .complete_delete(
            &command,
            operation_id,
            &response,
            &audit(
                scope,
                "service-instance.delete",
                scope.service_instance_id.to_string(),
            ),
        )
        .await
        .unwrap();
    assert_eq!(
        store.prepare_delete(&command).await.unwrap(),
        Prepare::Replay(response)
    );
}

#[tokio::test]
async fn stale_revoke_can_repeat_backend_revocation() {
    let _guard = DATABASE_TEST_LOCK.lock().await;
    let Some(store) = test_store(CredentialLimits::default()).await else {
        return;
    };
    let scope = provision_service(&store).await;
    let (credential_id, garage_key_id) =
        create_active_credential(&store, scope, "revoke-key").await;
    let command = revoke_command(scope, credential_id);
    let Prepare::Execute {
        operation_id: abandoned_operation_id,
        context: first_context,
    } = store.prepare_revoke_credential(&command).await.unwrap()
    else {
        panic!("first revoke must execute");
    };
    assert_eq!(first_context.garage_key_id, garage_key_id);
    assert!(!first_context.already_revoked);
    expire_lease(&store, command.operation.idempotency_key).await;

    let Prepare::Execute {
        operation_id,
        context,
    } = store.prepare_revoke_credential(&command).await.unwrap()
    else {
        panic!("stale revoke must be taken over");
    };
    assert_eq!(context.garage_key_id, first_context.garage_key_id);
    assert!(!context.already_revoked);
    assert_ne!(operation_id, abandoned_operation_id);
    let response = StoredHttpResponse {
        status: 200,
        body: json!({"status": "revoked"}),
        failed: false,
    };
    store
        .complete_revoke_credential(
            &command,
            operation_id,
            &response,
            &audit(scope, "credential.revoke", credential_id.to_string()),
        )
        .await
        .unwrap();
    assert_eq!(
        store.prepare_revoke_credential(&command).await.unwrap(),
        Prepare::Replay(response)
    );
}

#[tokio::test]
async fn failed_credential_operation_releases_reservation() {
    let _guard = DATABASE_TEST_LOCK.lock().await;
    let Some(store) = test_store(CredentialLimits::default()).await else {
        return;
    };
    let scope = provision_service(&store).await;
    let command = credential_command(scope, "failed-key");
    let Prepare::Execute { operation_id, .. } =
        store.prepare_create_credential(&command).await.unwrap()
    else {
        panic!("credential request must execute");
    };
    let response = StoredHttpResponse {
        status: 502,
        body: json!({"error": "backend unavailable"}),
        failed: true,
    };
    store
        .fail_operation(
            &command.operation,
            operation_id,
            &response,
            &audit(scope, "credential.create", "failed-key".into()),
        )
        .await
        .unwrap();
    let reservations: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM syouyu_credential_reservations WHERE service_instance_id = $1",
    )
    .bind(scope.service_instance_id)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(reservations, 0);
}

async fn test_store(limits: CredentialLimits) -> Option<PgStore> {
    let Ok(database_url) = env::var("TEST_DATABASE_URL") else {
        eprintln!("TEST_DATABASE_URL is not set; skipping PostgreSQL integration test");
        return None;
    };
    let store = PgStore::connect(&database_url, 8, &[9; 32], limits)
        .await
        .unwrap();
    store.migrate().await.unwrap();
    sqlx::query(
        r"
        TRUNCATE TABLE
            syouyu_usage_snapshots,
            syouyu_audit_events,
            syouyu_operation_receipts,
            syouyu_credential_reservations,
            syouyu_credentials,
            syouyu_buckets,
            syouyu_bucket_name_reservations,
            syouyu_service_instances
        CASCADE
        ",
    )
    .execute(store.pool())
    .await
    .unwrap();
    Some(store)
}

async fn provision_service(store: &PgStore) -> Scope {
    let scope = new_scope();
    let command = reconcile_command(scope);
    let Prepare::Execute { operation_id, .. } = store.prepare_reconcile(&command).await.unwrap()
    else {
        panic!("service reconcile must execute");
    };
    let response = StoredHttpResponse {
        status: 202,
        body: json!({"operation_id": operation_id, "status": "ready"}),
        failed: false,
    };
    store
        .complete_reconcile(
            &command,
            operation_id,
            &format!("garage-{}", scope.service_instance_id),
            &response,
            &audit(
                scope,
                "service-instance.reconcile",
                scope.service_instance_id.to_string(),
            ),
        )
        .await
        .unwrap();
    scope
}

fn new_scope() -> Scope {
    Scope {
        organization_id: Uuid::new_v4(),
        project_id: Uuid::new_v4(),
        service_instance_id: Uuid::new_v4(),
        principal_id: Uuid::new_v4(),
    }
}

fn reconcile_command(scope: Scope) -> ReconcileCommand {
    let spec = TargetSpec {
        region: "heteronet-global".into(),
        bucket_name: format!("bucket-{}", scope.service_instance_id.simple()),
        quota_bytes: 10_000_000,
        quota_objects: 10_000,
    };
    let body = json!({"generation": 1, "name": "store-test", "spec": spec});
    ReconcileCommand {
        operation: OperationRequest {
            generation: Some(1),
            ..operation(
                scope,
                "service-instance.reconcile",
                request_hash("service-instance.reconcile", &body).unwrap(),
            )
        },
        name: "store-test".into(),
        generation: 1,
        spec,
    }
}

fn credential_command(scope: Scope, name: &str) -> CreateCredentialCommand {
    let body = json!({
        "name": name,
        "permissions": {"read": true, "write": false}
    });
    CreateCredentialCommand {
        operation: operation(
            scope,
            "credential.create",
            request_hash("credential.create", &body).unwrap(),
        ),
        name: name.into(),
        permissions: BucketPermissions {
            read: true,
            write: false,
        },
        credential_limits: CredentialLimits::default(),
    }
}

async fn create_active_credential(store: &PgStore, scope: Scope, name: &str) -> (Uuid, String) {
    let command = credential_command(scope, name);
    let Prepare::Execute {
        operation_id,
        context,
    } = store.prepare_create_credential(&command).await.unwrap()
    else {
        panic!("credential request must execute");
    };
    let garage_key_id = format!("garage-key-{}", context.credential_id);
    let response = StoredHttpResponse {
        status: 201,
        body: json!({"credential_id": context.credential_id}),
        failed: false,
    };
    store
        .complete_create_credential(
            &command,
            operation_id,
            &NewCredential {
                id: context.credential_id,
                garage_key_id: garage_key_id.clone(),
                access_key_id: format!("access-key-{}", context.credential_id),
                secret_key_fingerprint: sha256("test-secret"),
                name: command.name.clone(),
                permissions: command.permissions,
            },
            &response,
            &audit(
                scope,
                "credential.create",
                context.credential_id.to_string(),
            ),
        )
        .await
        .unwrap();
    (context.credential_id, garage_key_id)
}

fn delete_command(scope: Scope, generation: i64) -> DeleteCommand {
    let body = json!({
        "service_instance_id": scope.service_instance_id,
        "generation": generation
    });
    DeleteCommand {
        operation: OperationRequest {
            generation: Some(generation),
            ..operation(
                scope,
                "service-instance.delete",
                request_hash("service-instance.delete", &body).unwrap(),
            )
        },
        generation,
    }
}

fn revoke_command(scope: Scope, credential_id: Uuid) -> RevokeCredentialCommand {
    let body = json!({"credential_id": credential_id});
    RevokeCredentialCommand {
        operation: operation(
            scope,
            "credential.revoke",
            request_hash("credential.revoke", &body).unwrap(),
        ),
        credential_id,
    }
}

async fn expire_lease(store: &PgStore, idempotency_key: Uuid) {
    let updated = sqlx::query(
        r"
        UPDATE syouyu_operation_receipts
        SET lease_expires_at = now() - interval '1 second'
        WHERE idempotency_key = $1 AND state = 'in_progress'
        ",
    )
    .bind(idempotency_key)
    .execute(store.pool())
    .await
    .unwrap();
    assert_eq!(updated.rows_affected(), 1);
}

fn operation(scope: Scope, action: &str, hash: [u8; 32]) -> OperationRequest {
    OperationRequest {
        idempotency_key: Uuid::new_v4(),
        organization_id: scope.organization_id,
        project_id: scope.project_id,
        service_instance_id: scope.service_instance_id,
        principal_id: scope.principal_id,
        action: action.into(),
        generation: None,
        request_hash: hash,
    }
}

fn audit(scope: Scope, action: &str, resource_id: String) -> AuditEvent {
    AuditEvent {
        organization_id: scope.organization_id,
        project_id: scope.project_id,
        service_instance_id: scope.service_instance_id,
        principal_id: scope.principal_id,
        principal_context_id: None,
        request_id: Uuid::new_v4().to_string(),
        action: action.into(),
        resource_type: "test".into(),
        resource_id: Some(resource_id),
        outcome: "allowed".into(),
        details: json!({}),
    }
}

fn sha256(value: &str) -> [u8; 32] {
    use sha2::{Digest, Sha256};

    Sha256::digest(value.as_bytes()).into()
}
