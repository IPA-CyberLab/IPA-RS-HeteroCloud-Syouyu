use std::env;

use serde_json::json;
use syouyu_domain::BucketPermissions;
use syouyu_store::{
    AuditEvent, CreateCredentialCommand, CredentialLimits, NewCredential, OperationRequest,
    PgStore, Prepare, ReconcileCommand, StoreError, StoredHttpResponse, TargetSpec, request_hash,
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
    let scope = Scope {
        organization_id: Uuid::new_v4(),
        project_id: Uuid::new_v4(),
        service_instance_id: Uuid::new_v4(),
        principal_id: Uuid::new_v4(),
    };
    let spec = TargetSpec {
        region: "heteronet-global".into(),
        bucket_name: format!("bucket-{}", scope.service_instance_id.simple()),
        quota_bytes: 10_000_000,
        quota_objects: 10_000,
    };
    let body = json!({"generation": 1, "name": "store-test", "spec": spec});
    let command = ReconcileCommand {
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
    };
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
