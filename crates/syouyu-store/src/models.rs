use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use syouyu_domain::{BucketPermissions, SyouyuSpec};
use uuid::Uuid;

use crate::StoreError;

pub type TargetSpec = SyouyuSpec;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialLimits {
    pub max_credentials_per_bucket: u32,
    pub max_total_credentials: u32,
}

impl CredentialLimits {
    pub fn validate(self) -> Result<Self, StoreError> {
        if self.max_credentials_per_bucket == 0 || self.max_total_credentials == 0 {
            return Err(StoreError::Configuration(
                "credential limits must both be positive",
            ));
        }
        Ok(self)
    }
}

impl Default for CredentialLimits {
    fn default() -> Self {
        Self {
            max_credentials_per_bucket: 10_000,
            max_total_credentials: 1_000_000,
        }
    }
}

#[derive(Debug, Clone)]
pub struct OperationRequest {
    pub idempotency_key: Uuid,
    pub organization_id: Uuid,
    pub project_id: Uuid,
    pub service_instance_id: Uuid,
    pub principal_id: Uuid,
    pub action: String,
    pub generation: Option<i64>,
    pub request_hash: [u8; 32],
}

impl OperationRequest {
    pub fn validate(&self) -> Result<(), StoreError> {
        if self.action.is_empty() || self.action.len() > 128 {
            return Err(StoreError::Validation(
                "operation action must contain between 1 and 128 bytes",
            ));
        }
        if self.generation.is_some_and(|generation| generation <= 0) {
            return Err(StoreError::Validation(
                "operation generation must be positive",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct ReconcileCommand {
    pub operation: OperationRequest,
    pub name: String,
    pub generation: i64,
    pub spec: TargetSpec,
}

impl ReconcileCommand {
    pub fn validate(&self) -> Result<(), StoreError> {
        self.operation.validate()?;
        if self.operation.generation != Some(self.generation) {
            return Err(StoreError::Validation(
                "operation and reconcile generations do not match",
            ));
        }
        if self.name.is_empty() || self.name.len() > 120 {
            return Err(StoreError::Validation(
                "service name must contain between 1 and 120 bytes",
            ));
        }
        self.spec.validate().map_err(StoreError::DomainValidation)
    }
}

#[derive(Debug, Clone)]
pub struct DeleteCommand {
    pub operation: OperationRequest,
    pub generation: i64,
}

impl DeleteCommand {
    pub fn validate(&self) -> Result<(), StoreError> {
        self.operation.validate()?;
        if self.operation.generation != Some(self.generation) {
            return Err(StoreError::Validation(
                "operation and delete generations do not match",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StoredHttpResponse {
    pub status: u16,
    pub body: Value,
    pub failed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Prepare<T> {
    Execute { operation_id: Uuid, context: T },
    Replay(StoredHttpResponse),
    InProgress { operation_id: Uuid },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BucketRecord {
    pub service_instance_id: Uuid,
    pub organization_id: Uuid,
    pub project_id: Uuid,
    pub physical_bucket_id: Option<String>,
    pub bucket_name: String,
    pub region: String,
    pub quota_bytes: u64,
    pub quota_objects: u64,
    pub used_bytes: u64,
    pub used_objects: u64,
    pub usage_measured_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ServiceRecord {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub project_id: Uuid,
    pub name: String,
    pub desired_generation: i64,
    pub observed_generation: i64,
    pub phase: String,
    pub operation_id: Uuid,
    pub spec: TargetSpec,
    pub bucket: BucketRecord,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReconcileContext {
    pub bucket: BucketRecord,
    pub previously_applied: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeleteContext {
    pub bucket: BucketRecord,
    pub garage_key_ids: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct CreateCredentialCommand {
    pub operation: OperationRequest,
    pub name: String,
    pub permissions: BucketPermissions,
    pub credential_limits: CredentialLimits,
}

impl CreateCredentialCommand {
    pub fn validate(&self) -> Result<(), StoreError> {
        self.operation.validate()?;
        self.credential_limits.validate()?;
        syouyu_domain::CredentialSpec {
            name: self.name.clone(),
            permissions: self.permissions,
        }
        .validate()
        .map_err(StoreError::DomainValidation)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateCredentialContext {
    pub bucket: BucketRecord,
    pub credential_id: Uuid,
}

#[derive(Debug, Clone)]
pub struct RevokeCredentialCommand {
    pub operation: OperationRequest,
    pub credential_id: Uuid,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevokeCredentialContext {
    pub garage_key_id: String,
    pub already_revoked: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CredentialRecord {
    pub id: Uuid,
    pub service_instance_id: Uuid,
    pub name: String,
    pub access_key_id: String,
    pub permissions: BucketPermissions,
    pub status: String,
    pub created_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UsageRecord {
    pub service_instance_id: Uuid,
    pub bytes_used: u64,
    pub objects_used: u64,
    pub quota_bytes: u64,
    pub quota_objects: u64,
    pub measured_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct NewCredential {
    pub id: Uuid,
    pub garage_key_id: String,
    pub access_key_id: String,
    pub secret_key_fingerprint: [u8; 32],
    pub name: String,
    pub permissions: BucketPermissions,
}

#[derive(Debug, Clone)]
pub struct AuditEvent {
    pub organization_id: Uuid,
    pub project_id: Uuid,
    pub service_instance_id: Uuid,
    pub principal_id: Uuid,
    pub principal_context_id: Option<Uuid>,
    pub request_id: String,
    pub action: String,
    pub resource_type: String,
    pub resource_id: Option<String>,
    pub outcome: String,
    pub details: Value,
}

pub fn request_hash<T: Serialize>(action: &str, request: &T) -> Result<[u8; 32], StoreError> {
    use sha2::{Digest, Sha256};

    let encoded = serde_json::to_vec(request)
        .map_err(|_| StoreError::CorruptData("operation request serialization"))?;
    let mut digest = Sha256::new();
    digest.update(b"syouyu-operation-v1\0");
    digest.update(action.as_bytes());
    digest.update(b"\0");
    digest.update(encoded);
    Ok(digest.finalize().into())
}

#[cfg(test)]
mod tests {
    use super::request_hash;

    #[test]
    fn operation_hash_binds_action_and_body() {
        let body = serde_json::json!({"value": 1});
        assert_eq!(
            request_hash("credential.create", &body).unwrap(),
            request_hash("credential.create", &body).unwrap()
        );
        assert_ne!(
            request_hash("credential.create", &body).unwrap(),
            request_hash("credential.revoke", &body).unwrap()
        );
    }
}
