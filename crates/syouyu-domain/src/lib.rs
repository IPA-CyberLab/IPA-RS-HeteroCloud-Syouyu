use std::{fmt, net::Ipv4Addr, str::FromStr};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use url::Url;
use utoipa::ToSchema;
use uuid::Uuid;

const MAX_REGION_LENGTH: usize = 63;
const MIN_BUCKET_NAME_LENGTH: usize = 3;
const MAX_BUCKET_NAME_LENGTH: usize = 63;
const MAX_CREDENTIAL_NAME_LENGTH: usize = 128;
const MAX_BACKEND_ID_LENGTH: usize = 256;
const MAX_STATUS_MESSAGE_LENGTH: usize = 1_024;
const MAX_GARAGE_QUOTA: u64 = i64::MAX as u64;
const RESERVED_BUCKET_PREFIXES: [&str; 3] = ["xn--", "sthree-", "amzn-s3-demo-"];
const RESERVED_BUCKET_SUFFIXES: [&str; 6] = [
    "-s3alias",
    "--ol-s3",
    ".mrap",
    "--x-s3",
    "--table-s3",
    "-an",
];

/// Identifies the `HeteroCloud` tenant scope owning one Syouyu bucket.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ServiceScope {
    pub organization_id: Uuid,
    pub project_id: Uuid,
    pub service_instance_id: Uuid,
}

impl ServiceScope {
    /// Rejects nil identifiers before the scope crosses a trust boundary.
    pub fn validate(&self) -> Result<(), ValidationError> {
        ensure_uuid("organization_id", self.organization_id)?;
        ensure_uuid("project_id", self.project_id)?;
        ensure_uuid("service_instance_id", self.service_instance_id)
    }
}

/// Desired state for one Syouyu service instance.
///
/// One service instance owns exactly one globally named S3 bucket. Account-wide
/// bucket and credential limits are enforced by `HeteroCloud`, not by this spec.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct SyouyuSpec {
    pub region: String,
    pub bucket_name: String,
    pub quota_bytes: u64,
    pub quota_objects: u64,
}

impl SyouyuSpec {
    /// Validates region, S3 bucket name, and Garage-compatible quota ranges.
    pub fn validate(&self) -> Result<(), ValidationError> {
        validate_region(&self.region)?;
        validate_bucket_name(&self.bucket_name)?;
        self.quota().validate()
    }

    #[must_use]
    pub const fn quota(&self) -> BucketQuota {
        BucketQuota {
            bytes: self.quota_bytes,
            objects: self.quota_objects,
        }
    }

    #[must_use]
    pub fn bucket_spec(&self) -> BucketSpec {
        BucketSpec {
            name: self.bucket_name.clone(),
            quota: self.quota(),
        }
    }
}

/// Backend-independent desired state of the bucket represented by a service.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct BucketSpec {
    pub name: String,
    pub quota: BucketQuota,
}

impl BucketSpec {
    pub fn validate(&self) -> Result<(), ValidationError> {
        validate_bucket_name(&self.name)?;
        self.quota.validate()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct BucketQuota {
    pub bytes: u64,
    pub objects: u64,
}

impl BucketQuota {
    pub fn validate(&self) -> Result<(), ValidationError> {
        ensure_quota("quota_bytes", self.bytes)?;
        ensure_quota("quota_objects", self.objects)
    }
}

/// Permissions exposed to a bucket-scoped customer credential.
///
/// Garage's owner permission is deliberately absent. Bucket configuration is
/// controlled by Syouyu's management plane. Garage write permission includes
/// object creation, replacement, multipart upload, and deletion.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct BucketPermissions {
    #[serde(default)]
    pub read: bool,
    #[serde(default)]
    pub write: bool,
}

impl BucketPermissions {
    pub fn validate(&self) -> Result<(), ValidationError> {
        if self.read || self.write {
            Ok(())
        } else {
            Err(ValidationError::InvalidField {
                field: "permissions",
                reason: "at least one bucket permission is required",
            })
        }
    }

    #[must_use]
    pub const fn allows(self, operation: BucketOperation) -> bool {
        match operation {
            BucketOperation::List | BucketOperation::Read => self.read,
            BucketOperation::Write | BucketOperation::Delete => self.write,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum BucketOperation {
    List,
    Read,
    Write,
    Delete,
}

/// Desired state for a credential below its parent bucket service.
///
/// It intentionally contains no bucket identifier, preventing a credential
/// request from escaping the parent service-instance scope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct CredentialSpec {
    pub name: String,
    pub permissions: BucketPermissions,
}

impl CredentialSpec {
    pub fn validate(&self) -> Result<(), ValidationError> {
        validate_human_name("credential_name", &self.name, MAX_CREDENTIAL_NAME_LENGTH)?;
        self.permissions.validate()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum BucketPhase {
    Provisioning,
    Ready,
    Degraded,
    Error,
    Deleting,
    Deleted,
}

impl fmt::Display for BucketPhase {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Provisioning => "provisioning",
            Self::Ready => "ready",
            Self::Degraded => "degraded",
            Self::Error => "error",
            Self::Deleting => "deleting",
            Self::Deleted => "deleted",
        })
    }
}

impl FromStr for BucketPhase {
    type Err = ValidationError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "provisioning" => Ok(Self::Provisioning),
            "ready" => Ok(Self::Ready),
            "degraded" => Ok(Self::Degraded),
            "error" => Ok(Self::Error),
            "deleting" => Ok(Self::Deleting),
            "deleted" => Ok(Self::Deleted),
            _ => Err(ValidationError::InvalidField {
                field: "phase",
                reason: "unknown bucket phase",
            }),
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct BucketUsage {
    pub bytes: u64,
    pub objects: u64,
    #[serde(default)]
    pub unfinished_upload_bytes: u64,
    #[serde(default)]
    pub unfinished_uploads: u64,
}

impl BucketUsage {
    #[must_use]
    pub const fn exceeds(self, quota: BucketQuota) -> bool {
        self.bytes > quota.bytes || self.objects > quota.objects
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct BucketStatus {
    pub observed_generation: u64,
    pub phase: BucketPhase,
    pub backend_bucket_id: Option<String>,
    pub endpoint: Option<String>,
    #[serde(default)]
    pub usage: BucketUsage,
    pub message: Option<String>,
    pub updated_at: DateTime<Utc>,
}

impl BucketStatus {
    /// Validates status shape without treating eventually consistent usage as
    /// invalid merely because it temporarily exceeds the desired quota.
    pub fn validate(&self) -> Result<(), ValidationError> {
        if let Some(id) = &self.backend_bucket_id {
            validate_identifier("backend_bucket_id", id, MAX_BACKEND_ID_LENGTH)?;
        }
        if let Some(endpoint) = &self.endpoint {
            validate_endpoint(endpoint)?;
        }
        if let Some(message) = &self.message {
            validate_human_name("message", message, MAX_STATUS_MESSAGE_LENGTH)?;
        }

        if matches!(self.phase, BucketPhase::Ready | BucketPhase::Degraded)
            && (self.backend_bucket_id.is_none() || self.endpoint.is_none())
        {
            return Err(ValidationError::InvalidState(
                "ready or degraded buckets require a backend ID and endpoint",
            ));
        }
        if self.phase == BucketPhase::Deleted
            && (self.backend_bucket_id.is_some() || self.endpoint.is_some())
        {
            return Err(ValidationError::InvalidState(
                "deleted buckets cannot retain a backend ID or endpoint",
            ));
        }
        Ok(())
    }
}

fn ensure_uuid(field: &'static str, value: Uuid) -> Result<(), ValidationError> {
    if value.is_nil() {
        Err(ValidationError::InvalidField {
            field,
            reason: "UUID must not be nil",
        })
    } else {
        Ok(())
    }
}

fn ensure_quota(field: &'static str, value: u64) -> Result<(), ValidationError> {
    if (1..=MAX_GARAGE_QUOTA).contains(&value) {
        Ok(())
    } else {
        Err(ValidationError::OutOfRange {
            field,
            minimum: 1,
            maximum: MAX_GARAGE_QUOTA,
            actual: value,
        })
    }
}

fn validate_region(value: &str) -> Result<(), ValidationError> {
    validate_identifier("region", value, MAX_REGION_LENGTH)?;
    let bytes = value.as_bytes();
    if !bytes[0].is_ascii_alphanumeric()
        || !bytes[bytes.len() - 1].is_ascii_alphanumeric()
        || !bytes
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
    {
        return Err(ValidationError::InvalidField {
            field: "region",
            reason: "region must use lowercase letters, digits, and internal hyphens",
        });
    }
    Ok(())
}

fn validate_bucket_name(value: &str) -> Result<(), ValidationError> {
    let length = value.len();
    if !(MIN_BUCKET_NAME_LENGTH..=MAX_BUCKET_NAME_LENGTH).contains(&length) {
        return Err(ValidationError::InvalidLength {
            field: "bucket_name",
            minimum: MIN_BUCKET_NAME_LENGTH,
            maximum: MAX_BUCKET_NAME_LENGTH,
            actual: length,
        });
    }

    let bytes = value.as_bytes();
    let valid_characters = bytes.iter().all(|byte| {
        byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'-')
    });
    if !valid_characters
        || !bytes[0].is_ascii_alphanumeric()
        || !bytes[bytes.len() - 1].is_ascii_alphanumeric()
        || value.contains("..")
        || value.parse::<Ipv4Addr>().is_ok()
    {
        return Err(ValidationError::InvalidField {
            field: "bucket_name",
            reason: "bucket name is not a valid S3 general-purpose bucket name",
        });
    }

    if RESERVED_BUCKET_PREFIXES
        .iter()
        .any(|prefix| value.starts_with(prefix))
        || RESERVED_BUCKET_SUFFIXES
            .iter()
            .any(|suffix| value.ends_with(suffix))
    {
        return Err(ValidationError::InvalidField {
            field: "bucket_name",
            reason: "bucket name uses an S3-reserved prefix or suffix",
        });
    }
    Ok(())
}

fn validate_identifier(
    field: &'static str,
    value: &str,
    maximum: usize,
) -> Result<(), ValidationError> {
    if value.is_empty() || value.len() > maximum {
        return Err(ValidationError::InvalidLength {
            field,
            minimum: 1,
            maximum,
            actual: value.len(),
        });
    }
    if value.chars().any(char::is_control) {
        return Err(ValidationError::InvalidField {
            field,
            reason: "control characters are not allowed",
        });
    }
    Ok(())
}

fn validate_human_name(
    field: &'static str,
    value: &str,
    maximum: usize,
) -> Result<(), ValidationError> {
    validate_identifier(field, value, maximum)?;
    if value.trim() != value {
        return Err(ValidationError::InvalidField {
            field,
            reason: "leading or trailing whitespace is not allowed",
        });
    }
    Ok(())
}

fn validate_endpoint(value: &str) -> Result<(), ValidationError> {
    let endpoint = Url::parse(value).map_err(|_| ValidationError::InvalidField {
        field: "endpoint",
        reason: "endpoint must be an absolute URL",
    })?;
    if !matches!(endpoint.scheme(), "http" | "https")
        || endpoint.host_str().is_none()
        || !endpoint.username().is_empty()
        || endpoint.password().is_some()
        || endpoint.query().is_some()
        || endpoint.fragment().is_some()
    {
        return Err(ValidationError::InvalidField {
            field: "endpoint",
            reason: "endpoint must be an HTTP(S) origin without credentials, query, or fragment",
        });
    }
    Ok(())
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ValidationError {
    #[error("{field} length must be between {minimum} and {maximum}, got {actual}")]
    InvalidLength {
        field: &'static str,
        minimum: usize,
        maximum: usize,
        actual: usize,
    },
    #[error("{field} must be between {minimum} and {maximum}, got {actual}")]
    OutOfRange {
        field: &'static str,
        minimum: u64,
        maximum: u64,
        actual: u64,
    },
    #[error("{field} is invalid: {reason}")]
    InvalidField {
        field: &'static str,
        reason: &'static str,
    },
    #[error("invalid state: {0}")]
    InvalidState(&'static str),
}

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use uuid::Uuid;

    use super::{
        BucketOperation, BucketPermissions, BucketPhase, BucketQuota, BucketStatus, BucketUsage,
        CredentialSpec, ServiceScope, SyouyuSpec, ValidationError,
    };

    fn valid_spec() -> SyouyuSpec {
        SyouyuSpec {
            region: "heteronet-global".into(),
            bucket_name: "project-assets-019f".into(),
            quota_bytes: 10 * 1024 * 1024 * 1024,
            quota_objects: 1_000_000,
        }
    }

    #[test]
    fn validates_single_bucket_service_spec() {
        let spec = valid_spec();
        spec.validate().unwrap();
        assert_eq!(spec.bucket_spec().name, spec.bucket_name);
        assert_eq!(spec.bucket_spec().quota, spec.quota());
    }

    #[test]
    fn rejects_invalid_s3_bucket_names() {
        for name in [
            "ab",
            "Uppercase",
            "192.168.1.1",
            "two..dots",
            "xn--reserved",
            "bucket--x-s3",
            "bucket-an",
            "trailing-",
        ] {
            let mut spec = valid_spec();
            spec.bucket_name = name.into();
            assert!(spec.validate().is_err(), "{name} must be rejected");
        }
    }

    #[test]
    fn rejects_zero_and_non_garage_quotas() {
        let mut spec = valid_spec();
        spec.quota_bytes = 0;
        assert!(matches!(
            spec.validate(),
            Err(ValidationError::OutOfRange {
                field: "quota_bytes",
                ..
            })
        ));

        spec.quota_bytes = i64::MAX as u64 + 1;
        assert!(spec.validate().is_err());
    }

    #[test]
    fn credential_is_parent_scoped_and_requires_permissions() {
        let spec = CredentialSpec {
            name: "flash-workspace".into(),
            permissions: BucketPermissions {
                read: true,
                write: false,
            },
        };
        spec.validate().unwrap();
        let encoded = serde_json::to_value(&spec).unwrap();
        assert!(encoded.get("bucket_id").is_none());
        assert!(spec.permissions.allows(BucketOperation::Read));
        assert!(!spec.permissions.allows(BucketOperation::Delete));

        let mut invalid = spec;
        invalid.permissions = BucketPermissions::default();
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn validates_scope_and_status_invariants() {
        let scope = ServiceScope {
            organization_id: Uuid::new_v4(),
            project_id: Uuid::new_v4(),
            service_instance_id: Uuid::new_v4(),
        };
        scope.validate().unwrap();

        let status = BucketStatus {
            observed_generation: 2,
            phase: BucketPhase::Ready,
            backend_bucket_id: Some("garage-bucket-id".into()),
            endpoint: Some("https://s3.syouyu.heterocloud.example".into()),
            usage: BucketUsage::default(),
            message: None,
            updated_at: Utc::now(),
        };
        status.validate().unwrap();

        let invalid = BucketStatus {
            endpoint: None,
            ..status
        };
        assert!(matches!(
            invalid.validate(),
            Err(ValidationError::InvalidState(_))
        ));
    }

    #[test]
    fn reports_usage_over_either_quota_dimension() {
        let quota = BucketQuota {
            bytes: 1_000,
            objects: 10,
        };
        assert!(
            BucketUsage {
                bytes: 1_001,
                ..BucketUsage::default()
            }
            .exceeds(quota)
        );
        assert!(
            BucketUsage {
                objects: 11,
                ..BucketUsage::default()
            }
            .exceeds(quota)
        );
    }
}
