use async_trait::async_trait;
use secrecy::ExposeSecret;
use syouyu_domain::{BucketPermissions, BucketUsage, SyouyuSpec};
use syouyu_garage::{
    BucketKeyPermissions, BucketQuotas, ClusterHealthStatus, CreateKeyRequest, GarageAdminClient,
    GarageError,
};
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReconciledBucket {
    pub physical_bucket_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuedCredential {
    pub garage_key_id: String,
    pub access_key_id: String,
    pub secret_access_key: String,
}

#[async_trait]
pub trait Garage: Send + Sync {
    async fn health(&self) -> Result<(), GarageBackendError>;

    async fn reconcile_bucket(
        &self,
        existing_physical_bucket_id: Option<&str>,
        spec: &SyouyuSpec,
    ) -> Result<ReconciledBucket, GarageBackendError>;

    async fn bucket_usage(
        &self,
        physical_bucket_id: &str,
    ) -> Result<BucketUsage, GarageBackendError>;

    async fn create_credential(
        &self,
        physical_bucket_id: &str,
        deterministic_name: &str,
        permissions: BucketPermissions,
    ) -> Result<IssuedCredential, GarageBackendError>;

    async fn revoke_credential(&self, garage_key_id: &str) -> Result<(), GarageBackendError>;

    async fn delete_bucket(&self, physical_bucket_id: &str) -> Result<(), GarageBackendError>;
}

#[derive(Clone)]
pub struct GarageAdapter {
    client: GarageAdminClient,
}

impl GarageAdapter {
    #[must_use]
    pub const fn new(client: GarageAdminClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl Garage for GarageAdapter {
    async fn health(&self) -> Result<(), GarageBackendError> {
        let health = self
            .client
            .health()
            .await
            .map_err(GarageBackendError::from)?;
        if health.status == ClusterHealthStatus::Unavailable
            || health.storage_nodes_up == 0
            || health.partitions_quorum < health.partitions
        {
            return Err(GarageBackendError::Unavailable(
                "Garage does not currently have write quorum".into(),
            ));
        }
        Ok(())
    }

    async fn reconcile_bucket(
        &self,
        existing_physical_bucket_id: Option<&str>,
        spec: &SyouyuSpec,
    ) -> Result<ReconciledBucket, GarageBackendError> {
        let bucket = if let Some(bucket_id) = existing_physical_bucket_id {
            let bucket = self
                .client
                .get_bucket(bucket_id)
                .await
                .map_err(GarageBackendError::from)?;
            if !bucket
                .global_aliases
                .iter()
                .any(|name| name == &spec.bucket_name)
            {
                return Err(GarageBackendError::Conflict(
                    "bucket_name is immutable after service creation".into(),
                ));
            }
            bucket
        } else {
            match self.client.get_bucket_by_alias(&spec.bucket_name).await {
                Ok(bucket) => bucket,
                Err(error) if error.is_not_found() => self
                    .client
                    .create_bucket(&spec.bucket_name)
                    .await
                    .map_err(GarageBackendError::from)?,
                Err(error) => return Err(GarageBackendError::from(error)),
            }
        };
        let quotas = BucketQuotas::limited(spec.quota_bytes, spec.quota_objects);
        let bucket = self
            .client
            .update_bucket_quotas(&bucket.id, quotas)
            .await
            .map_err(GarageBackendError::from)?;
        Ok(ReconciledBucket {
            physical_bucket_id: bucket.id,
        })
    }

    async fn bucket_usage(
        &self,
        physical_bucket_id: &str,
    ) -> Result<BucketUsage, GarageBackendError> {
        let bucket = self
            .client
            .get_bucket(physical_bucket_id)
            .await
            .map_err(GarageBackendError::from)?;
        Ok(BucketUsage {
            bytes: bucket.bytes,
            objects: bucket.objects,
            unfinished_upload_bytes: bucket.unfinished_multipart_upload_bytes,
            unfinished_uploads: bucket
                .unfinished_uploads
                .saturating_add(bucket.unfinished_multipart_uploads),
        })
    }

    async fn create_credential(
        &self,
        physical_bucket_id: &str,
        deterministic_name: &str,
        permissions: BucketPermissions,
    ) -> Result<IssuedCredential, GarageBackendError> {
        let key = self
            .client
            .create_key(&CreateKeyRequest::new(deterministic_name, None))
            .await
            .map_err(GarageBackendError::from)?;
        let access_key_id = key.access_key_id;
        let Some(secret_access_key) = key.secret_access_key else {
            let _ = self.client.delete_key(&access_key_id).await;
            return Err(GarageBackendError::InvalidResponse(
                "Garage omitted secretAccessKey from CreateKey".into(),
            ));
        };
        if let Err(error) = self
            .client
            .set_bucket_key_permissions(
                physical_bucket_id,
                &access_key_id,
                BucketKeyPermissions::from(permissions),
            )
            .await
        {
            let _ = self.client.delete_key(&access_key_id).await;
            return Err(GarageBackendError::from(error));
        }
        Ok(IssuedCredential {
            garage_key_id: access_key_id.clone(),
            access_key_id,
            secret_access_key: secret_access_key.expose_secret().to_owned(),
        })
    }

    async fn revoke_credential(&self, garage_key_id: &str) -> Result<(), GarageBackendError> {
        match self.client.delete_key(garage_key_id).await {
            Ok(()) => Ok(()),
            Err(error) if error.is_not_found() => Ok(()),
            Err(error) => Err(GarageBackendError::from(error)),
        }
    }

    async fn delete_bucket(&self, physical_bucket_id: &str) -> Result<(), GarageBackendError> {
        match self.client.delete_bucket(physical_bucket_id).await {
            Ok(()) => Ok(()),
            Err(error) if error.is_not_found() => Ok(()),
            Err(error) => Err(GarageBackendError::from(error)),
        }
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum GarageBackendError {
    #[error("Garage resource was not found: {0}")]
    NotFound(String),
    #[error("Garage is unavailable: {0}")]
    Unavailable(String),
    #[error("Garage rejected the operation: {0}")]
    Conflict(String),
    #[error("Garage returned an invalid response: {0}")]
    InvalidResponse(String),
}

impl From<GarageError> for GarageBackendError {
    fn from(error: GarageError) -> Self {
        if error.is_not_found() {
            Self::NotFound(error.to_string())
        } else if error
            .status_code()
            .is_some_and(|status| status.as_u16() == 409)
        {
            Self::Conflict(error.to_string())
        } else {
            Self::Unavailable(error.to_string())
        }
    }
}

#[must_use]
pub const fn bucket_is_empty(usage: BucketUsage) -> bool {
    usage.bytes == 0
        && usage.objects == 0
        && usage.unfinished_upload_bytes == 0
        && usage.unfinished_uploads == 0
}

#[cfg(test)]
mod tests {
    use syouyu_domain::BucketUsage;

    use super::bucket_is_empty;

    #[test]
    fn unfinished_uploads_make_bucket_non_empty() {
        assert!(bucket_is_empty(BucketUsage::default()));
        assert!(!bucket_is_empty(BucketUsage {
            unfinished_uploads: 1,
            ..BucketUsage::default()
        }));
        assert!(!bucket_is_empty(BucketUsage {
            bytes: 1,
            ..BucketUsage::default()
        }));
    }
}
