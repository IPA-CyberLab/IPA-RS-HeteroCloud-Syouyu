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
        let existing_key_ids = self
            .client
            .list_keys()
            .await
            .map_err(GarageBackendError::from)?
            .into_iter()
            .filter(|key| key.name == deterministic_name)
            .map(|key| key.id)
            .collect::<Vec<_>>();
        for access_key_id in existing_key_ids {
            match self.client.delete_key(&access_key_id).await {
                Ok(()) => {}
                Err(error) if error.is_not_found() => {}
                Err(error) => return Err(GarageBackendError::from(error)),
            }
        }
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
    use std::{
        io::{Read, Write},
        net::TcpListener,
        sync::mpsc,
        thread,
        time::Duration,
    };

    use syouyu_domain::{BucketPermissions, BucketUsage, SyouyuSpec};
    use syouyu_garage::GarageAdminClient;
    use url::Url;

    use super::{Garage, GarageAdapter, bucket_is_empty};

    const BUCKET_JSON: &str = r#"{
        "id":"bucket-id",
        "created":"2026-09-04T00:00:00Z",
        "globalAliases":["tenant-bucket"],
        "websiteAccess":false,
        "keys":[],
        "objects":0,
        "bytes":0,
        "unfinishedUploads":0,
        "unfinishedMultipartUploads":0,
        "unfinishedMultipartUploadParts":0,
        "unfinishedMultipartUploadBytes":0,
        "quotas":{"maxSize":1024,"maxObjects":100}
    }"#;

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

    #[tokio::test]
    async fn reconcile_recovers_bucket_created_before_database_completion() {
        let (endpoint, requests) = mock_server(vec![
            response("404 Not Found", r#"{"message":"missing"}"#),
            ok(BUCKET_JSON),
            ok(BUCKET_JSON),
            ok(BUCKET_JSON),
            ok(BUCKET_JSON),
        ]);
        let adapter = GarageAdapter::new(GarageAdminClient::new(endpoint, "token").unwrap());
        let spec = SyouyuSpec {
            region: "heteronet-global".into(),
            bucket_name: "tenant-bucket".into(),
            quota_bytes: 1_024,
            quota_objects: 100,
        };

        let first = adapter.reconcile_bucket(None, &spec).await.unwrap();
        let second = adapter.reconcile_bucket(None, &spec).await.unwrap();
        assert_eq!(first, second);

        let paths = receive_paths(&requests, 5);
        assert_eq!(
            paths,
            vec![
                "/v2/GetBucketInfo?globalAlias=tenant-bucket",
                "/v2/CreateBucket",
                "/v2/UpdateBucket?id=bucket-id",
                "/v2/GetBucketInfo?globalAlias=tenant-bucket",
                "/v2/UpdateBucket?id=bucket-id",
            ]
        );
    }

    #[tokio::test]
    async fn credential_retry_replaces_key_left_by_partial_success() {
        let first_key = key_json("key-one", "first-secret");
        let second_key = key_json("key-two", "second-secret");
        let (endpoint, requests) = mock_server(vec![
            ok("[]"),
            ok(&first_key),
            ok(BUCKET_JSON),
            ok(BUCKET_JSON),
            ok(
                r#"[{"id":"key-one","name":"deterministic","expired":false,"created":null,"expiration":null}]"#,
            ),
            empty("200 OK"),
            ok(&second_key),
            ok(BUCKET_JSON),
            ok(BUCKET_JSON),
        ]);
        let adapter = GarageAdapter::new(GarageAdminClient::new(endpoint, "token").unwrap());
        let permissions = BucketPermissions {
            read: true,
            write: true,
        };

        let first = adapter
            .create_credential("bucket-id", "deterministic", permissions)
            .await
            .unwrap();
        assert_eq!(first.garage_key_id, "key-one");
        let second = adapter
            .create_credential("bucket-id", "deterministic", permissions)
            .await
            .unwrap();
        assert_eq!(second.garage_key_id, "key-two");
        assert_eq!(second.secret_access_key, "second-secret");

        let paths = receive_paths(&requests, 9);
        assert_eq!(paths[0], "/v2/ListKeys");
        assert_eq!(paths[4], "/v2/ListKeys");
        assert_eq!(paths[5], "/v2/DeleteKey?id=key-one");
        assert_eq!(
            paths
                .iter()
                .filter(|path| path.as_str() == "/v2/CreateKey")
                .count(),
            2
        );
    }

    #[tokio::test]
    async fn delete_and_revoke_are_safe_after_external_partial_success() {
        let (endpoint, requests) = mock_server(vec![
            empty("200 OK"),
            response("404 Not Found", r#"{"message":"already deleted"}"#),
            empty("200 OK"),
            response("404 Not Found", r#"{"message":"already revoked"}"#),
        ]);
        let adapter = GarageAdapter::new(GarageAdminClient::new(endpoint, "token").unwrap());

        adapter.delete_bucket("bucket-id").await.unwrap();
        adapter.delete_bucket("bucket-id").await.unwrap();
        adapter.revoke_credential("key-id").await.unwrap();
        adapter.revoke_credential("key-id").await.unwrap();

        assert_eq!(
            receive_paths(&requests, 4),
            vec![
                "/v2/DeleteBucket?id=bucket-id",
                "/v2/DeleteBucket?id=bucket-id",
                "/v2/DeleteKey?id=key-id",
                "/v2/DeleteKey?id=key-id",
            ]
        );
    }

    fn key_json(access_key_id: &str, secret: &str) -> String {
        format!(
            r#"{{"accessKeyId":"{access_key_id}","name":"deterministic","expired":false,"created":null,"expiration":null,"permissions":{{"createBucket":false}},"buckets":[],"secretAccessKey":"{secret}"}}"#
        )
    }

    fn ok(body: &str) -> String {
        response("200 OK", body)
    }

    fn empty(status: &str) -> String {
        response(status, "")
    }

    fn response(status: &str, body: &str) -> String {
        format!(
            "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
    }

    fn mock_server(responses: Vec<String>) -> (Url, mpsc::Receiver<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let (sender, receiver) = mpsc::channel();
        thread::spawn(move || {
            for response in responses {
                let (mut stream, _) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                sender.send(read_request(&mut stream)).unwrap();
                stream.write_all(response.as_bytes()).unwrap();
            }
        });
        (Url::parse(&format!("http://{address}/")).unwrap(), receiver)
    }

    fn receive_paths(receiver: &mpsc::Receiver<String>, count: usize) -> Vec<String> {
        (0..count)
            .map(|_| {
                receiver
                    .recv_timeout(Duration::from_secs(2))
                    .unwrap()
                    .lines()
                    .next()
                    .unwrap()
                    .split_whitespace()
                    .nth(1)
                    .unwrap()
                    .to_owned()
            })
            .collect()
    }

    fn read_request(stream: &mut std::net::TcpStream) -> String {
        let mut bytes = Vec::new();
        let mut buffer = [0_u8; 4_096];
        let mut expected_length = None;
        loop {
            let count = stream.read(&mut buffer).unwrap();
            if count == 0 {
                break;
            }
            bytes.extend_from_slice(&buffer[..count]);
            if expected_length.is_none()
                && let Some(header_end) = bytes.windows(4).position(|window| window == b"\r\n\r\n")
            {
                let headers = String::from_utf8_lossy(&bytes[..header_end]);
                let content_length = headers
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse::<usize>().ok())
                            .flatten()
                    })
                    .unwrap_or(0);
                expected_length = Some(header_end + 4 + content_length);
            }
            if expected_length.is_some_and(|length| bytes.len() >= length) {
                break;
            }
        }
        String::from_utf8(bytes).unwrap()
    }
}
