use std::{fmt, time::Duration};

use chrono::{DateTime, Utc};
use reqwest::{
    Client, Method, RequestBuilder, Response, StatusCode,
    header::{ACCEPT, AUTHORIZATION, HeaderMap, HeaderValue},
};
use secrecy::SecretString;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use syouyu_domain::{BucketPermissions as DomainPermissions, BucketQuota as DomainQuota};
use thiserror::Error;
use url::Url;

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_SUCCESS_BODY_BYTES: usize = 8 * 1024 * 1024;
const MAX_ERROR_BODY_BYTES: usize = 16 * 1024;

/// Typed client for Garage's version 2 administration API.
#[derive(Clone)]
pub struct GarageAdminClient {
    base_url: Url,
    client: Client,
}

impl fmt::Debug for GarageAdminClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GarageAdminClient")
            .field("base_url", &self.base_url)
            .finish_non_exhaustive()
    }
}

impl GarageAdminClient {
    /// Creates a client with a ten-second request timeout.
    pub fn new(base_url: Url, admin_token: &str) -> Result<Self, GarageError> {
        Self::with_timeout(base_url, admin_token, DEFAULT_TIMEOUT)
    }

    pub fn with_timeout(
        mut base_url: Url,
        admin_token: &str,
        timeout: Duration,
    ) -> Result<Self, GarageError> {
        validate_base_url(&base_url)?;
        if admin_token.is_empty() {
            return Err(GarageError::InvalidConfiguration(
                "admin token must not be empty".into(),
            ));
        }
        if timeout.is_zero() {
            return Err(GarageError::InvalidConfiguration(
                "request timeout must not be zero".into(),
            ));
        }

        let normalized_path = format!("{}/", base_url.path().trim_end_matches('/'));
        base_url.set_path(&normalized_path);

        let mut authorization = HeaderValue::from_str(&format!("Bearer {admin_token}"))
            .map_err(|_| GarageError::InvalidConfiguration("admin token is invalid".into()))?;
        authorization.set_sensitive(true);
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, authorization);
        headers.insert(ACCEPT, HeaderValue::from_static("application/json"));

        let client = Client::builder()
            .default_headers(headers)
            .timeout(timeout)
            .user_agent(concat!("heterocloud-syouyu/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(GarageError::ClientBuild)?;

        Ok(Self { base_url, client })
    }

    #[must_use]
    pub const fn base_url(&self) -> &Url {
        &self.base_url
    }

    pub async fn health(&self) -> Result<ClusterHealth, GarageError> {
        let request = self.request(Method::GET, "GetClusterHealth")?;
        self.execute_json(request, "GetClusterHealth").await
    }

    pub async fn list_buckets(&self) -> Result<Vec<BucketSummary>, GarageError> {
        let request = self.request(Method::GET, "ListBuckets")?;
        self.execute_json(request, "ListBuckets").await
    }

    pub async fn create_bucket(&self, global_alias: &str) -> Result<Bucket, GarageError> {
        validate_input("global_alias", global_alias)?;
        let request = self
            .request(Method::POST, "CreateBucket")?
            .json(&CreateBucketRequest { global_alias });
        self.execute_json(request, "CreateBucket").await
    }

    pub async fn get_bucket(&self, bucket_id: &str) -> Result<Bucket, GarageError> {
        validate_input("bucket_id", bucket_id)?;
        let request = self
            .request(Method::GET, "GetBucketInfo")?
            .query(&[("id", bucket_id)]);
        self.execute_json(request, "GetBucketInfo").await
    }

    pub async fn get_bucket_by_alias(&self, global_alias: &str) -> Result<Bucket, GarageError> {
        validate_input("global_alias", global_alias)?;
        let request = self
            .request(Method::GET, "GetBucketInfo")?
            .query(&[("globalAlias", global_alias)]);
        self.execute_json(request, "GetBucketInfo").await
    }

    pub async fn update_bucket_quotas(
        &self,
        bucket_id: &str,
        quotas: BucketQuotas,
    ) -> Result<Bucket, GarageError> {
        validate_input("bucket_id", bucket_id)?;
        quotas.validate()?;
        let request = self
            .request(Method::POST, "UpdateBucket")?
            .query(&[("id", bucket_id)])
            .json(&UpdateBucketRequest { quotas });
        self.execute_json(request, "UpdateBucket").await
    }

    pub async fn delete_bucket(&self, bucket_id: &str) -> Result<(), GarageError> {
        validate_input("bucket_id", bucket_id)?;
        let request = self
            .request(Method::POST, "DeleteBucket")?
            .query(&[("id", bucket_id)]);
        self.execute_empty(request, "DeleteBucket").await
    }

    pub async fn list_keys(&self) -> Result<Vec<AccessKeySummary>, GarageError> {
        let request = self.request(Method::GET, "ListKeys")?;
        self.execute_json(request, "ListKeys").await
    }

    pub async fn create_key(&self, request: &CreateKeyRequest) -> Result<AccessKey, GarageError> {
        request.validate()?;
        let request = self.request(Method::POST, "CreateKey")?.json(request);
        self.execute_json(request, "CreateKey").await
    }

    pub async fn get_key(&self, access_key_id: &str) -> Result<AccessKey, GarageError> {
        self.get_key_inner(access_key_id, false).await
    }

    /// Returns key metadata including secret material when Garage still has it.
    /// Callers must never log or persist the response without encryption.
    pub async fn get_key_with_secret(&self, access_key_id: &str) -> Result<AccessKey, GarageError> {
        self.get_key_inner(access_key_id, true).await
    }

    pub async fn update_key(
        &self,
        access_key_id: &str,
        update: &UpdateKeyRequest,
    ) -> Result<AccessKey, GarageError> {
        validate_input("access_key_id", access_key_id)?;
        update.validate()?;
        let request = self
            .request(Method::POST, "UpdateKey")?
            .query(&[("id", access_key_id)])
            .json(update);
        self.execute_json(request, "UpdateKey").await
    }

    pub async fn delete_key(&self, access_key_id: &str) -> Result<(), GarageError> {
        validate_input("access_key_id", access_key_id)?;
        let request = self
            .request(Method::POST, "DeleteKey")?
            .query(&[("id", access_key_id)]);
        self.execute_empty(request, "DeleteKey").await
    }

    /// Enables only the `true` permission bits. Garage leaves `false` bits
    /// unchanged on this endpoint.
    pub async fn allow_bucket_key(
        &self,
        bucket_id: &str,
        access_key_id: &str,
        permissions: BucketKeyPermissions,
    ) -> Result<Bucket, GarageError> {
        self.change_bucket_key_permissions("AllowBucketKey", bucket_id, access_key_id, permissions)
            .await
    }

    /// Disables only the `true` permission bits. Garage leaves `false` bits
    /// unchanged on this endpoint.
    pub async fn deny_bucket_key(
        &self,
        bucket_id: &str,
        access_key_id: &str,
        permissions: BucketKeyPermissions,
    ) -> Result<Bucket, GarageError> {
        self.change_bucket_key_permissions("DenyBucketKey", bucket_id, access_key_id, permissions)
            .await
    }

    /// Replaces all bucket permissions using Garage's unconventional
    /// allow/deny API. Revocation happens first, so a partial failure cannot
    /// accidentally retain broader access.
    pub async fn set_bucket_key_permissions(
        &self,
        bucket_id: &str,
        access_key_id: &str,
        permissions: BucketKeyPermissions,
    ) -> Result<Bucket, GarageError> {
        let revoked = self
            .deny_bucket_key(bucket_id, access_key_id, BucketKeyPermissions::all())
            .await?;
        if permissions.is_empty() {
            return Ok(revoked);
        }
        self.allow_bucket_key(bucket_id, access_key_id, permissions)
            .await
    }

    async fn get_key_inner(
        &self,
        access_key_id: &str,
        show_secret: bool,
    ) -> Result<AccessKey, GarageError> {
        validate_input("access_key_id", access_key_id)?;
        let show_secret = if show_secret { "true" } else { "false" };
        let request = self
            .request(Method::GET, "GetKeyInfo")?
            .query(&[("id", access_key_id), ("showSecretKey", show_secret)]);
        self.execute_json(request, "GetKeyInfo").await
    }

    async fn change_bucket_key_permissions(
        &self,
        operation: &'static str,
        bucket_id: &str,
        access_key_id: &str,
        permissions: BucketKeyPermissions,
    ) -> Result<Bucket, GarageError> {
        validate_input("bucket_id", bucket_id)?;
        validate_input("access_key_id", access_key_id)?;
        let body = BucketKeyPermissionChangeRequest {
            bucket_id,
            access_key_id,
            permissions,
        };
        let request = self.request(Method::POST, operation)?.json(&body);
        self.execute_json(request, operation).await
    }

    fn request(
        &self,
        method: Method,
        operation: &'static str,
    ) -> Result<RequestBuilder, GarageError> {
        let endpoint = self
            .base_url
            .join(&format!("v2/{operation}"))
            .map_err(|error| {
                GarageError::InvalidConfiguration(format!(
                    "cannot build Garage endpoint for {operation}: {error}"
                ))
            })?;
        Ok(self.client.request(method, endpoint))
    }

    async fn execute_json<T>(
        &self,
        request: RequestBuilder,
        operation: &'static str,
    ) -> Result<T, GarageError>
    where
        T: DeserializeOwned,
    {
        let response = request
            .send()
            .await
            .map_err(|source| GarageError::Transport { operation, source })?;
        let status = response.status();
        if !status.is_success() {
            return Err(api_error(response, operation).await);
        }

        let (body, truncated) = read_limited(response, MAX_SUCCESS_BODY_BYTES, operation).await?;
        if truncated {
            return Err(GarageError::ResponseTooLarge {
                operation,
                status,
                limit: MAX_SUCCESS_BODY_BYTES,
            });
        }
        serde_json::from_slice(&body).map_err(|source| GarageError::Decode {
            operation,
            status,
            body: display_body(&body),
            source,
        })
    }

    async fn execute_empty(
        &self,
        request: RequestBuilder,
        operation: &'static str,
    ) -> Result<(), GarageError> {
        let response = request
            .send()
            .await
            .map_err(|source| GarageError::Transport { operation, source })?;
        if response.status().is_success() {
            Ok(())
        } else {
            Err(api_error(response, operation).await)
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ClusterHealthStatus {
    Healthy,
    Degraded,
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ClusterHealth {
    pub status: ClusterHealthStatus,
    pub known_nodes: u64,
    pub connected_nodes: u64,
    pub storage_nodes: u64,
    pub storage_nodes_up: u64,
    pub partitions: u64,
    pub partitions_quorum: u64,
    pub partitions_all_ok: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BucketQuotas {
    pub max_size: Option<u64>,
    pub max_objects: Option<u64>,
}

impl BucketQuotas {
    #[must_use]
    pub const fn limited(max_size: u64, max_objects: u64) -> Self {
        Self {
            max_size: Some(max_size),
            max_objects: Some(max_objects),
        }
    }

    #[must_use]
    pub const fn unlimited() -> Self {
        Self {
            max_size: None,
            max_objects: None,
        }
    }

    pub fn validate(self) -> Result<(), GarageError> {
        match (self.max_size, self.max_objects) {
            (Some(size), Some(objects)) if size > 0 && objects > 0 => Ok(()),
            (None, None) => Ok(()),
            (Some(_), Some(_)) => Err(GarageError::InvalidInput {
                field: "quotas",
                reason: "limited quotas must be non-zero",
            }),
            _ => Err(GarageError::InvalidInput {
                field: "quotas",
                reason: "Garage requires max_size and max_objects together",
            }),
        }
    }
}

impl TryFrom<DomainQuota> for BucketQuotas {
    type Error = GarageError;

    fn try_from(quota: DomainQuota) -> Result<Self, Self::Error> {
        quota.validate().map_err(|_| GarageError::InvalidInput {
            field: "quotas",
            reason: "domain quota is invalid",
        })?;
        Ok(Self::limited(quota.bytes, quota.objects))
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BucketKeyPermissions {
    #[serde(default)]
    pub read: bool,
    #[serde(default)]
    pub write: bool,
    #[serde(default)]
    pub owner: bool,
}

impl BucketKeyPermissions {
    #[must_use]
    pub const fn all() -> Self {
        Self {
            read: true,
            write: true,
            owner: true,
        }
    }

    #[must_use]
    pub const fn is_empty(self) -> bool {
        !self.read && !self.write && !self.owner
    }
}

impl From<DomainPermissions> for BucketKeyPermissions {
    fn from(permissions: DomainPermissions) -> Self {
        Self {
            read: permissions.read,
            write: permissions.write,
            owner: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BucketSummary {
    pub id: String,
    pub created: DateTime<Utc>,
    pub global_aliases: Vec<String>,
    pub local_aliases: Vec<BucketLocalAlias>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BucketLocalAlias {
    pub access_key_id: String,
    pub alias: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Bucket {
    pub id: String,
    pub created: DateTime<Utc>,
    pub global_aliases: Vec<String>,
    pub website_access: bool,
    pub keys: Vec<BucketKey>,
    pub objects: u64,
    pub bytes: u64,
    pub unfinished_uploads: u64,
    pub unfinished_multipart_uploads: u64,
    pub unfinished_multipart_upload_parts: u64,
    pub unfinished_multipart_upload_bytes: u64,
    pub quotas: BucketQuotas,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BucketKey {
    pub access_key_id: String,
    pub name: String,
    pub permissions: BucketKeyPermissions,
    pub bucket_local_aliases: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct AccessKeySummary {
    pub id: String,
    pub name: String,
    pub expired: bool,
    pub created: Option<DateTime<Utc>>,
    pub expiration: Option<DateTime<Utc>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccessKey {
    pub access_key_id: String,
    pub name: String,
    pub expired: bool,
    pub created: Option<DateTime<Utc>>,
    pub expiration: Option<DateTime<Utc>>,
    pub permissions: GlobalKeyPermissions,
    pub buckets: Vec<KeyBucket>,
    pub secret_access_key: Option<SecretString>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GlobalKeyPermissions {
    #[serde(default)]
    pub create_bucket: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyBucket {
    pub id: String,
    pub global_aliases: Vec<String>,
    pub local_aliases: Vec<String>,
    pub permissions: BucketKeyPermissions,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateKeyRequest {
    pub name: String,
    pub expiration: Option<DateTime<Utc>>,
    pub never_expires: bool,
}

impl CreateKeyRequest {
    #[must_use]
    pub fn new(name: impl Into<String>, expiration: Option<DateTime<Utc>>) -> Self {
        Self {
            name: name.into(),
            expiration,
            never_expires: expiration.is_none(),
        }
    }

    fn validate(&self) -> Result<(), GarageError> {
        validate_input("key_name", &self.name)?;
        if self.never_expires == self.expiration.is_some() {
            return Err(GarageError::InvalidInput {
                field: "expiration",
                reason: "set either expiration or never_expires",
            });
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateKeyRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expiration: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub never_expires: bool,
}

impl UpdateKeyRequest {
    fn validate(&self) -> Result<(), GarageError> {
        if let Some(name) = &self.name {
            validate_input("key_name", name)?;
        }
        if self.never_expires && self.expiration.is_some() {
            return Err(GarageError::InvalidInput {
                field: "expiration",
                reason: "expiration and never_expires are mutually exclusive",
            });
        }
        if self.name.is_none() && self.expiration.is_none() && !self.never_expires {
            return Err(GarageError::InvalidInput {
                field: "update",
                reason: "at least one key field must change",
            });
        }
        Ok(())
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CreateBucketRequest<'a> {
    global_alias: &'a str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct UpdateBucketRequest {
    quotas: BucketQuotas,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct BucketKeyPermissionChangeRequest<'a> {
    bucket_id: &'a str,
    access_key_id: &'a str,
    permissions: BucketKeyPermissions,
}

#[derive(Debug, Deserialize)]
struct GarageApiErrorBody {
    code: Option<String>,
    message: Option<String>,
}

async fn api_error(response: Response, operation: &'static str) -> GarageError {
    let status = response.status();
    match read_limited(response, MAX_ERROR_BODY_BYTES, operation).await {
        Ok((body, truncated)) => {
            let parsed = serde_json::from_slice::<GarageApiErrorBody>(&body).ok();
            let code = parsed.as_ref().and_then(|error| error.code.clone());
            let message = parsed
                .and_then(|error| error.message)
                .or_else(|| status.canonical_reason().map(str::to_owned))
                .unwrap_or_else(|| "Garage administration request failed".into());
            GarageError::Api {
                operation,
                status,
                code,
                message,
                body: display_body(&body),
                truncated,
            }
        }
        Err(error) => error,
    }
}

async fn read_limited(
    mut response: Response,
    limit: usize,
    operation: &'static str,
) -> Result<(Vec<u8>, bool), GarageError> {
    let mut body = Vec::new();
    let mut truncated = false;
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|source| GarageError::Transport { operation, source })?
    {
        let remaining = limit.saturating_sub(body.len());
        if chunk.len() > remaining {
            body.extend_from_slice(&chunk[..remaining]);
            truncated = true;
            break;
        }
        body.extend_from_slice(&chunk);
    }
    Ok((body, truncated))
}

fn display_body(body: &[u8]) -> String {
    String::from_utf8_lossy(body).trim().to_owned()
}

fn validate_base_url(url: &Url) -> Result<(), GarageError> {
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(GarageError::InvalidConfiguration(
            "base URL must be an HTTP(S) URL without credentials, query, or fragment".into(),
        ));
    }
    Ok(())
}

fn validate_input(field: &'static str, value: &str) -> Result<(), GarageError> {
    if value.is_empty() || value.len() > 256 || value.chars().any(char::is_control) {
        Err(GarageError::InvalidInput {
            field,
            reason: "value must contain 1 to 256 non-control characters",
        })
    } else {
        Ok(())
    }
}

#[derive(Debug, Error)]
pub enum GarageError {
    #[error("invalid Garage configuration: {0}")]
    InvalidConfiguration(String),
    #[error("invalid {field}: {reason}")]
    InvalidInput {
        field: &'static str,
        reason: &'static str,
    },
    #[error("failed to build Garage HTTP client: {0}")]
    ClientBuild(#[source] reqwest::Error),
    #[error("Garage {operation} transport failed: {source}")]
    Transport {
        operation: &'static str,
        #[source]
        source: reqwest::Error,
    },
    #[error("Garage {operation} returned HTTP {status}: {message}")]
    Api {
        operation: &'static str,
        status: StatusCode,
        code: Option<String>,
        message: String,
        body: String,
        truncated: bool,
    },
    #[error("Garage {operation} response exceeded {limit} bytes")]
    ResponseTooLarge {
        operation: &'static str,
        status: StatusCode,
        limit: usize,
    },
    #[error("Garage {operation} returned invalid JSON with HTTP {status}: {source}")]
    Decode {
        operation: &'static str,
        status: StatusCode,
        body: String,
        #[source]
        source: serde_json::Error,
    },
}

impl GarageError {
    #[must_use]
    pub const fn status_code(&self) -> Option<StatusCode> {
        match self {
            Self::Api { status, .. }
            | Self::ResponseTooLarge { status, .. }
            | Self::Decode { status, .. } => Some(*status),
            Self::InvalidConfiguration(_)
            | Self::InvalidInput { .. }
            | Self::ClientBuild(_)
            | Self::Transport { .. } => None,
        }
    }

    #[must_use]
    pub fn is_not_found(&self) -> bool {
        self.status_code() == Some(StatusCode::NOT_FOUND)
    }
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

    use secrecy::ExposeSecret;
    use url::Url;

    use super::{
        AccessKey, BucketKeyPermissions, BucketQuotas, ClusterHealth, ClusterHealthStatus,
        GarageAdminClient, GarageError,
    };

    const BUCKET_JSON: &str = r#"{
        "id":"0123456789abcdef",
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
        "quotas":{"maxSize":10737418240,"maxObjects":1000000}
    }"#;

    #[test]
    fn decodes_typed_health_and_secret_key() {
        let health: ClusterHealth = serde_json::from_str(
            r#"{"status":"degraded","knownNodes":5,"connectedNodes":4,"storageNodes":3,"storageNodesUp":2,"partitions":256,"partitionsQuorum":256,"partitionsAllOk":128}"#,
        )
        .unwrap();
        assert_eq!(health.status, ClusterHealthStatus::Degraded);
        assert_eq!(health.storage_nodes_up, 2);

        let key: AccessKey = serde_json::from_str(
            r#"{"accessKeyId":"GK123","name":"flash","expired":false,"created":null,"expiration":null,"permissions":{"createBucket":false},"buckets":[],"secretAccessKey":"secret-value"}"#,
        )
        .unwrap();
        assert_eq!(
            key.secret_access_key.unwrap().expose_secret(),
            "secret-value"
        );
    }

    #[test]
    fn quota_shape_requires_both_dimensions() {
        BucketQuotas::limited(1, 1).validate().unwrap();
        BucketQuotas::unlimited().validate().unwrap();
        assert!(
            BucketQuotas {
                max_size: Some(1),
                max_objects: None,
            }
            .validate()
            .is_err()
        );
    }

    #[tokio::test]
    async fn uses_v2_paths_bearer_auth_and_typed_quota_body() {
        let (mut endpoint, requests) = mock_server(vec![ok(BUCKET_JSON), ok(BUCKET_JSON)]);
        endpoint.set_path("/admin/");
        let client = GarageAdminClient::new(endpoint, "admin-secret").unwrap();

        client.create_bucket("tenant-bucket").await.unwrap();
        client
            .update_bucket_quotas("0123456789abcdef", BucketQuotas::limited(2_048, 100))
            .await
            .unwrap();

        let create = requests.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(create.starts_with("POST /admin/v2/CreateBucket HTTP/1.1"));
        assert!(create.contains("authorization: Bearer admin-secret"));
        assert!(create.contains(r#"{"globalAlias":"tenant-bucket"}"#));

        let update = requests.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(update.contains("/admin/v2/UpdateBucket?id=0123456789abcdef"));
        assert!(update.contains(r#""quotas":{"maxSize":2048,"maxObjects":100}"#));
    }

    #[tokio::test]
    async fn permission_replacement_revokes_before_allowing() {
        let (endpoint, requests) = mock_server(vec![ok(BUCKET_JSON), ok(BUCKET_JSON)]);
        let client = GarageAdminClient::new(endpoint, "admin-secret").unwrap();
        client
            .set_bucket_key_permissions(
                "bucket-id",
                "key-id",
                BucketKeyPermissions {
                    read: true,
                    write: false,
                    owner: false,
                },
            )
            .await
            .unwrap();

        let deny = requests.recv_timeout(Duration::from_secs(2)).unwrap();
        let allow = requests.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(deny.starts_with("POST /v2/DenyBucketKey HTTP/1.1"));
        assert!(deny.contains(r#""permissions":{"read":true,"write":true,"owner":true}"#));
        assert!(allow.starts_with("POST /v2/AllowBucketKey HTTP/1.1"));
        assert!(allow.contains(r#""permissions":{"read":true,"write":false,"owner":false}"#));
    }

    #[tokio::test]
    async fn preserves_structured_api_errors_without_exposing_token() {
        let (endpoint, requests) = mock_server(vec![response(
            "404 Not Found",
            r#"{"code":"NoSuchBucket","message":"bucket does not exist"}"#,
        )]);
        let client = GarageAdminClient::new(endpoint, "do-not-log-this").unwrap();
        let error = client.get_bucket("missing").await.unwrap_err();
        assert!(error.is_not_found());
        assert!(!error.to_string().contains("do-not-log-this"));
        match error {
            GarageError::Api { code, message, .. } => {
                assert_eq!(code.as_deref(), Some("NoSuchBucket"));
                assert_eq!(message, "bucket does not exist");
            }
            other => panic!("unexpected error: {other}"),
        }
        requests.recv_timeout(Duration::from_secs(2)).unwrap();
    }

    fn ok(body: &str) -> String {
        response("200 OK", body)
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
                let request = read_request(&mut stream);
                sender.send(request).unwrap();
                stream.write_all(response.as_bytes()).unwrap();
            }
        });
        (Url::parse(&format!("http://{address}/")).unwrap(), receiver)
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
