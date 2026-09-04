use std::sync::Arc;

use async_trait::async_trait;
use axum::{
    Json, Router,
    extract::{
        DefaultBodyLimit, FromRequest, FromRequestParts, Path, Query, Request, State,
        rejection::{JsonRejection, PathRejection, QueryRejection},
    },
    http::{
        HeaderMap, HeaderValue, StatusCode,
        header::{CACHE_CONTROL, CONTENT_TYPE, PRAGMA},
        request::Parts,
    },
    response::{IntoResponse, Response},
    routing::{delete, get, post, put},
};
use chrono::Utc;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use syouyu_auth::{
    PROVIDER_DELETE_ACTION, PROVIDER_RECONCILE_ACTION, ProviderAuthenticator,
    require_idempotency_key,
};
use syouyu_domain::{
    BucketPermissions, BucketPhase, BucketQuota, BucketStatus, BucketUsage, CredentialSpec,
    SyouyuSpec,
};
use syouyu_store::{
    AuditEvent, CreateCredentialCommand, CreateCredentialContext, CredentialRecord, DeleteCommand,
    DeleteContext, NewCredential, OperationRequest, PgStore, Prepare, ReconcileCommand,
    ReconcileContext, RevokeCredentialCommand, RevokeCredentialContext, ServiceRecord, StoreError,
    StoredHttpResponse, UsageRecord, request_hash,
};
use tower_http::{
    request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer},
    trace::TraceLayer,
};
use tracing::{error, warn};
use url::Url;
use utoipa::{
    Modify, OpenApi, ToSchema,
    openapi::security::{ApiKey, ApiKeyValue, SecurityScheme},
};
use utoipa_swagger_ui::SwaggerUi;
use uuid::Uuid;

use crate::{
    PrincipalAuthenticator,
    error::{ApiError, ErrorEnvelope},
    garage::{Garage, GarageBackendError, bucket_is_empty},
    principal_auth::{
        PRINCIPAL_HEADER, PRINCIPAL_SIGNATURE_HEADER, PRINCIPAL_TIMESTAMP_HEADER, Principal,
    },
};

const IDEMPOTENCY_KEY: &str = "idempotency-key";
const REQUEST_ID: &str = "x-request-id";
const CREDENTIAL_CREATE_ACTION: &str = "credential.create";
const CREDENTIAL_REVOKE_ACTION: &str = "credential.revoke";
const CREDENTIAL_CREATE_PERMISSION: &str = "syouyu.credential.create";
const CREDENTIAL_READ_PERMISSION: &str = "syouyu.credential.read";
const CREDENTIAL_REVOKE_PERMISSION: &str = "syouyu.credential.revoke";
const OVERVIEW_READ_PERMISSION: &str = "syouyu.overview.read";
const USAGE_READ_PERMISSION: &str = "syouyu.usage.read";

#[async_trait]
pub trait Repository: Send + Sync {
    async fn health(&self) -> Result<(), StoreError>;
    async fn prepare_reconcile(
        &self,
        command: &ReconcileCommand,
    ) -> Result<Prepare<ReconcileContext>, StoreError>;
    async fn complete_reconcile(
        &self,
        command: &ReconcileCommand,
        operation_id: Uuid,
        physical_bucket_id: &str,
        response: &StoredHttpResponse,
        audit: &AuditEvent,
    ) -> Result<(), StoreError>;
    async fn prepare_delete(
        &self,
        command: &DeleteCommand,
    ) -> Result<Prepare<DeleteContext>, StoreError>;
    async fn complete_delete(
        &self,
        command: &DeleteCommand,
        operation_id: Uuid,
        response: &StoredHttpResponse,
        audit: &AuditEvent,
    ) -> Result<(), StoreError>;
    async fn prepare_create_credential(
        &self,
        command: &CreateCredentialCommand,
    ) -> Result<Prepare<CreateCredentialContext>, StoreError>;
    async fn complete_create_credential(
        &self,
        command: &CreateCredentialCommand,
        operation_id: Uuid,
        credential: &NewCredential,
        response: &StoredHttpResponse,
        audit: &AuditEvent,
    ) -> Result<(), StoreError>;
    async fn prepare_revoke_credential(
        &self,
        command: &RevokeCredentialCommand,
    ) -> Result<Prepare<RevokeCredentialContext>, StoreError>;
    async fn complete_revoke_credential(
        &self,
        command: &RevokeCredentialCommand,
        operation_id: Uuid,
        response: &StoredHttpResponse,
        audit: &AuditEvent,
    ) -> Result<(), StoreError>;
    async fn renew_operation(
        &self,
        operation: &OperationRequest,
        operation_id: Uuid,
    ) -> Result<(), StoreError>;
    async fn fail_operation(
        &self,
        operation: &OperationRequest,
        operation_id: Uuid,
        response: &StoredHttpResponse,
        audit: &AuditEvent,
    ) -> Result<(), StoreError>;
    async fn service_overview(
        &self,
        organization_id: Uuid,
        project_id: Uuid,
        service_instance_id: Uuid,
    ) -> Result<ServiceRecord, StoreError>;
    async fn list_credentials(
        &self,
        organization_id: Uuid,
        project_id: Uuid,
        service_instance_id: Uuid,
    ) -> Result<Vec<CredentialRecord>, StoreError>;
    async fn record_usage(
        &self,
        organization_id: Uuid,
        project_id: Uuid,
        service_instance_id: Uuid,
        bytes_used: u64,
        objects_used: u64,
        measured_at: chrono::DateTime<Utc>,
    ) -> Result<UsageRecord, StoreError>;
    async fn record_audit(&self, audit: &AuditEvent) -> Result<(), StoreError>;
}

#[async_trait]
impl Repository for PgStore {
    async fn health(&self) -> Result<(), StoreError> {
        PgStore::health(self).await
    }

    async fn prepare_reconcile(
        &self,
        command: &ReconcileCommand,
    ) -> Result<Prepare<ReconcileContext>, StoreError> {
        PgStore::prepare_reconcile(self, command).await
    }

    async fn complete_reconcile(
        &self,
        command: &ReconcileCommand,
        operation_id: Uuid,
        physical_bucket_id: &str,
        response: &StoredHttpResponse,
        audit: &AuditEvent,
    ) -> Result<(), StoreError> {
        PgStore::complete_reconcile(
            self,
            command,
            operation_id,
            physical_bucket_id,
            response,
            audit,
        )
        .await
    }

    async fn prepare_delete(
        &self,
        command: &DeleteCommand,
    ) -> Result<Prepare<DeleteContext>, StoreError> {
        PgStore::prepare_delete(self, command).await
    }

    async fn complete_delete(
        &self,
        command: &DeleteCommand,
        operation_id: Uuid,
        response: &StoredHttpResponse,
        audit: &AuditEvent,
    ) -> Result<(), StoreError> {
        PgStore::complete_delete(self, command, operation_id, response, audit).await
    }

    async fn prepare_create_credential(
        &self,
        command: &CreateCredentialCommand,
    ) -> Result<Prepare<CreateCredentialContext>, StoreError> {
        PgStore::prepare_create_credential(self, command).await
    }

    async fn complete_create_credential(
        &self,
        command: &CreateCredentialCommand,
        operation_id: Uuid,
        credential: &NewCredential,
        response: &StoredHttpResponse,
        audit: &AuditEvent,
    ) -> Result<(), StoreError> {
        PgStore::complete_create_credential(
            self,
            command,
            operation_id,
            credential,
            response,
            audit,
        )
        .await
    }

    async fn prepare_revoke_credential(
        &self,
        command: &RevokeCredentialCommand,
    ) -> Result<Prepare<RevokeCredentialContext>, StoreError> {
        PgStore::prepare_revoke_credential(self, command).await
    }

    async fn complete_revoke_credential(
        &self,
        command: &RevokeCredentialCommand,
        operation_id: Uuid,
        response: &StoredHttpResponse,
        audit: &AuditEvent,
    ) -> Result<(), StoreError> {
        PgStore::complete_revoke_credential(self, command, operation_id, response, audit).await
    }

    async fn renew_operation(
        &self,
        operation: &OperationRequest,
        operation_id: Uuid,
    ) -> Result<(), StoreError> {
        PgStore::renew_operation(self, operation, operation_id).await
    }

    async fn fail_operation(
        &self,
        operation: &OperationRequest,
        operation_id: Uuid,
        response: &StoredHttpResponse,
        audit: &AuditEvent,
    ) -> Result<(), StoreError> {
        PgStore::fail_operation(self, operation, operation_id, response, audit).await
    }

    async fn service_overview(
        &self,
        organization_id: Uuid,
        project_id: Uuid,
        service_instance_id: Uuid,
    ) -> Result<ServiceRecord, StoreError> {
        PgStore::service_overview(self, organization_id, project_id, service_instance_id).await
    }

    async fn list_credentials(
        &self,
        organization_id: Uuid,
        project_id: Uuid,
        service_instance_id: Uuid,
    ) -> Result<Vec<CredentialRecord>, StoreError> {
        PgStore::list_credentials(self, organization_id, project_id, service_instance_id).await
    }

    async fn record_usage(
        &self,
        organization_id: Uuid,
        project_id: Uuid,
        service_instance_id: Uuid,
        bytes_used: u64,
        objects_used: u64,
        measured_at: chrono::DateTime<Utc>,
    ) -> Result<UsageRecord, StoreError> {
        PgStore::record_usage(
            self,
            organization_id,
            project_id,
            service_instance_id,
            bytes_used,
            objects_used,
            measured_at,
        )
        .await
    }

    async fn record_audit(&self, audit: &AuditEvent) -> Result<(), StoreError> {
        PgStore::record_audit(self, audit).await
    }
}

#[derive(Clone)]
pub struct AppState {
    pub store: Arc<dyn Repository>,
    pub garage: Arc<dyn Garage>,
    pub provider_auth: ProviderAuthenticator,
    pub principal_auth: PrincipalAuthenticator,
    pub storage_region: Arc<str>,
    pub s3_endpoint: Url,
}

pub fn router(state: AppState) -> Router {
    let openapi = ApiDoc::openapi();
    Router::new()
        .route("/health/live", get(live))
        .route("/health/ready", get(ready))
        .route("/metrics", get(metrics))
        .route(
            "/internal/v1/service-instances/{service_instance_id}",
            put(reconcile_service_instance).delete(delete_service_instance),
        )
        .route("/v1/service-overview", get(service_overview))
        .route("/v1/usage", get(service_usage))
        .route(
            "/v1/credentials",
            post(create_credential).get(list_credentials),
        )
        .route("/v1/credentials/{credential_id}", delete(revoke_credential))
        .merge(SwaggerUi::new("/docs").url("/openapi.json", openapi))
        .method_not_allowed_fallback(method_not_allowed)
        .fallback(not_found)
        .layer(DefaultBodyLimit::max(64 * 1024))
        .layer(PropagateRequestIdLayer::new(HeaderNameExt::request_id()))
        .layer(SetRequestIdLayer::new(
            HeaderNameExt::request_id(),
            MakeRequestUuid,
        ))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

struct HeaderNameExt;

impl HeaderNameExt {
    fn request_id() -> axum::http::HeaderName {
        axum::http::HeaderName::from_static(REQUEST_ID)
    }
}

async fn live() -> Json<Value> {
    Json(json!({"status": "ok"}))
}

async fn ready(State(state): State<AppState>) -> Result<Json<Value>, ApiError> {
    state.store.health().await?;
    state.garage.health().await?;
    Ok(Json(json!({"status": "ready"})))
}

async fn metrics() -> impl IntoResponse {
    (
        [(CONTENT_TYPE, "text/plain; version=0.0.4; charset=utf-8")],
        "# HELP syouyu_api_up Whether the Syouyu API process is running.\n\
# TYPE syouyu_api_up gauge\n\
syouyu_api_up 1\n",
    )
}

async fn not_found() -> ApiError {
    ApiError::not_found()
}

async fn method_not_allowed() -> ApiError {
    ApiError::method_not_allowed()
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
struct ReconcileRequest {
    generation: i64,
    name: String,
    spec: SyouyuSpec,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct DeleteQuery {
    generation: i64,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
struct ProviderOperationResponse {
    operation_id: Uuid,
    status: BucketStatus,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
struct ServiceOverviewResponse {
    service_instance_id: Uuid,
    name: String,
    region: String,
    bucket_name: String,
    phase: BucketPhase,
    endpoint: String,
    quota: BucketQuota,
    usage: BucketUsage,
    active_credentials: u64,
    measured_at: chrono::DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
struct UsageResponse {
    service_instance_id: Uuid,
    bytes_used: u64,
    objects_used: u64,
    unfinished_upload_bytes: u64,
    unfinished_uploads: u64,
    quota_bytes: u64,
    quota_objects: u64,
    measured_at: chrono::DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
struct CreateCredentialRequest {
    name: String,
    permissions: BucketPermissions,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
struct CredentialResponse {
    id: Uuid,
    name: String,
    access_key_id: String,
    permissions: BucketPermissions,
    status: String,
    created_at: chrono::DateTime<Utc>,
    revoked_at: Option<chrono::DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
struct IssuedCredentialResponse {
    credential: CredentialResponse,
    secret_access_key: String,
    bucket_name: String,
    endpoint: String,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
struct CredentialListResponse {
    credentials: Vec<CredentialResponse>,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
struct RevokedCredentialResponse {
    credential_id: Uuid,
    status: String,
}

struct StrictJson<T>(T);

struct StrictPath<T>(T);

struct StrictQuery<T>(T);

impl<S, T> FromRequest<S> for StrictJson<T>
where
    S: Send + Sync,
    T: DeserializeOwned,
{
    type Rejection = ApiError;

    async fn from_request(request: Request, state: &S) -> Result<Self, Self::Rejection> {
        Json::<T>::from_request(request, state)
            .await
            .map(|Json(value)| Self(value))
            .map_err(|error: JsonRejection| ApiError::bad_request(error.body_text()))
    }
}

impl<S, T> FromRequestParts<S> for StrictPath<T>
where
    S: Send + Sync,
    T: DeserializeOwned + Send,
{
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        Path::<T>::from_request_parts(parts, state)
            .await
            .map(|Path(value)| Self(value))
            .map_err(|error: PathRejection| ApiError::bad_request(error.body_text()))
    }
}

impl<S, T> FromRequestParts<S> for StrictQuery<T>
where
    S: Send + Sync,
    T: DeserializeOwned + Send,
{
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        Query::<T>::from_request_parts(parts, state)
            .await
            .map(|Query(value)| Self(value))
            .map_err(|error: QueryRejection| ApiError::bad_request(error.body_text()))
    }
}

async fn reconcile_service_instance(
    State(state): State<AppState>,
    StrictPath(service_instance_id): StrictPath<Uuid>,
    headers: HeaderMap,
    StrictJson(request): StrictJson<ReconcileRequest>,
) -> Result<Response, ApiError> {
    let claims = state
        .provider_auth
        .authenticate_headers_for_action(&headers, PROVIDER_RECONCILE_ACTION)?;
    require_idempotency_key(&headers, claims.jwt_id)?;
    if claims.service_instance_id != service_instance_id || claims.generation != request.generation
    {
        return Err(ApiError::forbidden());
    }
    request
        .spec
        .validate()
        .map_err(|error| ApiError::bad_request(error.to_string()))?;
    if request.spec.region != state.storage_region.as_ref() {
        return Err(ApiError::bad_request(format!(
            "region must match the configured storage region {}",
            state.storage_region
        )));
    }
    let generation = request.generation;
    let operation = OperationRequest {
        idempotency_key: claims.jwt_id,
        organization_id: claims.organization_id,
        project_id: claims.project_id,
        service_instance_id,
        principal_id: claims.subject,
        action: PROVIDER_RECONCILE_ACTION.into(),
        generation: Some(generation),
        request_hash: request_hash(PROVIDER_RECONCILE_ACTION, &request)?,
    };
    let command = ReconcileCommand {
        operation,
        name: request.name,
        generation,
        spec: request.spec,
    };
    let prepared = state.store.prepare_reconcile(&command).await?;
    let Prepare::Execute {
        operation_id,
        context,
    } = prepared
    else {
        return prepared_response(prepared);
    };

    let physical_bucket_id = if context.previously_applied {
        context
            .bucket
            .physical_bucket_id
            .clone()
            .ok_or_else(ApiError::internal)?
    } else {
        state
            .store
            .renew_operation(&command.operation, operation_id)
            .await?;
        match state
            .garage
            .reconcile_bucket(context.bucket.physical_bucket_id.as_deref(), &command.spec)
            .await
        {
            Ok(bucket) => bucket.physical_bucket_id,
            Err(error) => {
                return Err(persist_backend_failure(
                    &state,
                    &command.operation,
                    operation_id,
                    error,
                    audit_for_operation(
                        &command.operation,
                        None,
                        request_id(&headers),
                        "service_instance",
                        Some(service_instance_id.to_string()),
                        json!({"generation": generation}),
                    ),
                )
                .await);
            }
        }
    };
    let status = BucketStatus {
        observed_generation: request_generation(generation)?,
        phase: BucketPhase::Ready,
        backend_bucket_id: Some(physical_bucket_id.clone()),
        endpoint: Some(state.s3_endpoint.to_string()),
        usage: BucketUsage::default(),
        message: None,
        updated_at: Utc::now(),
    };
    let response = ProviderOperationResponse {
        operation_id,
        status,
    };
    let response_status = if context.previously_applied {
        StatusCode::OK
    } else {
        StatusCode::ACCEPTED
    };
    let stored = success_response(response_status, &response)?;
    let audit = audit_for_operation(
        &command.operation,
        None,
        request_id(&headers),
        "service_instance",
        Some(service_instance_id.to_string()),
        json!({
            "generation": generation,
            "bucket_name": command.spec.bucket_name,
            "quota_bytes": command.spec.quota_bytes,
            "quota_objects": command.spec.quota_objects
        }),
    );
    state
        .store
        .complete_reconcile(&command, operation_id, &physical_bucket_id, &stored, &audit)
        .await?;
    stored_into_response(stored)
}

async fn delete_service_instance(
    State(state): State<AppState>,
    StrictPath(service_instance_id): StrictPath<Uuid>,
    StrictQuery(query): StrictQuery<DeleteQuery>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let claims = state
        .provider_auth
        .authenticate_headers_for_action(&headers, PROVIDER_DELETE_ACTION)?;
    require_idempotency_key(&headers, claims.jwt_id)?;
    if claims.service_instance_id != service_instance_id || claims.generation != query.generation {
        return Err(ApiError::forbidden());
    }
    let generation = query.generation;
    let operation = OperationRequest {
        idempotency_key: claims.jwt_id,
        organization_id: claims.organization_id,
        project_id: claims.project_id,
        service_instance_id,
        principal_id: claims.subject,
        action: PROVIDER_DELETE_ACTION.into(),
        generation: Some(generation),
        request_hash: request_hash(
            PROVIDER_DELETE_ACTION,
            &json!({"service_instance_id": service_instance_id, "generation": generation}),
        )?,
    };
    let command = DeleteCommand {
        operation,
        generation,
    };
    let prepared = state.store.prepare_delete(&command).await?;
    let Prepare::Execute {
        operation_id,
        context,
    } = prepared
    else {
        return prepared_response(prepared);
    };
    let physical_bucket_id = context
        .bucket
        .physical_bucket_id
        .as_deref()
        .ok_or_else(ApiError::internal)?;
    state
        .store
        .renew_operation(&command.operation, operation_id)
        .await?;
    let usage = match state.garage.bucket_usage(physical_bucket_id).await {
        Ok(usage) => usage,
        Err(GarageBackendError::NotFound(_)) => BucketUsage::default(),
        Err(error) => {
            return Err(persist_backend_failure(
                &state,
                &command.operation,
                operation_id,
                error,
                audit_for_operation(
                    &command.operation,
                    None,
                    request_id(&headers),
                    "service_instance",
                    Some(service_instance_id.to_string()),
                    json!({"generation": generation, "phase": "usage_check"}),
                ),
            )
            .await);
        }
    };
    if !bucket_is_empty(usage) {
        let error = ApiError::conflict(
            "bucket_not_empty",
            "service bucket must contain no objects or unfinished uploads before deletion",
        );
        persist_failure(
            &state,
            &command.operation,
            operation_id,
            &error,
            audit_for_operation(
                &command.operation,
                None,
                request_id(&headers),
                "service_instance",
                Some(service_instance_id.to_string()),
                json!({
                    "generation": generation,
                    "bytes": usage.bytes,
                    "objects": usage.objects,
                    "unfinished_upload_bytes": usage.unfinished_upload_bytes,
                    "unfinished_uploads": usage.unfinished_uploads
                }),
            ),
        )
        .await?;
        return Err(error);
    }
    for garage_key_id in &context.garage_key_ids {
        state
            .store
            .renew_operation(&command.operation, operation_id)
            .await?;
        if let Err(error) = state.garage.revoke_credential(garage_key_id).await {
            return Err(persist_backend_failure(
                &state,
                &command.operation,
                operation_id,
                error,
                audit_for_operation(
                    &command.operation,
                    None,
                    request_id(&headers),
                    "service_instance",
                    Some(service_instance_id.to_string()),
                    json!({"generation": generation, "phase": "key_revocation"}),
                ),
            )
            .await);
        }
    }
    state
        .store
        .renew_operation(&command.operation, operation_id)
        .await?;
    if let Err(error) = state.garage.delete_bucket(physical_bucket_id).await {
        return Err(persist_backend_failure(
            &state,
            &command.operation,
            operation_id,
            error,
            audit_for_operation(
                &command.operation,
                None,
                request_id(&headers),
                "service_instance",
                Some(service_instance_id.to_string()),
                json!({"generation": generation, "phase": "bucket_deletion"}),
            ),
        )
        .await);
    }
    let response = ProviderOperationResponse {
        operation_id,
        status: BucketStatus {
            observed_generation: request_generation(generation)?,
            phase: BucketPhase::Deleted,
            backend_bucket_id: None,
            endpoint: None,
            usage: BucketUsage::default(),
            message: None,
            updated_at: Utc::now(),
        },
    };
    let stored = success_response(StatusCode::OK, &response)?;
    let audit = audit_for_operation(
        &command.operation,
        None,
        request_id(&headers),
        "service_instance",
        Some(service_instance_id.to_string()),
        json!({"generation": generation}),
    );
    state
        .store
        .complete_delete(&command, operation_id, &stored, &audit)
        .await?;
    stored_into_response(stored)
}

#[utoipa::path(
    get,
    path = "/v1/service-overview",
    responses(
        (status = 200, body = ServiceOverviewResponse),
        (status = 401, body = ErrorEnvelope),
        (status = 403, body = ErrorEnvelope),
        (status = 404, body = ErrorEnvelope)
    ),
    security(("syouyu_principal" = [], "syouyu_timestamp" = [], "syouyu_signature" = []))
)]
async fn service_overview(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<ServiceOverviewResponse>, ApiError> {
    let principal = authorize(&state, &headers, OVERVIEW_READ_PERMISSION)?;
    let record = state
        .store
        .service_overview(
            principal.scope.organization_id,
            principal.scope.project_id,
            principal.scope.service_instance_id,
        )
        .await?;
    let credentials = state
        .store
        .list_credentials(
            principal.scope.organization_id,
            principal.scope.project_id,
            principal.scope.service_instance_id,
        )
        .await?;
    let phase = record
        .phase
        .parse::<BucketPhase>()
        .map_err(|_| ApiError::internal())?;
    record_read_audit(
        &state,
        &principal,
        &headers,
        "service.overview.read",
        "service_instance",
    )
    .await?;
    Ok(Json(ServiceOverviewResponse {
        service_instance_id: record.id,
        name: record.name,
        region: record.bucket.region,
        bucket_name: record.bucket.bucket_name,
        phase,
        endpoint: state.s3_endpoint.to_string(),
        quota: BucketQuota {
            bytes: record.bucket.quota_bytes,
            objects: record.bucket.quota_objects,
        },
        usage: BucketUsage {
            bytes: record.bucket.used_bytes,
            objects: record.bucket.used_objects,
            ..BucketUsage::default()
        },
        active_credentials: u64::try_from(
            credentials
                .iter()
                .filter(|credential| credential.status == "active")
                .count(),
        )
        .unwrap_or(u64::MAX),
        measured_at: record.bucket.usage_measured_at.unwrap_or_else(Utc::now),
    }))
}

#[utoipa::path(
    get,
    path = "/v1/usage",
    responses(
        (status = 200, body = UsageResponse),
        (status = 401, body = ErrorEnvelope),
        (status = 403, body = ErrorEnvelope),
        (status = 502, body = ErrorEnvelope)
    ),
    security(("syouyu_principal" = [], "syouyu_timestamp" = [], "syouyu_signature" = []))
)]
async fn service_usage(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<UsageResponse>, ApiError> {
    let principal = authorize(&state, &headers, USAGE_READ_PERMISSION)?;
    let service = state
        .store
        .service_overview(
            principal.scope.organization_id,
            principal.scope.project_id,
            principal.scope.service_instance_id,
        )
        .await?;
    let physical_bucket_id = service
        .bucket
        .physical_bucket_id
        .as_deref()
        .ok_or_else(ApiError::internal)?;
    let usage = state.garage.bucket_usage(physical_bucket_id).await?;
    let measured_at = Utc::now();
    let stored = state
        .store
        .record_usage(
            principal.scope.organization_id,
            principal.scope.project_id,
            principal.scope.service_instance_id,
            usage.bytes,
            usage.objects,
            measured_at,
        )
        .await?;
    record_read_audit(&state, &principal, &headers, "usage.read", "bucket").await?;
    Ok(Json(UsageResponse {
        service_instance_id: stored.service_instance_id,
        bytes_used: stored.bytes_used,
        objects_used: stored.objects_used,
        unfinished_upload_bytes: usage.unfinished_upload_bytes,
        unfinished_uploads: usage.unfinished_uploads,
        quota_bytes: stored.quota_bytes,
        quota_objects: stored.quota_objects,
        measured_at: stored.measured_at,
    }))
}

#[utoipa::path(
    post,
    path = "/v1/credentials",
    request_body = CreateCredentialRequest,
    responses(
        (status = 201, body = IssuedCredentialResponse),
        (status = 400, body = ErrorEnvelope),
        (status = 401, body = ErrorEnvelope),
        (status = 403, body = ErrorEnvelope),
        (status = 409, body = ErrorEnvelope),
        (status = 502, body = ErrorEnvelope),
        (status = 503, body = ErrorEnvelope)
    ),
    params(
        ("Idempotency-Key" = Uuid, Header, description = "Canonical UUID unique to this credential creation")
    ),
    security(("syouyu_principal" = [], "syouyu_timestamp" = [], "syouyu_signature" = []))
)]
async fn create_credential(
    State(state): State<AppState>,
    headers: HeaderMap,
    StrictJson(request): StrictJson<CreateCredentialRequest>,
) -> Result<Response, ApiError> {
    let principal = authorize(&state, &headers, CREDENTIAL_CREATE_PERMISSION)?;
    CredentialSpec {
        name: request.name.clone(),
        permissions: request.permissions,
    }
    .validate()
    .map_err(|error| ApiError::bad_request(error.to_string()))?;
    let idempotency_key = public_idempotency_key(&headers)?;
    let operation = principal_operation(
        &principal,
        idempotency_key,
        CREDENTIAL_CREATE_ACTION,
        request_hash(
            CREDENTIAL_CREATE_ACTION,
            &json!({
                "request": &request,
                "credential_limits": principal.credential_limits,
            }),
        )?,
    );
    let command = CreateCredentialCommand {
        operation,
        name: request.name,
        permissions: request.permissions,
        credential_limits: principal.credential_limits,
    };
    let prepared = state.store.prepare_create_credential(&command).await?;
    let (operation_id, context) = match prepared {
        Prepare::Execute {
            operation_id,
            context,
        } => (operation_id, context),
        other => return prepared_response(other),
    };
    let physical_bucket_id = context
        .bucket
        .physical_bucket_id
        .as_deref()
        .ok_or_else(ApiError::internal)?;
    let deterministic_name = format!(
        "syouyu-{}-{}",
        principal.scope.service_instance_id, context.credential_id
    );
    state
        .store
        .renew_operation(&command.operation, operation_id)
        .await?;
    let issued = match state
        .garage
        .create_credential(physical_bucket_id, &deterministic_name, command.permissions)
        .await
    {
        Ok(issued) => issued,
        Err(error) => {
            return Err(persist_backend_failure(
                &state,
                &command.operation,
                operation_id,
                error,
                audit_for_operation(
                    &command.operation,
                    Some(principal.context_id),
                    request_id(&headers),
                    "credential",
                    Some(context.credential_id.to_string()),
                    json!({"name": command.name}),
                ),
            )
            .await);
        }
    };
    let created_at = Utc::now();
    let response = IssuedCredentialResponse {
        credential: CredentialResponse {
            id: context.credential_id,
            name: command.name.clone(),
            access_key_id: issued.access_key_id.clone(),
            permissions: command.permissions,
            status: "active".into(),
            created_at,
            revoked_at: None,
        },
        secret_access_key: issued.secret_access_key.clone(),
        bucket_name: context.bucket.bucket_name,
        endpoint: state.s3_endpoint.to_string(),
    };
    let stored = success_response(StatusCode::CREATED, &response)?;
    let secret_key_fingerprint: [u8; 32] =
        Sha256::digest(issued.secret_access_key.as_bytes()).into();
    let credential = NewCredential {
        id: context.credential_id,
        garage_key_id: issued.garage_key_id.clone(),
        access_key_id: issued.access_key_id,
        secret_key_fingerprint,
        name: command.name.clone(),
        permissions: command.permissions,
    };
    let audit = audit_for_operation(
        &command.operation,
        Some(principal.context_id),
        request_id(&headers),
        "credential",
        Some(context.credential_id.to_string()),
        json!({
            "name": command.name,
            "permissions": command.permissions,
            "access_key_id": credential.access_key_id
        }),
    );
    if let Err(error) = state
        .store
        .complete_create_credential(&command, operation_id, &credential, &stored, &audit)
        .await
    {
        if matches!(&error, StoreError::OperationLeaseLost { .. })
            && let Err(revoke_error) = state
                .garage
                .revoke_credential(&credential.garage_key_id)
                .await
        {
            error!(%revoke_error, credential_id = %credential.id, "failed to remove key created by a fenced operation");
        }
        return Err(ApiError::from(error));
    }
    stored_into_response(stored)
}

#[utoipa::path(
    get,
    path = "/v1/credentials",
    responses(
        (status = 200, body = CredentialListResponse),
        (status = 401, body = ErrorEnvelope),
        (status = 403, body = ErrorEnvelope),
        (status = 404, body = ErrorEnvelope)
    ),
    security(("syouyu_principal" = [], "syouyu_timestamp" = [], "syouyu_signature" = []))
)]
async fn list_credentials(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<CredentialListResponse>, ApiError> {
    let principal = authorize(&state, &headers, CREDENTIAL_READ_PERMISSION)?;
    let credentials = state
        .store
        .list_credentials(
            principal.scope.organization_id,
            principal.scope.project_id,
            principal.scope.service_instance_id,
        )
        .await?
        .into_iter()
        .map(CredentialResponse::from)
        .collect();
    record_read_audit(
        &state,
        &principal,
        &headers,
        "credential.list",
        "credential",
    )
    .await?;
    Ok(Json(CredentialListResponse { credentials }))
}

#[utoipa::path(
    delete,
    path = "/v1/credentials/{credential_id}",
    params(
        ("credential_id" = Uuid, Path, description = "Credential identifier"),
        ("Idempotency-Key" = Uuid, Header, description = "Canonical UUID unique to this credential revocation")
    ),
    responses(
        (status = 200, body = RevokedCredentialResponse),
        (status = 401, body = ErrorEnvelope),
        (status = 403, body = ErrorEnvelope),
        (status = 404, body = ErrorEnvelope),
        (status = 409, body = ErrorEnvelope),
        (status = 502, body = ErrorEnvelope),
        (status = 503, body = ErrorEnvelope)
    ),
    security(("syouyu_principal" = [], "syouyu_timestamp" = [], "syouyu_signature" = []))
)]
async fn revoke_credential(
    State(state): State<AppState>,
    StrictPath(credential_id): StrictPath<Uuid>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let principal = authorize(&state, &headers, CREDENTIAL_REVOKE_PERMISSION)?;
    let idempotency_key = public_idempotency_key(&headers)?;
    let hash = request_hash(
        CREDENTIAL_REVOKE_ACTION,
        &json!({"credential_id": credential_id}),
    )?;
    let operation =
        principal_operation(&principal, idempotency_key, CREDENTIAL_REVOKE_ACTION, hash);
    let command = RevokeCredentialCommand {
        operation,
        credential_id,
    };
    let prepared = state.store.prepare_revoke_credential(&command).await?;
    let (operation_id, context) = match prepared {
        Prepare::Execute {
            operation_id,
            context,
        } => (operation_id, context),
        other => return prepared_response(other),
    };
    state
        .store
        .renew_operation(&command.operation, operation_id)
        .await?;
    if !context.already_revoked
        && let Err(error) = state.garage.revoke_credential(&context.garage_key_id).await
    {
        return Err(persist_backend_failure(
            &state,
            &command.operation,
            operation_id,
            error,
            audit_for_operation(
                &command.operation,
                Some(principal.context_id),
                request_id(&headers),
                "credential",
                Some(credential_id.to_string()),
                json!({}),
            ),
        )
        .await);
    }
    let response = RevokedCredentialResponse {
        credential_id,
        status: "revoked".into(),
    };
    let stored = success_response(StatusCode::OK, &response)?;
    let audit = audit_for_operation(
        &command.operation,
        Some(principal.context_id),
        request_id(&headers),
        "credential",
        Some(credential_id.to_string()),
        json!({"already_revoked": context.already_revoked}),
    );
    state
        .store
        .complete_revoke_credential(&command, operation_id, &stored, &audit)
        .await?;
    stored_into_response(stored)
}

impl From<CredentialRecord> for CredentialResponse {
    fn from(value: CredentialRecord) -> Self {
        Self {
            id: value.id,
            name: value.name,
            access_key_id: value.access_key_id,
            permissions: value.permissions,
            status: value.status,
            created_at: value.created_at,
            revoked_at: value.revoked_at,
        }
    }
}

fn authorize(
    state: &AppState,
    headers: &HeaderMap,
    permission: &str,
) -> Result<Principal, ApiError> {
    let principal = state.principal_auth.authenticate(headers)?;
    principal.require(permission)?;
    Ok(principal)
}

fn principal_operation(
    principal: &Principal,
    idempotency_key: Uuid,
    action: &str,
    hash: [u8; 32],
) -> OperationRequest {
    OperationRequest {
        idempotency_key,
        organization_id: principal.scope.organization_id,
        project_id: principal.scope.project_id,
        service_instance_id: principal.scope.service_instance_id,
        principal_id: principal.principal_id,
        action: action.into(),
        generation: None,
        request_hash: hash,
    }
}

fn public_idempotency_key(headers: &HeaderMap) -> Result<Uuid, ApiError> {
    let value = headers
        .get(IDEMPOTENCY_KEY)
        .ok_or_else(|| ApiError::bad_request("Idempotency-Key is required"))?
        .to_str()
        .map_err(|_| ApiError::bad_request("Idempotency-Key is invalid"))?;
    let parsed = Uuid::parse_str(value)
        .map_err(|_| ApiError::bad_request("Idempotency-Key must be a canonical UUID"))?;
    if parsed.to_string() != value {
        return Err(ApiError::bad_request(
            "Idempotency-Key must use canonical lowercase UUID encoding",
        ));
    }
    Ok(parsed)
}

fn prepared_response<T>(prepared: Prepare<T>) -> Result<Response, ApiError> {
    match prepared {
        Prepare::Replay(response) => stored_into_response(response),
        Prepare::InProgress { operation_id } => Err(ApiError::operation_in_progress(operation_id)),
        Prepare::Execute { .. } => Err(ApiError::internal()),
    }
}

fn success_response<T: Serialize>(
    status: StatusCode,
    value: &T,
) -> Result<StoredHttpResponse, ApiError> {
    Ok(StoredHttpResponse {
        status: status.as_u16(),
        body: serde_json::to_value(value).map_err(|_| ApiError::internal())?,
        failed: false,
    })
}

fn stored_into_response(stored: StoredHttpResponse) -> Result<Response, ApiError> {
    let status = StatusCode::from_u16(stored.status).map_err(|_| ApiError::internal())?;
    let mut response = (status, Json(stored.body)).into_response();
    response
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store, private"));
    response
        .headers_mut()
        .insert(PRAGMA, HeaderValue::from_static("no-cache"));
    Ok(response)
}

async fn persist_backend_failure(
    state: &AppState,
    operation: &OperationRequest,
    operation_id: Uuid,
    backend_error: GarageBackendError,
    mut audit: AuditEvent,
) -> ApiError {
    warn!(error = %backend_error, %operation_id, "Garage operation failed");
    let api_error = ApiError::from(backend_error);
    audit.outcome = "failed".into();
    if let Err(error) = state
        .store
        .fail_operation(
            operation,
            operation_id,
            &api_error.stored_response(),
            &audit,
        )
        .await
    {
        error!(%error, %operation_id, "failed to persist operation failure receipt");
        return ApiError::from(error);
    }
    api_error
}

async fn persist_failure(
    state: &AppState,
    operation: &OperationRequest,
    operation_id: Uuid,
    api_error: &ApiError,
    mut audit: AuditEvent,
) -> Result<(), ApiError> {
    audit.outcome = "failed".into();
    state
        .store
        .fail_operation(
            operation,
            operation_id,
            &api_error.stored_response(),
            &audit,
        )
        .await?;
    Ok(())
}

fn audit_for_operation(
    operation: &OperationRequest,
    principal_context_id: Option<Uuid>,
    request_id: String,
    resource_type: &str,
    resource_id: Option<String>,
    details: Value,
) -> AuditEvent {
    AuditEvent {
        organization_id: operation.organization_id,
        project_id: operation.project_id,
        service_instance_id: operation.service_instance_id,
        principal_id: operation.principal_id,
        principal_context_id,
        request_id,
        action: operation.action.clone(),
        resource_type: resource_type.into(),
        resource_id,
        outcome: "allowed".into(),
        details,
    }
}

async fn record_read_audit(
    state: &AppState,
    principal: &Principal,
    headers: &HeaderMap,
    action: &str,
    resource_type: &str,
) -> Result<(), ApiError> {
    state
        .store
        .record_audit(&AuditEvent {
            organization_id: principal.scope.organization_id,
            project_id: principal.scope.project_id,
            service_instance_id: principal.scope.service_instance_id,
            principal_id: principal.principal_id,
            principal_context_id: Some(principal.context_id),
            request_id: request_id(headers),
            action: action.into(),
            resource_type: resource_type.into(),
            resource_id: Some(principal.scope.service_instance_id.to_string()),
            outcome: "allowed".into(),
            details: json!({}),
        })
        .await?;
    Ok(())
}

fn request_id(headers: &HeaderMap) -> String {
    headers
        .get(REQUEST_ID)
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.is_empty() && value.len() <= 256)
        .map_or_else(|| Uuid::now_v7().to_string(), str::to_owned)
}

fn request_generation(generation: i64) -> Result<u64, ApiError> {
    u64::try_from(generation).map_err(|_| ApiError::internal())
}

#[derive(OpenApi)]
#[openapi(
    paths(service_overview, service_usage, create_credential, list_credentials, revoke_credential),
    components(schemas(
        ServiceOverviewResponse,
        UsageResponse,
        CreateCredentialRequest,
        CredentialResponse,
        IssuedCredentialResponse,
        CredentialListResponse,
        RevokedCredentialResponse,
        ErrorEnvelope,
        BucketPermissions,
        BucketQuota,
        BucketUsage,
        BucketPhase
    )),
    modifiers(&SecurityAddon),
    tags((name = "Syouyu", description = "Bucket-scoped S3 credential and usage API"))
)]
struct ApiDoc;

struct SecurityAddon;

impl Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        let components = openapi.components.get_or_insert_default();
        components.add_security_scheme(
            "syouyu_principal",
            SecurityScheme::ApiKey(ApiKey::Header(ApiKeyValue::new(PRINCIPAL_HEADER.as_str()))),
        );
        components.add_security_scheme(
            "syouyu_timestamp",
            SecurityScheme::ApiKey(ApiKey::Header(ApiKeyValue::new(
                PRINCIPAL_TIMESTAMP_HEADER.as_str(),
            ))),
        );
        components.add_security_scheme(
            "syouyu_signature",
            SecurityScheme::ApiKey(ApiKey::Header(ApiKeyValue::new(
                PRINCIPAL_SIGNATURE_HEADER.as_str(),
            ))),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::{ApiDoc, CreateCredentialRequest, public_idempotency_key};
    use http::{HeaderMap, HeaderValue};
    use syouyu_domain::BucketPermissions;
    use utoipa::OpenApi;
    use uuid::Uuid;

    #[test]
    fn rejects_unknown_credential_request_fields() {
        let request = serde_json::from_value::<CreateCredentialRequest>(serde_json::json!({
            "name": "flash-workspace",
            "permissions": {"read": true, "write": true},
            "bucket_id": "scope-escape"
        }));
        assert!(request.is_err());
        let valid = serde_json::from_value::<CreateCredentialRequest>(serde_json::json!({
            "name": "flash-workspace",
            "permissions": {"read": true, "write": false}
        }))
        .unwrap();
        assert_eq!(
            valid.permissions,
            BucketPermissions {
                read: true,
                write: false
            }
        );
    }

    #[test]
    fn requires_canonical_idempotency_uuid() {
        let id = Uuid::new_v4();
        let mut headers = HeaderMap::new();
        headers.insert(
            "idempotency-key",
            HeaderValue::from_str(&id.to_string()).unwrap(),
        );
        assert_eq!(public_idempotency_key(&headers).unwrap(), id);
        headers.insert(
            "idempotency-key",
            HeaderValue::from_str(&id.to_string().to_uppercase()).unwrap(),
        );
        assert!(public_idempotency_key(&headers).is_err());
    }

    #[test]
    fn openapi_exposes_only_public_principal_routes() {
        let document = serde_json::to_value(ApiDoc::openapi()).unwrap();
        let paths = document["paths"].as_object().unwrap();
        assert_eq!(paths.len(), 4);
        assert!(paths.contains_key("/v1/service-overview"));
        assert!(paths.contains_key("/v1/credentials/{credential_id}"));
        assert!(!paths.keys().any(|path| path.starts_with("/internal")));
        assert_eq!(
            document["components"]["securitySchemes"]["syouyu_principal"]["name"],
            "x-syouyu-principal"
        );
    }
}
