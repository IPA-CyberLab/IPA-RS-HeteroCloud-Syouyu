use axum::{
    Json,
    http::{HeaderValue, StatusCode},
    response::{IntoResponse, Response},
};
use serde::Serialize;
use syouyu_auth::AuthError;
use syouyu_store::{StoreError, StoredHttpResponse};
use tracing::error;
use utoipa::ToSchema;

use crate::{garage::GarageBackendError, principal_auth::PrincipalAuthError};

#[derive(Debug, Clone)]
pub struct ApiError {
    status: StatusCode,
    code: &'static str,
    message: String,
    operation_id: Option<uuid::Uuid>,
    retry_after_seconds: Option<u64>,
}

impl ApiError {
    pub fn bad_request(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "invalid_request", message)
    }

    pub fn unauthorized(message: impl Into<String>) -> Self {
        Self::new(StatusCode::UNAUTHORIZED, "invalid_credentials", message)
    }

    pub fn forbidden() -> Self {
        Self::new(
            StatusCode::FORBIDDEN,
            "permission_denied",
            "principal does not have the required permission",
        )
    }

    pub fn not_found() -> Self {
        Self::new(StatusCode::NOT_FOUND, "not_found", "resource was not found")
    }

    pub fn method_not_allowed() -> Self {
        Self::new(
            StatusCode::METHOD_NOT_ALLOWED,
            "method_not_allowed",
            "HTTP method is not allowed for this route",
        )
    }

    pub fn conflict(code: &'static str, message: impl Into<String>) -> Self {
        Self::new(StatusCode::CONFLICT, code, message)
    }

    pub fn dependency(message: impl Into<String>) -> Self {
        Self::new(
            StatusCode::BAD_GATEWAY,
            "storage_backend_unavailable",
            message,
        )
    }

    pub fn operation_in_progress(operation_id: uuid::Uuid) -> Self {
        Self {
            status: StatusCode::SERVICE_UNAVAILABLE,
            code: "operation_in_progress",
            message: "another operation for this service is still in progress".into(),
            operation_id: Some(operation_id),
            retry_after_seconds: Some(2),
        }
    }

    pub fn internal() -> Self {
        Self::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            "internal service error",
        )
    }

    fn new(status: StatusCode, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status,
            code,
            message: message.into(),
            operation_id: None,
            retry_after_seconds: None,
        }
    }

    pub fn stored_response(&self) -> StoredHttpResponse {
        StoredHttpResponse {
            status: self.status.as_u16(),
            body: serde_json::to_value(self.envelope())
                .expect("serializing the static error envelope cannot fail"),
            failed: true,
        }
    }

    fn envelope(&self) -> ErrorEnvelope {
        ErrorEnvelope {
            error: ErrorBody {
                code: self.code,
                message: self.message.clone(),
                operation_id: self.operation_id,
            },
        }
    }
}

impl From<AuthError> for ApiError {
    fn from(error: AuthError) -> Self {
        Self::unauthorized(error.to_string())
    }
}

impl From<PrincipalAuthError> for ApiError {
    fn from(error: PrincipalAuthError) -> Self {
        match error {
            PrincipalAuthError::PermissionDenied => Self::forbidden(),
            other => Self::unauthorized(other.to_string()),
        }
    }
}

impl From<GarageBackendError> for ApiError {
    fn from(error: GarageBackendError) -> Self {
        match error {
            GarageBackendError::Conflict(message) => {
                Self::conflict("storage_backend_conflict", message)
            }
            GarageBackendError::NotFound(message)
            | GarageBackendError::Unavailable(message)
            | GarageBackendError::InvalidResponse(message) => Self::dependency(message),
        }
    }
}

impl From<StoreError> for ApiError {
    fn from(error_value: StoreError) -> Self {
        match error_value {
            StoreError::NotFound => Self::not_found(),
            StoreError::Validation(message) => Self::bad_request(message),
            StoreError::DomainValidation(error) => Self::bad_request(error.to_string()),
            StoreError::InvalidNumericValue(field) => {
                Self::bad_request(format!("{field} is outside the supported range"))
            }
            StoreError::Conflict(message) => Self::conflict("conflict", message),
            StoreError::IdempotencyConflict => Self::conflict(
                "idempotency_conflict",
                "Idempotency-Key was previously used for a different request",
            ),
            StoreError::BucketNameUnavailable => Self::conflict(
                "bucket_name_unavailable",
                "bucket name is already owned by another service",
            ),
            StoreError::StaleGeneration { current, requested } => Self::conflict(
                "stale_generation",
                format!("generation {requested} is stale; current generation is {current}"),
            ),
            StoreError::OperationInProgress(operation_id) => {
                Self::operation_in_progress(operation_id)
            }
            StoreError::OperationLeaseLost {
                current_operation_id,
            } => Self::operation_in_progress(current_operation_id),
            StoreError::ServiceNotReady => {
                Self::conflict("service_not_ready", "service instance is not ready")
            }
            StoreError::CredentialLimitExceeded { scope, limit } => Self::conflict(
                "credential_limit_exceeded",
                format!("{scope} active credential limit of {limit} has been reached"),
            ),
            other => {
                error!(error = %other, "Syouyu persistence operation failed");
                Self::internal()
            }
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let retry_after = self.retry_after_seconds;
        let mut response = (self.status, Json(self.envelope())).into_response();
        if let Some(seconds) = retry_after
            && let Ok(value) = HeaderValue::from_str(&seconds.to_string())
        {
            response.headers_mut().insert("retry-after", value);
        }
        response
    }
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ErrorEnvelope {
    pub error: ErrorBody,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ErrorBody {
    pub code: &'static str,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operation_id: Option<uuid::Uuid>,
}
