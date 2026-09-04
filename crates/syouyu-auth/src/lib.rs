use std::{collections::BTreeMap, sync::Arc};

use chrono::Utc;
use http::{
    HeaderMap,
    header::{AUTHORIZATION, HeaderName},
};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use serde::{Deserialize, Serialize};
use syouyu_domain::ServiceScope;
use thiserror::Error;
use uuid::Uuid;

pub const PROVIDER_RECONCILE_ACTION: &str = "service-instance.reconcile";
pub const PROVIDER_DELETE_ACTION: &str = "service-instance.delete";
pub const PROVIDER_CREDENTIAL_REVOKE_ACTION: &str = "credential.revoke";
pub const PROVIDER_MAX_TOKEN_TTL_SECONDS: i64 = 60;
pub const PROVIDER_NOT_BEFORE_OFFSET_SECONDS: i64 = 5;
pub const IDEMPOTENCY_KEY_HEADER: HeaderName = HeaderName::from_static("idempotency-key");

#[derive(Clone)]
pub struct ProviderAuthenticator {
    issuer: String,
    audience: String,
    keys: Arc<BTreeMap<String, DecodingKey>>,
    clock_skew_seconds: u64,
}

impl ProviderAuthenticator {
    /// Builds an Ed25519 verifier from a JSON object mapping each `kid` to a
    /// public-key PEM.
    pub fn from_public_keys_json(
        issuer: impl Into<String>,
        audience: impl Into<String>,
        public_keys_json: &str,
    ) -> Result<Self, AuthError> {
        let issuer = issuer.into();
        let audience = audience.into();
        if issuer.is_empty() || audience.is_empty() {
            return Err(AuthError::InvalidConfiguration(
                "provider issuer and audience are required",
            ));
        }

        let encoded_keys: BTreeMap<String, String> = serde_json::from_str(public_keys_json)
            .map_err(|_| AuthError::InvalidConfiguration("provider public key JSON is invalid"))?;
        if encoded_keys.is_empty() {
            return Err(AuthError::InvalidConfiguration(
                "at least one provider public key is required",
            ));
        }

        let keys = encoded_keys
            .into_iter()
            .map(|(key_id, pem)| {
                validate_key_id(&key_id)?;
                let key = DecodingKey::from_ed_pem(pem.as_bytes()).map_err(|_| {
                    AuthError::InvalidConfiguration("provider public key is invalid")
                })?;
                Ok((key_id, key))
            })
            .collect::<Result<_, AuthError>>()?;

        Ok(Self {
            issuer,
            audience,
            keys: Arc::new(keys),
            clock_skew_seconds: 5,
        })
    }

    /// Verifies a reconcile bearer token without path-scope or idempotency
    /// checks. HTTP handlers should normally use [`Self::authenticate_command`].
    pub fn authenticate_headers(&self, headers: &HeaderMap) -> Result<ProviderClaims, AuthError> {
        self.authenticate_headers_for_action(headers, PROVIDER_RECONCILE_ACTION)
    }

    pub fn authenticate_headers_for_action(
        &self,
        headers: &HeaderMap,
        expected_action: &str,
    ) -> Result<ProviderClaims, AuthError> {
        let token = bearer_token(headers)?;
        self.verify_token_for_action(token, expected_action)
    }

    /// Verifies the JWT, exact command action, path scope, and the required
    /// `Idempotency-Key == jti` binding as one trust-boundary operation.
    pub fn authenticate_command(
        &self,
        headers: &HeaderMap,
        expected_action: &str,
        expected_scope: ServiceScope,
    ) -> Result<ProviderClaims, AuthError> {
        expected_scope
            .validate()
            .map_err(|_| AuthError::InvalidExpectedScope)?;
        let claims = self.authenticate_headers_for_action(headers, expected_action)?;
        claims.require_scope(expected_scope)?;
        require_idempotency_key(headers, claims.jwt_id)?;
        Ok(claims)
    }

    pub fn verify_token(&self, token: &str) -> Result<ProviderClaims, AuthError> {
        self.verify_token_for_action(token, PROVIDER_RECONCILE_ACTION)
    }

    /// Verifies the Flow-compatible provider JWT contract: `EdDSA`, trusted
    /// `kid`, exact issuer/audience/action, non-nil scope, positive generation,
    /// `nbf = iat - 5`, and a maximum lifetime of 60 seconds.
    pub fn verify_token_for_action(
        &self,
        token: &str,
        expected_action: &str,
    ) -> Result<ProviderClaims, AuthError> {
        if expected_action.is_empty() {
            return Err(AuthError::InvalidConfiguration(
                "expected provider action is required",
            ));
        }

        let header = decode_header(token).map_err(|_| AuthError::InvalidToken)?;
        if header.alg != Algorithm::EdDSA {
            return Err(AuthError::InvalidToken);
        }
        let key_id = header.kid.ok_or(AuthError::MissingKeyId)?;
        let key = self.keys.get(&key_id).ok_or(AuthError::UnknownKeyId)?;

        let mut validation = Validation::new(Algorithm::EdDSA);
        validation.set_issuer(&[self.issuer.as_str()]);
        validation.set_audience(&[self.audience.as_str()]);
        validation.set_required_spec_claims(&["exp", "iat", "nbf", "iss", "aud", "sub", "jti"]);
        validation.leeway = self.clock_skew_seconds;
        validation.validate_exp = true;
        validation.validate_nbf = true;

        let claims = decode::<ProviderClaims>(token, key, &validation)
            .map_err(|_| AuthError::InvalidToken)?
            .claims;

        if claims.action != expected_action || claims.generation <= 0 {
            return Err(AuthError::InvalidProviderCommand);
        }
        if claims.subject.is_nil() || claims.jwt_id.is_nil() || claims.scope().validate().is_err() {
            return Err(AuthError::InvalidProviderScope);
        }
        if claims.expires_at <= claims.issued_at
            || claims.expires_at.saturating_sub(claims.issued_at) > PROVIDER_MAX_TOKEN_TTL_SECONDS
            || claims
                .issued_at
                .checked_sub(PROVIDER_NOT_BEFORE_OFFSET_SECONDS)
                != Some(claims.not_before)
        {
            return Err(AuthError::TokenLifetimeExceeded);
        }

        let now = Utc::now().timestamp();
        let skew = i64::try_from(self.clock_skew_seconds)
            .map_err(|_| AuthError::InvalidConfiguration("provider clock skew is invalid"))?;
        if claims.issued_at > now.saturating_add(skew) {
            return Err(AuthError::InvalidToken);
        }
        Ok(claims)
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProviderClaims {
    #[serde(rename = "iss")]
    pub issuer: String,
    #[serde(rename = "aud")]
    pub audience: String,
    #[serde(rename = "sub")]
    pub subject: Uuid,
    pub organization_id: Uuid,
    pub project_id: Uuid,
    pub service_instance_id: Uuid,
    pub action: String,
    pub generation: i64,
    #[serde(rename = "jti")]
    pub jwt_id: Uuid,
    #[serde(rename = "iat")]
    pub issued_at: i64,
    #[serde(rename = "nbf")]
    pub not_before: i64,
    #[serde(rename = "exp")]
    pub expires_at: i64,
}

impl ProviderClaims {
    #[must_use]
    pub const fn scope(&self) -> ServiceScope {
        ServiceScope {
            organization_id: self.organization_id,
            project_id: self.project_id,
            service_instance_id: self.service_instance_id,
        }
    }

    pub fn require_scope(&self, expected: ServiceScope) -> Result<(), AuthError> {
        if self.scope() == expected {
            Ok(())
        } else {
            Err(AuthError::ScopeMismatch)
        }
    }
}

/// Requires one canonical UUID idempotency header matching the verified JWT's
/// `jti`. The exact textual check prevents alternate encodings from creating
/// multiple receipt keys for the same token.
pub fn require_idempotency_key(headers: &HeaderMap, jwt_id: Uuid) -> Result<(), AuthError> {
    let value = headers
        .get(&IDEMPOTENCY_KEY_HEADER)
        .ok_or(AuthError::MissingIdempotencyKey)?
        .to_str()
        .map_err(|_| AuthError::InvalidIdempotencyKey)?;
    if value == jwt_id.to_string() {
        Ok(())
    } else {
        Err(AuthError::IdempotencyKeyMismatch)
    }
}

fn bearer_token(headers: &HeaderMap) -> Result<&str, AuthError> {
    let value = headers
        .get(AUTHORIZATION)
        .ok_or(AuthError::MissingCredentials)?
        .to_str()
        .map_err(|_| AuthError::InvalidHeader)?;
    value
        .strip_prefix("Bearer ")
        .filter(|token| !token.is_empty())
        .ok_or(AuthError::InvalidHeader)
}

fn validate_key_id(value: &str) -> Result<(), AuthError> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(AuthError::InvalidConfiguration(
            "provider key ID is invalid",
        ));
    }
    Ok(())
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum AuthError {
    #[error("credentials are missing")]
    MissingCredentials,
    #[error("credential header is invalid")]
    InvalidHeader,
    #[error("token is invalid or expired")]
    InvalidToken,
    #[error("provider token has no key ID")]
    MissingKeyId,
    #[error("provider token key ID is not trusted")]
    UnknownKeyId,
    #[error("provider command claims are invalid")]
    InvalidProviderCommand,
    #[error("provider token contains an invalid scope")]
    InvalidProviderScope,
    #[error("expected request scope is invalid")]
    InvalidExpectedScope,
    #[error("provider token scope does not match the request path")]
    ScopeMismatch,
    #[error("credential lifetime exceeds the service limit")]
    TokenLifetimeExceeded,
    #[error("idempotency key is missing")]
    MissingIdempotencyKey,
    #[error("idempotency key is not a canonical UUID")]
    InvalidIdempotencyKey,
    #[error("idempotency key does not match provider token jti")]
    IdempotencyKeyMismatch,
    #[error("invalid authentication configuration: {0}")]
    InvalidConfiguration(&'static str),
}

#[cfg(test)]
mod tests {
    use http::{HeaderMap, HeaderValue, header::AUTHORIZATION};
    use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
    use syouyu_domain::ServiceScope;
    use uuid::Uuid;

    use super::{
        AuthError, IDEMPOTENCY_KEY_HEADER, PROVIDER_DELETE_ACTION,
        PROVIDER_NOT_BEFORE_OFFSET_SECONDS, PROVIDER_RECONCILE_ACTION, ProviderAuthenticator,
        ProviderClaims,
    };

    const PRIVATE_KEY: &[u8] = br"-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIFTAxDs5JPZKnyxcfE0FA8mmr+9KN0LmQ1co4bxZ6Vq/
-----END PRIVATE KEY-----
";
    const PUBLIC_KEY: &str = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAQnTjC0+B/djS2k/sebsW6/7yCb+Am2NFtI1EzKH/ZTA=\n-----END PUBLIC KEY-----\n";

    fn authenticator() -> ProviderAuthenticator {
        ProviderAuthenticator::from_public_keys_json(
            "heterocloud",
            "heterocloud-syouyu",
            &serde_json::json!({"heterocloud-provider-1": PUBLIC_KEY}).to_string(),
        )
        .unwrap()
    }

    fn scope() -> ServiceScope {
        ServiceScope {
            organization_id: Uuid::new_v4(),
            project_id: Uuid::new_v4(),
            service_instance_id: Uuid::new_v4(),
        }
    }

    fn claims(scope: ServiceScope, action: &str) -> ProviderClaims {
        let now = chrono::Utc::now().timestamp();
        ProviderClaims {
            issuer: "heterocloud".into(),
            audience: "heterocloud-syouyu".into(),
            subject: Uuid::new_v4(),
            organization_id: scope.organization_id,
            project_id: scope.project_id,
            service_instance_id: scope.service_instance_id,
            action: action.into(),
            generation: 1,
            jwt_id: Uuid::now_v7(),
            issued_at: now,
            not_before: now - PROVIDER_NOT_BEFORE_OFFSET_SECONDS,
            expires_at: now + 60,
        }
    }

    fn token(claims: &ProviderClaims, kid: Option<&str>) -> String {
        let mut header = Header::new(Algorithm::EdDSA);
        header.kid = kid.map(str::to_owned);
        encode(
            &header,
            claims,
            &EncodingKey::from_ed_pem(PRIVATE_KEY).unwrap(),
        )
        .unwrap()
    }

    fn headers(claims: &ProviderClaims) -> HeaderMap {
        let token = token(claims, Some("heterocloud-provider-1"));
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
        );
        headers.insert(
            IDEMPOTENCY_KEY_HEADER,
            HeaderValue::from_str(&claims.jwt_id.to_string()).unwrap(),
        );
        headers
    }

    #[test]
    fn authenticates_exact_action_scope_and_idempotency_binding() {
        let expected_scope = scope();
        let claims = claims(expected_scope, PROVIDER_RECONCILE_ACTION);
        let verified = authenticator()
            .authenticate_command(&headers(&claims), PROVIDER_RECONCILE_ACTION, expected_scope)
            .unwrap();
        assert_eq!(verified, claims);
    }

    #[test]
    fn rejects_scope_confusion() {
        let claims = claims(scope(), PROVIDER_RECONCILE_ACTION);
        assert_eq!(
            authenticator().authenticate_command(
                &headers(&claims),
                PROVIDER_RECONCILE_ACTION,
                scope(),
            ),
            Err(AuthError::ScopeMismatch)
        );
    }

    #[test]
    fn rejects_mismatched_or_noncanonical_idempotency_key() {
        let expected_scope = scope();
        let claims = claims(expected_scope, PROVIDER_RECONCILE_ACTION);
        let mut request_headers = headers(&claims);
        request_headers.insert(
            IDEMPOTENCY_KEY_HEADER,
            HeaderValue::from_str(&Uuid::new_v4().to_string()).unwrap(),
        );
        assert_eq!(
            authenticator().authenticate_command(
                &request_headers,
                PROVIDER_RECONCILE_ACTION,
                expected_scope,
            ),
            Err(AuthError::IdempotencyKeyMismatch)
        );

        request_headers.insert(
            IDEMPOTENCY_KEY_HEADER,
            HeaderValue::from_str(&claims.jwt_id.to_string().to_uppercase()).unwrap(),
        );
        assert_eq!(
            authenticator().authenticate_command(
                &request_headers,
                PROVIDER_RECONCILE_ACTION,
                expected_scope,
            ),
            Err(AuthError::IdempotencyKeyMismatch)
        );
    }

    #[test]
    fn rejects_missing_kid_and_wrong_action() {
        let expected_scope = scope();
        let claims = claims(expected_scope, PROVIDER_DELETE_ACTION);
        assert_eq!(
            authenticator().verify_token_for_action(&token(&claims, None), PROVIDER_DELETE_ACTION,),
            Err(AuthError::MissingKeyId)
        );
        assert_eq!(
            authenticator().verify_token(&token(&claims, Some("heterocloud-provider-1"),)),
            Err(AuthError::InvalidProviderCommand)
        );
    }

    #[test]
    fn rejects_tokens_longer_than_sixty_seconds() {
        let mut claims = claims(scope(), PROVIDER_RECONCILE_ACTION);
        claims.expires_at = claims.issued_at + 61;
        assert_eq!(
            authenticator().verify_token(&token(&claims, Some("heterocloud-provider-1"),)),
            Err(AuthError::TokenLifetimeExceeded)
        );
    }
}
