use std::{collections::BTreeSet, sync::Arc, time::Duration};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{TimeZone, Utc};
use hmac::{Hmac, Mac};
use http::{HeaderMap, header::HeaderName};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use syouyu_domain::ServiceScope;
use syouyu_store::CredentialLimits;
use thiserror::Error;
use uuid::Uuid;

pub const PRINCIPAL_HEADER: HeaderName = HeaderName::from_static("x-syouyu-principal");
pub const PRINCIPAL_TIMESTAMP_HEADER: HeaderName = HeaderName::from_static("x-syouyu-timestamp");
pub const PRINCIPAL_SIGNATURE_HEADER: HeaderName = HeaderName::from_static("x-syouyu-signature");

#[derive(Clone)]
pub struct PrincipalAuthenticator {
    issuer: Arc<str>,
    audience: Arc<str>,
    secret: Arc<[u8]>,
    max_ttl: Duration,
    clock_skew: Duration,
}

impl PrincipalAuthenticator {
    pub fn new(
        issuer: impl Into<String>,
        audience: impl Into<String>,
        secret: impl Into<Vec<u8>>,
        max_ttl: Duration,
    ) -> Result<Self, PrincipalAuthError> {
        let issuer = issuer.into();
        let audience = audience.into();
        let secret = secret.into();
        if issuer.is_empty() || audience.is_empty() {
            return Err(PrincipalAuthError::InvalidConfiguration(
                "principal issuer and audience are required",
            ));
        }
        if secret.len() < 32 {
            return Err(PrincipalAuthError::InvalidConfiguration(
                "principal HMAC secret must contain at least 32 bytes",
            ));
        }
        if max_ttl.is_zero() || max_ttl > Duration::from_mins(5) {
            return Err(PrincipalAuthError::InvalidConfiguration(
                "principal maximum TTL must be between one and 300 seconds",
            ));
        }
        Ok(Self {
            issuer: issuer.into(),
            audience: audience.into(),
            secret: secret.into(),
            max_ttl,
            clock_skew: Duration::from_secs(15),
        })
    }

    pub fn authenticate(&self, headers: &HeaderMap) -> Result<Principal, PrincipalAuthError> {
        let encoded = required_header(headers, &PRINCIPAL_HEADER)?;
        let timestamp_text = required_header(headers, &PRINCIPAL_TIMESTAMP_HEADER)?;
        let signature_text = required_header(headers, &PRINCIPAL_SIGNATURE_HEADER)?;
        let signed_at = timestamp_text
            .parse::<u64>()
            .map_err(|_| PrincipalAuthError::InvalidHeader)?;

        let mut mac = Hmac::<Sha256>::new_from_slice(&self.secret)
            .map_err(|_| PrincipalAuthError::InvalidConfiguration("HMAC secret is invalid"))?;
        mac.update(timestamp_text.as_bytes());
        mac.update(b".");
        mac.update(encoded.as_bytes());
        let signature = URL_SAFE_NO_PAD
            .decode(signature_text)
            .map_err(|_| PrincipalAuthError::InvalidSignature)?;
        mac.verify_slice(&signature)
            .map_err(|_| PrincipalAuthError::InvalidSignature)?;

        let serialized = URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|_| PrincipalAuthError::InvalidPrincipal)?;
        let signed: SignedPrincipal = serde_json::from_slice(&serialized)
            .map_err(|_| PrincipalAuthError::InvalidPrincipal)?;
        if signed_at != signed.issued_at
            || signed.issuer != self.issuer.as_ref()
            || signed.audience != self.audience.as_ref()
        {
            return Err(PrincipalAuthError::InvalidPrincipal);
        }
        if signed.expires_at <= signed.issued_at
            || signed.expires_at - signed.issued_at > self.max_ttl.as_secs()
        {
            return Err(PrincipalAuthError::InvalidLifetime);
        }
        let now = u64::try_from(Utc::now().timestamp())
            .map_err(|_| PrincipalAuthError::InvalidPrincipal)?;
        if signed.issued_at > now.saturating_add(self.clock_skew.as_secs())
            || signed.expires_at.saturating_add(self.clock_skew.as_secs()) <= now
        {
            return Err(PrincipalAuthError::Expired);
        }
        signed
            .scope
            .validate()
            .map_err(|_| PrincipalAuthError::InvalidPrincipal)?;
        if signed.principal_id.is_nil() || signed.context_id.is_nil() {
            return Err(PrincipalAuthError::InvalidPrincipal);
        }
        let issued_at = timestamp(signed.issued_at)?;
        let expires_at = timestamp(signed.expires_at)?;
        Ok(Principal {
            scope: signed.scope,
            principal_id: signed.principal_id,
            permissions: signed.permissions,
            credential_limits: signed.credential_limits,
            context_id: signed.context_id,
            issued_at,
            expires_at,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::struct_field_names)]
pub struct Principal {
    pub scope: ServiceScope,
    pub principal_id: Uuid,
    pub permissions: BTreeSet<String>,
    pub credential_limits: CredentialLimits,
    pub context_id: Uuid,
    pub issued_at: chrono::DateTime<Utc>,
    pub expires_at: chrono::DateTime<Utc>,
}

impl Principal {
    pub fn require(&self, permission: &str) -> Result<(), PrincipalAuthError> {
        if self.permissions.contains(permission) {
            Ok(())
        } else {
            Err(PrincipalAuthError::PermissionDenied)
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedPrincipal {
    pub issuer: String,
    pub audience: String,
    #[serde(flatten)]
    pub scope: ServiceScope,
    pub principal_id: Uuid,
    #[serde(default)]
    pub permissions: BTreeSet<String>,
    pub credential_limits: CredentialLimits,
    pub issued_at: u64,
    pub expires_at: u64,
    pub context_id: Uuid,
}

fn required_header<'a>(
    headers: &'a HeaderMap,
    name: &HeaderName,
) -> Result<&'a str, PrincipalAuthError> {
    headers
        .get(name)
        .ok_or(PrincipalAuthError::MissingCredentials)?
        .to_str()
        .map_err(|_| PrincipalAuthError::InvalidHeader)
}

fn timestamp(value: u64) -> Result<chrono::DateTime<Utc>, PrincipalAuthError> {
    let seconds = i64::try_from(value).map_err(|_| PrincipalAuthError::InvalidPrincipal)?;
    Utc.timestamp_opt(seconds, 0)
        .single()
        .ok_or(PrincipalAuthError::InvalidPrincipal)
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum PrincipalAuthError {
    #[error("credentials are missing")]
    MissingCredentials,
    #[error("credential header is invalid")]
    InvalidHeader,
    #[error("principal signature is invalid")]
    InvalidSignature,
    #[error("principal context is invalid")]
    InvalidPrincipal,
    #[error("principal context lifetime is invalid")]
    InvalidLifetime,
    #[error("principal context is expired")]
    Expired,
    #[error("principal lacks the required permission")]
    PermissionDenied,
    #[error("invalid principal authentication configuration: {0}")]
    InvalidConfiguration(&'static str),
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeSet, time::Duration};

    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use hmac::{Hmac, Mac};
    use http::{HeaderMap, HeaderValue};
    use sha2::Sha256;
    use syouyu_domain::ServiceScope;
    use syouyu_store::CredentialLimits;
    use uuid::Uuid;

    use super::{
        PRINCIPAL_HEADER, PRINCIPAL_SIGNATURE_HEADER, PRINCIPAL_TIMESTAMP_HEADER,
        PrincipalAuthenticator, SignedPrincipal,
    };

    const SECRET: &[u8] = b"syouyu-principal-test-secret-at-least-32-bytes";

    #[test]
    fn verifies_signed_service_scoped_context() {
        let now = u64::try_from(chrono::Utc::now().timestamp()).unwrap();
        let signed = SignedPrincipal {
            issuer: "heterocloud".into(),
            audience: "heterocloud-syouyu-data".into(),
            scope: ServiceScope {
                organization_id: Uuid::new_v4(),
                project_id: Uuid::new_v4(),
                service_instance_id: Uuid::new_v4(),
            },
            principal_id: Uuid::new_v4(),
            permissions: BTreeSet::from(["syouyu.credential.read".into()]),
            credential_limits: CredentialLimits {
                max_credentials_per_bucket: 10,
                max_total_credentials: 100,
            },
            issued_at: now,
            expires_at: now + 120,
            context_id: Uuid::now_v7(),
        };
        let encoded = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&signed).unwrap());
        let timestamp = now.to_string();
        let mut mac = Hmac::<Sha256>::new_from_slice(SECRET).unwrap();
        mac.update(timestamp.as_bytes());
        mac.update(b".");
        mac.update(encoded.as_bytes());
        let signature = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
        let mut headers = HeaderMap::new();
        headers.insert(PRINCIPAL_HEADER, HeaderValue::from_str(&encoded).unwrap());
        headers.insert(
            PRINCIPAL_TIMESTAMP_HEADER,
            HeaderValue::from_str(&timestamp).unwrap(),
        );
        headers.insert(
            PRINCIPAL_SIGNATURE_HEADER,
            HeaderValue::from_str(&signature).unwrap(),
        );
        let principal = PrincipalAuthenticator::new(
            "heterocloud",
            "heterocloud-syouyu-data",
            SECRET,
            Duration::from_mins(5),
        )
        .unwrap()
        .authenticate(&headers)
        .unwrap();
        assert_eq!(principal.scope, signed.scope);
        principal.require("syouyu.credential.read").unwrap();
        assert!(principal.require("syouyu.credential.create").is_err());
    }
}
