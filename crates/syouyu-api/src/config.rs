use std::{env, net::SocketAddr, str::FromStr, time::Duration};

use anyhow::{Context, Result, bail};
use base64::{Engine, engine::general_purpose::STANDARD};
use syouyu_auth::ProviderAuthenticator;
use syouyu_store::CredentialLimits;
use url::Url;

use crate::principal_auth::PrincipalAuthenticator;

pub struct Config {
    pub bind_addr: SocketAddr,
    pub database_url: String,
    pub database_max_connections: u32,
    pub migrate_on_start: bool,
    pub receipt_encryption_key: Vec<u8>,
    pub credential_limits: CredentialLimits,
    pub provider_authenticator: ProviderAuthenticator,
    pub principal_authenticator: PrincipalAuthenticator,
    pub garage_admin_endpoint: Url,
    pub garage_admin_token: String,
    pub garage_region: String,
    pub s3_public_endpoint: Url,
}

impl Config {
    pub fn from_env() -> Result<Self> {
        let bind_addr = parse_or("SYOUYU_BIND_ADDR", "0.0.0.0:8080")?;
        let database_url = required("DATABASE_URL")?;
        let database_max_connections = parse_or("DATABASE_MAX_CONNECTIONS", "20")?;
        let migrate_on_start = parse_or("MIGRATE_ON_START", "true")?;
        let receipt_encryption_key = STANDARD
            .decode(required("SYOUYU_RECEIPT_ENCRYPTION_KEY_BASE64")?)
            .context("SYOUYU_RECEIPT_ENCRYPTION_KEY_BASE64 is invalid")?;
        if receipt_encryption_key.len() != 32 {
            bail!("SYOUYU_RECEIPT_ENCRYPTION_KEY_BASE64 must decode to exactly 32 bytes");
        }
        let credential_limits = CredentialLimits {
            max_credentials_per_bucket: parse_or("SYOUYU_MAX_CREDENTIALS_PER_BUCKET", "10000")?,
            max_total_credentials: parse_or("SYOUYU_MAX_TOTAL_CREDENTIALS", "1000000")?,
        }
        .validate()
        .context("invalid credential limits")?;
        let provider_authenticator = ProviderAuthenticator::from_public_keys_json(
            required("HETEROCLOUD_PROVIDER_ISSUER")?,
            required("HETEROCLOUD_PROVIDER_AUDIENCE")?,
            &required("HETEROCLOUD_PROVIDER_PUBLIC_KEYS_JSON")?,
        )
        .context("invalid provider authentication configuration")?;
        let principal_authenticator = PrincipalAuthenticator::new(
            required("SYOUYU_PRINCIPAL_ISSUER")?,
            required("SYOUYU_PRINCIPAL_AUDIENCE")?,
            required("SYOUYU_PRINCIPAL_CONTEXT_HMAC_SECRET")?.into_bytes(),
            Duration::from_secs(parse_or("SYOUYU_PRINCIPAL_MAX_TTL_SECONDS", "300")?),
        )
        .context("invalid principal authentication configuration")?;
        let garage_admin_endpoint =
            absolute_http_url("GARAGE_ADMIN_ENDPOINT", &required("GARAGE_ADMIN_ENDPOINT")?)?;
        let garage_admin_token = required("GARAGE_ADMIN_TOKEN")?;
        let garage_region =
            env::var("GARAGE_REGION").unwrap_or_else(|_| "heteronet-global".to_owned());
        validate_region(&garage_region)?;
        let s3_public_endpoint = absolute_http_url(
            "SYOUYU_S3_PUBLIC_ENDPOINT",
            &required("SYOUYU_S3_PUBLIC_ENDPOINT")?,
        )?;
        Ok(Self {
            bind_addr,
            database_url,
            database_max_connections,
            migrate_on_start,
            receipt_encryption_key,
            credential_limits,
            provider_authenticator,
            principal_authenticator,
            garage_admin_endpoint,
            garage_admin_token,
            garage_region,
            s3_public_endpoint,
        })
    }
}

fn required(name: &'static str) -> Result<String> {
    env::var(name).with_context(|| format!("{name} is required"))
}

fn parse_or<T>(name: &'static str, default: &'static str) -> Result<T>
where
    T: FromStr,
    T::Err: std::error::Error + Send + Sync + 'static,
{
    env::var(name)
        .unwrap_or_else(|_| default.to_owned())
        .parse()
        .with_context(|| format!("{name} is invalid"))
}

fn absolute_http_url(name: &'static str, value: &str) -> Result<Url> {
    let mut url = Url::parse(value).with_context(|| format!("{name} is invalid"))?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        bail!("{name} must be an HTTP(S) URL without credentials, query, or fragment");
    }
    let normalized = format!("{}/", url.path().trim_end_matches('/'));
    url.set_path(&normalized);
    Ok(url)
}

fn validate_region(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 63
        || value.starts_with('-')
        || value.ends_with('-')
        || value
            .bytes()
            .any(|byte| !byte.is_ascii_lowercase() && !byte.is_ascii_digit() && byte != b'-')
    {
        bail!("GARAGE_REGION must be a lowercase DNS label of at most 63 characters");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{absolute_http_url, validate_region};

    #[test]
    fn validates_service_origins() {
        assert_eq!(
            absolute_http_url("TEST", "https://s3.example.test")
                .unwrap()
                .as_str(),
            "https://s3.example.test/"
        );
        assert!(absolute_http_url("TEST", "ftp://s3.example.test").is_err());
        assert!(absolute_http_url("TEST", "https://user@s3.example.test").is_err());
    }

    #[test]
    fn validates_garage_region() {
        assert!(validate_region("heteronet-global").is_ok());
        for invalid in ["", "Heteronet", "-leading", "trailing-", "with.dot"] {
            assert!(validate_region(invalid).is_err());
        }
    }
}
