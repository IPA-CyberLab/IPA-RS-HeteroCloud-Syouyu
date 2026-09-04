use std::{process::ExitCode, sync::Arc};

use anyhow::{Context, Result};
use syouyu_api::{AppState, Config, GarageAdapter, router};
use syouyu_garage::GarageAdminClient;
use syouyu_store::PgStore;
use tokio::net::TcpListener;
use tracing::info;
use tracing_subscriber::{EnvFilter, fmt};

#[tokio::main]
async fn main() -> ExitCode {
    init_tracing();
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            tracing::error!(error = ?error, "syouyu-api terminated");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<()> {
    let config = Config::from_env()?;
    let store = PgStore::connect(
        &config.database_url,
        config.database_max_connections,
        &config.receipt_encryption_key,
        config.credential_limits,
    )
    .await
    .context("connect to PostgreSQL")?;
    if config.migrate_on_start || std::env::args().nth(1).as_deref() == Some("migrate") {
        store.migrate().await.context("run database migrations")?;
    }
    if std::env::args().nth(1).as_deref() == Some("migrate") {
        info!("database migrations completed");
        return Ok(());
    }

    let garage_client =
        GarageAdminClient::new(config.garage_admin_endpoint, &config.garage_admin_token)
            .context("configure Garage administration client")?;
    let bind_addr = config.bind_addr;
    let app = router(AppState {
        store: Arc::new(store),
        garage: Arc::new(GarageAdapter::new(garage_client)),
        provider_auth: config.provider_authenticator,
        principal_auth: config.principal_authenticator,
        s3_endpoint: config.s3_public_endpoint,
    });
    let listener = TcpListener::bind(bind_addr)
        .await
        .with_context(|| format!("bind {bind_addr}"))?;
    info!(%bind_addr, "syouyu-api listening");
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("serve Syouyu API")
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    fmt().json().with_env_filter(filter).init();
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("install Ctrl+C handler");
    };
    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("install SIGTERM handler")
            .recv()
            .await;
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {},
        () = terminate => {},
    }
}
