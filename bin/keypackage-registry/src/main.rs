//! Testnet KeyPackage Registry HTTP service.
//!
//! Throwaway service for issue #110 — replaced by λLEZ in v0.3. Intentionally
//! self-contained: depends only on axum + sqlite + ed25519, no libchat core.
//!
//! Wire:
//!   POST /v0/keypackage             — submit a signed keypackage bundle
//!   GET  /v0/keypackage/{device_id} — fetch the latest stored keypackage bundle
//!   POST /v0/account                — upsert a signed account device-list bundle
//!   GET  /v0/account/{account_id}   — fetch the account device-list bundle

mod handlers;
mod store;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use tracing_subscriber::EnvFilter;

use store::Store;

#[derive(Parser, Debug)]
#[command(name = "keypackage-registry", about = "Testnet KeyPackage Registry")]
struct Cli {
    /// Address to bind the HTTP server.
    #[arg(long, default_value = "0.0.0.0:8080")]
    bind: SocketAddr,

    /// SQLite database path.
    #[arg(long, default_value = "keypackage-registry.db")]
    db: PathBuf,

    /// Maximum number of bundles retained per account_id.
    #[arg(long, default_value_t = 100)]
    max_per_identity: usize,

    /// Retention window in days; older bundles are pruned.
    #[arg(long, default_value_t = 30)]
    retention_days: u64,

    /// How often the prune task runs.
    #[arg(long, default_value_t = 3600)]
    prune_interval_secs: u64,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();

    let store = Arc::new(Store::open(&cli.db).context("failed to open store")?);

    let prune_store = store.clone();
    let max_per_id = cli.max_per_identity;
    let retention = Duration::from_secs(cli.retention_days * 24 * 3600);
    let interval = Duration::from_secs(cli.prune_interval_secs);
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        loop {
            ticker.tick().await;
            if let Err(e) = prune_store.prune_key_packages(max_per_id, retention) {
                tracing::warn!("prune (keypackages) failed: {e}");
            }
            if let Err(e) = prune_store.prune_accounts(retention) {
                tracing::warn!("prune (accounts) failed: {e}");
            }
        }
    });

    let app = handlers::router(store);
    let listener = tokio::net::TcpListener::bind(cli.bind)
        .await
        .with_context(|| format!("failed to bind {}", cli.bind))?;
    tracing::info!("keypackage-registry listening on {}", cli.bind);
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("server error")?;
    Ok(())
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
    tracing::info!("shutdown signal received");
}
