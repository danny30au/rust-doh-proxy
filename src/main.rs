mod cache;
mod config;
mod dns;
mod status;
mod upstream;

use anyhow::Result;
use clap::Parser;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::{error, info};

use crate::config::{CliOverrides, Config};
use crate::dns::server::DnsServer;
use crate::status::Stats;
use crate::upstream::pool::UpstreamPool;

/// DNS-over-HTTPS proxy daemon for OpenWrt.
#[derive(Parser, Debug)]
#[command(name = "doh-proxy", version, about, long_about = None)]
struct Cli {
    /// Path to TOML config file
    #[arg(short, long, default_value = "/etc/doh-proxy/config.toml")]
    config: PathBuf,

    /// Override listen address (e.g. 0.0.0.0:53)
    #[arg(long)]
    listen: Option<String>,

    /// Add upstream DoH URL (repeatable, overrides config file upstreams)
    #[arg(long = "upstream", action = clap::ArgAction::Append)]
    upstream: Vec<String>,

    /// Enable HTTP/3 upstream queries
    #[arg(long)]
    http3: bool,

    /// Log level (trace/debug/info/warn/error)
    #[arg(long)]
    log_level: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Load config from file (or defaults if missing)
    let mut cfg = Config::load_or_default(&cli.config);

    // Apply CLI overrides
    let overrides = CliOverrides {
        listen_addr: cli.listen,
        upstream: cli.upstream,
        http3: cli.http3,
        log_level: cli.log_level,
    };
    cfg.apply_overrides(&overrides);

    // Initialize tracing
    let log_filter = format!("doh_proxy={},warn", cfg.log_level);
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(&log_filter)),
        )
        .with_writer(std::io::stderr)
        .init();

    info!(
        version = env!("CARGO_PKG_VERSION"),
        listen = %cfg.listen_addr,
        upstreams = cfg.upstream.len(),
        strategy = ?cfg.upstream_strategy,
        cache_enabled = cfg.cache_enabled,
        http3 = cfg.http3_enabled,
        "Starting doh-proxy"
    );

    let cfg = Arc::new(cfg);

    // Build shared stats counter
    let stats = Arc::new(Stats::new());

    // Build upstream pool
    let pool = Arc::new(
        UpstreamPool::new(cfg.clone())
            .await
            .map_err(|e| anyhow::anyhow!("Failed to create upstream pool: {e}"))?,
    );

    // Build DNS server
    let dns_server = DnsServer::new(cfg.clone(), pool.clone(), stats.clone())
        .await
        .map_err(|e| anyhow::anyhow!("Failed to create DNS server: {e}"))?;

    // Optionally start status server
    #[cfg(feature = "status")]
    let status_server = {
        let status_addr = cfg.status_addr.clone();
        let stats_clone = stats.clone();
        async move {
            if let Some(addr) = status_addr {
                if let Err(e) = crate::status::run_status_server(&addr, stats_clone).await {
                    error!("Status server error: {e}");
                }
            }
        }
    };

    #[cfg(not(feature = "status"))]
    let status_server = async {};

    // Run DNS server and optional status server concurrently
    tokio::select! {
        result = dns_server.run() => {
            match result {
                Err(e) => {
                    // Log BEFORE exit so syslog captures the reason.
                    error!("DNS server fatal error: {e:#}");
                    // Give tracing a moment to flush to stderr.
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                    std::process::exit(1);
                }
                Ok(()) => {
                    error!("DNS server exited unexpectedly with no error");
                    std::process::exit(1);
                }
            }
        }
        _ = status_server => {}
        _ = tokio::signal::ctrl_c() => {
            info!("Received SIGINT, shutting down");
        }
        _ = async {
            #[cfg(unix)]
            {
                use tokio::signal::unix::{signal, SignalKind};
                if let Ok(mut s) = signal(SignalKind::terminate()) {
                    s.recv().await;
                } else {
                    std::future::pending::<()>().await;
                }
            }
            #[cfg(not(unix))]
            std::future::pending::<()>().await;
        } => {
            info!("Received SIGTERM, shutting down");
        }
    }

    Ok(())
}
