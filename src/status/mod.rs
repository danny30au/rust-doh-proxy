use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

/// Shared atomic statistics counters.
pub struct Stats {
    pub queries_total: AtomicU64,
    pub cache_hits: AtomicU64,
    pub cache_misses: AtomicU64,
    pub started_at: Instant,
}

impl Stats {
    pub fn new() -> Self {
        Self {
            queries_total: AtomicU64::new(0),
            cache_hits: AtomicU64::new(0),
            cache_misses: AtomicU64::new(0),
            started_at: Instant::now(),
        }
    }

    pub fn increment_queries(&self) {
        self.queries_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn increment_cache_hits(&self) {
        self.cache_hits.fetch_add(1, Ordering::Relaxed);
    }

    pub fn increment_cache_misses(&self) {
        self.cache_misses.fetch_add(1, Ordering::Relaxed);
    }

    pub fn queries_total(&self) -> u64 {
        self.queries_total.load(Ordering::Relaxed)
    }

    pub fn cache_hits(&self) -> u64 {
        self.cache_hits.load(Ordering::Relaxed)
    }

    pub fn cache_misses(&self) -> u64 {
        self.cache_misses.load(Ordering::Relaxed)
    }

    pub fn cache_hit_rate(&self) -> f64 {
        let hits = self.cache_hits();
        let misses = self.cache_misses();
        let total = hits + misses;
        if total == 0 {
            0.0
        } else {
            hits as f64 / total as f64
        }
    }

    pub fn uptime_secs(&self) -> u64 {
        self.started_at.elapsed().as_secs()
    }
}

impl Default for Stats {
    fn default() -> Self {
        Self::new()
    }
}

// ── Status HTTP server (axum, behind `status` feature) ───────────────────────

#[cfg(feature = "status")]
pub async fn run_status_server(addr: &str, stats: Arc<Stats>) -> anyhow::Result<()> {
    use axum::routing::get;
    use axum::{Json, Router};
    use serde::Serialize;

    #[derive(Serialize)]
    struct StatsResponse {
        queries_total: u64,
        cache_hits: u64,
        cache_misses: u64,
        cache_hit_rate: f64,
        uptime_secs: u64,
    }

    let stats_clone = stats.clone();
    let app = Router::new()
        .route(
            "/health",
            get(|| async { axum::http::StatusCode::OK }),
        )
        .route(
            "/stats",
            get(move || {
                let s = stats_clone.clone();
                async move {
                    Json(StatsResponse {
                        queries_total: s.queries_total(),
                        cache_hits: s.cache_hits(),
                        cache_misses: s.cache_misses(),
                        cache_hit_rate: s.cache_hit_rate(),
                        uptime_secs: s.uptime_secs(),
                    })
                }
            }),
        );

    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!("Status server listening on http://{addr}");
    axum::serve(listener, app).await?;
    Ok(())
}

#[cfg(not(feature = "status"))]
pub async fn run_status_server(_addr: &str, _stats: Arc<Stats>) -> anyhow::Result<()> {
    anyhow::bail!("Status server requires the 'status' feature")
}
