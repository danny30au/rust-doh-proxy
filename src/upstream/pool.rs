use anyhow::Result;
use bytes::Bytes;
use std::sync::atomic::{AtomicU64, AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use std::sync::Mutex;
use tracing::{debug, warn};

use crate::config::{Config, UpstreamStrategy};
use crate::upstream::doh::DohClient;
use crate::upstream::doh3::Doh3Client;
use crate::upstream::UpstreamClient;

const UNHEALTHY_DURATION: Duration = Duration::from_secs(30);

/// Health state for an upstream.
struct UpstreamHealth {
    /// Last time this upstream failed
    last_error: Mutex<Option<Instant>>,
    /// Consecutive error count
    error_count: AtomicU32,
}

impl UpstreamHealth {
    fn new() -> Self {
        Self {
            last_error: Mutex::new(None),
            error_count: AtomicU32::new(0),
        }
    }

    fn mark_success(&self) {
        self.error_count.store(0, Ordering::Relaxed);
        *self.last_error.lock().unwrap() = None;
    }

    fn mark_failure(&self) {
        self.error_count.fetch_add(1, Ordering::Relaxed);
        *self.last_error.lock().unwrap() = Some(Instant::now());
    }

    fn is_healthy(&self) -> bool {
        match *self.last_error.lock().unwrap() {
            None => true,
            Some(last) => last.elapsed() > UNHEALTHY_DURATION,
        }
    }
}

struct Upstream {
    client: Box<dyn UpstreamClient>,
    health: UpstreamHealth,
}

/// Pool of upstream DoH clients supporting round-robin and failover strategies.
pub struct UpstreamPool {
    upstreams: Vec<Upstream>,
    strategy: UpstreamStrategy,
    rr_counter: AtomicU64,
}

impl UpstreamPool {
    pub async fn new(config: Arc<Config>) -> Result<Self> {
        if config.upstream.is_empty() {
            anyhow::bail!("No upstream servers configured");
        }

        let mut upstreams = Vec::new();

        for upstream_cfg in &config.upstream {
            let client: Box<dyn UpstreamClient> = if config.http3_enabled {
                Box::new(Doh3Client::new(
                    upstream_cfg.url.clone(),
                    upstream_cfg.name.clone(),
                    config.timeout_ms,
                )?)
            } else {
                Box::new(DohClient::new(
                    upstream_cfg.url.clone(),
                    upstream_cfg.name.clone(),
                    config.timeout_ms,
                    config.tls_insecure,
                )?)
            };

            tracing::info!(
                "Registered upstream: {} ({})",
                client.name(),
                upstream_cfg.url
            );

            upstreams.push(Upstream {
                client,
                health: UpstreamHealth::new(),
            });
        }

        Ok(Self {
            upstreams,
            strategy: config.upstream_strategy.clone(),
            rr_counter: AtomicU64::new(0),
        })
    }

    /// Send a DNS query to an upstream according to the configured strategy.
    pub async fn query(&self, dns_query: Bytes) -> Result<Bytes> {
        match self.strategy {
            UpstreamStrategy::RoundRobin => self.query_roundrobin(dns_query).await,
            UpstreamStrategy::Failover => self.query_failover(dns_query).await,
        }
    }

    async fn query_roundrobin(&self, dns_query: Bytes) -> Result<Bytes> {
        let n = self.upstreams.len();
        // Try each upstream starting from the round-robin position
        let start = self.rr_counter.fetch_add(1, Ordering::Relaxed) as usize % n;

        for i in 0..n {
            let idx = (start + i) % n;
            let upstream = &self.upstreams[idx];

            match upstream.client.query(dns_query.clone()).await {
                Ok(response) => {
                    upstream.health.mark_success();
                    debug!(upstream = upstream.client.name(), "Query succeeded");
                    return Ok(response);
                }
                Err(e) => {
                    upstream.health.mark_failure();
                    warn!(upstream = upstream.client.name(), "Query failed: {e}");
                }
            }
        }

        anyhow::bail!("All upstreams failed");
    }

    async fn query_failover(&self, dns_query: Bytes) -> Result<Bytes> {
        let mut last_err: Option<anyhow::Error> = None;

        for upstream in &self.upstreams {
            // Skip recently-failed upstreams unless they're the only option
            if !upstream.health.is_healthy() && self.upstreams.len() > 1 {
                debug!(upstream = upstream.client.name(), "Skipping unhealthy upstream");
                continue;
            }

            match upstream.client.query(dns_query.clone()).await {
                Ok(response) => {
                    upstream.health.mark_success();
                    debug!(upstream = upstream.client.name(), "Query succeeded");
                    return Ok(response);
                }
                Err(e) => {
                    upstream.health.mark_failure();
                    warn!(upstream = upstream.client.name(), "Query failed: {e}");
                    last_err = Some(e);
                }
            }
        }

        // If all healthy upstreams failed, try unhealthy ones as last resort
        for upstream in &self.upstreams {
            if upstream.health.is_healthy() {
                continue; // already tried
            }
            match upstream.client.query(dns_query.clone()).await {
                Ok(response) => {
                    upstream.health.mark_success();
                    return Ok(response);
                }
                Err(e) => {
                    last_err = Some(e);
                }
            }
        }

        Err(last_err.unwrap_or_else(|| anyhow::anyhow!("All upstreams failed")))
    }

    /// Return the number of registered upstreams.
    pub fn len(&self) -> usize {
        self.upstreams.len()
    }

    pub fn is_empty(&self) -> bool {
        self.upstreams.is_empty()
    }
}
