use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// A single upstream DoH server configuration.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct UpstreamConfig {
    /// Full DoH URL, e.g. https://1.1.1.1/dns-query
    pub url: String,
    /// Human-readable name used in logs
    pub name: Option<String>,
}

/// Strategy used to select among multiple upstream servers.
#[derive(Debug, Clone, Deserialize, Serialize, Default, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum UpstreamStrategy {
    /// Distribute queries evenly across all upstreams
    RoundRobin,
    /// Try upstreams in order, move to next on error
    #[default]
    Failover,
}

/// Top-level application configuration.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Config {
    /// Address to listen on for DNS queries (UDP + TCP)
    /// Default: 0.0.0.0:53
    pub listen_addr: String,

    /// List of upstream DoH servers.
    /// Examples:
    ///   url = "https://1.1.1.1/dns-query"       # Cloudflare
    ///   url = "https://8.8.8.8/dns-query"        # Google
    ///   url = "https://9.9.9.9/dns-query"        # Quad9
    ///   url = "https://dns.nextdns.io/dns-query"  # NextDNS
    #[serde(default = "default_upstreams")]
    pub upstream: Vec<UpstreamConfig>,

    /// Strategy to select upstream: "roundrobin" or "failover"
    #[serde(default)]
    pub upstream_strategy: UpstreamStrategy,

    /// Whether to enable the in-memory DNS cache
    #[serde(default = "default_true")]
    pub cache_enabled: bool,

    /// Maximum number of cache entries (LRU eviction)
    #[serde(default = "default_cache_max_entries")]
    pub cache_max_entries: u32,

    /// Minimum TTL to cache responses (seconds)
    #[serde(default = "default_cache_min_ttl")]
    pub cache_min_ttl: u32,

    /// Enable HTTP/3 (QUIC) for upstream queries (requires http3 feature)
    #[serde(default)]
    pub http3_enabled: bool,

    /// Upstream query timeout in milliseconds
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u32,

    /// Log level: trace, debug, info, warn, error
    #[serde(default = "default_log_level")]
    pub log_level: String,

    /// Optional address for the HTTP status/health endpoint
    /// e.g. "127.0.0.1:8053"
    pub status_addr: Option<String>,

    /// Disable TLS certificate verification (for testing only)
    #[serde(default)]
    pub tls_insecure: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen_addr: "0.0.0.0:53".to_string(),
            upstream: default_upstreams(),
            upstream_strategy: UpstreamStrategy::Failover,
            cache_enabled: true,
            cache_max_entries: 10_000,
            cache_min_ttl: 60,
            http3_enabled: false,
            timeout_ms: 5_000,
            log_level: "info".to_string(),
            status_addr: None,
            tls_insecure: false,
        }
    }
}

fn default_true() -> bool {
    true
}

fn default_cache_max_entries() -> u32 {
    10_000
}

fn default_cache_min_ttl() -> u32 {
    60
}

fn default_timeout_ms() -> u32 {
    5_000
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_upstreams() -> Vec<UpstreamConfig> {
    vec![
        UpstreamConfig {
            url: "https://1.1.1.1/dns-query".to_string(),
            name: Some("Cloudflare".to_string()),
        },
        UpstreamConfig {
            url: "https://9.9.9.9/dns-query".to_string(),
            name: Some("Quad9".to_string()),
        },
    ]
}

impl Config {
    /// Load configuration from a TOML file.
    pub fn load(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read config file: {}", path.display()))?;
        let config: Config = toml::from_str(&content)
            .with_context(|| format!("Failed to parse config file: {}", path.display()))?;
        Ok(config)
    }

    /// Load from file if it exists, otherwise return defaults.
    pub fn load_or_default(path: &Path) -> Self {
        if path.exists() {
            match Self::load(path) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("Warning: failed to load config {}: {e}", path.display());
                    Self::default()
                }
            }
        } else {
            Self::default()
        }
    }

    /// Apply CLI overrides to this config (only non-None values override).
    pub fn apply_overrides(&mut self, overrides: &CliOverrides) {
        if let Some(addr) = &overrides.listen_addr {
            self.listen_addr = addr.clone();
        }
        if !overrides.upstream.is_empty() {
            self.upstream = overrides
                .upstream
                .iter()
                .map(|url| UpstreamConfig {
                    url: url.clone(),
                    name: None,
                })
                .collect();
        }
        if overrides.http3 {
            self.http3_enabled = true;
        }
        if let Some(level) = &overrides.log_level {
            self.log_level = level.clone();
        }
    }
}

/// CLI-sourced values that can override config file values.
#[derive(Debug, Default)]
pub struct CliOverrides {
    pub listen_addr: Option<String>,
    pub upstream: Vec<String>,
    pub http3: bool,
    pub log_level: Option<String>,
}
