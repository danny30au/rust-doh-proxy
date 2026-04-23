use anyhow::{Context, Result};
use bytes::Bytes;
use reqwest::header::{ACCEPT, CONTENT_TYPE};
use reqwest::Client;
use std::time::Duration;

use crate::upstream::{BoxFuture, UpstreamClient};

const DNS_MESSAGE_CONTENT_TYPE: &str = "application/dns-message";

/// HTTP/2 DoH client using reqwest + rustls.
pub struct DohClient {
    client: Client,
    url: String,
    upstream_name: String,
}

impl DohClient {
    /// Create a new DoH client.
    pub fn new(url: String, name: Option<String>, timeout_ms: u32, tls_insecure: bool) -> Result<Self> {
        let upstream_name = name.unwrap_or_else(|| url.clone());
        let timeout = Duration::from_millis(timeout_ms as u64);

        let mut builder = Client::builder()
            .timeout(timeout)
            // Do NOT use http2_prior_knowledge() — that forces h2c (cleartext HTTP/2)
            // which fails on TLS DoH endpoints. Let ALPN negotiate HTTP/2 over TLS.
            .use_rustls_tls()
            .connection_verbose(false)
            .pool_idle_timeout(Duration::from_secs(60))
            .pool_max_idle_per_host(5);

        if tls_insecure {
            builder = builder.danger_accept_invalid_certs(true);
        }

        let client = builder.build().context("Failed to build reqwest client")?;

        Ok(Self {
            client,
            url,
            upstream_name,
        })
    }

    /// Send a DoH query and return the raw DNS response bytes.
    async fn do_query(&self, dns_query: Bytes) -> Result<Bytes> {
        // Try up to 2 times (1 retry on connection error)
        let mut last_err = None;
        for attempt in 0..2 {
            match self.send_once(dns_query.clone()).await {
                Ok(bytes) => return Ok(bytes),
                Err(e) => {
                    if attempt == 0 {
                        tracing::debug!(
                            upstream = %self.upstream_name,
                            "DoH attempt {} failed: {e}, retrying",
                            attempt + 1
                        );
                        last_err = Some(e);
                    } else {
                        return Err(e);
                    }
                }
            }
        }
        Err(last_err.unwrap())
    }

    async fn send_once(&self, dns_query: Bytes) -> Result<Bytes> {
        let response = self
            .client
            .post(&self.url)
            .header(CONTENT_TYPE, DNS_MESSAGE_CONTENT_TYPE)
            .header(ACCEPT, DNS_MESSAGE_CONTENT_TYPE)
            .body(dns_query)
            .send()
            .await
            .with_context(|| format!("DoH POST failed to {}", self.url))?;

        if !response.status().is_success() {
            anyhow::bail!(
                "DoH upstream {} returned HTTP {}",
                self.url,
                response.status()
            );
        }

        let bytes = response
            .bytes()
            .await
            .context("Failed to read DoH response body")?;

        Ok(bytes)
    }
}

impl UpstreamClient for DohClient {
    fn query<'a>(&'a self, dns_query: Bytes) -> BoxFuture<'a, Result<Bytes>> {
        Box::pin(self.do_query(dns_query))
    }

    fn name(&self) -> &str {
        &self.upstream_name
    }
}
