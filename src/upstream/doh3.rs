//! HTTP/3 (QUIC) DoH client.
//!
//! Enabled via the `http3` feature flag. When disabled, this module provides
//! a stub that always returns an error.

use anyhow::Result;
use bytes::Bytes;

use crate::upstream::{BoxFuture, UpstreamClient};

#[cfg(feature = "http3")]
mod http3_impl {
    use anyhow::{Context, Result};
    use bytes::Bytes;
    use h3_quinn::Connection as H3QuinnConnection;
    use http::{Method, Request, Version};
    use quinn::{ClientConfig, Connection, Endpoint};
    use rustls::RootCertStore;
    use std::net::SocketAddr;
    use std::sync::Arc;
    use tokio::sync::Mutex;
    use tracing::{debug, warn};

    use crate::upstream::{BoxFuture, UpstreamClient};

    const DNS_MESSAGE_CONTENT_TYPE: &str = "application/dns-message";

    /// Cached QUIC connection state.
    struct QuicConn {
        conn: Connection,
        send_request: h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
    }

    pub struct Doh3Client {
        upstream_name: String,
        host: String,
        port: u16,
        path: String,
        endpoint: Endpoint,
        /// Cached connection — created lazily, replaced on error.
        cached: Mutex<Option<QuicConn>>,
    }

    impl Doh3Client {
        pub fn new(url: String, name: Option<String>, _timeout_ms: u32) -> Result<Self> {
            let upstream_name = name.unwrap_or_else(|| url.clone());

            // Parse URL — only extract host/port/path here, no DNS resolution.
            let parsed = url::Url::parse(&url).context("Invalid DoH3 URL")?;
            let host = parsed.host_str().context("No host in DoH3 URL")?.to_string();
            let port = parsed.port().unwrap_or(443);
            let path = parsed.path().to_string();

            // Build rustls config with bundled WebPKI roots.
            let mut root_store = RootCertStore::empty();
            root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            let tls_config = rustls::ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth();

            let quic_config =
                quinn::crypto::rustls::QuicClientConfig::try_from(Arc::new(tls_config))
                    .context("Failed to create QUIC config")?;
            let client_config = ClientConfig::new(Arc::new(quic_config));

            // Bind to an ephemeral local UDP port — no DNS lookup yet.
            let mut endpoint =
                Endpoint::client("0.0.0.0:0".parse().unwrap())
                    .context("Failed to bind QUIC endpoint")?;
            endpoint.set_default_client_config(client_config);

            // url is consumed by the parser above; host/port/path are stored instead.
            let _ = url;

            Ok(Self {
                upstream_name,
                host,
                port,
                path,
                endpoint,
                cached: Mutex::new(None),
            })
        }

        /// Resolve hostname to SocketAddr asynchronously using tokio's resolver.
        async fn resolve(&self) -> Result<SocketAddr> {
            use tokio::net::lookup_host;
            let host_port = format!("{}:{}", self.host, self.port);
            let mut addrs = lookup_host(&host_port)
                .await
                .with_context(|| format!("DNS lookup failed for {host_port}"))?;
            addrs
                .next()
                .ok_or_else(|| anyhow::anyhow!("No addresses for {host_port}"))
        }

        /// Get or create a cached QUIC+H3 connection.
        async fn get_connection(&self) -> Result<QuicConn> {
            // Open a fresh connection — no persistent state shared between calls here;
            // the caller holds the lock for the duration of one query.
            let server_addr = self.resolve().await?;

            debug!(
                upstream = %self.upstream_name,
                addr = %server_addr,
                "Opening QUIC connection"
            );

            let conn = self
                .endpoint
                .connect(server_addr, &self.host)
                .context("QUIC connect failed")?
                .await
                .context("QUIC handshake failed")?;

            let h3_conn = H3QuinnConnection::new(conn.clone());
            let (mut driver, send_request) =
                h3::client::new(h3_conn).await.context("H3 client setup failed")?;

            // Drive the connection in the background.
            tokio::spawn(async move {
                let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
            });

            Ok(QuicConn { conn, send_request })
        }

        pub async fn do_query(&self, dns_query: Bytes) -> Result<Bytes> {
            // Try with existing cached connection first, fall back to new connection.
            let mut guard = self.cached.lock().await;

            // Check if cached connection is still alive.
            let needs_reconnect = match &*guard {
                None => true,
                Some(q) => q.conn.close_reason().is_some(),
            };

            if needs_reconnect {
                if guard.is_some() {
                    warn!(upstream = %self.upstream_name, "QUIC connection closed, reconnecting");
                }
                *guard = Some(self.get_connection().await?);
            }

            let send_req = &mut guard.as_mut().unwrap().send_request;

            let result = Self::send_h3_query(send_req, &self.host, &self.path, dns_query.clone()).await;

            // On any stream-level error, invalidate cached connection so next
            // query opens a fresh one.
            if result.is_err() {
                *guard = None;
            }

            result
        }

        async fn send_h3_query(
            send_request: &mut h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
            host: &str,
            path: &str,
            dns_query: Bytes,
        ) -> Result<Bytes> {
            let request = Request::builder()
                .method(Method::POST)
                .uri(format!("https://{host}{path}"))
                .version(Version::HTTP_3)
                .header("content-type", DNS_MESSAGE_CONTENT_TYPE)
                .header("accept", DNS_MESSAGE_CONTENT_TYPE)
                .header("content-length", dns_query.len().to_string())
                .body(())
                .context("Failed to build H3 request")?;

            let mut stream = send_request
                .send_request(request)
                .await
                .context("H3 send_request failed")?;

            stream
                .send_data(dns_query)
                .await
                .context("H3 send_data failed")?;
            stream.finish().await.context("H3 finish failed")?;

            let response = stream
                .recv_response()
                .await
                .context("H3 recv_response failed")?;

            if !response.status().is_success() {
                anyhow::bail!("DoH3 upstream returned HTTP {}", response.status());
            }

            let mut body = Vec::new();
            while let Some(mut chunk) =
                stream.recv_data().await.context("H3 recv_data failed")?
            {
                use bytes::Buf;
                let remaining = chunk.remaining();
                let mut tmp = vec![0u8; remaining];
                chunk.copy_to_slice(&mut tmp);
                body.extend_from_slice(&tmp);
            }

            Ok(Bytes::from(body))
        }
    }

    impl UpstreamClient for Doh3Client {
        fn query<'a>(&'a self, dns_query: Bytes) -> BoxFuture<'a, Result<Bytes>> {
            Box::pin(self.do_query(dns_query))
        }

        fn name(&self) -> &str {
            &self.upstream_name
        }
    }

    pub use Doh3Client as InnerDoh3Client;
}

// ── Public wrapper ────────────────────────────────────────────────────────────

pub struct Doh3Client {
    upstream_name: String,
    #[cfg(feature = "http3")]
    inner: http3_impl::InnerDoh3Client,
}

impl Doh3Client {
    pub fn new(url: String, name: Option<String>, timeout_ms: u32) -> Result<Self> {
        let upstream_name = name.clone().unwrap_or_else(|| url.clone());

        #[cfg(feature = "http3")]
        let inner = http3_impl::InnerDoh3Client::new(url, name, timeout_ms)?;

        #[cfg(not(feature = "http3"))]
        let _ = (url, name, timeout_ms);

        Ok(Self {
            upstream_name,
            #[cfg(feature = "http3")]
            inner,
        })
    }

    async fn do_query(&self, dns_query: Bytes) -> Result<Bytes> {
        #[cfg(feature = "http3")]
        {
            self.inner.do_query(dns_query).await
        }
        #[cfg(not(feature = "http3"))]
        {
            let _ = dns_query;
            anyhow::bail!("HTTP/3 support not compiled in (enable the 'http3' feature)")
        }
    }
}

impl UpstreamClient for Doh3Client {
    fn query<'a>(&'a self, dns_query: Bytes) -> BoxFuture<'a, Result<Bytes>> {
        Box::pin(self.do_query(dns_query))
    }

    fn name(&self) -> &str {
        &self.upstream_name
    }
}
