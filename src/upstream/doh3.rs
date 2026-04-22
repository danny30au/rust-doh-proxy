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
    use h3::client::SendRequest;
    use h3_quinn::Connection as H3QuinnConnection;
    use http::{Method, Request, Version};
    use quinn::{ClientConfig, Endpoint};
    use rustls::RootCertStore;
    use std::net::SocketAddr;
    use std::sync::Arc;

    use crate::upstream::{BoxFuture, UpstreamClient};

    const DNS_MESSAGE_CONTENT_TYPE: &str = "application/dns-message";

    pub struct Doh3Client {
        url: String,
        upstream_name: String,
        endpoint: Endpoint,
        server_name: String,
        server_addr: SocketAddr,
    }

    impl Doh3Client {
        pub fn new(url: String, name: Option<String>, _timeout_ms: u32) -> Result<Self> {
            let upstream_name = name.unwrap_or_else(|| url.clone());

            // Parse URL to extract host/port
            let parsed = url::Url::parse(&url).context("Invalid DoH3 URL")?;
            let host = parsed.host_str().context("No host in DoH3 URL")?.to_string();
            let port = parsed.port().unwrap_or(443);
            let server_addr: SocketAddr = format!("{host}:{port}")
                .parse()
                .context("Failed to parse DoH3 server address")?;

            // Build rustls config with bundled WebPKI roots
            let mut root_store = RootCertStore::empty();
            root_store.extend(
                webpki_roots::TLS_SERVER_ROOTS
                    .iter()
                    .cloned(),
            );
            let tls_config = rustls::ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth();

            let quic_config =
                quinn::crypto::rustls::QuicClientConfig::try_from(Arc::new(tls_config))
                    .context("Failed to create QUIC config")?;
            let client_config = ClientConfig::new(Arc::new(quic_config));

            let mut endpoint = Endpoint::client("0.0.0.0:0".parse().unwrap())
                .context("Failed to bind QUIC endpoint")?;
            endpoint.set_default_client_config(client_config);

            Ok(Self {
                url,
                upstream_name,
                endpoint,
                server_name: host,
                server_addr,
            })
        }

        pub async fn do_query(&self, dns_query: Bytes) -> Result<Bytes> {
            let conn = self
                .endpoint
                .connect(self.server_addr, &self.server_name)
                .context("QUIC connect failed")?
                .await
                .context("QUIC handshake failed")?;

            let h3_conn = H3QuinnConnection::new(conn);
            let (mut driver, mut send_request) =
                h3::client::new(h3_conn).await.context("H3 client setup failed")?;

            // Drive connection in background
            tokio::spawn(async move {
                let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
            });

            let parsed = url::Url::parse(&self.url).unwrap();
            let path = parsed.path();

            let request = Request::builder()
                .method(Method::POST)
                .uri(format!("https://{}{}", self.server_name, path))
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

    /// Public re-export so the outer module can use it.
    pub use Doh3Client as InnerDoh3Client;
}

// ── Stub when http3 feature is disabled ──────────────────────────────────────

/// DoH3 client. When the `http3` feature is enabled, delegates to the real
/// HTTP/3 implementation. Otherwise always returns an error.
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
        {
            let _ = (url, name, timeout_ms);
        }

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
            anyhow::bail!("HTTP/3 support is not compiled in (enable the 'http3' feature)")
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
