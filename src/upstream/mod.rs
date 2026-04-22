pub mod doh;
pub mod doh3;
pub mod pool;

use anyhow::Result;
use bytes::Bytes;
use std::future::Future;
use std::pin::Pin;

/// Boxed async future alias
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Trait implemented by all upstream DoH clients.
pub trait UpstreamClient: Send + Sync {
    /// Send a raw DNS query (wire format) and return the raw DNS response.
    fn query<'a>(&'a self, dns_query: Bytes) -> BoxFuture<'a, Result<Bytes>>;

    /// Return the human-readable name for this upstream.
    fn name(&self) -> &str;
}
