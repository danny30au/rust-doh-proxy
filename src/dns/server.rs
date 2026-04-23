use anyhow::Result;
use bytes::Bytes;
use socket2::{Domain, Protocol, Socket, Type};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tracing::{debug, error, warn};

use crate::cache::lru::DnsCache;
use crate::config::Config;
use crate::dns::parser::{build_servfail, encode_dns_message, min_answer_ttl, parse_dns_message, query_info};
use crate::status::Stats;
use crate::upstream::pool::UpstreamPool;

const MAX_UDP_SIZE: usize = 4096;
const MAX_TCP_MSG_SIZE: usize = 65535;

pub struct DnsServer {
    config: Arc<Config>,
    pool: Arc<UpstreamPool>,
    cache: Option<Arc<DnsCache>>,
    stats: Arc<Stats>,
}

impl DnsServer {
    pub async fn new(
        config: Arc<Config>,
        pool: Arc<UpstreamPool>,
        stats: Arc<Stats>,
    ) -> Result<Self> {
        let cache = if config.cache_enabled {
            Some(Arc::new(DnsCache::new(
                config.cache_max_entries as usize,
                config.cache_min_ttl,
            )))
        } else {
            None
        };

        Ok(Self {
            config,
            pool,
            cache,
            stats,
        })
    }

    pub async fn run(self) -> Result<()> {
        let addr: SocketAddr = self.config.listen_addr.parse()?;

        // Build UDP socket with SO_REUSEADDR + SO_REUSEPORT so fast procd
        // restarts don't hit EADDRINUSE while the old socket is in TIME_WAIT.
        let udp_std = {
            let sock = Socket::new(
                if addr.is_ipv6() { Domain::IPV6 } else { Domain::IPV4 },
                Type::DGRAM,
                Some(Protocol::UDP),
            )?;
            sock.set_reuse_address(true)?;
            #[cfg(unix)]
            sock.set_reuse_port(true)?;
            sock.set_nonblocking(true)?;
            sock.bind(&addr.into())?;
            std::net::UdpSocket::from(sock)
        };
        let udp_socket = Arc::new(UdpSocket::from_std(udp_std)?);

        // TCP listener with SO_REUSEADDR + SO_REUSEPORT.
        let tcp_std = {
            let sock = Socket::new(
                if addr.is_ipv6() { Domain::IPV6 } else { Domain::IPV4 },
                Type::STREAM,
                Some(Protocol::TCP),
            )?;
            sock.set_reuse_address(true)?;
            #[cfg(unix)]
            sock.set_reuse_port(true)?;
            sock.set_nonblocking(true)?;
            sock.bind(&addr.into())?;
            sock.listen(128)?;
            std::net::TcpListener::from(sock)
        };
        let tcp_listener = TcpListener::from_std(tcp_std)?;

        tracing::info!("DNS server listening on UDP+TCP {addr}");

        let server = Arc::new(self);

        let udp_server = server.clone();
        let udp_task = tokio::spawn(async move {
            udp_server.run_udp(udp_socket).await
        });

        let tcp_server = server.clone();
        let tcp_task = tokio::spawn(async move {
            tcp_server.run_tcp(tcp_listener).await
        });

        // Select: if either listener exits (error or not), surface it.
        tokio::select! {
            res = udp_task => {
                match res {
                    Ok(Ok(())) => error!("UDP listener exited unexpectedly (no error)"),
                    Ok(Err(ref e)) => error!("UDP listener exited with error: {e:#}"),
                    Err(ref e) => error!("UDP listener task panicked: {e}"),
                }
                res.unwrap_or_else(|e| Err(anyhow::anyhow!("UDP task panicked: {e}")))
            }
            res = tcp_task => {
                match res {
                    Ok(Ok(())) => error!("TCP listener exited unexpectedly (no error)"),
                    Ok(Err(ref e)) => error!("TCP listener exited with error: {e:#}"),
                    Err(ref e) => error!("TCP listener task panicked: {e}"),
                }
                res.unwrap_or_else(|e| Err(anyhow::anyhow!("TCP task panicked: {e}")))
            }
        }
    }

    async fn run_udp(self: Arc<Self>, socket: Arc<UdpSocket>) -> Result<()> {
        let mut buf = vec![0u8; MAX_UDP_SIZE];
        loop {
            // Use a non-fatal loop: transient OS errors (ICMP unreachable bounce,
            // EAGAIN, ENETDOWN during interface flap) must not kill the listener.
            let (len, peer) = match socket.recv_from(&mut buf).await {
                Ok(v) => v,
                Err(e) => {
                    use std::io::ErrorKind::*;
                    match e.kind() {
                        // These are always transient — log at debug and continue.
                        WouldBlock | Interrupted | TimedOut | ConnectionRefused => {
                            debug!("UDP recv transient error: {e}");
                            continue;
                        }
                        // Fatal socket errors.
                        _ => {
                            error!("UDP recv fatal error: {e}");
                            return Err(e.into());
                        }
                    }
                }
            };

            let query_bytes = Bytes::copy_from_slice(&buf[..len]);
            let socket_clone = socket.clone();
            let server = self.clone();

            tokio::spawn(async move {
                match server.handle_query(query_bytes).await {
                    Ok(response) => {
                        if let Err(e) = socket_clone.send_to(&response, peer).await {
                            warn!("UDP send error to {peer}: {e}");
                        }
                    }
                    Err(e) => {
                        warn!("Query handling error from {peer}: {e}");
                    }
                }
            });
        }
    }

    async fn run_tcp(self: Arc<Self>, listener: TcpListener) -> Result<()> {
        loop {
            let (mut stream, peer) = match listener.accept().await {
                Ok(v) => v,
                Err(e) => {
                    use std::io::ErrorKind::*;
                    match e.kind() {
                        WouldBlock | Interrupted | TimedOut | ConnectionRefused
                        | ConnectionReset | ConnectionAborted => {
                            debug!("TCP accept transient error: {e}");
                            continue;
                        }
                        _ => {
                            error!("TCP accept fatal error: {e}");
                            return Err(e.into());
                        }
                    }
                }
            };

            let server = self.clone();

            tokio::spawn(async move {
                loop {
                    let mut len_buf = [0u8; 2];
                    match stream.read_exact(&mut len_buf).await {
                        Ok(_) => {}
                        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
                        Err(e) => {
                            warn!("TCP read length error from {peer}: {e}");
                            break;
                        }
                    }

                    let msg_len = u16::from_be_bytes(len_buf) as usize;
                    if msg_len == 0 || msg_len > MAX_TCP_MSG_SIZE {
                        warn!("TCP invalid message length {msg_len} from {peer}");
                        break;
                    }

                    let mut msg_buf = vec![0u8; msg_len];
                    if let Err(e) = stream.read_exact(&mut msg_buf).await {
                        warn!("TCP read message error from {peer}: {e}");
                        break;
                    }

                    let query_bytes = Bytes::from(msg_buf);
                    let response = match server.handle_query(query_bytes).await {
                        Ok(r) => r,
                        Err(e) => {
                            warn!("TCP query handling error from {peer}: {e}");
                            break;
                        }
                    };

                    let resp_len = response.len() as u16;
                    if let Err(e) = stream.write_all(&resp_len.to_be_bytes()).await {
                        warn!("TCP write length error to {peer}: {e}");
                        break;
                    }
                    if let Err(e) = stream.write_all(&response).await {
                        warn!("TCP write response error to {peer}: {e}");
                        break;
                    }
                }
            });
        }
    }

    async fn handle_query(&self, query_bytes: Bytes) -> Result<Bytes> {
        self.stats.increment_queries();

        let request = match parse_dns_message(&query_bytes) {
            Ok(m) => m,
            Err(e) => {
                warn!("Failed to parse DNS query: {e}");
                return Err(e);
            }
        };

        let (name, qtype) = query_info(&request)
            .unwrap_or_else(|| ("<unknown>".to_string(), "<unknown>".to_string()));

        debug!(name = %name, qtype = %qtype, "DNS query");

        // Check cache
        if let Some(cache) = &self.cache {
            if let Some(cached) = cache.get(&name, &qtype) {
                debug!(name = %name, qtype = %qtype, "Cache hit");
                self.stats.increment_cache_hits();

                match patch_response_id(&cached, request.id()) {
                    Ok(patched) => return Ok(patched),
                    Err(e) => {
                        warn!("Failed to patch cached response ID: {e}");
                    }
                }
            } else {
                self.stats.increment_cache_misses();
            }
        }

        // Forward to upstream
        let timeout = std::time::Duration::from_millis(self.config.timeout_ms as u64);
        let response_bytes = match tokio::time::timeout(
            timeout,
            self.pool.query(query_bytes.clone()),
        )
        .await
        {
            Ok(Ok(bytes)) => bytes,
            Ok(Err(e)) => {
                warn!(name = %name, "Upstream query failed: {e}");
                return build_servfail(&request).map_err(Into::into);
            }
            Err(_) => {
                warn!(name = %name, "Upstream query timed out");
                return build_servfail(&request).map_err(Into::into);
            }
        };

        // Cache the response
        if let Some(cache) = &self.cache {
            match parse_dns_message(&response_bytes) {
                Ok(response_msg) => {
                    let ttl = min_answer_ttl(&response_msg);
                    cache.insert(name, qtype, response_bytes.clone(), ttl);
                }
                Err(e) => {
                    warn!("Failed to parse upstream response for caching: {e}");
                }
            }
        }

        Ok(response_bytes)
    }
}

fn patch_response_id(data: &Bytes, id: u16) -> Result<Bytes> {
    let mut msg = parse_dns_message(data)?;
    msg.set_id(id);
    encode_dns_message(&msg)
}
