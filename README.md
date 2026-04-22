# rust-doh-proxy

A DNS-over-HTTPS (DoH) proxy daemon for OpenWrt, written in Rust.

Listens for DNS queries on UDP and TCP (default port 53), forwards them to
configurable upstream DoH resolvers via HTTP/2 (with optional HTTP/3/QUIC
support), caches responses with TTL-aware LRU eviction, and optionally serves a
lightweight HTTP status endpoint.

## Features

- **Standard DNS server** — UDP + TCP listener with RFC 1035 wire-format support
- **DoH upstream (RFC 8484)** — POST `application/dns-message` over HTTPS with HTTP/2
- **Optional HTTP/3 / QUIC** — DoH/3 using `h3` + `quinn` (compile-time feature flag)
- **LRU DNS cache** — TTL-respecting, thread-safe, configurable max entries and minimum TTL
- **Multiple upstreams** — round-robin or failover strategies with automatic health tracking
- **TOML configuration** — all options configurable via file; CLI flags override config
- **Structured logging** — via `tracing` + `tracing-subscriber`, written to stderr
- **Health endpoint** — optional `/health` and `/stats` routes via axum (feature flag)
- **OpenWrt procd** — ships with a ready-to-use init script
- **Static binary** — builds to `x86_64-unknown-linux-musl` (~5–10 MB stripped)

## Building

### Native build

```sh
cargo build --release
```

### Static musl build (for OpenWrt x86_64)

```sh
# Install the musl target
rustup target add x86_64-unknown-linux-musl

# Install musl-tools on Debian/Ubuntu
sudo apt-get install musl-tools

# Build
cargo build --release --target x86_64-unknown-linux-musl

# Strip the binary
strip target/x86_64-unknown-linux-musl/release/doh-proxy
```

### Cross-compile for OpenWrt aarch64 (e.g. Raspberry Pi)

```sh
rustup target add aarch64-unknown-linux-musl
sudo apt-get install gcc-aarch64-linux-gnu musl-tools

# Add to ~/.cargo/config.toml:
# [target.aarch64-unknown-linux-musl]
# linker = "aarch64-linux-gnu-gcc"

cargo build --release --target aarch64-unknown-linux-musl
strip target/aarch64-unknown-linux-musl/release/doh-proxy
```

### Feature flags

| Flag     | Default | Description                                       |
|----------|---------|---------------------------------------------------|
| `status` | enabled | HTTP health/stats endpoint via axum               |
| `http3`  | disabled | HTTP/3 (QUIC) upstream support via h3 + quinn   |

```sh
# Build with HTTP/3 support
cargo build --release --features http3

# Build without the status endpoint (smaller binary)
cargo build --release --no-default-features
```

## Configuration

Default config path: `/etc/doh-proxy/config.toml`  
Override with `--config <path>`.

See [`config.example.toml`](config.example.toml) for a fully documented example.

### Configuration reference

| Field               | Type    | Default             | Description                                          |
|---------------------|---------|---------------------|------------------------------------------------------|
| `listen_addr`       | string  | `"0.0.0.0:53"`      | Address:port to listen for DNS queries               |
| `upstream`          | array   | Cloudflare + Quad9  | List of `[[upstream]]` entries (url, name)           |
| `upstream_strategy` | string  | `"failover"`        | `"failover"` or `"roundrobin"`                       |
| `cache_enabled`     | bool    | `true`              | Enable in-memory LRU DNS cache                       |
| `cache_max_entries` | integer | `10000`             | Maximum LRU cache entries                            |
| `cache_min_ttl`     | integer | `60`                | Minimum TTL to cache (seconds)                       |
| `http3_enabled`     | bool    | `false`             | Use HTTP/3 (QUIC) for upstream (requires feature)    |
| `timeout_ms`        | integer | `5000`              | Upstream query timeout (milliseconds)                |
| `log_level`         | string  | `"info"`            | Log level: trace/debug/info/warn/error               |
| `status_addr`       | string  | _(unset)_           | Optional HTTP status endpoint address                |
| `tls_insecure`      | bool    | `false`             | Skip TLS cert verification (testing only)            |

### Minimal config example

```toml
listen_addr = "127.0.0.1:5353"
upstream_strategy = "failover"

[[upstream]]
url = "https://1.1.1.1/dns-query"
name = "Cloudflare"

[[upstream]]
url = "https://9.9.9.9/dns-query"
name = "Quad9"
```

## CLI flags

```
doh-proxy [OPTIONS]

Options:
  -c, --config <CONFIG>      Path to TOML config file [default: /etc/doh-proxy/config.toml]
      --listen <LISTEN>      Override listen address
      --upstream <UPSTREAM>  Add upstream URL (repeatable, overrides config)
      --http3                Enable HTTP/3 upstream queries
      --log-level <LEVEL>    Log level (trace/debug/info/warn/error)
  -h, --help                 Print help
  -V, --version              Print version
```

## OpenWrt Installation

### 1. Transfer the binary

```sh
scp target/x86_64-unknown-linux-musl/release/doh-proxy root@192.168.1.1:/usr/bin/
ssh root@192.168.1.1 "chmod +x /usr/bin/doh-proxy"
```

### 2. Create config directory and copy config

```sh
ssh root@192.168.1.1 "mkdir -p /etc/doh-proxy"
scp files/config.toml root@192.168.1.1:/etc/doh-proxy/config.toml
```

### 3. Install the init script

```sh
scp files/doh-proxy.init root@192.168.1.1:/etc/init.d/doh-proxy
ssh root@192.168.1.1 "chmod +x /etc/init.d/doh-proxy"
```

### 4. Enable and start the service

```sh
ssh root@192.168.1.1 "/etc/init.d/doh-proxy enable"
ssh root@192.168.1.1 "/etc/init.d/doh-proxy start"
```

### 5. Verify the service is running

```sh
ssh root@192.168.1.1 "/etc/init.d/doh-proxy status"
```

### Using as a dnsmasq upstream

To use doh-proxy as an upstream resolver for dnsmasq (listening on port 5353):

```sh
# In /etc/doh-proxy/config.toml:
listen_addr = "127.0.0.1:5353"

# In /etc/dnsmasq.conf (or /etc/config/dhcp):
server=127.0.0.1#5353
```

## Usage Examples

### Test with dig

```sh
# Query via UDP
dig @127.0.0.1 example.com A

# Query via TCP
dig @127.0.0.1 +tcp example.com A

# Check AAAA record
dig @127.0.0.1 example.com AAAA

# Reverse lookup
dig @127.0.0.1 -x 1.1.1.1
```

### Check health endpoint (when status_addr is set)

```sh
# Health check
curl http://127.0.0.1:8053/health

# Stats
curl -s http://127.0.0.1:8053/stats | python3 -m json.tool
```

Example stats output:

```json
{
  "queries_total": 1234,
  "cache_hits": 987,
  "cache_misses": 247,
  "cache_hit_rate": 0.7997,
  "uptime_secs": 3600
}
```

## Project Structure

```
rust-doh-proxy/
├── Cargo.toml
├── config.example.toml        # Fully documented example configuration
├── README.md
├── src/
│   ├── main.rs                # Entry point, CLI parsing, server startup
│   ├── config.rs              # Config structs, TOML parsing, CLI overrides
│   ├── dns/
│   │   ├── mod.rs
│   │   ├── server.rs          # UDP + TCP DNS listener
│   │   ├── parser.rs          # DNS wire format parsing (hickory-proto)
│   │   └── response.rs        # DNS response building helpers
│   ├── cache/
│   │   ├── mod.rs
│   │   └── lru.rs             # LRU TTL cache with atomic stats
│   ├── upstream/
│   │   ├── mod.rs             # UpstreamClient trait
│   │   ├── pool.rs            # Client pool, round-robin/failover
│   │   ├── doh.rs             # HTTP/2 DoH client (reqwest)
│   │   └── doh3.rs            # HTTP/3 DoH client (h3/quinn, optional)
│   └── status/
│       └── mod.rs             # Optional HTTP status server (axum)
├── files/
│   ├── doh-proxy.init         # OpenWrt procd init script
│   └── config.toml            # Default OpenWrt config
└── .github/
    └── workflows/
        └── build.yml          # Cross-compile CI + GitHub Releases
```

## License

MIT
