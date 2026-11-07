use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};

use serde::{Deserialize, Serialize};

/// Where DNS queries for a chain (or bypass tier) are forwarded.
///
/// Each variant routes resolution through a different path:
/// - `DohOverChain` — DoH POST over an existing chain's SOCKS5 tunnel.
/// - `DotOverChain` — DoT TCP over a chain's SOCKS5 tunnel.
/// - `DohDirect` — DoH POST directly to a known IP, no chain involved.
/// - `DotDirect` — DoT TCP directly to a known IP, no chain involved.
/// - `SystemResolver` — fall through to the OS resolver (`getaddrinfo`).
///
/// Only `SystemResolver` and `DohDirect` are suitable for the bypass tier.
/// Proxied chains MUST NOT use `SystemResolver` — it leaks hostnames.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DnsBackend {
    /// Tunnel DoH requests through the named chain's SOCKS5 listener.
    DohOverChain {
        /// ID of the chain whose SOCKS5 port to use.
        chain_id: String,
        /// DoH endpoint URL (e.g. `"https://dns.google/dns-query"`).
        doh_url: String,
        /// TLS SNI for the DoH server.
        sni: String,
        /// ALPN protocols (e.g. `["h2", "http/1.1"]`).
        #[serde(default)]
        alpn: Vec<String>,
    },

    /// Tunnel DoT (DNS-over-TLS) requests through the named chain's SOCKS5 listener.
    DotOverChain {
        /// ID of the chain whose SOCKS5 port to use.
        chain_id: String,
        /// `"ip:port"` of the DoT server, e.g. `"1.1.1.1:853"`.
        dot_addr: String,
        /// TLS SNI for the DoT server.
        sni: String,
    },

    /// DoH direct to a known IP — avoids circular resolution of the server hostname.
    DohDirect {
        /// Socket address of the DoH server (already resolved, no DNS needed).
        server: SocketAddr,
        /// TLS SNI for the DoH server.
        sni: String,
        /// Bootstrap IPs used to pre-resolve the DoH hostname when `server` is
        /// not yet known. Typically a single IP like `1.1.1.1`.
        #[serde(default)]
        bootstrap_ips: Vec<IpAddr>,
    },

    /// DoT direct to a known IP.
    DotDirect {
        /// Socket address of the DoT server.
        server: SocketAddr,
        /// TLS SNI for the DoT server.
        sni: String,
    },

    /// Fall through to the OS system resolver.
    ///
    /// **Only use for the bypass tier.** Using this for proxied chains leaks
    /// hostnames to the ISP/observer watching the exit.
    SystemResolver,
}

impl Default for DnsBackend {
    fn default() -> Self {
        Self::SystemResolver
    }
}

/// Per-chain and bypass DNS routing topology.
///
/// Deserialized from `ClientConfig.dns_topology`. Old configs that omit the
/// field get `DnsTopology::default()` which is all-`SystemResolver` — safe for
/// backwards compatibility but provides no leak isolation. Operators SHOULD
/// configure explicit backends.
///
/// ## Lookup precedence (for a proxied flow on `chain_id`):
///
/// 1. `per_chain[chain_id]` — chain-specific backend.
/// 2. `chain_set_fallback` — if `per_chain` has no entry for this chain.
/// 3. `SystemResolver` (implicit last resort, with a WARN log).
///
/// ## Bypass tier:
///
/// `bypass` — used for flows NOT routed through any chain.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DnsTopology {
    /// Backend for bypass-tier (LAN / direct) traffic.
    /// Defaults to `SystemResolver` when absent.
    pub bypass: Option<DnsBackend>,

    /// Per-chain DNS backends.  Key = chain_id string.
    #[serde(default)]
    pub per_chain: HashMap<String, DnsBackend>,

    /// Fallback backend when `per_chain` has no entry for the requested chain.
    pub chain_set_fallback: Option<DnsBackend>,
}

impl DnsTopology {
    /// Return the backend to use for the given chain (or bypass tier).
    ///
    /// `chain_id = None` → bypass tier.
    /// `chain_id = Some(id)` → proxied chain.
    pub fn backend_for(&self, chain_id: Option<&str>) -> &DnsBackend {
        match chain_id {
            None => self.bypass.as_ref().unwrap_or(&DnsBackend::SystemResolver),
            Some(id) => self
                .per_chain
                .get(id)
                .or(self.chain_set_fallback.as_ref())
                .unwrap_or(&DnsBackend::SystemResolver),
        }
    }
}
