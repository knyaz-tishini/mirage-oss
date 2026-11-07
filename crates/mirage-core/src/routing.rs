use std::net::IpAddr;

use crate::config::RoutingConfig;

/// Routing decision for an outgoing connection.
pub enum RouteDecision {
    Direct,
    Chain,
}

/// A parsed CIDR range.
pub struct CidrRange {
    pub network: IpAddr,
    pub prefix_len: u8,
}

impl CidrRange {
    /// Check whether `ip` falls inside this range using manual bit comparison.
    pub fn contains(&self, ip: &IpAddr) -> bool {
        match (&self.network, ip) {
            (IpAddr::V4(net), IpAddr::V4(addr)) => {
                let net_bits = u32::from_be_bytes(net.octets());
                let addr_bits = u32::from_be_bytes(addr.octets());
                if self.prefix_len == 0 {
                    return true;
                }
                let shift = 32u32.saturating_sub(self.prefix_len as u32);
                (net_bits >> shift) == (addr_bits >> shift)
            }
            (IpAddr::V6(net), IpAddr::V6(addr)) => {
                let net_bits = u128::from_be_bytes(net.octets());
                let addr_bits = u128::from_be_bytes(addr.octets());
                if self.prefix_len == 0 {
                    return true;
                }
                let shift = 128u32.saturating_sub(self.prefix_len as u32);
                (net_bits >> shift) == (addr_bits >> shift)
            }
            // IPv4 vs IPv6 mismatch — no match.
            _ => false,
        }
    }
}

/// Table of routing rules derived from configuration.
pub struct RoutingTable {
    /// Parsed CIDR ranges whose traffic travels direct.
    direct_ranges: Vec<CidrRange>,
    /// Domain patterns (exact or suffix) that bypass the VPN.
    direct_domains: Vec<String>,
    /// Domain patterns (exact or suffix) that must go through the chain.
    blocked_domains: Vec<String>,
}

impl RoutingTable {
    /// Build a routing table from a [`RoutingConfig`], parsing all CIDR strings.
    ///
    /// Unparseable or malformed CIDR entries are silently skipped.
    pub fn new(config: &RoutingConfig) -> Self {
        let direct_ranges = config
            .direct_cidrs
            .iter()
            .filter_map(|s| parse_cidr(s))
            .collect();
        Self {
            direct_ranges,
            direct_domains: config.direct_domains.clone(),
            blocked_domains: config.blocked_domains.clone(),
        }
    }

    /// Decide routing for a resolved IP address.
    pub fn decide_ip(&self, ip: &IpAddr) -> RouteDecision {
        for range in &self.direct_ranges {
            if range.contains(ip) {
                return RouteDecision::Direct;
            }
        }
        RouteDecision::Chain
    }

    /// Decide routing for a domain name.
    ///
    /// Priority order:
    /// 1. `blocked_domains` — exact or suffix match → [`RouteDecision::Chain`] (force-tunnel)
    /// 2. `direct_domains` — exact or suffix match → [`RouteDecision::Direct`] (bypass VPN)
    /// 3. Default → [`RouteDecision::Chain`] (everything tunnelled by default)
    pub fn decide_domain(&self, domain: &str) -> RouteDecision {
        // blocked_domains take top priority — explicitly force-tunnel even if
        // the domain would otherwise match a direct_domains entry.
        for pattern in &self.blocked_domains {
            if domain_matches(pattern, domain) {
                return RouteDecision::Chain;
            }
        }
        for pattern in &self.direct_domains {
            if domain_matches(pattern, domain) {
                return RouteDecision::Direct;
            }
        }
        RouteDecision::Chain
    }
}

/// Return `true` if `host` matches `pattern` exactly or as a subdomain suffix.
///
/// Examples:
/// - `"google.com"` matches `"google.com"` (exact)
/// - `"google.com"` matches `"www.google.com"` (suffix: `".google.com"`)
/// - `"google.com"` does NOT match `"notgoogle.com"`
fn domain_matches(pattern: &str, host: &str) -> bool {
    if host.eq_ignore_ascii_case(pattern) {
        return true;
    }
    // Suffix match: host must end with ".<pattern>".
    let suffix_len = pattern.len() + 1; // +1 for the leading dot
    if host.len() > suffix_len {
        let candidate = &host[host.len() - suffix_len..];
        // The extra byte must be a '.' separator.
        candidate[0..1].eq_ignore_ascii_case(".")
            && candidate[1..].eq_ignore_ascii_case(pattern)
    } else {
        false
    }
}

/// Parse a CIDR string such as `"10.0.0.0/8"` or `"2001:db8::/32"`.
fn parse_cidr(s: &str) -> Option<CidrRange> {
    let (addr_str, prefix_str) = s.split_once('/')?;
    let network: IpAddr = addr_str.parse().ok()?;
    let prefix_len: u8 = prefix_str.parse().ok()?;
    let max_prefix = match network {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    };
    if prefix_len > max_prefix {
        return None;
    }
    Some(CidrRange {
        network,
        prefix_len,
    })
}
