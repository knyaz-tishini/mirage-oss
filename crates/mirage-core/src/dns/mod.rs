//! Per-chain DNS isolation — `DnsTopology`, `DnsBackend`, `DnsCache`.
//!
//! See `docs/plans/wave3-dns-secrets-apikeys.md` Track A for the design rationale.

pub mod cache;
pub mod error;
pub mod forward_client;
pub mod topology;

pub use cache::DnsCache;
pub use error::DnsError;
pub use forward_client::dns_forward_via_socks5;
pub use topology::{DnsBackend, DnsTopology};
