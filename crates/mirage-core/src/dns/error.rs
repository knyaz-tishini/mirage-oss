use thiserror::Error;

/// Errors from DNS topology resolution.
#[derive(Debug, Error)]
pub enum DnsError {
    /// The per_chain map has no entry for this chain and chain_set_fallback is absent.
    #[error("no DNS backend configured for chain {0}")]
    ChainNotFound(String),

    /// The upstream backend (DoH, DoT, or system) returned an error.
    #[error("DNS upstream failed (backend: {backend}): {source}")]
    UpstreamFailed {
        backend: String,
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    /// The name does not exist (NXDOMAIN).
    #[error("NXDOMAIN: {0}")]
    NxDomain(String),

    /// Resolution timed out.
    #[error("DNS resolution timed out")]
    Timeout,

    /// System resolver failure.
    #[error("system resolver error: {0}")]
    SystemResolver(String),
}
