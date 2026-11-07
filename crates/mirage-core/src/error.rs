use thiserror::Error;

#[derive(Error, Debug)]
pub enum MirageError {
    #[error("crypto error: {0}")]
    Crypto(String),
    #[error("handshake failed: {0}")]
    Handshake(String),
    #[error("authentication failed")]
    AuthFailed,
    #[error("protocol error: {0}")]
    Protocol(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("config error: {0}")]
    Config(String),
    #[error("tunnel closed")]
    TunnelClosed,
    #[error("timeout")]
    Timeout,
    #[error("node unreachable: {0}")]
    NodeUnreachable(String),
    #[error("handshake timed out: {0}")]
    HandshakeTimedOut(String),
    #[error("provisioning failed: {0}")]
    Provisioning(String),
    #[error("unsupported protocol: {0}")]
    UnsupportedProtocol(String),
    #[error("heartbeat timeout")]
    HeartbeatTimeout,
    #[error("pool exhausted: no tunnels available")]
    PoolExhausted,
    #[error("circuit breaker open: chain is failing fast")]
    CircuitOpen,
}

pub type Result<T> = std::result::Result<T, MirageError>;
