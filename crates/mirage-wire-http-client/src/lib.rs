//! Wire-HTTP-over-V9 client for a non-opbox process.
//!
//! Lets any process that holds its own operator-signed `DeclaredIdentity` +
//! static X25519 keypair — not just opbox — dial a Mirage monitor's HTTP
//! routes over the V9 wire with the same V9 sender-proof headers opbox's
//! `wire_http::wire_request` already builds. See this crate's own
//! `CLAUDE.md` for what it mirrors from `operator-box::wire_http` and what
//! it deliberately leaves out.

mod client;
mod error;
mod face;
mod http;
mod sender_proof;

pub use client::{
    WireHttpClient, DEFAULT_FACE_CONNECT_TIMEOUT, DEFAULT_FACE_HANDSHAKE_TIMEOUT,
    DEFAULT_RESPONSE_RECV_IDLE,
};
pub use error::{FaceAttempt, WireHttpError};
pub use face::WireFace;
