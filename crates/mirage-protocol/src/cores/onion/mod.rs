//! Onion routing wire format + layer wrap/peel primitives.
//!
//! Every layer has the form:
//!   [1B addr_tag][var-length addr][AEAD ciphertext]
//!
//! The ciphertext decrypts to either:
//!   - another layer (if addr_tag != Terminal)
//!   - raw user data (if addr_tag == Terminal, meaning this is the innermost)
//!
//! # Handshake strategy
//!
//! [`mirage_core::config::HandshakeStrategy::Telescopic`] is the only strategy
//! this crate implements: the client establishes the circuit hop-by-hop,
//! deriving each layer key from an ephemeral-ephemeral + ephemeral-static ECDH
//! pair (see [`builder::peel_onion_fs_layer`]), so no hop's key material
//! outlives the session. Wire frames live in [`fs_frame`].
//!
//! The earlier non-forward-secret strategy — which sealed every layer up
//! front from each hop's long-lived static key, and carried the full
//! `chain_node_ids` route in a cleartext header every relay forwarded
//! verbatim — was deleted along with `v7_frame`/`v8_frame`/`v9_frame`. It is
//! not coming back; see `docs/mirage/plans/chain-plane-execution-order-2026-09-02.md`.

pub mod builder;
pub mod fs_frame;
pub mod layer;
