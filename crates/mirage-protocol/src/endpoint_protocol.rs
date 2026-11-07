//! `EndpointProtocol` — adapter that bridges `MirageEndpointConfig` to the
//! [`TcpProtocol`] trait on the client side.
//!
//! Wraps a `MirageEndpointConfig` + `mesh_id` and delegates to
//! [`crate::client_transport::run_client_v9_transport_aware`] for outbound
//! tunnels — which picks the wire transport from the camouflage: a stream
//! camouflage (raw TCP / TLS / WebSocket / xhttp / Reality / SSH / gRPC)
//! is dialled over TCP, a datagram camouflage (QUIC / HTTP/3 /
//! WebTransport / WireGuard / raw UDP / DNS / ICMP) over UDP.
//!
//! Only the client-side `connect` path is meaningful here.
//!
//! Lives in `mirage-protocol` (not `mirage-client-core`) so monitor /
//! mesh-client can build a `ProtocolChain` without pulling client
//! runtime crate transitively.

use std::net::SocketAddr;

use async_trait::async_trait;
use mirage_core::{
    config::{CamouflageMode, MirageEndpointConfig, TcpProtocolId, TransportCamouflage},
    error::MirageError,
};
use tokio::net::TcpStream;

use crate::{
    client_transport::run_client_v9_transport_aware,
    traits::{AcceptResult, TcpProtocol, Tunnel},
};

/// Client-side adapter that wraps a `MirageEndpointConfig` and implements
/// [`TcpProtocol`].
///
/// Only `connect` is meaningful on the client side.  `accept` is included to
/// satisfy the trait but will always return an error.
///
/// `mesh_id` is stored on the struct and passed to every handshake — callers
/// MUST supply the actual mesh identifier for the target network.
pub struct EndpointProtocol {
    config: MirageEndpointConfig,
    protocol_id: TcpProtocolId,
    /// Mesh identifier baked into the Blake3 confirm label.
    mesh_id: Vec<u8>,
    /// Wire version. V8 single-hop TCP handshake removed — only `9` is valid.
    /// Kept for API stability: callers that call `.with_wire_version(9)` still compile.
    wire_version: u8,
    /// Optional anonymous credential attached to V9 dials.
    ///
    /// When `Some`, the credential scheme byte is placed in `V9ClientHello`
    /// byte 92 and a `[2B len BE][token]` frame follows the hello.
    /// When `None`, byte 92 is zero — legacy behaviour, no credential frame.
    credential: Option<crate::driver::ClientCredential>,
}

impl EndpointProtocol {
    /// Create a new client-side adapter.
    ///
    /// `mesh_id` — the mesh identifier bytes for the target network (e.g. UUID
    /// bytes or an ASCII string).  Passed verbatim to every handshake confirm.
    ///
    /// Defaults to wire version 9 (V9, forward-secret mutual auth).
    pub fn new(config: MirageEndpointConfig, protocol_id: TcpProtocolId, mesh_id: Vec<u8>) -> Self {
        Self { config, protocol_id, mesh_id, wire_version: 9, credential: None }
    }

    /// Set the wire version for this adapter.
    ///
    /// V8 single-hop TCP handshake has been removed; the only valid value is `9`.
    /// Kept for API stability — callers that already pass `.with_wire_version(9)` compile unchanged.
    #[must_use]
    pub fn with_wire_version(mut self, wire_version: u8) -> Self {
        self.wire_version = wire_version;
        self
    }

    /// Attach an anonymous credential to every V9 dial made by this adapter.
    ///
    /// The credential is passed verbatim to
    /// [`crate::client_transport::run_client_v9_transport_aware`] — scheme
    /// byte at wire position 92, followed by the `[2B len BE][token]` frame.
    /// Both the stream and the datagram path carry it in the same shape.
    #[must_use]
    pub fn with_credential(mut self, credential: Option<crate::driver::ClientCredential>) -> Self {
        self.credential = credential;
        self
    }
}

#[async_trait]
impl TcpProtocol for EndpointProtocol {
    async fn connect(
        &self,
        addr: SocketAddr,
        server_pubkey: &[u8; 32],
        sni: &str,
        _camouflage: CamouflageMode,
    ) -> Result<Box<dyn Tunnel>, MirageError> {
        // V8 single-hop TCP handshake removed; fleet is V9-only.
        // Callers may still call `.with_wire_version(9)`; any other value is a
        // configuration mistake but we proceed with V9 regardless.
        debug_assert_eq!(self.wire_version, 9, "V8 handshake removed; only wire_version=9 is valid");
        // Forward-secret V9 data leg. Throwaway per-dial static key — the node's
        // data-leg client_auth is permissive (|_| true), so a self-consistent
        // V9 proof from an ephemeral key is accepted; preserves Phase-8 unlinkability.
        let client_static_priv =
            x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng).to_bytes();
        run_client_v9_transport_aware(
            &self.config, addr, server_pubkey, &client_static_priv, sni, &self.mesh_id,
            self.credential.as_ref(),
        ).await
    }

    async fn connect_with_credential(
        &self,
        addr: std::net::SocketAddr,
        server_pubkey: &[u8; 32],
        sni: &str,
        hop_camouflage: Option<TransportCamouflage>,
        credential: Option<crate::driver::ClientCredential>,
    ) -> Result<Box<dyn crate::traits::Tunnel>, MirageError> {
        // Use the passed-in credential (fresh per-dial token) in preference
        // to any credential baked into self — this is the per-dial override path.
        let effective_credential = credential.or_else(|| self.credential.clone());
        let client_static_priv =
            x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng).to_bytes();
        // If the caller supplies a per-hop transport camouflage, build an
        // effective config with that camouflage applied.  When `None` we use
        // `self.config` unchanged — the production cli path pre-sets
        // `config.camouflage` directly, so `None` preserves that behaviour.
        let effective_config;
        let config_ref = if let Some(camo) = hop_camouflage {
            effective_config = MirageEndpointConfig { camouflage: camo, ..self.config.clone() };
            &effective_config
        } else {
            &self.config
        };
        run_client_v9_transport_aware(
            config_ref, addr, server_pubkey, &client_static_priv, sni, &self.mesh_id,
            effective_credential.as_ref(),
        ).await
    }

    async fn accept(
        &self,
        _stream: TcpStream,
        _peeked: &[u8],
    ) -> Result<AcceptResult, MirageError> {
        // Client-side protocol adapters are never used for server accept.
        Err(MirageError::Protocol(
            "EndpointProtocol::accept called on client-side adapter".into(),
        ))
    }

    fn id(&self) -> TcpProtocolId {
        self.protocol_id
    }

    fn probe_resistant(&self) -> bool {
        true
    }
}
