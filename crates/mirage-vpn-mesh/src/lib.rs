//! The **mesh variant** of Mirage: the VPN session inside an onion chain.
//!
//! # Where this sits
//!
//! ```text
//!   ┌─ variants ──────────────────────────────────────────────────────────┐
//!   │  VPN   — a session between a client and a terminator, no onion      │
//!   │  mesh  — the same session inside an onion chain of N hops           │
//!   └────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! This crate is the mesh variant. It differs from the VPN variant in
//! exactly one thing: **the carrier**. The handshake, the session, the flow
//! plane and the SOCKS5 surface are the same code — the ones in
//! `mirage-vpn`.
//!
//! # The difference between the two variants
//!
//! | | VPN | mesh |
//! |---|---|---|
//! | the session | between a client and a terminator, end to end | between a client and a terminator, end to end — **inside** the chain |
//! | an intermediate node | a **pump**: it carries the bytes and does not take the layer off | a **peel**: it takes exactly one layer off and knows only the hop before it and the hop after it |
//! | what the node sees | that this is a VPN session (no onion inside) | how many hops there are and who they are |
//!
//! So the two variants are **not two protocols**. They are the same core
//! under a different carrier:
//!
//! - MWG (МиражВГ) — UDP with a junk burst and a magic marker;
//! - КВИК (МиражКВИК) — a QUIC connection with our ALPN;
//! - a SOCKS5 tube — a CONNECT tunnel through a proxy;
//! - **onion** — the chain. This crate.
//!
//! # Why a separate crate
//!
//! `mirage-vpn` must not know about the onion: a crate that pulled the whole
//! mesh in to carry one session would drag the mesh into everything that
//! uses the VPN. This crate is the one place where both are known, and a
//! product that wants the VPN over the mesh depends on this crate and not on
//! the mesh separately.

use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use mirage_control_plane::tunnel::establish_raw_tunnel;
use mirage_core::config::ChainConfig;
use mirage_core::crypto::credential::CredentialParams;
use mirage_core::mirage::mesh::PeerTable;
use mirage_protocol::driver::ClientCredential;
use mirage_protocol::negotiation::ProtocolChain;
use mirage_protocol::traits::Tunnel;
use mirage_vpn::carrier::{open_over_stream, tunnel_to_stream, Carrier, CarrierError};
use mirage_vpn::connector::Connector;

/// What can go wrong on the way into the chain.
#[derive(Debug, thiserror::Error)]
pub enum MeshError {
    /// The chain could not be established.
    #[error("the chain could not be established: {0}")]
    Chain(String),

    /// The VPN handshake inside the chain failed.
    #[error("the vpn handshake inside the chain failed: {0}")]
    Carrier(#[from] CarrierError),
}

/// The onion carrier: the VPN session rides inside an onion chain.
///
/// The chain is established first, and the VPN handshake runs inside it: the
/// peer that answers is the peer the handshake says it is, and the chain only
/// decides who carried the bytes there.
pub struct OnionCarrier {
    chain_protocols: ProtocolChain,
    chain: ChainConfig,
    peer_table: PeerTable,
    pre_minted: Option<ClientCredential>,
    credential_params: Option<CredentialParams>,
}

impl OnionCarrier {
    /// A carrier over the chain.
    pub fn new(chain_protocols: ProtocolChain, chain: ChainConfig, peer_table: PeerTable) -> Self {
        Self {
            chain_protocols,
            chain,
            peer_table,
            pre_minted: None,
            credential_params: None,
        }
    }

    /// A carrier with a credential that was minted before the dial.
    pub fn with_credential(mut self, credential: ClientCredential) -> Self {
        self.pre_minted = Some(credential);
        self
    }

    /// A carrier that mints its credential at the dial.
    pub fn with_credential_params(mut self, params: CredentialParams) -> Self {
        self.credential_params = Some(params);
        self
    }

    /// The address of the last hop — where the session comes out.
    ///
    /// It is only ever written into the transport's metadata: the far side is
    /// identified by its key, not by its address.
    fn exit_addr(&self) -> SocketAddr {
        self.chain
            .hops
            .last()
            .and_then(|hop| hop.addr.parse().ok())
            .unwrap_or_else(|| "127.0.0.1:0".parse().expect("an address"))
    }
}

#[async_trait]
impl Carrier for OnionCarrier {
    fn name(&self) -> &'static str {
        "onion"
    }

    async fn open(
        &self,
        server_static_pub: &[u8; 32],
        client_static_priv: &[u8; 32],
        mesh_id: &[u8],
    ) -> Result<Box<dyn Tunnel>, CarrierError> {
        let tunnel = establish_raw_tunnel(
            &self.chain_protocols,
            &self.chain,
            &self.peer_table,
            mesh_id,
            self.pre_minted.as_ref(),
            self.credential_params.as_ref(),
        )
        .await
        .map_err(|err| CarrierError::Open(err.to_string()))?;

        // The chain is a tunnel; the session wants a stream.
        let stream = tunnel_to_stream(tunnel);
        open_over_stream(
            stream,
            server_static_pub,
            client_static_priv,
            mesh_id,
            self.exit_addr(),
        )
        .await
    }
}

/// A connector that reaches the terminator through the chain.
///
/// This is the mesh's answer to the connector of the VPN variant: the same
/// `Connector`, with the onion carrier instead of MWG or КВИК.
pub fn onion_connector(
    carrier: OnionCarrier,
    server_static_pub: [u8; 32],
    client_static_priv: [u8; 32],
    mesh_id: impl Into<Vec<u8>>,
) -> Connector {
    Connector::new(
        Arc::new(carrier),
        server_static_pub,
        client_static_priv,
        mesh_id,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A tunnel that says nothing — the stream is closed at once.
    struct DeadTunnel {
        info: mirage_protocol::traits::TransportInfo,
    }

    #[async_trait::async_trait]
    impl Tunnel for DeadTunnel {
        async fn send(&mut self, _data: &[u8]) -> Result<(), mirage_core::error::MirageError> {
            Ok(())
        }
        async fn recv(&mut self, _buf: &mut [u8]) -> Result<usize, mirage_core::error::MirageError> {
            Ok(0)
        }
        async fn close(&mut self) -> Result<(), mirage_core::error::MirageError> {
            Ok(())
        }
        fn transport_info(&self) -> &mirage_protocol::traits::TransportInfo {
            &self.info
        }
    }

    #[tokio::test]
    async fn a_closed_tunnel_says_so() {
        let tunnel = DeadTunnel {
            info: mirage_protocol::traits::TransportInfo::tcp_raw(
                "127.0.0.1:1".parse().expect("addr"),
            ),
        };
        // The bridge hands back a stream that is closed at once: the session
        // on top of it says so instead of waiting for bytes that never come.
        let mut stream = tunnel_to_stream(Box::new(tunnel));
        let mut buffer = [0u8; 16];
        let count = tokio::io::AsyncReadExt::read(&mut stream, &mut buffer)
            .await
            .expect("read");
        assert_eq!(count, 0);
    }
}
