//! The tests of the chain leg: the configuration, the credential, the protocol
//! and the framing of the destination.

use std::sync::Arc;

use mirage_chain_leg::{
    build_datagram_config, build_protocol_chain, build_stream_config, mint_credential, write_target,
    LegHop, LegSpec,
};
use mirage_core::capsule::RoleSlice;
use mirage_core::config::{HopRole, ProtocolId, TcpProtocolId, TransportCamouflage, UdpProtocolId};
use mirage_core::crypto::credential::role_signed::sign_role_signed_excerpt;
use mirage_core::identity::ServiceRole;
use mirage_core::mirage::mesh::peer_table::PeerTable;
use mirage_protocol::traits::{TransportInfo, Tunnel};

/// A tunnel that keeps what was written in it.
struct FakeTunnel {
    written: Vec<u8>,
    info: TransportInfo,
}

impl FakeTunnel {
    fn new() -> Self {
        Self {
            written: Vec::new(),
            info: TransportInfo {
                remote_addr: "127.0.0.1:1".parse().expect("an address"),
                established_at: std::time::Instant::now(),
                protocol_tcp: None,
                protocol_udp: None,
            },
        }
    }
}

#[async_trait::async_trait]
impl Tunnel for FakeTunnel {
    async fn send(&mut self, data: &[u8]) -> Result<(), mirage_core::error::MirageError> {
        self.written.extend_from_slice(data);
        Ok(())
    }

    async fn recv(&mut self, _buf: &mut [u8]) -> Result<usize, mirage_core::error::MirageError> {
        Ok(0)
    }

    async fn close(&mut self) -> Result<(), mirage_core::error::MirageError> {
        Ok(())
    }

    fn transport_info(&self) -> &TransportInfo {
        &self.info
    }
}

/// A chain of two hops: an entry and an exit.
fn two_hop_spec() -> LegSpec {
    LegSpec {
        chain_id: "chain-a".to_owned(),
        datagram_chain_id: Some("chain-a-dgram".to_owned()),
        hops: vec![
            LegHop {
                addr: "10.0.0.1:443".to_owned(),
                udp_addr: Some("10.0.0.1:5000".to_owned()),
                public_key: Some("aa".repeat(32)),
                node_id: Some("node-a".to_owned()),
                role: HopRole::Entry,
                camouflage: Some(TransportCamouflage::TlsReal {
                    sni: "example.com".to_owned(),
                    alpn: Vec::new(),
                }),
            },
            LegHop {
                addr: "10.0.0.2:443".to_owned(),
                udp_addr: Some("10.0.0.2:5000".to_owned()),
                public_key: Some("bb".repeat(32)),
                node_id: Some("node-b".to_owned()),
                role: HopRole::Exit,
                camouflage: None,
            },
        ],
        mesh_id: "mesh-1".to_owned(),
        exit_node_id: "node-b".to_owned(),
    }
}

#[test]
fn the_stream_config_carries_the_chain() {
    let config = build_stream_config(&two_hop_spec());
    assert_eq!(config.chain_id, "chain-a");
    assert_eq!(config.hops.len(), 2);
    assert_eq!(config.hops[0].addr, "10.0.0.1:443");
    assert_eq!(config.hops[1].addr, "10.0.0.2:443");
    assert_eq!(config.hops[1].node_id.as_deref(), Some("node-b"));
    assert_eq!(config.protocol, ProtocolId::Tcp(TcpProtocolId::Mirage));
}

#[test]
fn the_entry_hops_disguise_is_left_to_the_peer_table() {
    let config = build_stream_config(&two_hop_spec());
    // The entry hop's camouflage is the hop's own published face: the dialer
    // resolves it from the peer table, so it must not be baked in here.
    assert!(config.hops[0].camouflage.is_none());
}

#[test]
fn the_datagram_config_is_its_own_chain() {
    let config = build_datagram_config(&two_hop_spec()).expect("the chain has datagram doors");
    assert_eq!(config.chain_id, "chain-a-dgram");
    assert_eq!(config.protocol, ProtocolId::Udp(UdpProtocolId::MirageUdp));
    assert_eq!(config.hops[0].addr, "10.0.0.1:5000");
    // The datagram door speaks raw UDP.
    assert!(matches!(
        config.hops[0].camouflage,
        Some(TransportCamouflage::RawUdp { .. })
    ));
}

#[test]
fn a_chain_without_datagram_doors_carries_tcp_only() {
    let mut spec = two_hop_spec();
    spec.hops[1].udp_addr = None;
    assert!(build_datagram_config(&spec).is_none());
    assert!(!spec.carries_datagrams());
}

#[test]
fn a_chain_without_a_datagram_chain_id_carries_tcp_only() {
    let mut spec = two_hop_spec();
    spec.datagram_chain_id = None;
    assert!(build_datagram_config(&spec).is_none());
}

#[test]
fn the_protocol_chain_is_built() {
    // A chain with no protocols panics on construction — so building it IS
    // the assertion.
    let _chain = build_protocol_chain(b"mesh-1", None);
}

#[test]
fn the_credential_verifies_under_the_operator_key() {
    let signing = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
    let signing_pub_hex = hex::encode(signing.verifying_key().to_bytes());
    let slice = RoleSlice {
        role: ServiceRole::Edge,
        wire_privkey: [0x11u8; 32],
        signing_privkey: Some(signing.to_bytes()),
        wire_pubkey_hex: "aa".repeat(32),
        signing_pubkey_hex: Some(signing_pub_hex.clone()),
    };
    let operator = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
    let excerpt = sign_role_signed_excerpt(
        &operator,
        uuid::Uuid::new_v4(),
        "mesh-1",
        ServiceRole::Edge,
        &signing_pub_hex,
        4_102_444_800_000,
    )
    .expect("the Edge role must be encodable");

    let credential = mint_credential(&slice, &excerpt, "node-b", 1_700_000_000_000)
        .expect("the credential must be minted");

    let token = mirage_core::crypto::credential::role_signed::RoleSignedToken::decode(&credential.token)
        .expect("the token must decode");
    let verified = mirage_core::crypto::credential::role_signed::verify_role_signed(
        &token,
        &operator.verifying_key(),
        "node-b",
        1_700_000_000_000,
    )
    .expect("the token must verify under the operator key");

    assert_eq!(verified.self_id, token.self_id);
}

#[tokio::test]
async fn the_destination_is_framed_the_way_the_exit_reads_it() {
    let mut tunnel = FakeTunnel::new();
    write_target(&mut tunnel, "example.com:443")
        .await
        .expect("the destination must be written");

    let written = tunnel.written.clone();
    assert_eq!(&written[..2], &[0x00, 0x0f]);
    assert_eq!(&written[2..], b"example.com:443");
}

#[test]
fn a_peer_table_is_not_needed_to_build_the_config() {
    // The peer table is consulted at dial time, not at build time — a chain
    // can be built before the table has anything in it.
    let table = PeerTable::empty();
    let spec = two_hop_spec();
    let config = build_stream_config(&spec);
    assert_eq!(config.hops.len(), 2);
    let _ = Arc::new(table);
}
