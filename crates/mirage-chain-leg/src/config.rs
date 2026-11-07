//! The chain's two configurations.
//!
//! The stream plane and the datagram plane are two chains, and this is where
//! they are built.

use mirage_core::config::{
    CamouflageMode, ChainConfig, CoverTrafficConfig, HandshakeStrategy, HopConfig, ProtocolId,
    ReplyMode, ShapingPreset, TcpProtocolId, TransportCamouflage, UdpProtocolId,
};
use mirage_core::crypto::AeadSuite;
use mirage_core::mirage::wire::RelayMode;

use crate::spec::LegSpec;

/// The chain's configuration, as the dialer sees it.
pub fn build_stream_config(spec: &LegSpec) -> ChainConfig {
    let hops = spec
        .hops
        .iter()
        .enumerate()
        .map(|(index, hop)| HopConfig {
            addr: hop.addr.clone(),
            public_key: hop.public_key.clone(),
            node_id: hop.node_id.clone(),
            sni: None,
            role: hop.role,
            display_name: None,
            // The entry hop's camouflage is NOT set here: it is the hop's own
            // published face, and the dialer resolves it from the peer table.
            // That is also what makes a one-hop chain take the onion path
            // instead of a plain handshake.
            camouflage: if index == 0 {
                None
            } else {
                hop.camouflage.clone()
            },
            byte_cipher: None,
            camo_server_pubkey: None,
            selector_token_hex: None,
            relay_mode: RelayMode::OnionPeel,
        })
        .collect();

    ChainConfig {
        chain_id: spec.chain_id.clone(),
        hops,
        handshake: HandshakeStrategy::Telescopic,
        reply: ReplyMode::Onion,
        protocol: ProtocolId::Tcp(TcpProtocolId::Mirage),
        priority: 0,
        shaping: ShapingPreset::default(),
        camouflage: CamouflageMode::default(),
        cover_traffic: CoverTrafficConfig::default(),
        socks5_bind: None,
        aead_suite: AeadSuite::ChaCha20Poly1305,
        kill_switch: None,
        group: None,
        nature: None,
    }
}

/// The chain's datagram configuration — the same hops, on their datagram
/// doors.
///
/// The datagram chain is not the stream chain with another mask: it is a chain
/// of its own, spoken over native UDP, whose hops are the same boxes and whose
/// entry hop is answered on its own datagram door. The datagram leg therefore
/// carries its own handshake and its own frames — a datagram stays a datagram
/// all the way down and never rides a stream.
///
/// `None` when any hop of the chain has no datagram door. A datagram leg
/// cannot skip a hop: a chain that carried datagrams only halfway would
/// deliver them out of the wrong box, which is worse than not carrying them at
/// all.
pub fn build_datagram_config(spec: &LegSpec) -> Option<ChainConfig> {
    let datagram_chain_id = spec.datagram_chain_id.as_ref()?;
    if spec.hops.is_empty() {
        return None;
    }
    if spec.hops.iter().any(|hop| hop.udp_addr.is_none()) {
        return None;
    }

    let hops = spec
        .hops
        .iter()
        .map(|hop| HopConfig {
            addr: hop.udp_addr.clone().unwrap_or_default(),
            public_key: hop.public_key.clone(),
            node_id: hop.node_id.clone(),
            sni: None,
            role: hop.role,
            display_name: None,
            // The datagram door speaks raw UDP on the wire: the disguise of a
            // datagram face is the PORT's own business, and the one disguise
            // the perimeter binds today is raw UDP itself.
            camouflage: Some(TransportCamouflage::RawUdp {
                bind_addr: "0.0.0.0:0".parse().expect("a literal address parses"),
            }),
            byte_cipher: None,
            camo_server_pubkey: None,
            selector_token_hex: None,
            relay_mode: RelayMode::OnionPeel,
        })
        .collect();

    Some(ChainConfig {
        chain_id: datagram_chain_id.clone(),
        hops,
        handshake: HandshakeStrategy::Telescopic,
        reply: ReplyMode::Onion,
        protocol: ProtocolId::Udp(UdpProtocolId::MirageUdp),
        priority: 0,
        shaping: ShapingPreset::default(),
        camouflage: CamouflageMode::default(),
        cover_traffic: CoverTrafficConfig::default(),
        socks5_bind: None,
        aead_suite: AeadSuite::ChaCha20Poly1305,
        kill_switch: None,
        group: None,
        nature: None,
    })
}
