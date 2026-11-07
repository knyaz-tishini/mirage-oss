//! The carriers — the pipes a session may ride in.
//!
//! # A carrier is the only thing that differs
//!
//! The handshake, the session and the flow plane are **one protocol**. What
//! differs between the products we ship is the pipe under the session:
//!
//! | carrier | pipe | variant |
//! |---|---|---|
//! | **MWG** (МиражВГ) | UDP with a junk burst and a magic marker | VPN |
//! | **КВИК** (МиражКВИК) | a real QUIC connection, TLS 1.3 underneath | VPN |
//! | **SOCKS5** | a CONNECT tunnel through a proxy | VPN |
//! | **onion** | the chain itself, N hops | mesh |
//!
//! So «MWG, КВИК and the full Mirage» are **not three protocols** — they are
//! three carriers of one core. The full Mirage differs from MWG and КВИК only
//! in that its carrier is the onion chain.
//!
//! # Where the axes live
//!
//! The camouflage axes — MWG is `camouflage::wireguard`, КВИК is
//! `protocols::l4::quic` — are in [`crate::protocols`]. This module names them
//! and maps a configuration onto the carrier it selects, so that the rest of
//! the stack can talk about «the MWG carrier» without knowing how the axis
//! is built.
//!
//! The trait that a carrier implements lives with the variant that owns it:
//! `mirage-vpn` carries the VPN carriers, `mirage-vpn-mesh` carries the onion
//! one. What is shared is the **shape**, not the implementation.

use mirage_core::config::TransportCamouflage;

/// The named carriers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CarrierKind {
    /// МиражВГ — UDP with a junk burst and a magic marker.
    Mwg,
    /// МиражКВИК — a QUIC connection with our ALPN.
    Mkvik,
    /// A session inside a SOCKS5 CONNECT tunnel.
    Socks5,
    /// A session inside an onion chain — the mesh carrier.
    Onion,
}

impl CarrierKind {
    /// The name of the carrier, for the operator's log.
    pub fn name(&self) -> &'static str {
        match self {
            CarrierKind::Mwg => "mwg",
            CarrierKind::Mkvik => "mkvik",
            CarrierKind::Socks5 => "socks5",
            CarrierKind::Onion => "onion",
        }
    }

    /// Whether the carrier belongs to the VPN variant.
    ///
    /// The onion carrier does not: it is the mesh, and it carries N hops
    /// instead of one end-to-end session.
    pub fn is_vpn(&self) -> bool {
        !matches!(self, CarrierKind::Onion)
    }

    /// The carrier that a camouflage axis selects.
    ///
    /// `None` for the axes that are not VPN carriers: the TCP axes carry the
    /// mesh's own hops, and the onion chain carries the mesh session.
    pub fn of_camouflage(camouflage: &TransportCamouflage) -> Option<CarrierKind> {
        match camouflage {
            TransportCamouflage::WireGuard { .. } => Some(CarrierKind::Mwg),
            TransportCamouflage::Quic { .. } => Some(CarrierKind::Mkvik),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_wireguard_axis_is_the_mwg_carrier() {
        let camouflage = TransportCamouflage::WireGuard {
            magic_byte: 0x01,
            junk_count: 4,
            junk_min: 10,
            junk_max: 20,
            bind_addr: "127.0.0.1:1".parse().expect("addr"),
        };
        assert_eq!(
            CarrierKind::of_camouflage(&camouflage),
            Some(CarrierKind::Mwg)
        );
    }

    #[test]
    fn the_quic_axis_is_the_mkvik_carrier() {
        let camouflage = TransportCamouflage::Quic {
            alpn: vec!["mirage".to_owned()],
            bind_addr: "127.0.0.1:1".parse().expect("addr"),
        };
        assert_eq!(
            CarrierKind::of_camouflage(&camouflage),
            Some(CarrierKind::Mkvik)
        );
    }

    #[test]
    fn the_onion_carrier_is_not_a_vpn_carrier() {
        assert!(!CarrierKind::Onion.is_vpn());
        assert!(CarrierKind::Mwg.is_vpn());
        assert!(CarrierKind::Mkvik.is_vpn());
        assert!(CarrierKind::Socks5.is_vpn());
    }
}
