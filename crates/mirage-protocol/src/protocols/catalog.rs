//! One index of every protocol, by layer.
//!
//! Two kinds share a shelf. A codec parses a packet. An engine runs a session.
//! A scanner takes codecs from `mirage_tcpip_stack::catalog`. A VPN takes
//! engines from [`crate::protocols`]. Neither kind is a camouflage of Mirage.

/// Where the protocol sits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layer {
    L2,
    L3,
    L4,
    L5,
    L7,
}

/// What a caller can do with it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// Parse and build a packet.
    Codec,
    /// Open a session.
    Engine,
}

/// One row of the catalog.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Item {
    pub name: &'static str,
    pub layer: Layer,
    pub kind: Kind,
    /// Crate the caller depends on.
    pub crate_name: &'static str,
    /// Path the caller imports.
    pub path: &'static str,
    /// Features that crate needs for this row. Empty means it is always built.
    pub features: &'static [&'static str],
}

const STACK: &str = "mirage-tcpip-stack";
const PROTOCOL: &str = "mirage-protocol";

/// Every protocol we have, codecs and engines.
pub const ALL: &[Item] = &[
    Item { name: "ethernet", layer: Layer::L2, kind: Kind::Codec, crate_name: STACK, path: "mirage_tcpip_stack::catalog::l2", features: &["medium-ethernet"] },
    Item { name: "arp", layer: Layer::L2, kind: Kind::Codec, crate_name: STACK, path: "mirage_tcpip_stack::catalog::l2", features: &["medium-ethernet", "proto-ipv4"] },
    Item { name: "ieee802154", layer: Layer::L2, kind: Kind::Codec, crate_name: STACK, path: "mirage_tcpip_stack::catalog::l2", features: &["medium-ieee802154"] },
    Item { name: "sixlowpan", layer: Layer::L2, kind: Kind::Codec, crate_name: STACK, path: "mirage_tcpip_stack::catalog::l2", features: &["proto-sixlowpan", "medium-ieee802154"] },
    Item { name: "ipv4", layer: Layer::L3, kind: Kind::Codec, crate_name: STACK, path: "mirage_tcpip_stack::catalog::l3", features: &["proto-ipv4"] },
    Item { name: "ipv6", layer: Layer::L3, kind: Kind::Codec, crate_name: STACK, path: "mirage_tcpip_stack::catalog::l3", features: &["proto-ipv6"] },
    Item { name: "icmpv4", layer: Layer::L3, kind: Kind::Codec, crate_name: STACK, path: "mirage_tcpip_stack::catalog::l3", features: &["proto-ipv4"] },
    Item { name: "icmpv6", layer: Layer::L3, kind: Kind::Codec, crate_name: STACK, path: "mirage_tcpip_stack::catalog::l3", features: &["proto-ipv6"] },
    Item { name: "igmp", layer: Layer::L3, kind: Kind::Codec, crate_name: STACK, path: "mirage_tcpip_stack::catalog::l3", features: &["proto-ipv4"] },
    Item { name: "mld", layer: Layer::L3, kind: Kind::Codec, crate_name: STACK, path: "mirage_tcpip_stack::catalog::l3", features: &["proto-ipv6"] },
    Item { name: "ndisc", layer: Layer::L3, kind: Kind::Codec, crate_name: STACK, path: "mirage_tcpip_stack::catalog::l3", features: &["proto-ipv6", "medium-ethernet"] },
    Item { name: "rpl", layer: Layer::L3, kind: Kind::Codec, crate_name: STACK, path: "mirage_tcpip_stack::catalog::l3", features: &["proto-rpl"] },
    Item { name: "ipsec-ah", layer: Layer::L3, kind: Kind::Codec, crate_name: STACK, path: "mirage_tcpip_stack::catalog::l3", features: &["proto-ipsec-ah"] },
    Item { name: "ipsec-esp", layer: Layer::L3, kind: Kind::Codec, crate_name: STACK, path: "mirage_tcpip_stack::catalog::l3", features: &["proto-ipsec-esp"] },
    Item { name: "icmp", layer: Layer::L3, kind: Kind::Engine, crate_name: PROTOCOL, path: "mirage_protocol::protocols::l3::icmp", features: &[] },
    Item { name: "wireguard", layer: Layer::L3, kind: Kind::Engine, crate_name: PROTOCOL, path: "mirage_protocol::protocols::l3::wireguard", features: &[] },
    Item { name: "amneziawg", layer: Layer::L3, kind: Kind::Engine, crate_name: PROTOCOL, path: "mirage_protocol::protocols::l3::amneziawg", features: &[] },
    Item { name: "tcp", layer: Layer::L4, kind: Kind::Codec, crate_name: STACK, path: "mirage_tcpip_stack::catalog::l4", features: &[] },
    Item { name: "udp", layer: Layer::L4, kind: Kind::Codec, crate_name: STACK, path: "mirage_tcpip_stack::catalog::l4", features: &[] },
    Item { name: "quic", layer: Layer::L4, kind: Kind::Engine, crate_name: PROTOCOL, path: "mirage_protocol::protocols::l4::quic", features: &[] },
    Item { name: "tls", layer: Layer::L5, kind: Kind::Engine, crate_name: PROTOCOL, path: "mirage_protocol::protocols::l5::tls", features: &[] },
    Item { name: "dhcpv4", layer: Layer::L7, kind: Kind::Codec, crate_name: STACK, path: "mirage_tcpip_stack::catalog::l7", features: &["proto-dhcpv4"] },
    Item { name: "dns", layer: Layer::L7, kind: Kind::Codec, crate_name: STACK, path: "mirage_tcpip_stack::catalog::l7", features: &["proto-dns"] },
    Item { name: "dns-tunnel", layer: Layer::L7, kind: Kind::Engine, crate_name: PROTOCOL, path: "mirage_protocol::protocols::l7::dns", features: &[] },
    Item { name: "grpc", layer: Layer::L7, kind: Kind::Engine, crate_name: PROTOCOL, path: "mirage_protocol::protocols::l7::grpc", features: &["grpc"] },
    Item { name: "http3", layer: Layer::L7, kind: Kind::Engine, crate_name: PROTOCOL, path: "mirage_protocol::protocols::l7::http3", features: &[] },
    Item { name: "mirage", layer: Layer::L7, kind: Kind::Engine, crate_name: PROTOCOL, path: "mirage_protocol::protocols::l7::mirage", features: &[] },
    Item { name: "shadowsocks", layer: Layer::L7, kind: Kind::Engine, crate_name: PROTOCOL, path: "mirage_protocol::protocols::l7::shadowsocks", features: &[] },
    Item { name: "ssh", layer: Layer::L7, kind: Kind::Engine, crate_name: PROTOCOL, path: "mirage_protocol::protocols::l7::ssh", features: &["ssh"] },
    Item { name: "websocket", layer: Layer::L7, kind: Kind::Engine, crate_name: PROTOCOL, path: "mirage_protocol::protocols::l7::websocket", features: &[] },
    Item { name: "webtransport", layer: Layer::L7, kind: Kind::Engine, crate_name: PROTOCOL, path: "mirage_protocol::protocols::l7::webtransport", features: &[] },
];

/// Rows of one layer, in catalog order.
pub fn layer(layer: Layer) -> impl Iterator<Item = &'static Item> {
    ALL.iter().filter(move |item| item.layer == layer)
}
