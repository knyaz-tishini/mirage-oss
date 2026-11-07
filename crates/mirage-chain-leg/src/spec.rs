//! What a leg needs to know about a chain.
//!
//! The two consumers describe a chain in two different ways — a standalone box
//! reads it from a TOML file, the fleet's edge reads it from the monitor's
//! peer table — and both of them end up with the same thing: a list of hops,
//! each with an address, a key, a node id and a role. That list is what this
//! crate takes.

use mirage_core::config::HopRole;
use mirage_core::mirage::wire::TransportCamouflage;

/// One hop of a chain.
#[derive(Clone, Debug)]
pub struct LegHop {
    /// Where the hop is reached on the stream plane.
    pub addr: String,
    /// Where the hop is reached on the datagram plane.
    ///
    /// `None` when the hop has no datagram door — and then the whole chain
    /// carries TCP only.
    pub udp_addr: Option<String>,
    /// The hop's static public key.
    pub public_key: Option<String>,
    /// The hop's node id.
    pub node_id: Option<String>,
    /// The hop's role in the chain.
    pub role: HopRole,
    /// The hop's own disguise.
    ///
    /// The ENTRY hop's disguise is never set here: it is the hop's own
    /// published face, and the dialer resolves it from the peer table at dial
    /// time. That is also what makes a one-hop chain take the onion path
    /// instead of a plain handshake.
    pub camouflage: Option<TransportCamouflage>,
}

/// A chain, in the form a leg walks it.
#[derive(Clone, Debug)]
pub struct LegSpec {
    /// The chain's own id.
    pub chain_id: String,
    /// The datagram chain's own id.
    ///
    /// The two planes are two chains: the datagram one has its own hops, its
    /// own handshake and its own listener addresses, and sharing the stream
    /// chain's id would put the two planes on one address in the node's
    /// registry.
    pub datagram_chain_id: Option<String>,
    /// The hops, in order.
    pub hops: Vec<LegHop>,
    /// The mesh id the handshake confirms against.
    pub mesh_id: String,
    /// The exit hop's node id — the credential binds to it.
    pub exit_node_id: String,
}

impl LegSpec {
    /// Whether every hop of the chain has a datagram door.
    pub fn carries_datagrams(&self) -> bool {
        self.datagram_chain_id.is_some()
            && !self.hops.is_empty()
            && self.hops.iter().all(|hop| hop.udp_addr.is_some())
    }
}
