//! The peers of the VPN: who may come, and who is already in.
//!
//! # A peer is a name
//!
//! A peer's **static public key is its name**. The table is keyed by it, and
//! the handshake proves the private half — so a peer that is in the table is a
//! peer that has proven itself.
//!
//! In the VPN variant there is nothing else about a peer: there is no
//! `AllowedIPs`, no address pool, no route table. Those belonged to the
//! packet plane, and the packet plane is gone — the VPN carries flows, not
//! IP packets. See the crate's own doc for why.
//!
//! What a peer does have is a **label** — a name for the operator's log. The
//! label is never used for anything else.

use std::collections::HashMap;

/// The length of a static public key.
pub const KEY_LEN: usize = 32;

/// What can go wrong while reading a peer.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PeerError {
    /// The peer is already in the table.
    #[error("the peer is already known")]
    Duplicate,

    /// The peer is not in the table.
    #[error("the peer is not known")]
    Unknown,
}

/// A node this one talks to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Peer {
    /// The peer's static public key — its name.
    pub public_key: [u8; KEY_LEN],
    /// A label for the operator. It is only ever a label.
    pub name: Option<String>,
}

impl Peer {
    /// A peer with nothing but a name.
    pub fn new(public_key: [u8; KEY_LEN]) -> Self {
        Self {
            public_key,
            name: None,
        }
    }

    /// A peer with a label.
    pub fn named(public_key: [u8; KEY_LEN], name: impl Into<String>) -> Self {
        Self {
            public_key,
            name: Some(name.into()),
        }
    }

    /// The label of the peer, or its key in hex when it has none.
    pub fn label(&self) -> String {
        match &self.name {
            Some(name) => name.clone(),
            None => hex::encode(self.public_key),
        }
    }
}

/// The peers of one node.
#[derive(Debug, Default, Clone)]
pub struct PeerTable {
    peers: HashMap<[u8; KEY_LEN], Peer>,
}

impl PeerTable {
    /// An empty table.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a peer. A peer that is already in the table is refused: a table
    /// with two entries under one name would have to pick one of them, and
    /// picking silently is how traffic ends up in the wrong tunnel.
    pub fn insert(&mut self, peer: Peer) -> Result<(), PeerError> {
        if self.peers.contains_key(&peer.public_key) {
            return Err(PeerError::Duplicate);
        }
        self.peers.insert(peer.public_key, peer);
        Ok(())
    }

    /// Remove a peer.
    pub fn remove(&mut self, public_key: &[u8; KEY_LEN]) -> Result<Peer, PeerError> {
        self.peers.remove(public_key).ok_or(PeerError::Unknown)
    }

    /// The peer with this name.
    pub fn get(&self, public_key: &[u8; KEY_LEN]) -> Option<&Peer> {
        self.peers.get(public_key)
    }

    /// Whether the peer may come.
    ///
    /// This is the allowlist the terminator hands to its handshake: a peer
    /// that is not in the table is refused before the session keys are
    /// derived.
    pub fn allows(&self, public_key: &[u8; KEY_LEN]) -> bool {
        self.peers.contains_key(public_key)
    }

    /// How many peers there are.
    pub fn len(&self) -> usize {
        self.peers.len()
    }

    /// Whether there are no peers.
    pub fn is_empty(&self) -> bool {
        self.peers.is_empty()
    }

    /// Every peer.
    pub fn iter(&self) -> impl Iterator<Item = &Peer> {
        self.peers.values()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_peer_is_found_by_its_name() {
        let key = [7u8; KEY_LEN];
        let mut table = PeerTable::new();
        table.insert(Peer::named(key, "laptop")).expect("insert");
        assert!(table.allows(&key));
        assert_eq!(table.len(), 1);
        assert_eq!(table.get(&key).expect("peer").label(), "laptop");
    }

    #[test]
    fn a_peer_cannot_be_in_the_table_twice() {
        let key = [7u8; KEY_LEN];
        let mut table = PeerTable::new();
        table.insert(Peer::new(key)).expect("insert");
        assert_eq!(table.insert(Peer::new(key)), Err(PeerError::Duplicate));
    }

    #[test]
    fn a_stranger_is_not_allowed() {
        let mut table = PeerTable::new();
        table.insert(Peer::new([1u8; KEY_LEN])).expect("insert");
        assert!(!table.allows(&[2u8; KEY_LEN]));
    }

    #[test]
    fn a_peer_without_a_label_falls_back_to_its_key() {
        let peer = Peer::new([3u8; KEY_LEN]);
        assert_eq!(peer.label(), hex::encode([3u8; KEY_LEN]));
    }
}
