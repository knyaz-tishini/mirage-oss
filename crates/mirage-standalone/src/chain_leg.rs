//! The chain leg — how the **edge** puts a customer's session INTO its chain.
//!
//! # Why this exists
//!
//! A box that stands alone opens the socket to the target itself: it *is* the
//! exit (see [`crate::exit_port::LocalExit`]). A box that stands at the front
//! of a chain has nothing to open — the traffic has to go somewhere else
//! first, and the chain is what it goes through.
//!
//! This module is that "somewhere else". The edge holds the chain, dials its
//! first hop, and hands the customer a stream that comes out of the chain's
//! last hop.
//!
//! # The edge is not a hop
//!
//! The chain's hops are the boxes that RELAY. The box the customer knocks on
//! is the edge: it owns the chain and dials it, and it is not a hop of its own
//! chain. That is the fleet's rule, and it is the rule that makes the two
//! ends of a chain different things:
//!
//! * the edge knows the chain's first hop — it dials it;
//! * the exit knows the whole chain — it has to accept the leg the hop before
//!   it sends, and it has to know who that hop is.
//!
//! # What the leg is
//!
//! The leg is the chain's own protocol, spoken by the edge: the same onion
//! the fleet's edge speaks, over the same hop addresses, with the same
//! credentials. Nothing here is a new protocol — this module is the edge's
//! dialer.
//!
//! # The machinery lives in `mirage-chain-leg`
//!
//! The leg itself — the chain's two configurations, the credential, the
//! protocol chain, the dial — is in the OSS crate
//! [`mirage_chain_leg`](../../../mirage-oss/crates/mirage-chain-leg), because
//! the fleet's edge speaks the very same leg and the two must not drift
//! apart. This module is what is left when that is taken out: how a
//! standalone box describes its chain, and the operator key it signs with.
//!
//! # The credential
//!
//! A hop refuses a leg it cannot authenticate. The credential is
//! `RoleSigned`: an identity excerpt signed by the chain's operator key, and
//! a per-dial signature bound to the exit's node id. The chain's operator key
//! is the chain's trust — every box of the chain knows its public half, and
//! only the edge holds the secret half, because only the edge signs legs.
//!
//! The mesh id rides the same way: the hop compares it with its own, byte for
//! byte, so the boxes of one chain share one.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use ed25519_dalek::SigningKey;
use mirage_chain_leg::{LegHop, LegSpec};
use mirage_core::capsule::RoleSlice;
use mirage_core::crypto::credential::role_signed::sign_role_signed_excerpt;
use mirage_core::identity::ServiceRole;
use mirage_core::mirage::mesh::peer_table::PeerTable;

use mirage_node::client::chain_store::ExitChoice;
use mirage_node::client::exit_port::{
    DatagramFlowError, DatagramFlowOpener, DatagramSinkBox, DatagramSourceBox, MeshStream,
    StreamOpenError, StreamOpener,
};

use crate::chain::ChainSpec;

/// How long the chain's operator key stays good for.
///
/// The excerpt says when it stops being honoured; the hop compares that with
/// its own clock. A chain outlives its installation, so this is counted in
/// months, not minutes — and the operator can always re-key the chain.
const OPERATOR_KEY_TTL_MS: u64 = 365 * 24 * 60 * 60 * 1000;

/// Why a chain leg could not be built or could not be opened.
#[derive(Debug, thiserror::Error)]
pub enum ChainLegError {
    /// The chain has no hop to dial.
    #[error("chain leg: the chain {chain_id} has no hop to dial")]
    NoHop {
        /// The chain that has no hop.
        chain_id: String,
    },

    /// The chain's operator key is not a usable ed25519 seed.
    #[error("chain leg: the chain's operator key is malformed: {reason}")]
    BadOperatorKey {
        /// Why the key was refused.
        reason: String,
    },

    /// The chain's mesh id is not a usable id.
    #[error("chain leg: the chain's mesh id is malformed: {reason}")]
    BadMeshId {
        /// Why the id was refused.
        reason: String,
    },

    /// The exit hop has no node id, so the credential has nothing to bind to.
    #[error("chain leg: the chain {chain_id} has no exit node id to bind the credential to")]
    NoExitNodeId {
        /// The chain that has no exit node id.
        chain_id: String,
    },

    /// The chain could not be dialled.
    #[error("chain leg: chain {chain_id}: {message}")]
    Dial {
        /// The chain that could not be dialled.
        chain_id: String,
        /// Why.
        message: String,
    },

    /// The credential could not be minted.
    #[error("chain leg: the credential could not be minted: {reason}")]
    Credential {
        /// Why.
        reason: String,
    },
}

/// The edge's way into its chain.
///
/// One leg per edge: the chain is the edge's own, and every customer session
/// walks it.
pub struct ChainLeg {
    /// The leg itself — the OSS crate's.
    inner: mirage_chain_leg::ChainLeg,
}

impl std::fmt::Debug for ChainLeg {
    /// Hand-written: the leg carries key material, and this must never print
    /// it.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChainLeg")
            .field("chain_id", &self.inner.chain_id())
            .field("hops", &self.inner.hop_count())
            .finish_non_exhaustive()
    }
}

impl ChainLeg {
    /// Build the edge's leg for `chain`.
    ///
    /// * `peer_table` — the table the chain is dialled through. The edge's own
    ///   control plane builds it: one row per hop, each with the hop's own
    ///   published chain face.
    /// * `mesh_id` — the chain's shared mesh id. It must be the SAME id the
    ///   hops carry, or the hop refuses the leg.
    /// * `operator_secret_hex` — the chain's operator secret seed. Only the
    ///   edge holds it: it is what signs the legs.
    /// * `slice` — the edge's own role slice: the per-dial signing key.
    pub fn build(
        chain: &ChainSpec,
        peer_table: PeerTable,
        mesh_id: &str,
        operator_secret_hex: &str,
        slice: RoleSlice,
    ) -> Result<Self, ChainLegError> {
        if chain.hops.is_empty() {
            return Err(ChainLegError::NoHop {
                chain_id: chain.chain_id.clone(),
            });
        }

        let seed = operator_seed(operator_secret_hex)?;
        let operator = SigningKey::from_bytes(&seed);
        let operator_pub_hex = hex::encode(operator.verifying_key().to_bytes());

        // The role slice signs the per-dial token; its signing key must be
        // the key the excerpt names, or the mint refuses the pair.
        let mut slice = slice;
        slice.signing_privkey = Some(seed);
        slice.signing_pubkey_hex = Some(operator_pub_hex.clone());

        let excerpt = sign_role_signed_excerpt(
            &operator,
            edge_self_id(),
            mesh_id,
            ServiceRole::Edge,
            &operator_pub_hex,
            now_ms().saturating_add(OPERATOR_KEY_TTL_MS),
        )
        .map_err(|e| ChainLegError::Credential {
            reason: e.to_string(),
        })?;

        // The exit is the LAST hop — the one the customer's bytes come out of.
        let exit = chain.hops.last().expect("the chain has at least one hop");
        let exit_node_id = crate::control_plane::node_id_for(exit, chain.hops.len() - 1);

        let spec = LegSpec {
            chain_id: chain.chain_id.clone(),
            datagram_chain_id: Some(chain.datagram_chain_id()),
            hops: chain
                .hops
                .iter()
                .enumerate()
                .map(|(index, hop)| LegHop {
                    addr: hop.addr.clone(),
                    udp_addr: hop.udp_addr.clone(),
                    public_key: hop.public_key.clone(),
                    node_id: Some(crate::control_plane::node_id_for(hop, index)),
                    role: hop.role,
                    camouflage: hop.camouflage.clone(),
                })
                .collect(),
            mesh_id: mesh_id.to_owned(),
            exit_node_id,
        };

        let inner = mirage_chain_leg::ChainLeg::new(spec, Arc::new(peer_table), slice, excerpt)
            .map_err(|e| match e {
                mirage_chain_leg::LegError::NoHop { chain_id } => ChainLegError::NoHop { chain_id },
                mirage_chain_leg::LegError::Credential { reason } => {
                    ChainLegError::Credential { reason }
                }
            })?;

        Ok(Self { inner })
    }

    /// The chain this leg walks.
    pub fn chain_id(&self) -> &str {
        self.inner.chain_id()
    }

    /// Whether this chain carries DATAGRAMS.
    ///
    /// True when every hop of the chain has a datagram door — the chain's
    /// datagram leg is then a native UDP tunnel with its own handshake, and a
    /// datagram stays a datagram the whole way down. False when any hop has
    /// none: the chain carries TCP only, and a datagram flow is refused rather
    /// than carried by the stream leg.
    pub fn carries_datagrams(&self) -> bool {
        self.inner.carries_datagrams()
    }
}

/// The edge's TCP exit — the customer's session, carried by the chain.
#[async_trait]
impl StreamOpener for ChainLeg {
    async fn open_stream(
        &self,
        exit: &ExitChoice,
        target: &str,
    ) -> Result<MeshStream, StreamOpenError> {
        self.inner.open_stream(exit, target).await
    }
}

/// The edge's DATAGRAM exit — the customer's datagrams, carried by the chain.
#[async_trait]
impl DatagramFlowOpener for ChainLeg {
    async fn open_datagram_flow(
        &self,
        exit: &ExitChoice,
        target: &str,
    ) -> Result<(DatagramSinkBox, DatagramSourceBox), DatagramFlowError> {
        self.inner.open_datagram_flow(exit, target).await
    }
}

/// The edge's datagram arm — this build carries TCP only.
///
/// The fleet's edge walks a UDP-native chain of its own for datagrams. This
/// build does not, and it says so instead of quietly sending the datagram out
/// of the WRONG box: a datagram that left from the edge instead of the exit
/// would look like it worked and would not be.
pub struct ChainLegNoDatagrams {
    chain_id: String,
}

impl ChainLegNoDatagrams {
    /// Name the chain this arm belongs to, for the refusal.
    pub fn new(chain_id: &str) -> Self {
        Self {
            chain_id: chain_id.to_owned(),
        }
    }
}

impl std::fmt::Debug for ChainLegNoDatagrams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChainLegNoDatagrams")
            .field("chain_id", &self.chain_id)
            .finish()
    }
}

#[async_trait]
impl mirage_node::client::exit_port::DatagramFlowOpener for ChainLegNoDatagrams {
    async fn open_datagram_flow(
        &self,
        _exit: &ExitChoice,
        _target: &str,
    ) -> Result<
        (
            mirage_node::client::exit_port::DatagramSinkBox,
            mirage_node::client::exit_port::DatagramSourceBox,
        ),
        mirage_node::client::exit_port::DatagramFlowError,
    > {
        Err(
            mirage_node::client::exit_port::DatagramFlowError::Dial {
                chain_id: self.chain_id.clone(),
                message: "this chain carries TCP only — the datagram path is not wired yet"
                    .to_owned(),
            },
        )
    }
}

/// The chain's operator key, as the box that holds it sees it.
pub fn operator_key_from_env(secret_hex: &str) -> Result<SigningKey, ChainLegError> {
    let seed = operator_seed(secret_hex)?;
    Ok(SigningKey::from_bytes(&seed))
}

/// Read the chain's operator seed out of its hex form.
///
/// The seed is 32 bytes of hex. A seed of another length is refused: a
/// half-written key is a key that will not sign anything, and the operator
/// has to hear about it at once rather than at the first leg.
fn operator_seed(secret_hex: &str) -> Result<[u8; 32], ChainLegError> {
    let bytes = hex::decode(secret_hex).map_err(|e| ChainLegError::BadOperatorKey {
        reason: e.to_string(),
    })?;
    if bytes.len() != 32 {
        return Err(ChainLegError::BadOperatorKey {
            reason: format!("the seed is {} bytes, an ed25519 seed is 32", bytes.len()),
        });
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&bytes);
    Ok(seed)
}

/// The chain's shared mesh id, checked.
///
/// The id is hex, and the box compares it with its own byte for byte — a
/// mistyped id is a chain that does not work, and it is refused here rather
/// than at the first leg.
pub fn checked_mesh_id(mesh_id: &str) -> Result<&str, ChainLegError> {
    let trimmed = mesh_id.trim();
    if trimmed.is_empty() {
        return Err(ChainLegError::BadMeshId {
            reason: "the mesh id is empty".to_owned(),
        });
    }
    if trimmed.len() % 2 != 0 || hex::decode(trimmed).is_err() {
        return Err(ChainLegError::BadMeshId {
            reason: "the mesh id is not hex".to_owned(),
        });
    }
    Ok(trimmed)
}

/// The peer table the leg walks, kept for the operator's log.
pub fn peer_rows(peer_table: &PeerTable) -> Vec<(String, String)> {
    peer_table
        .peers
        .iter()
        .map(|peer| (peer.node_id.to_string(), peer.addr.clone()))
        .collect()
}

/// The leg's own hop count — for the operator's log.
pub fn hop_count(leg: &ChainLeg) -> usize {
    leg.inner.hop_count()
}

/// The chain's id — for the operator's log.
pub fn leg_chain_id(leg: &ChainLeg) -> &str {
    leg.chain_id()
}

/// This box's own id as the fleet's edges carry it — one UUID per box.
///
/// It is minted once per process and never leaves it: the credential's
/// `self_id` is a name for this box, not a secret.
fn edge_self_id() -> uuid::Uuid {
    use std::sync::OnceLock;
    static SELF_ID: OnceLock<uuid::Uuid> = OnceLock::new();
    *SELF_ID.get_or_init(uuid::Uuid::new_v4)
}

/// Milliseconds since the epoch.
fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// A shared handle to the leg, for the box runtime.
pub type SharedChainLeg = Arc<ChainLeg>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::ChainHop;
    use mirage_core::config::HopRole;
    use mirage_core::config::{ProtocolId, UdpProtocolId};
    use mirage_core::mirage::mesh::ids::{MeshId, NodeId};
    use mirage_core::mirage::mesh::peer_table::{ChainFace, PeerTableEntry};
    use mirage_core::mirage::wire::TransportCamouflage;

    fn pubkey(byte: u8) -> String {
        hex::encode([byte; 32])
    }

    fn hop(addr: &str, key: u8, role: HopRole) -> ChainHop {
        ChainHop {
            addr: addr.to_owned(),
            public_key: Some(pubkey(key)),
            node_id: None,
            role,
            camouflage: Some(TransportCamouflage::TlsReal {
                sni: "a.example".to_owned(),
                alpn: vec!["h2".to_owned()],
            }),
            udp_addr: None,
        }
    }

    fn peer_table(hops: &[ChainHop]) -> PeerTable {
        PeerTable {
            generation: 1,
            peers: hops
                .iter()
                .enumerate()
                .map(|(_index, hop)| {
                    let port = hop.addr.rsplit(':').next().unwrap().parse().unwrap();
                    PeerTableEntry {
                        mesh_id: MeshId::new("m".to_owned()),
                        responsible_monitor_id: String::new(),
                        node_id: NodeId::new(format!("node-{}", &hop.public_key.clone().unwrap()[..12])),
                        pubkey_hex: hop.public_key.clone().unwrap(),
                        addr: hop.addr.clone(),
                        labels: Vec::new(),
                        updated_at_ms: 0,
                        aead_suite_preference: Vec::new(),
                        chain_face: Some(ChainFace {
                            port,
                            camouflage: hop.camouflage.clone().unwrap(),
                        }),
                        chain_face_udp: None,
                    }
                })
                .collect(),
        }
    }

    fn slice() -> RoleSlice {
        RoleSlice {
            role: ServiceRole::Edge,
            wire_privkey: [7u8; 32],
            signing_privkey: None,
            wire_pubkey_hex: pubkey(9),
            signing_pubkey_hex: None,
        }
    }

    #[test]
    fn a_one_hop_chain_builds_a_leg_that_dials_the_exit() {
        let hops = vec![hop("203.0.113.9:443", 3, HopRole::Exit)];
        let chain = ChainSpec {
            chain_id: "stand-2hop".to_owned(),
            hops: hops.clone(),
        };
        let leg = ChainLeg::build(
            &chain,
            peer_table(&hops),
            "ab".repeat(32).as_str(),
            &pubkey(5),
            slice(),
        )
        .expect("the leg builds");

        assert_eq!(leg.inner.hops().len(), 1);
        // The entry hop's camouflage is the hop's own published face, so the
        // leg does not carry one — that is what makes a one-hop chain take
        // the onion path.
        assert!(leg.inner.hops()[0].camouflage.is_none());
        assert_eq!(
            leg.inner.exit_node_id(),
            format!("node-{}", &pubkey(3)[..12])
        );
    }

    #[test]
    fn a_multi_hop_chain_keeps_the_inner_masks() {
        let hops = vec![
            hop("203.0.113.1:443", 1, HopRole::Entry),
            hop("203.0.113.2:443", 2, HopRole::Middle),
            hop("203.0.113.3:443", 3, HopRole::Exit),
        ];
        let chain = ChainSpec {
            chain_id: "stand-3hop".to_owned(),
            hops: hops.clone(),
        };
        let leg = ChainLeg::build(
            &chain,
            peer_table(&hops),
            "ab".repeat(32).as_str(),
            &pubkey(5),
            slice(),
        )
        .expect("the leg builds");

        assert_eq!(leg.inner.hops().len(), 3);
        assert!(leg.inner.hops()[0].camouflage.is_none());
        assert!(leg.inner.hops()[1].camouflage.is_some());
        assert!(leg.inner.hops()[2].camouflage.is_some());
        assert_eq!(
            leg.inner.exit_node_id(),
            format!("node-{}", &pubkey(3)[..12])
        );
    }

    #[test]
    fn a_chain_with_a_datagram_door_on_every_hop_carries_datagrams() {
        let mut hops = vec![hop("203.0.113.9:443", 3, HopRole::Exit)];
        hops[0].udp_addr = Some("203.0.113.9:51820".to_owned());
        let chain = ChainSpec {
            chain_id: "stand-2hop".to_owned(),
            hops: hops.clone(),
        };
        let leg = ChainLeg::build(
            &chain,
            peer_table(&hops),
            "ab".repeat(32).as_str(),
            &pubkey(5),
            slice(),
        )
        .expect("the leg builds");

        assert!(leg.carries_datagrams());
        // The datagram chain is a chain OF ITS OWN: it speaks UDP, and it
        // dials the hop's datagram door — not the stream door.
        let udp = leg.inner.datagram_chain().expect("the datagram chain");
        assert_eq!(udp.protocol, ProtocolId::Udp(UdpProtocolId::MirageUdp));
        assert_eq!(udp.hops[0].addr, "203.0.113.9:51820");
        assert_eq!(udp.hops.len(), 1);
    }

    #[test]
    fn the_edge_and_the_hop_name_the_same_datagram_chain() {
        // The edge dials the datagram chain by its id, and the hop answers
        // the datagram leg on the listener that id names. If the two sides
        // disagreed about that id, the datagram leg would land on a listener
        // nobody serves and the chain would carry TCP only — silently.
        let mut hops = vec![hop("203.0.113.9:443", 3, HopRole::Exit)];
        hops[0].udp_addr = Some("203.0.113.9:51820".to_owned());
        let chain = ChainSpec {
            chain_id: "stand-2hop".to_owned(),
            hops: hops.clone(),
        };
        let leg = ChainLeg::build(
            &chain,
            peer_table(&hops),
            "ab".repeat(32).as_str(),
            &pubkey(5),
            slice(),
        )
        .expect("the leg builds");

        let identity = crate::identity::ServerIdentity::mint();
        let plane = crate::control_plane::build_control_plane(
            &identity,
            &chain,
            Some(0),
            &[crate::env::Face {
                port: 443,
                id: "mirage".to_owned(),
                protocol: mirage_core::mirage::wire::Protocol::Mirage {
                    carrier: mirage_core::mirage::wire::MirageCarrier::Tcp,
                    camouflage: mirage_core::mirage::wire::MirageCamouflage::None,
                },
            }],
        )
        .expect("the plane builds");
        let datagram = plane
            .datagram_listener_spec
            .as_ref()
            .expect("the hop serves a datagram listener");

        assert_eq!(
            leg.inner
                .datagram_chain()
                .expect("the datagram chain")
                .chain_id,
            datagram
                .chain_role
                .as_ref()
                .expect("the listener names its chain")
                .chain_id,
            "the edge's datagram chain and the hop's datagram listener are the same chain"
        );
        assert_eq!(
            datagram.id.0,
            format!("{}-h0", chain.datagram_chain_id()),
            "the hop's datagram listener is addressed by the datagram chain's id"
        );
    }

    #[test]
    fn a_chain_without_a_datagram_door_carries_streams_only() {
        let hops = vec![hop("203.0.113.9:443", 3, HopRole::Exit)];
        let chain = ChainSpec {
            chain_id: "stand-2hop".to_owned(),
            hops: hops.clone(),
        };
        let leg = ChainLeg::build(
            &chain,
            peer_table(&hops),
            "ab".repeat(32).as_str(),
            &pubkey(5),
            slice(),
        )
        .expect("the leg builds");

        // No datagram door means no datagram chain — and the leg says so
        // rather than pretending the stream leg can carry datagrams.
        assert!(!leg.carries_datagrams());
        assert!(leg.inner.datagram_chain().is_none());
    }

    #[test]
    fn a_datagram_leg_cannot_skip_a_hop_without_a_door() {
        // A chain whose middle hop has no datagram door carries TCP only: a
        // datagram leg cannot skip a hop, and delivering datagrams out of the
        // wrong box would be worse than not carrying them at all.
        let mut hops = vec![
            hop("203.0.113.1:443", 1, HopRole::Entry),
            hop("203.0.113.2:443", 2, HopRole::Middle),
            hop("203.0.113.3:443", 3, HopRole::Exit),
        ];
        hops[0].udp_addr = Some("203.0.113.1:51820".to_owned());
        hops[2].udp_addr = Some("203.0.113.3:51820".to_owned());
        let chain = ChainSpec {
            chain_id: "stand-3hop".to_owned(),
            hops: hops.clone(),
        };
        let leg = ChainLeg::build(
            &chain,
            peer_table(&hops),
            "ab".repeat(32).as_str(),
            &pubkey(5),
            slice(),
        )
        .expect("the leg builds");

        assert!(!leg.carries_datagrams());
    }
}
