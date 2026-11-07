//! The box's **local control plane** — the three objects the monitor used to push.
//!
//! A node in the fleet learns what it is supposed to do from the monitor: the
//! listener specs it must serve, the peer table it must dial through, and the
//! chain bindings that name the hops of each circuit. A standalone box has no
//! monitor and no capsule. It owns its identity locally, and it builds the
//! very same three objects itself, from its own chain configuration and its
//! own keys.
//!
//! Nothing here is a private dialect: every type is the wire type the rest of
//! the fleet already speaks, and the node's own registry checks them exactly
//! as it checks a monitor's — the listener spec's fingerprint is recomputed
//! here, and the node recomputes it again on activation and refuses a
//! mismatch.
//!
//! # What is built
//!
//! | object | what it says |
//! |---|---|
//! | [`StaticControlPlane::listener_spec`] | which listener this box serves, in which role, at which position of the chain |
//! | [`StaticControlPlane::peer_table`] | one row per hop — the next hop's node id, key, address and chain face |
//! | [`StaticControlPlane::chain_bindings`] | the chain's legs and its exit, as the relay hops must see it |
//!
//! # Roles
//!
//! The chain file speaks the CLIENT's roles (`Entry`, `Middle`, `Exit` —
//! `mirage_core::config::HopRole`). The node's own listener spec speaks the
//! NODE's roles (`mirage_core::mirage::wire::ListenerRole`): a relay leg is
//! either the first reachable node (`EntryHop::Entry`) or an intermediate hop
//! (`EntryHop::Hop`), and the chain's last hop is the exit
//! (`ListenerRole::Exit`).
//!
//! The mapping is one-to-one, and a one-hop chain is always an exit — that is
//! the rule [`ChainSpec::validate`] enforces, and this module keeps it.

use std::time::{SystemTime, UNIX_EPOCH};

use mirage_core::config::{HandshakeStrategy, HopRole};
use mirage_core::crypto::credential::{CredentialParams, EpochEntry};
use mirage_core::mirage::mesh::chain_binding::OnionReplyMode;
use mirage_core::mirage::mesh::ids::{ChainId, MeshId, NodeId};
use mirage_core::mirage::mesh::peer_table::{ChainFace, PeerTable, PeerTableEntry};
use mirage_core::mirage::mesh::{ChainBinding, ChainBindings, ChainExit, ChainLeg};
use mirage_core::mirage::wire::{
    AeadSuite, ChainRole, CredentialScheme, EntryHop, ExitMode, Framing, LayerSpec, ListenerId,
    ListenerRole, MirageListenerKind, MirageListenerSpec, RelayMode, SpecFingerprint,
    TransportCamouflage,
};

use crate::chain::{ChainHop, ChainSpec};
use crate::env::Face;
use crate::identity::ServerIdentity;
use crate::subscriber::SUBSCRIPTION_TTL_MS;

/// The generation this box's own credential parameters carry.
///
/// A standalone box has exactly one issuer — itself — so the generation never
/// rolls. It is here because the wire type carries one and the node compares
/// generations when gossip replaces parameters.
const LOCAL_CREDENTIAL_GENERATION: u64 = 1;

/// The epoch id this box's own credential parameters carry.
const LOCAL_CREDENTIAL_EPOCH_ID: u32 = 0;

/// Why a local control plane could not be built.
#[derive(Debug, thiserror::Error)]
pub enum ControlPlaneError {
    /// The chain has no hop at the index the caller named as this box's own.
    #[error("control plane: the chain has no hop at index {index}")]
    NoSuchHop {
        /// The index that was asked for.
        index: usize,
    },

    /// The chain is empty — there is nothing to serve.
    #[error("control plane: the chain is empty")]
    EmptyChain,

    /// The box publishes no face, so there is nothing for a listener to wear.
    #[error("control plane: the box publishes no face")]
    NoFace,

    /// A hop the box would have to dial has no port in its address.
    #[error("control plane: the hop at index {index} has no port in its address")]
    HopWithoutPort {
        /// The index of the offending hop.
        index: usize,
    },

    /// The credential parameters this box built do not verify against the
    /// box's own operator key — a build bug, refused rather than served.
    #[error("control plane: the credential parameters do not verify ({reason})")]
    CredentialVerification {
        /// Why the verification failed.
        reason: String,
    },

    /// This box's own face is not a mask the chain listener can wear.
    #[error("control plane: the face on port {port} is not a mask ({reason})")]
    FaceProtocol {
        /// The door's port.
        port: u16,
        /// Why the link refused to become a mask.
        reason: String,
    },
}

fn face_mask(face: &Face) -> Result<mirage_core::mirage::wire::TransportCamouflage, ControlPlaneError> {
    face.protocol
        .to_mask(face.port)
        .map_err(|reason| ControlPlaneError::FaceProtocol {
            port: face.port,
            reason,
        })
}

/// The three objects a standalone box serves instead of the ones a monitor
/// pushes.
///
/// The **edge** — the box the customer knocks on — serves only the peer table:
/// it owns the chain and dials it, so it needs to know the hops, and it
/// serves no listener of its own, because it is not a hop of its own chain.
/// A **hop** — a box that relays — serves all three: the listener the chain
/// knocks on, the peer table it dials through, and the chain's bindings.
#[derive(Debug, Clone)]
pub struct StaticControlPlane {
    /// The listener this box serves, when it is a hop of the chain.
    ///
    /// `None` for the edge: the edge has no chain listener, and a box that
    /// is not a hop has nothing to answer for.
    pub listener_spec: Option<MirageListenerSpec>,
    /// The DATAGRAM listener this box serves, when it is a hop of the chain
    /// AND the chain carries datagrams.
    ///
    /// The datagram twin of [`Self::listener_spec`]: the same hop, the same
    /// chain, the same position, wearing the datagram transport. The node's
    /// registry addresses a listener by the chain id and the position and
    /// filters by transport — a datagram session resolves only a `TunnelUdp`
    /// listener — so the datagram door needs a listener of its own.
    ///
    /// `None` for the edge (it serves no chain listener at all) and for a hop
    /// whose chain carries no datagrams.
    pub datagram_listener_spec: Option<MirageListenerSpec>,
    /// One row per hop of the chain.
    pub peer_table: PeerTable,
    /// The chain binding — the legs and the exit.
    ///
    /// Empty for the edge: the edge does not relay, it dials.
    pub chain_bindings: ChainBindings,
}

/// Build the box's control plane from its chain and its identity.
///
/// `local_index` is this box's own place in `chain` — the hop whose listener
/// the returned spec describes. `None` means the box is the chain's **edge**:
/// it owns the chain and dials it, and it serves no chain listener.
///
/// `faces` are the faces this box publishes; the first one is the face the
/// box's own listener wears.
pub fn build_control_plane(
    identity: &ServerIdentity,
    chain: &ChainSpec,
    local_index: Option<usize>,
    faces: &[Face],
) -> Result<StaticControlPlane, ControlPlaneError> {
    if chain.hops.is_empty() {
        return Err(ControlPlaneError::EmptyChain);
    }
    // A hop serves the chain on a Mirage TCP face. An edge or a solo box may
    // publish only protocol doors, and those are not chain faces.
    if local_index.is_some() && faces.is_empty() {
        return Err(ControlPlaneError::NoFace);
    }

    let node_ids = node_ids(chain);
    let peer_table = build_peer_table(identity, chain, &node_ids, local_index, faces)?;

    // The edge owns the chain and dials it; it serves no listener and carries
    // no bindings. Only a hop relays, and only a hop answers.
    let Some(local_index) = local_index else {
        return Ok(StaticControlPlane {
            listener_spec: None,
            datagram_listener_spec: None,
            peer_table,
            chain_bindings: ChainBindings {
                generation: 1,
                bindings: Vec::new(),
            },
        });
    };

    let local = chain
        .hops
        .get(local_index)
        .ok_or(ControlPlaneError::NoSuchHop {
            index: local_index,
        })?;
    let chain_bindings = build_chain_bindings(identity, chain, &node_ids);
    let listener_spec = build_listener_spec(identity, chain, &node_ids, local_index, faces)?;

    // The datagram twin of that listener — built only when this hop has a
    // datagram door of its own. A hop that answers datagrams on one door and
    // not the other would carry a chain whose two planes disagree about how
    // long it is, which is a chain that delivers datagrams out of the wrong
    // box.
    let datagram_listener_spec = match local.udp_addr.as_ref() {
        Some(_) => Some(build_datagram_listener_spec(
            identity,
            chain,
            &node_ids,
            local_index,
        )?),
        None => None,
    };

    debug_assert_eq!(
        listener_spec.role,
        listener_role(local.role),
        "the listener's role must be the local hop's role"
    );

    Ok(StaticControlPlane {
        listener_spec: Some(listener_spec),
        datagram_listener_spec,
        peer_table,
        chain_bindings,
    })
}

/// Build the credential parameters this box serves, signed by its own operator
/// key.
///
/// The parameters are the fail-closed half of the data plane: a node without
/// them rejects every dial, so a box that serves traffic must have them.
///
/// The scheme is [`CredentialScheme::RoleSigned`] — the holder of the
/// credential is the authority that vouches for it, which is exactly the
/// standalone case: this box's operator key signs the box's own identity
/// excerpt, and the node's credential gate verifies it against the pinned
/// operator key. The gate does not consult the epoch below, so the epoch
/// carries no key material — it only records the subscription's end.
pub fn build_credential_params(
    identity: &ServerIdentity,
    now_ms: u64,
) -> Result<CredentialParams, ControlPlaneError> {
    let not_after_ms = now_ms.saturating_add(SUBSCRIPTION_TTL_MS);
    let mut params = CredentialParams::single(
        LOCAL_CREDENTIAL_GENERATION,
        CredentialScheme::RoleSigned,
        vec![EpochEntry::with_secret(
            LOCAL_CREDENTIAL_EPOCH_ID,
            not_after_ms,
            [0u8; 32],
        )],
    );
    params.sign(&identity.operator_signing_key());
    params
        .verify(&identity.operator_signing_key().verifying_key())
        .map_err(|e| ControlPlaneError::CredentialVerification {
            reason: e.to_string(),
        })?;
    Ok(params)
}

/// The node's own role for a chain hop.
///
/// The chain file speaks the client's roles; the node's listener spec speaks
/// the node's.
fn listener_role(role: HopRole) -> ListenerRole {
    match role {
        HopRole::Entry => ListenerRole::Relay {
            position: EntryHop::Entry,
            relay_mode: RelayMode::OnionPeel,
        },
        HopRole::Middle => ListenerRole::Relay {
            position: EntryHop::Hop,
            relay_mode: RelayMode::OnionPeel,
        },
        HopRole::Exit => ListenerRole::Exit {
            exit_mode: ExitMode::Onion,
        },
    }
}

/// The node id of every hop, in chain order.
///
/// A hop that names its own node id keeps it; otherwise the id is derived from
/// the hop's public key, so that every box in the chain derives the SAME id
/// for the same hop without having to be told it.
fn node_ids(chain: &ChainSpec) -> Vec<String> {
    chain
        .hops
        .iter()
        .enumerate()
        .map(|(index, hop)| node_id_for(hop, index))
        .collect()
}

/// The node id of one hop.
///
/// The edge and the hop derive it the SAME way — from the hop's public key —
/// because the edge binds its credential to the exit's node id, and the exit
/// checks that binding against its own id.
pub fn node_id_for(hop: &ChainHop, index: usize) -> String {
    if let Some(node_id) = hop.node_id.as_ref() {
        return node_id.clone();
    }
    match hop.public_key.as_ref() {
        Some(key) if key.len() >= 12 => format!("node-{}", &key[..12]),
        _ => format!("hop-{index}"),
    }
}

/// The peer table this box serves — one row per hop.
///
/// The row that matters is the next hop's: the relay leg reads the next
/// hop's node id out of the chain binding and then reads its key, address and
/// chain face out of this table.
fn build_peer_table(
    identity: &ServerIdentity,
    chain: &ChainSpec,
    node_ids: &[String],
    local_index: Option<usize>,
    faces: &[Face],
) -> Result<PeerTable, ControlPlaneError> {
    let mesh_id = MeshId::new(identity.mesh_id().to_owned());
    let mut peers = Vec::with_capacity(chain.hops.len());
    for (index, hop) in chain.hops.iter().enumerate() {
        let face = chain_face(hop, index, local_index, faces)?;
        peers.push(PeerTableEntry {
            mesh_id: mesh_id.clone(),
            responsible_monitor_id: String::new(),
            node_id: NodeId::new(node_ids[index].clone()),
            pubkey_hex: hop.public_key.clone().unwrap_or_default(),
            addr: hop.addr.clone(),
            labels: Vec::new(),
            updated_at_ms: now_ms(),
            aead_suite_preference: Vec::new(),
            chain_face: Some(face),
            chain_face_udp: None,
        });
    }
    Ok(PeerTable {
        generation: 1,
        peers,
    })
}

/// The chain face of one hop.
///
/// The box's own face is the one it publishes. A remote hop's face is what
/// the chain says about it — its own mask and the port in its address — never
/// this box's face worn on another box's behalf.
fn chain_face(
    hop: &ChainHop,
    index: usize,
    local_index: Option<usize>,
    faces: &[Face],
) -> Result<ChainFace, ControlPlaneError> {
    if local_index == Some(index) {
        let face = &faces[0];
        return Ok(ChainFace {
            port: face.port,
            camouflage: face_mask(face)?,
        });
    }
    let port = port_of(&hop.addr).ok_or(ControlPlaneError::HopWithoutPort { index })?;
    let camouflage = hop
        .camouflage
        .clone()
        .unwrap_or(TransportCamouflage::None);
    Ok(ChainFace { port, camouflage })
}

/// The port in a `host:port` address.
fn port_of(addr: &str) -> Option<u16> {
    let (_, port) = addr.rsplit_once(':')?;
    port.parse().ok()
}

/// The chain binding this box serves — the legs and the exit.
///
/// The last hop is the exit; every hop before it is a relay leg. A one-hop
/// chain has no legs at all, which is what
/// [`ChainBinding::is_direct`] means.
fn build_chain_bindings(
    identity: &ServerIdentity,
    chain: &ChainSpec,
    node_ids: &[String],
) -> ChainBindings {
    let last = chain.hops.len() - 1;
    let legs: Vec<ChainLeg> = chain
        .hops
        .iter()
        .take(last)
        .enumerate()
        .map(|(index, _)| ChainLeg {
            node_id: NodeId::new(node_ids[index].clone()),
            relay_mode: RelayMode::OnionPeel,
            aead_suite: AeadSuite::ChaCha20Poly1305,
            byte_cipher: None,
            selector_token_hex: None,
        })
        .collect();
    let exit = ChainExit {
        node_id: NodeId::new(node_ids[last].clone()),
        exit_mode: ExitMode::Onion,
        aead_suite: AeadSuite::ChaCha20Poly1305,
        selector_token_hex: None,
    };
    ChainBindings {
        generation: 1,
        bindings: vec![ChainBinding {
            mesh_id: MeshId::new(identity.mesh_id().to_owned()),
            chain_id: ChainId::new(chain.chain_id.clone()),
            legs,
            exit,
            onion_reply_mode: Some(OnionReplyMode::Onion),
            handshake: Some(HandshakeStrategy::Telescopic),
        }],
    }
}

/// The listener spec this box serves, with its fingerprint recomputed.
///
/// The fingerprint is over every other field of the spec, so it has to be
/// recomputed here — a spec that carries a stale or zero fingerprint is
/// refused by the node's registry on activation.
fn build_listener_spec(
    identity: &ServerIdentity,
    chain: &ChainSpec,
    node_ids: &[String],
    local_index: usize,
    faces: &[Face],
) -> Result<MirageListenerSpec, ControlPlaneError> {
    let local = chain
        .hops
        .get(local_index)
        .ok_or(ControlPlaneError::NoSuchHop { index: local_index })?;
    let length = chain.hops.len();
    let position = local_index as u8;

    let outgoing_layer = if local_index + 1 < length {
        chain
            .hops
            .get(local_index + 1)
            .and_then(|hop| hop.camouflage.clone())
            .map(|camouflage| LayerSpec {
                camouflage: Some(camouflage),
                byte_cipher: None,
                auth: None,
                relay_mode: Some(RelayMode::OnionPeel),
            })
    } else {
        None
    };

    let mut spec = MirageListenerSpec {
        // The listener's name IS its address: a hop that gets a leg from the
        // one before it resolves it by this name, and the name has to be the
        // same on both sides. The fleet's own shape is `{chain_id}-h{position}`
        // (see `mirage2monitor/crates/monitor/src/chains_build.rs`), and the
        // fallback resolution of a frame without a selector token derives
        // exactly that name — so a box that named itself anything else would
        // be a hop nobody could reach.
        id: ListenerId(format!("{}-h{position}", chain.chain_id)),
        mesh_id: identity.mesh_id().to_owned(),
        kind: MirageListenerKind::TunnelTcp,
        role: listener_role(local.role),
        framing: Framing::Onion,
        ingress_layer: Some(LayerSpec {
            camouflage: Some(face_mask(&faces[0])?),
            byte_cipher: None,
            auth: None,
            relay_mode: Some(RelayMode::OnionPeel),
        }),
        outgoing_layer,
        aead_suite: AeadSuite::ChaCha20Poly1305,
        bind_port: Some(faces[0].port),
        chain_role: Some(ChainRole {
            chain_id: chain.chain_id.clone(),
            chain_position: position,
            chain_length: length as u8,
            chain_node_ids: node_ids.to_vec(),
            next_hop_addr: chain.hops.get(local_index + 1).map(|hop| hop.addr.clone()),
            selector_token_hex: None,
        }),
        control_target: None,
        payload: None,
        fingerprint: SpecFingerprint::ZERO,
    };
    spec.fingerprint = spec.compute_fingerprint();
    Ok(spec)
}

/// The DATAGRAM listener this box serves — the datagram twin of
/// [`build_listener_spec`].
///
/// A hop that has a datagram door answers the chain's datagram leg on it, and
/// the node's datagram plane finds that door through the registry: a datagram
/// session resolves a listener by the chain id and the position, and it
/// filters by transport, so only a `TunnelUdp` listener can answer a
/// datagram. The stream listener above cannot answer one, and this one cannot
/// answer a stream — that separation is the point.
///
/// # Its id is the datagram chain's id
///
/// The listener's name IS its address, and the address a frame falls back to
/// is `{chain_id}-h{position}`. The datagram chain has its own id
/// ([`ChainSpec::datagram_chain_id`]), so this listener is addressed as
/// `{chain_id}-dgram-h{position}` and the stream listener keeps
/// `{chain_id}-h{position}`. One registry, two addresses, no collision.
///
/// # Its role is the hop's role in the datagram plane's terms
///
/// The chain's exit is a DIRECT datagram exit: the destination travels as the
/// session's first whole datagram, in the open inside the encrypted session,
/// and there is no onion envelope left for the exit to peel. Every hop before
/// it is a RELAY that peels one layer and forwards the datagram onward.
fn build_datagram_listener_spec(
    identity: &ServerIdentity,
    chain: &ChainSpec,
    node_ids: &[String],
    local_index: usize,
) -> Result<MirageListenerSpec, ControlPlaneError> {
    let local = chain
        .hops
        .get(local_index)
        .ok_or(ControlPlaneError::NoSuchHop {
            index: local_index,
        })?;
    let length = chain.hops.len();
    let position = local_index as u8;

    let role = match local.role {
        HopRole::Entry => ListenerRole::Relay {
            position: EntryHop::Entry,
            relay_mode: RelayMode::OnionPeel,
        },
        HopRole::Middle => ListenerRole::Relay {
            position: EntryHop::Hop,
            relay_mode: RelayMode::OnionPeel,
        },
        HopRole::Exit => ListenerRole::Exit {
            exit_mode: ExitMode::Direct,
        },
    };

    // The datagram door wears raw UDP: the disguise of a datagram face is the
    // PORT's own business, and the perimeter binds it.
    let ingress_layer = LayerSpec {
        camouflage: Some(TransportCamouflage::RawUdp {
            bind_addr: "0.0.0.0:0".parse().expect("a literal address parses"),
        }),
        byte_cipher: None,
        auth: None,
        relay_mode: Some(RelayMode::OnionPeel),
    };

    // The outgoing layer is the NEXT HOP's datagram door — the same hop, on
    // its datagram address.
    let next_hop_door = chain
        .hops
        .get(local_index + 1)
        .and_then(|hop| hop.udp_addr.clone());
    let outgoing_layer = next_hop_door.as_ref().map(|_| LayerSpec {
        camouflage: Some(TransportCamouflage::RawUdp {
            bind_addr: "0.0.0.0:0".parse().expect("a literal address parses"),
        }),
        byte_cipher: None,
        auth: None,
        relay_mode: Some(RelayMode::OnionPeel),
    });

    let mut spec = MirageListenerSpec {
        id: ListenerId(format!("{}-h{position}", chain.datagram_chain_id())),
        mesh_id: identity.mesh_id().to_owned(),
        kind: MirageListenerKind::TunnelUdp,
        role,
        framing: Framing::Onion,
        ingress_layer: Some(ingress_layer),
        outgoing_layer,
        aead_suite: AeadSuite::ChaCha20Poly1305,
        // A chain hop binds nothing of its own: the perimeter holds the door.
        bind_port: None,
        chain_role: Some(ChainRole {
            chain_id: chain.datagram_chain_id(),
            chain_position: position,
            chain_length: length as u8,
            chain_node_ids: node_ids.to_vec(),
            next_hop_addr: chain
                .hops
                .get(local_index + 1)
                .and_then(|hop| hop.udp_addr.clone()),
            selector_token_hex: None,
        }),
        control_target: None,
        payload: None,
        fingerprint: SpecFingerprint::ZERO,
    };
    spec.fingerprint = spec.compute_fingerprint();
    Ok(spec)
}

/// Milliseconds since the epoch.
fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use mirage_core::mirage::wire::{MirageCamouflage, MirageCarrier, Protocol, TransportCamouflage};

    /// A 64-hex-character key, distinct per hop.
    fn key(seed: u8) -> String {
        format!("{seed:02x}").repeat(32)
    }

    /// The face a box publishes.
    fn face(port: u16) -> Face {
        Face {
            port,
            id: "mirage".to_owned(),
            protocol: Protocol::Mirage {
                carrier: MirageCarrier::Tcp,
                camouflage: MirageCamouflage::None,
            },
        }
    }

    /// One hop of a chain.
    fn hop(addr: &str, role: HopRole, public_key: String) -> ChainHop {
        ChainHop {
            addr: addr.to_owned(),
            public_key: Some(public_key),
            node_id: None,
            role,
            camouflage: Some(TransportCamouflage::None),
            udp_addr: None,
        }
    }

    /// One hop of a chain that also answers datagrams.
    fn hop_with_udp(addr: &str, udp_addr: &str, role: HopRole, public_key: String) -> ChainHop {
        ChainHop {
            udp_addr: Some(udp_addr.to_owned()),
            ..hop(addr, role, public_key)
        }
    }

    /// A chain that satisfies the chain rules.
    fn chain(hops: Vec<ChainHop>) -> ChainSpec {
        let spec = ChainSpec {
            chain_id: "test-chain".to_owned(),
            hops,
        };
        spec.validate().expect("the test chain satisfies the chain rules");
        spec
    }

    #[test]
    fn a_one_hop_chain_makes_the_box_the_exit() {
        let identity = ServerIdentity::mint();
        let chain = chain(vec![hop(
            "10.0.0.1:443",
            HopRole::Exit,
            identity.node_wire_pubkey_hex(),
        )]);

        let plane = build_control_plane(&identity, &chain, Some(0), &[face(443)]).expect("the plane builds");

        assert_eq!(
            plane.listener_spec.as_ref().expect("the listener").role,
            ListenerRole::Exit {
                exit_mode: ExitMode::Onion
            },
            "a one-hop chain has no relay leg — the box IS the exit"
        );
        assert_eq!(plane.peer_table.peers.len(), 1);
        let binding = plane
            .chain_bindings
            .bindings
            .first()
            .expect("the binding is there");
        assert!(binding.is_direct(), "a one-hop chain has no legs");
        assert_eq!(binding.legs.len(), 0);
    }

    #[test]
    fn a_two_hop_chain_makes_the_box_the_entry() {        let identity = ServerIdentity::mint();
        let chain = chain(vec![
            hop("10.0.0.1:443", HopRole::Entry, identity.node_wire_pubkey_hex()),
            hop("10.0.0.2:443", HopRole::Exit, key(0x02)),
        ]);

        let plane = build_control_plane(&identity, &chain, Some(0), &[face(443)]).expect("the plane builds");

        assert_eq!(
            plane.listener_spec.as_ref().expect("the listener").role,
            ListenerRole::Relay {
                position: EntryHop::Entry,
                relay_mode: RelayMode::OnionPeel,
            },
            "the first hop of a multi-hop chain is the entry"
        );
        let binding = plane
            .chain_bindings
            .bindings
            .first()
            .expect("the binding is there");
        assert_eq!(binding.legs.len(), 1, "one relay leg before the exit");
        assert!(!binding.is_direct());
        assert_eq!(binding.exit.node_id.as_str(), "node-020202020202");
    }

    #[test]
    fn a_three_hop_chain_makes_the_box_the_entry_with_two_legs() {
        let identity = ServerIdentity::mint();
        let chain = chain(vec![
            hop("10.0.0.1:443", HopRole::Entry, identity.node_wire_pubkey_hex()),
            hop("10.0.0.2:443", HopRole::Middle, key(0x02)),
            hop("10.0.0.3:443", HopRole::Exit, key(0x03)),
        ]);

        let plane = build_control_plane(&identity, &chain, Some(0), &[face(443)]).expect("the plane builds");

        assert_eq!(
            plane.listener_spec.as_ref().expect("the listener").role,
            ListenerRole::Relay {
                position: EntryHop::Entry,
                relay_mode: RelayMode::OnionPeel,
            }
        );
        let binding = plane
            .chain_bindings
            .bindings
            .first()
            .expect("the binding is there");
        assert_eq!(binding.legs.len(), 2, "two relay legs before the exit");
        assert_eq!(binding.exit.node_id.as_str(), "node-030303030303");
        assert_eq!(plane.peer_table.peers.len(), 3);
    }

    #[test]
    fn the_middle_hop_of_a_chain_is_a_hop_and_not_an_entry() {
        let identity = ServerIdentity::mint();
        let chain = chain(vec![
            hop("10.0.0.1:443", HopRole::Entry, key(0x01)),
            hop("10.0.0.2:443", HopRole::Middle, identity.node_wire_pubkey_hex()),
            hop("10.0.0.3:443", HopRole::Exit, key(0x03)),
        ]);

        let plane = build_control_plane(&identity, &chain, Some(1), &[face(443)]).expect("the plane builds");

        assert_eq!(
            plane.listener_spec.as_ref().expect("the listener").role,
            ListenerRole::Relay {
                position: EntryHop::Hop,
                relay_mode: RelayMode::OnionPeel,
            },
            "a middle hop is a hop — the entry position belongs to the first hop"
        );
    }

    #[test]
    fn the_specs_position_is_the_local_hops_own() {
        let identity = ServerIdentity::mint();
        let chain = chain(vec![
            hop("10.0.0.1:443", HopRole::Entry, key(0x01)),
            hop("10.0.0.2:443", HopRole::Middle, identity.node_wire_pubkey_hex()),
            hop("10.0.0.3:443", HopRole::Exit, key(0x03)),
        ]);

        let plane = build_control_plane(&identity, &chain, Some(1), &[face(443)]).expect("the plane builds");
        let role = plane
            .listener_spec
            .as_ref()
            .expect("the listener")
            .chain_role
            .as_ref()
            .expect("the spec carries its chain role");

        assert_eq!(
            role.chain_position, 1,
            "the position is where THIS box sits, not where the exit sits"
        );
        assert_eq!(role.chain_length, 3);
        assert_eq!(role.chain_node_ids.len(), 3);
        assert_eq!(
            role.next_hop_addr.as_deref(),
            Some("10.0.0.3:443"),
            "the next hop is the one after this box"
        );
    }

    #[test]
    fn the_fingerprint_is_computed_over_the_spec() {
        let identity = ServerIdentity::mint();
        let chain = chain(vec![
            hop("10.0.0.1:443", HopRole::Entry, identity.node_wire_pubkey_hex()),
            hop("10.0.0.2:443", HopRole::Exit, key(0x02)),
        ]);

        let plane = build_control_plane(&identity, &chain, Some(0), &[face(443)]).expect("the plane builds");
        let spec = plane.listener_spec.as_ref().expect("the listener");

        assert_eq!(
            spec.fingerprint,
            spec.compute_fingerprint(),
            "the fingerprint is over every other field of the spec"
        );
        assert_ne!(
            spec.fingerprint,
            SpecFingerprint::ZERO,
            "a zero fingerprint is what the node refuses"
        );
    }

    #[test]
    fn the_peer_table_carries_every_hop() {
        let identity = ServerIdentity::mint();
        let chain = chain(vec![
            hop("10.0.0.1:443", HopRole::Entry, identity.node_wire_pubkey_hex()),
            hop("10.0.0.2:8443", HopRole::Exit, key(0x02)),
        ]);

        let plane = build_control_plane(&identity, &chain, Some(0), &[face(443)]).expect("the plane builds");
        let peers = &plane.peer_table.peers;

        assert_eq!(peers.len(), 2);
        assert_eq!(peers[0].addr, "10.0.0.1:443");
        assert_eq!(
            peers[0].node_id.as_str(),
            format!("node-{}", &identity.node_wire_pubkey_hex()[..12]),
            "the node id of a hop is derived from that hop's own key"
        );
        assert_eq!(
            peers[0].chain_face.as_ref().map(|face| face.port),
            Some(443),
            "the box's own face is the face it published"
        );
        assert_eq!(peers[1].addr, "10.0.0.2:8443");
        assert_eq!(peers[1].pubkey_hex, key(0x02));
        assert_eq!(
            peers[1].chain_face.as_ref().map(|face| face.port),
            Some(8443),
            "a remote hop wears its OWN face, not the box's"
        );
    }

    #[test]
    fn a_next_hop_without_a_port_is_refused() {
        let identity = ServerIdentity::mint();
        let chain = ChainSpec {
            chain_id: "test-chain".to_owned(),
            hops: vec![
                hop("10.0.0.1:443", HopRole::Entry, identity.node_wire_pubkey_hex()),
                hop("10.0.0.2", HopRole::Exit, key(0x02)),
            ],
        };

        let error = build_control_plane(&identity, &chain, Some(0), &[face(443)])
            .expect_err("a next hop with no port cannot be dialled");
        assert!(
            matches!(error, ControlPlaneError::HopWithoutPort { index: 1 }),
            "the refusal names the hop: {error}"
        );
    }

    #[test]
    fn a_chain_with_no_hop_at_the_local_index_is_refused() {
        let identity = ServerIdentity::mint();
        let chain = chain(vec![hop(
            "10.0.0.1:443",
            HopRole::Exit,
            identity.node_wire_pubkey_hex(),
        )]);

        let error = build_control_plane(&identity, &chain, Some(3), &[face(443)])
            .expect_err("there is no hop at that index");
        assert!(
            matches!(error, ControlPlaneError::NoSuchHop { index: 3 }),
            "the refusal names the index: {error}"
        );
    }

    #[test]
    fn the_credential_parameters_verify_against_the_box_own_operator_key() {
        let identity = ServerIdentity::mint();

        let params = build_credential_params(&identity, 1_000).expect("the parameters build");

        assert_eq!(
            params.primary_scheme(),
            CredentialScheme::RoleSigned,
            "the holder of the credential is the authority that vouches for it"
        );
        params
            .verify(&identity.operator_signing_key().verifying_key())
            .expect("the parameters verify against the box's own operator key");
    }

    #[test]
    fn the_credential_parameters_do_not_verify_against_another_key() {
        let identity = ServerIdentity::mint();
        let other = ServerIdentity::mint();

        let params = build_credential_params(&identity, 1_000).expect("the parameters build");

        assert!(
            params
                .verify(&other.operator_signing_key().verifying_key())
                .is_err(),
            "another box's operator key must not vouch for these parameters"
        );
    }

    #[test]
    fn a_hop_with_a_datagram_door_serves_a_datagram_listener_of_its_own() {
        let identity = ServerIdentity::mint();
        let chain = chain(vec![hop_with_udp(
            "10.0.0.1:443",
            "10.0.0.1:51820",
            HopRole::Exit,
            identity.node_wire_pubkey_hex(),
        )]);

        let plane =
            build_control_plane(&identity, &chain, Some(0), &[face(443)]).expect("the plane builds");

        let datagram = plane
            .datagram_listener_spec
            .as_ref()
            .expect("a hop with a datagram door serves a datagram listener");

        assert_eq!(
            datagram.kind,
            MirageListenerKind::TunnelUdp,
            "the datagram plane resolves a TunnelUdp listener and nothing else"
        );
        assert_eq!(
            datagram.role,
            ListenerRole::Exit {
                exit_mode: ExitMode::Direct
            },
            "the datagram exit reads its destination off the first whole datagram — \
             there is no onion envelope left to peel"
        );
        assert_eq!(
            datagram.chain_role.as_ref().map(|role| role.chain_id.as_str()),
            Some("test-chain-dgram"),
            "the datagram chain is a chain of its own, with its own id"
        );
        assert_eq!(
            datagram.id.0,
            "test-chain-dgram-h0",
            "the listener's name IS its address"
        );
        assert_eq!(
            datagram.fingerprint,
            datagram.compute_fingerprint(),
            "the fingerprint is over every other field of the spec"
        );
    }

    #[test]
    fn the_two_planes_of_one_chain_hold_two_addresses() {
        let identity = ServerIdentity::mint();
        let chain = chain(vec![hop_with_udp(
            "10.0.0.1:443",
            "10.0.0.1:51820",
            HopRole::Exit,
            identity.node_wire_pubkey_hex(),
        )]);

        let plane =
            build_control_plane(&identity, &chain, Some(0), &[face(443)]).expect("the plane builds");

        let stream = plane.listener_spec.as_ref().expect("the stream listener");
        let datagram = plane
            .datagram_listener_spec
            .as_ref()
            .expect("the datagram listener");

        assert_eq!(stream.id.0, "test-chain-h0");
        assert_eq!(datagram.id.0, "test-chain-dgram-h0");
        assert_ne!(
            stream.id.0, datagram.id.0,
            "one registry holds one address per listener — the two planes of one hop \
             must not want the same one"
        );
    }

    #[test]
    fn a_hop_without_a_datagram_door_serves_no_datagram_listener() {
        let identity = ServerIdentity::mint();
        let chain = chain(vec![hop(
            "10.0.0.1:443",
            HopRole::Exit,
            identity.node_wire_pubkey_hex(),
        )]);

        let plane =
            build_control_plane(&identity, &chain, Some(0), &[face(443)]).expect("the plane builds");

        assert!(
            plane.datagram_listener_spec.is_none(),
            "a hop with no datagram door has nothing for a datagram session to land on"
        );
    }

    #[test]
    fn a_relay_hop_relays_datagrams_instead_of_exiting_them() {
        let identity = ServerIdentity::mint();
        let chain = chain(vec![
            hop_with_udp(
                "10.0.0.1:443",
                "10.0.0.1:51820",
                HopRole::Entry,
                identity.node_wire_pubkey_hex(),
            ),
            hop_with_udp("10.0.0.2:443", "10.0.0.2:51820", HopRole::Exit, key(0x02)),
        ]);

        let plane =
            build_control_plane(&identity, &chain, Some(0), &[face(443)]).expect("the plane builds");

        let datagram = plane
            .datagram_listener_spec
            .as_ref()
            .expect("the datagram listener");
        assert_eq!(
            datagram.role,
            ListenerRole::Relay {
                position: EntryHop::Entry,
                relay_mode: RelayMode::OnionPeel,
            },
            "a hop that is not the chain's exit must relay the datagram onward"
        );
        assert_eq!(
            datagram
                .chain_role
                .as_ref()
                .and_then(|role| role.next_hop_addr.clone()),
            Some("10.0.0.2:51820".to_owned()),
            "the next hop is reached on ITS datagram door"
        );
    }
}
