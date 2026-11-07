//! The box, running: the perimeter in front, the client entrance inside, the
//! box's own exit behind it.
//!
//! # The shape of a standalone box
//!
//! ```text
//!   customer ──▶ face (port 443, TLS camouflage)
//!                     │
//!               ┌─────▼──────────────────────────────┐
//!               │  perimeter                          │  strips the camouflage,
//!               │  (mirage-perimeter)                 │  classifies the bytes
//!               └─────┬──────────────────────────────┘
//!                     │  box-local channel (unix socket)
//!               ┌─────▼──────────────────────────────┐
//!               │  client entrance (mirage-node)     │  admits the subscriber,
//!               │  V9 handshake + edge-session wire  │  muxes the session
//!               └─────┬──────────────────────────────┘
//!                     │
//!               ┌─────▼──────────────────────────────┐
//!               │  the box's own exit                 │  a plain socket to the
//!               │  (crate::exit_port::LocalExit)      │  target, policy-checked
//!               └────────────────────────────────────┘
//! ```
//!
//! There is no edge unit and no monitor: the perimeter and the node are one
//! process, and the box's exit is the box itself. The chain splice — the
//! node's own socket for MESH peers — is still served, because a box that
//! stands in a chain of boxes has to accept the hop before it.
//!
//! # What is NOT here
//!
//! * No monitor, no operator API, no capsule: the box is configured by its
//!   own `server.env` and its own `identity.json`.
//! * No mesh client: a solo box never walks a chain to reach an exit, it IS
//!   the exit. A box that stands in a chain serves its own chain splice and
//!   forwards to the next hop through the node's own machinery — that is the
//!   node's business, not the perimeter's.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use mirage_core::capsule::FacePurpose;
use mirage_core::crypto::credential::subscriber_set::EdgeScopeView;
use mirage_core::mirage::wire::{MirageCarrier, Protocol, TransportCamouflage};
use mirage_node::client::chain_store::HeldChainStore;
use mirage_node::client::entrance::EntranceDeps;
use mirage_node::client::exit_port::{
    DatagramFlowOpener, ExitCountryOracle, StreamOpener,
};
use mirage_node::client::live_sessions::LiveSessionRegistry;
use mirage_node::client::pump::ByteCounterRegistry;
use mirage_node::client::udp_flow::{
    UdpFlowLimiter, MAX_LIVE_UDP_FLOWS_PER_PROCESS, MAX_UDP_STREAMS_PER_SESSION,
};
use mirage_perimeter::config::{PerimeterConfig, PerimeterFace, DEFAULT_INNER_ADDR};
use mirage_perimeter::identity::Identity;
use mirage_subscriber_gate::bandwidth_cap::SubscriberBandwidthRegistry;
use mirage_subscriber_gate::subscriber_keys::SubscriberKeyStore;
use tokio_util::sync::CancellationToken;

use crate::env::Face;
use crate::exit_port::LocalExit;
use crate::identity::ServerIdentity;
use crate::node::StandaloneNode;

/// How often the box re-reads its own subscriber allowlist.
///
/// The box writes that file itself and the operator may replace it under the
/// running process; a short poll is what makes a replaced allowlist take
/// effect without a restart.
const SUBSCRIBER_SET_POLL: Duration = Duration::from_secs(5);

/// Why a box could not be put together.
#[derive(Debug, thiserror::Error)]
pub enum BoxError {
    /// The perimeter's own configuration was refused.
    #[error("box: the perimeter configuration was refused: {0}")]
    Perimeter(#[from] mirage_perimeter::config::PerimeterConfigError),

    /// The client entrance could not start.
    #[error("box: the client entrance could not start: {0}")]
    Entrance(#[from] mirage_node::client::entrance::EntranceError),

    /// The node could not be built or served.
    #[error("box: {0}")]
    Node(#[from] crate::node::NodeError),

    /// A UDP endpoint the node holds could not be built or bound.
    #[error("box: {0}")]
    UdpEndpoint(#[from] crate::udp_endpoint::UdpEndpointError),

    /// A perimeter face's link is not Mirage over TCP.
    #[error("box: the face on port {port} is not a mask the perimeter binds ({reason})")]
    FaceProtocol {
        /// The door's port.
        port: u16,
        /// Why it is not a perimeter face.
        reason: String,
    },

    /// A protocol door could not be built or bound.
    #[error(transparent)]
    ProtocolDoor(#[from] crate::protocol_door::DoorError),
}

/// The box's faces, as the perimeter sees them.
///
/// The purpose of a face says what the bytes that arrive on it are allowed to
/// reach — and there are two kinds of bytes, and they must not be mixed:
///
/// * the **customer's** bytes reach the client entrance, and nothing else.
///   Every face of the edge and of a solo box carries
///   [`FacePurpose::EdgeEntrance`], and a face that carried anything else
///   would be a door the customer could walk into the node's own mesh
///   machinery through — which is exactly the door the fleet keeps shut by
///   signing a capsule that names the purpose of every face.
/// * the **chain's** bytes — a leg from the hop before it — reach the node's
///   own chain splice, and nothing else. A box that is a HOP of its chain
///   gives its faces [`FacePurpose::NodeChain`], so a leg that arrives on one
///   of them is answered by the node's chain machinery instead of by the
///   customer entrance.
///
/// Which kind a box is follows from its place in the chain, and that is a
/// property of the box's ROLE, never a per-connection decision.
///
/// Only Mirage over TCP belongs here. TLS, QUIC and the other protocols are
/// doors of their own — handing one to the perimeter would put a Mirage
/// handshake behind a protocol that is not Mirage. [`crate::env::ServerEnv::faces`]
/// keeps them apart; a face that still arrives here stops the box.
pub fn perimeter_faces(faces: &[Face], is_hop: bool) -> Result<Vec<PerimeterFace>, BoxError> {
    let purpose = if is_hop {
        FacePurpose::NodeChain
    } else {
        FacePurpose::EdgeEntrance
    };
    let mut built = Vec::with_capacity(faces.len());
    for face in faces {
        let mirage_tcp = matches!(
            face.protocol,
            Protocol::Mirage {
                carrier: MirageCarrier::Tcp,
                ..
            }
        );
        if !mirage_tcp {
            return Err(BoxError::FaceProtocol {
                port: face.port,
                reason: "only mirage over tcp is a perimeter face".to_owned(),
            });
        }
        let camouflage = face.protocol.to_mask(face.port).map_err(|reason| {
            BoxError::FaceProtocol {
                port: face.port,
                reason,
            }
        })?;
        built.push(PerimeterFace {
            port: face.port,
            camouflage,
            label: format!("{}:{}", face.id, face.port),
            purpose,
        });
    }
    Ok(built)
}

/// The box, ready to serve.
pub struct BoxRuntime {
    node: StandaloneNode,
    entrance: EntranceDeps,
    /// `None` when the box has no Mirage TCP face. The perimeter refuses an
    /// empty face list, so a door-only box does not start one.
    perimeter: Option<PerimeterConfig>,
    perimeter_identity: Identity,
    /// Mirage over UDP. Prepared before the box reports itself up.
    udp_endpoints: Vec<crate::udp_endpoint::Prepared>,
    /// Every non-Mirage protocol. Prepared before the box reports itself up.
    protocol_doors: Vec<crate::protocol_door::Prepared>,
    /// Relays in front of a terminator. Prepared before the box reports itself up.
    relays: Vec<crate::protocol_door::PreparedRelay>,
}

/// The box's own description, WITHOUT the wire keypair.
///
/// The perimeter's identity carries the box's wire key. A `Debug` that printed
/// it would put a private key into every log line that ever mentioned the
/// box, so the key is named and nothing more.
impl std::fmt::Debug for BoxRuntime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BoxRuntime")
            .field("perimeter_id", &self.perimeter_identity.perimeter_id)
            .field("mesh_id", &self.perimeter_identity.mesh_id)
            .field("shortname", &self.perimeter_identity.shortname)
            .field(
                "faces",
                &self.perimeter.as_ref().map(|perimeter| perimeter.faces.len()).unwrap_or(0),
            )
            .field(
                "udp_faces",
                &self
                    .perimeter
                    .as_ref()
                    .map(|perimeter| perimeter.udp_faces.len())
                    .unwrap_or(0),
            )
            .field("protocol_doors", &self.protocol_doors.len())
            .field("relays", &self.relays.len())
            .field("wire_keypair", &"<held, not printed>")
            .finish()
    }
}

impl BoxRuntime {
    /// Build the box from its own identity, its faces and its chain.
    ///
    /// `subscriber_set` is the path of the allowlist the box enforces;
    /// `exit_country` is the country the operator named for this box;
    /// `allow_private_targets` says whether private address ranges are valid
    /// exit targets (the intranet-exit mode, off by default).
    ///
    /// `chain_leg` is the box's way into its chain, when it has one. The edge
    /// — the box the customer knocks on — carries it, and the customer's
    /// session rides the chain instead of leaving from this box. A box without
    /// a chain leg is the exit itself.
    pub fn build(
        identity: &ServerIdentity,
        node: StandaloneNode,
        faces: &[Face],
        udp_endpoints: &[crate::env::UdpEndpoint],
        protocol_doors: &[Face],
        relays: &[crate::env::RelayDoor],
        subscriber_set: PathBuf,
        exit_country: Option<&str>,
        allow_private_targets: bool,
        chain_leg: Option<Arc<crate::chain_leg::ChainLeg>>,
        chain_udp_port: Option<u16>,
    ) -> Result<Self, BoxError> {
        // A box that is a HOP of its chain answers the chain's legs on its own
        // faces; the edge and the solo box answer the customer there.
        let is_hop = node.control_plane().listener_spec.is_some();
        // The inner address is NOT used on this path — the inward destination
        // is the box-local CHANNEL the face's own purpose names, not a TCP
        // address (see `mirage_perimeter::face`'s own doc). The value is the
        // perimeter's own default so nothing on this path reads a lie.
        let inner_addr: std::net::SocketAddr = DEFAULT_INNER_ADDR
            .parse()
            .expect("the perimeter's default inner address is a constant and parses");
        let perimeter = if faces.is_empty() {
            None
        } else {
            let perimeter_faces = perimeter_faces(faces, is_hop)?;
            let mut perimeter = PerimeterConfig::from_local_faces(perimeter_faces, inner_addr)?;

        // The chain's DATAGRAM door — the port a hop answers the chain's
        // datagram leg on.
        //
        // It is a perimeter face, not a node-held endpoint: the datagram leg
        // arrives as datagrams, and the perimeter is what classifies them and
        // relays the wire ones into the node's chain splice. The face's
        // purpose is the CHAIN's, so the relay lands in the node's chain
        // splice and never in the customer entrance — a hop serves the chain,
        // not the customer.
        //
        // The port may equal a TCP face's port number: TCP and UDP have
        // separate port spaces, and sharing the number is what QUIC does.
        if let (true, Some(port)) = (is_hop, chain_udp_port) {
            perimeter.udp_faces.push(mirage_perimeter::config::UdpFace {
                port,
                camouflage: TransportCamouflage::RawUdp {
                    bind_addr: format!("0.0.0.0:{port}")
                        .parse()
                        .expect("a literal address parses"),
                },
                label: format!("raw_udp:{port}"),
                purpose: mirage_perimeter::config::FacePurpose::NodeChain,
            });
        }
            Some(perimeter)
        };

        // The box's own exit: it resolves the target with the resolver the
        // node already runs, and applies the node's own address policy.
        let exit = Arc::new(LocalExit::with_private_targets(
            node.runtime().doh.load_full(),
            exit_country,
            allow_private_targets,
        ));

        // The node's OWN exit path follows the same rule — one setting, one
        // meaning: an operator who relaxes the guard relaxes it for the whole
        // box, not for half of it.
        mirage_node::family::mirage::exit::policy::set_allow_private_exit_targets(
            allow_private_targets,
        );

        // The subscriber allowlist this box enforces is signed by the box's
        // OWN issuer key — there is nobody else to sign it.
        let subscriber_keys = SubscriberKeyStore::empty(identity.subscriber_issuer_verifying_key());
        mirage_node::client::start_subscriber_set(
            Arc::clone(&subscriber_keys),
            subscriber_set,
            SUBSCRIBER_SET_POLL,
            Arc::new(|| tracing::info!("[box] subscriber allowlist reloaded")),
        );

        // Where the customer's session goes: through the chain when the box
        // has one, and out of the box itself when it does not.
        //
        // The datagram arm follows the same rule, and says so out loud: a
        // chain whose hops have no datagram door must refuse a datagram flow
        // rather than quietly send it out of the wrong box.
        let (stream_opener, datagram_opener): (
            Arc<dyn StreamOpener>,
            Arc<dyn DatagramFlowOpener>,
        ) = match chain_leg {
            Some(leg) => (
                Arc::clone(&leg) as Arc<dyn StreamOpener>,
                if leg.carries_datagrams() {
                    // The chain carries datagrams: the customer's datagrams ride
                    // the chain's OWN datagram leg — a native UDP tunnel with
                    // its own handshake — and never ride the stream leg.
                    Arc::clone(&leg) as Arc<dyn DatagramFlowOpener>
                } else {
                    Arc::new(crate::chain_leg::ChainLegNoDatagrams::new(leg.chain_id()))
                        as Arc<dyn DatagramFlowOpener>
                },
            ),
            None => (
                Arc::clone(&exit) as Arc<dyn StreamOpener>,
                Arc::clone(&exit) as Arc<dyn DatagramFlowOpener>,
            ),
        };

        let entrance = EntranceDeps {
            // A solo box holds no chain: there is nothing to walk to, because
            // the box IS the exit. The stores stay here because the entrance
            // records demand on them for every session, and a demand with no
            // chain behind it is exactly what a local exit answers.
            chain_store: Arc::new(HeldChainStore::new()),
            chain_store_udp: Arc::new(HeldChainStore::new()),
            stream_opener,
            datagram_opener,
            exit_countries: Arc::clone(&exit) as Arc<dyn ExitCountryOracle>,
            subscriber_keys,
            subscriber_bandwidth: SubscriberBandwidthRegistry::new(),
            subscriber_cfg: Arc::new(mirage_node::client::default_subscriber_cfg()),
            byte_counters: Arc::new(ByteCounterRegistry::new()),
            udp_flow_limiter: UdpFlowLimiter::new(
                MAX_UDP_STREAMS_PER_SESSION,
                MAX_LIVE_UDP_FLOWS_PER_PROCESS,
            ),
            wire_keypair: Arc::new(identity.node_wire()),
            // The mesh id is folded into the V9 handshake as BYTES, and the
            // client folds in the ASCII of the artefact's own `mesh_id` string
            // — so the box must fold in the ASCII of its own, not the decoded
            // hex. `mirage2app/crates/subscriber-client/src/assembly.rs` does
            // `artefact.mesh_id.as_bytes().to_vec()`; this is the other half
            // of that same line.
            fleet_mesh_id: Arc::new(identity.mesh_id().as_bytes().to_vec()),
            // The box is its own operator and its allowlist is its own, so
            // the box admits a subscriber at the PUBLIC scope.
            own_scope: EdgeScopeView::Public,
            live_sessions: LiveSessionRegistry::new(),
            face_loads: Arc::new(Mutex::new(HashMap::new())),
            face_draw: Arc::new(AtomicU64::new(0)),
        };

        let perimeter_identity = Identity::wire_only(identity.node_wire());

        // The node's own UDP endpoints are built and bound HERE, before the
        // box reports itself up: a mask that cannot be built, or a port that
        // cannot be bound, is a door the box promised and cannot open, and
        // that has to be said out loud rather than left dark.
        let udp_endpoints = crate::udp_endpoint::prepare(udp_endpoints)?;
        let protocol_doors = crate::protocol_door::prepare(protocol_doors)?;
        let relays = crate::protocol_door::prepare_relays(relays)?;

        Ok(Self {
            node,
            entrance,
            perimeter,
            perimeter_identity,
            udp_endpoints,
            protocol_doors,
            relays,
        })
    }

    /// Serve the box until `cancel` fires.
    ///
    /// Three things run at once, and the box is only up when all three are:
    /// the perimeter (the faces), the client entrance (the subscriber gate)
    /// and the node's chain splice (the hop before it, for a box in a chain).
    ///
    /// The runtime is CONSUMED: the perimeter's identity holds a wire keypair
    /// that is not clonable, and a box that had two of them would be a box
    /// with two wire identities.
    pub async fn serve(self, cancel: CancellationToken) -> Result<(), BoxError> {
        let has_udp_chain = self
            .perimeter
            .as_ref()
            .is_some_and(|perimeter| !perimeter.udp_faces.is_empty());
        let perimeter = match self.perimeter {
            Some(config) => {
                let identity = self.perimeter_identity;
                Some(tokio::spawn(async move {
                    if let Err(e) = mirage_perimeter::run_standalone(config, identity).await {
                        // A perimeter that cannot start is a box with no
                        // Mirage TCP door. Say so loudly.
                        tracing::error!(error = %e, "box: the perimeter stopped");
                    }
                }))
            }
            None => {
                drop(self.perimeter_identity);
                None
            }
        };

        let entrance = tokio::spawn({
            let deps = self.entrance.clone();
            async move {
                if let Err(e) = mirage_node::client::entrance::run(deps).await {
                    // Same for the entrance: a box whose entrance cannot bind
                    // admits nobody, and says so rather than looking alive.
                    tracing::error!(error = %e, "box: the client entrance stopped");
                }
            }
        });

        // The node's own listener registry — the UDP chain splice needs it,
        // and the node itself is moved into the chain splice task below.
        let udp_registry = Arc::clone(self.node.registry());

        let chain = tokio::spawn({
            let node = self.node;
            let cancel = cancel.clone();
            async move {
                if let Err(e) = node.serve(cancel).await {
                    tracing::error!(error = %e, "box: the node's chain splice stopped");
                }
            }
        });

        // The node's UDP chain splice — the datagram counterpart of the chain
        // splice above. It binds the box-local channel the perimeter's
        // NodeChain-purpose datagram face relays into, runs the V9 DATAGRAM
        // handshake per new peer and hands the tunnel to the UDP exit.
        //
        // It is started only when the box has a datagram door: the perimeter
        // binds its own relay side only then, and the two halves of that
        // rendezvous must be bound together.
        let udp_chain = if !has_udp_chain {
            None
        } else {
            Some(tokio::spawn({
                let registry = udp_registry;
                let cancel = cancel.clone();
                async move {
                    if let Err(e) =
                        mirage_node::core::udp_chain_splice::serve(registry, cancel).await
                    {
                        tracing::error!(
                            error = %e,
                            "box: the node's UDP chain splice stopped — the chain carries TCP only"
                        );
                    }
                }
            }))
        };

        // The node's own UDP endpoints — the ports wearing a real UDP mask.
        // They were bound before the box reported itself up; here they are
        // served, and what comes out of the camouflage goes into the SAME
        // client entrance as the perimeter's splice.
        let udp = tokio::spawn({
            let endpoints = self.udp_endpoints;
            let deps = self.entrance.clone();
            let cancel = cancel.clone();
            async move {
                crate::udp_endpoint::serve(endpoints, deps, cancel).await;
            }
        });

        let doors = tokio::spawn({
            let doors = self.protocol_doors;
            let cancel = cancel.clone();
            async move {
                crate::protocol_door::serve(doors, cancel).await;
            }
        });

        let relays = tokio::spawn({
            let relays = self.relays;
            let cancel = cancel.clone();
            async move {
                crate::protocol_door::serve_relays(relays, cancel).await;
            }
        });

        cancel.cancelled().await;

        // The box is going down: stop the accept loops before the process
        // exits, so a restart does not race a listener that is still holding
        // its port.
        entrance.abort();
        chain.abort();
        if let Some(handle) = perimeter {
            handle.abort();
        }
        udp.abort();
        doors.abort();
        relays.abort();
        if let Some(handle) = udp_chain {
            handle.abort();
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mirage_core::mirage::wire::{MirageCamouflage, Protocol};

    fn mirage_face() -> Face {
        Face {
            port: 443,
            id: "mirage".to_owned(),
            protocol: Protocol::Mirage {
                carrier: MirageCarrier::Tcp,
                camouflage: MirageCamouflage::None,
            },
        }
    }

    #[test]
    fn every_face_of_a_standalone_box_opens_the_client_entrance() {
        let faces = vec![mirage_face()];
        let built = perimeter_faces(&faces, false).expect("mirage over tcp is a perimeter face");
        assert_eq!(built.len(), 1);
        assert_eq!(built[0].port, 443);
        assert_eq!(built[0].purpose, FacePurpose::EdgeEntrance);
        assert_eq!(built[0].label, "mirage:443");
    }

    #[test]
    fn a_hop_serves_the_chain_on_its_faces_instead_of_the_customer() {
        let faces = vec![mirage_face()];
        let built = perimeter_faces(&faces, true).expect("mirage over tcp is a perimeter face");
        assert_eq!(built.len(), 1);
        assert_eq!(
            built[0].purpose,
            FacePurpose::NodeChain,
            "a leg that arrives on this face belongs to the chain, not to a customer"
        );
    }

    #[test]
    fn tls_is_not_a_perimeter_face() {
        let faces = vec![Face {
            port: 443,
            id: "https".to_owned(),
            protocol: Protocol::Tls {
                sni: "example.com".to_owned(),
                alpn: Vec::new(),
            },
        }];
        let err = perimeter_faces(&faces, false).expect_err("tls is a protocol door");
        let text = err.to_string();
        assert!(
            text.contains("mirage"),
            "the refusal names mirage over tcp: {text}"
        );
    }
}
