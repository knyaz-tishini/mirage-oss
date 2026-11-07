//! The standalone node — the node runtime, built from local state.
//!
//! A fleet node gets its identity from the box's keeper and its
//! configuration from the monitor. A standalone box has neither: it owns its
//! keys on local disk and its chain in local configuration. This module is
//! the bridge — it takes the two together and produces the thing the data
//! plane actually runs on:
//!
//! * a [`NodeRuntime`] carrying the box's wire key, its mesh id, its
//!   credential parameters and its replay guards;
//! * a [`ListenerRegistry`] holding the one listener this box serves;
//! * the chain splice, bound and serving.
//!
//! Nothing is invented here. The runtime, the registry and the splice are the
//! node's own — this crate only fills them in from local state.

use std::sync::{Arc, Mutex};

use arc_swap::ArcSwap;
use mirage_core::config::NodeConfig;
use mirage_core::crypto::{KeyPair, SpentSet};
use mirage_node::core::doh::DoHResolver;
use mirage_node::core::endpoint_protocol::CredentialAuthState;
use mirage_node::core::management::builder::build_protocols;
use mirage_node::core::registry::registry::{
    Activation, ActivationContext, ListenerRegistry, RegistryError,
};
use mirage_node::core::role_signed_gate::RoleSignedReplayCache;
use mirage_node::core::runtime::{NodeRuntime, NodeRuntimeSnapshot};
use tokio_util::sync::CancellationToken;

use crate::chain::ChainSpec;
use crate::control_plane::{
    build_control_plane, build_credential_params, ControlPlaneError, StaticControlPlane,
};
use crate::env::Face;
use crate::identity::ServerIdentity;

/// Why a standalone node could not be built or could not serve.
#[derive(Debug, thiserror::Error)]
pub enum NodeError {
    /// The local control plane could not be built.
    #[error("standalone node: {0}")]
    ControlPlane(#[from] ControlPlaneError),

    /// The node's listener could not be activated.
    #[error("standalone node: the listener could not be activated: {0}")]
    Activation(#[from] RegistryError),

    /// The node's protocols could not be built.
    #[error("standalone node: the protocols could not be built: {0}")]
    Protocols(String),

    /// The node's DNS resolver could not be built.
    #[error("standalone node: the DNS resolver could not be built: {0}")]
    Dns(String),

    /// The chain splice could not be served.
    #[error("standalone node: the chain splice could not be served: {0}")]
    Serve(#[from] std::io::Error),
}

/// A standalone node, ready to serve.
pub struct StandaloneNode {
    runtime: Arc<NodeRuntime>,
    registry: Arc<ListenerRegistry>,
    control_plane: StaticControlPlane,
}

impl std::fmt::Debug for StandaloneNode {
    /// The node's own shape — never its keys.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StandaloneNode")
            .field("mesh_id", &self.runtime.mesh_id)
            .field(
                "listener",
                &self
                    .control_plane
                    .listener_spec
                    .as_ref()
                    .map(|spec| spec.id.clone()),
            )
            .field("peers", &self.control_plane.peer_table.peers.len())
            .finish()
    }
}

impl StandaloneNode {
    /// Build the node from the box's own identity and its chain.
    ///
    /// `local_index` is this box's own place in `chain` — the hop whose
    /// listener the node serves. `None` means the box is the chain's **edge**:
    /// it owns the chain and dials it, and it serves no chain listener.
    /// `faces` are the faces the box publishes; the first one is the face the
    /// listener wears.
    ///
    /// `doh` is the box's DNS resolver. When it names an HTTPS endpoint it
    /// also becomes the node's own resolver — the node resolves the hostnames
    /// its clients ask for. When it is absent the node uses the system
    /// resolver.
    pub fn build(
        identity: &ServerIdentity,
        chain: &ChainSpec,
        local_index: Option<usize>,
        faces: &[Face],
        doh: Option<&str>,
    ) -> Result<Self, NodeError> {
        let control_plane = build_control_plane(identity, chain, local_index, faces)?;
        let credential_params = build_credential_params(identity, now_ms())?;

        let keypair: KeyPair = identity.node_wire();
        let mesh_id: Arc<str> = Arc::from(identity.mesh_id());
        let node_id = node_id_of(identity);

        // The credential state is shared by every accept path: the chain
        // splice's own entrance handshake reads the SAME ArcSwap the protocol
        // closure does, so a credential that changes is seen everywhere at
        // once.
        let credential_params: Arc<ArcSwap<Option<mirage_core::crypto::CredentialParams>>> =
            Arc::new(ArcSwap::from_pointee(Some(credential_params)));
        let spent_set: Arc<Mutex<SpentSet>> = Arc::new(Mutex::new(SpentSet::default()));
        let role_signed_replay: Arc<Mutex<RoleSignedReplayCache>> =
            Arc::new(Mutex::new(RoleSignedReplayCache::new()));

        let credential_auth = CredentialAuthState {
            params: Arc::clone(&credential_params),
            spent: Arc::clone(&spent_set),
            role_signed_replay: Arc::clone(&role_signed_replay),
        };

        let built = build_protocols(
            &keypair,
            &mesh_id,
            &node_id,
            Some(credential_auth),
            false,
        )
        .map_err(|e| NodeError::Protocols(e.to_string()))?;

        let snapshot = NodeRuntimeSnapshot {
            protocols: built.protocols,
            pools: Vec::new(),
            relay_metrics: None,
            node_config: node_config(&node_id),
            credential_params,
            spent_set,
            role_signed_replay,
            allow_legacy_v8: false,
        };

        let doh = match doh.filter(|endpoint| endpoint.starts_with("https://")) {
            Some(endpoint) => Some(Arc::new(
                DoHResolver::new(endpoint, true).map_err(|e| NodeError::Dns(e.to_string()))?,
            )),
            None => None,
        };

        let runtime = NodeRuntime::new(
            snapshot,
            keypair,
            mesh_id,
            doh,
            Some(Arc::new(identity.operator_signing_key().verifying_key())),
        );

        // The control plane the box built locally is what the node serves —
        // the peer table it dials through, and the chain bindings that name
        // the hops.
        runtime
            .peer_table
            .store(Arc::new(control_plane.peer_table.clone()));
        runtime
            .chain_bindings
            .store(Arc::new(control_plane.chain_bindings.clone()));

        let registry = Arc::new(ListenerRegistry::new(ActivationContext {
            runtime: Arc::clone(&runtime),
            outbound_protocol: None,
            doh: None,
        }));

        Ok(Self {
            runtime,
            registry,
            control_plane,
        })
    }

    /// The node's runtime.
    pub fn runtime(&self) -> &Arc<NodeRuntime> {
        &self.runtime
    }

    /// The node's listener registry.
    pub fn registry(&self) -> &Arc<ListenerRegistry> {
        &self.registry
    }

    /// The control plane this node was built from.
    pub fn control_plane(&self) -> &StaticControlPlane {
        &self.control_plane
    }

    /// Activate the box's listener.
    ///
    /// The registry recomputes the spec's fingerprint and refuses a spec that
    /// does not match — so this is also the check that the box's own
    /// fingerprint was computed over the same fields the node reads.
    ///
    /// The edge has no listener to activate: it is not a hop of its own
    /// chain. It still serves — the customer knocks on its own door, and its
    /// own chain splice answers for the legs that arrive.
    ///
    /// A hop that carries datagrams activates TWO listeners: the stream one
    /// and its datagram twin. They are two addresses for one hop, not two
    /// hops — the registry keeps them apart by transport, and the chain's two
    /// planes never address each other.
    pub async fn activate(&self) -> Result<Option<Activation>, NodeError> {
        let Some(spec) = self.control_plane.listener_spec.clone() else {
            return Ok(None);
        };
        let activated = self.registry.activate(spec).await?;
        if let Some(datagram_spec) = self.control_plane.datagram_listener_spec.clone() {
            self.registry.activate(datagram_spec).await?;
        }
        Ok(Some(activated))
    }

    /// Serve the chain splice until `cancel` is cancelled.
    ///
    /// The splice is the box's own socket: on Unix, the node's chain socket
    /// under the runtime directory; the perimeter dials it.
    pub async fn serve(&self, cancel: CancellationToken) -> Result<(), NodeError> {
        Ok(mirage_node::core::chain_splice::serve(
            Arc::clone(&self.registry),
            cancel,
        )
        .await?)
    }
}

/// The node's own id — the one the fleet derives from the node's public key.
fn node_id_of(identity: &ServerIdentity) -> String {
    let key = identity.node_wire_pubkey_hex();
    if key.len() >= 12 {
        format!("node-{}", &key[..12])
    } else {
        "node-standalone".to_owned()
    }
}

/// The node configuration the runtime carries.
///
/// The standalone box has no `node.toml` — the fleet's on-disk node
/// configuration — so this is the same stub the configurator path builds for
/// a node that is waiting for its monitor to push the real thing. What
/// matters here is the node's id and its mode: a standalone box is a direct
/// exit.
fn node_config(node_id: &str) -> NodeConfig {
    let stub = serde_json::json!({
        "node_id": node_id,
        "listen_addr": "0.0.0.0:0",
        "mode": {
            "Exit": {
                "mode": "direct",
                "dns_resolver": "https://1.1.1.1/dns-query",
                "dns_prefer_ipv6": null,
                "nat_enabled": true
            }
        },
        "protocols": ["Mirage"],
        "health_interval_secs": 30,
        "management_addr": "127.0.0.1:0",
        "role": { "role": "exit_node", "mirage_listeners": [] },
    });
    serde_json::from_value(stub)
        .expect("the standalone node's stub configuration is a constant and must deserialise")
}

/// Milliseconds since the epoch.
fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::ChainHop;
    use mirage_core::config::HopRole;
    use mirage_core::mirage::wire::{MirageCamouflage, MirageCarrier, Protocol, TransportCamouflage};

    /// A one-hop chain: the box is the exit.
    fn solo_chain(identity: &ServerIdentity) -> ChainSpec {
        ChainSpec {
            chain_id: "test-chain".to_owned(),
            hops: vec![ChainHop {
                addr: "10.0.0.1:443".to_owned(),
                public_key: Some(identity.node_wire_pubkey_hex()),
                node_id: None,
                role: HopRole::Exit,
                camouflage: Some(TransportCamouflage::None),
                udp_addr: None,
            }],
        }
    }

    /// The face the box publishes.
    fn face() -> Face {
        Face {
            port: 443,
            id: "mirage".to_owned(),
            protocol: Protocol::Mirage {
                carrier: MirageCarrier::Tcp,
                camouflage: MirageCamouflage::None,
            },
        }
    }

    #[tokio::test]
    async fn the_node_activates_the_listener_it_built() {
        let identity = ServerIdentity::mint();
        let chain = solo_chain(&identity);

        let node = StandaloneNode::build(&identity, &chain, Some(0), &[face()], None).expect("the node builds");
        let activation = node.activate().await.expect("the listener activates");

        assert!(
            matches!(activation, Some(Activation::Registered(_))),
            "a chain hop is a routing entry — the perimeter reaches it through the chain splice"
        );
    }

    #[tokio::test]
    async fn the_node_carries_the_box_own_credential_parameters() {
        let identity = ServerIdentity::mint();
        let chain = solo_chain(&identity);

        let node = StandaloneNode::build(&identity, &chain, Some(0), &[face()], None).expect("the node builds");
        let snapshot = node.runtime().snapshot.load_full();
        let held = snapshot.credential_params.load_full();
        let params = match &*held {
            Some(params) => params,
            None => panic!(
                "the node carries credential parameters — without them it refuses every dial"
            ),
        };

        params
            .verify(&identity.operator_signing_key().verifying_key())
            .expect("the parameters verify against the box's own operator key");
    }

    #[tokio::test]
    async fn the_node_carries_the_peer_table_it_built() {
        let identity = ServerIdentity::mint();
        let chain = solo_chain(&identity);

        let node = StandaloneNode::build(&identity, &chain, Some(0), &[face()], None).expect("the node builds");
        let peer_table = node.runtime().peer_table.load_full();

        assert_eq!(peer_table.peers.len(), 1);
        assert_eq!(peer_table.peers[0].addr, "10.0.0.1:443");
    }
}
