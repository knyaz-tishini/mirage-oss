//! Monitor ↔ Node WS control-channel frames.
//!
//! Lifted verbatim (modulo doc cleanup) from
//! `mirage2monitor::monitor::node_control_ws` — the canonical schema
//! that both sides have always agreed on; the duplication was just
//! poor placement.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// monitor → node frames.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum MonitorToNode {
    /// Authoritative listener set for this node. `generation` lets the
    /// node distinguish a fresh push from a duplicate replay.
    PushListenerSet {
        generation: u64,
        listeners: Vec<PushListenerEntry>,
    },
    /// Authoritative full peer table snapshot. Replaces the in-memory
    /// map on the node; `UpstreamRef::PeerListener` resolution picks it
    /// up on the next dial. Hot — no listener rebind required.
    PushPeerTable {
        peer_table: mirage_core::mirage::mesh::PeerTable,
        /// Commit (b), node-peer-table-split-and-merge: this monitor's own
        /// `lm_id`, stamped so the node can gate per-monitor-slice ownership
        /// (LWW union + eviction) instead of racing N monitors' pushes
        /// against one shared generation. `#[serde(default)]` keeps this
        /// additive/backward-compatible — old monitors omit the field, node
        /// treats `""` as "unknown owner, never auto-evict from this push".
        #[serde(default)]
        origin_monitor_id: String,
    },
    /// Authoritative full chain-bindings snapshot. Replaces the
    /// in-memory map; listener accept paths resolve their chain_id
    /// against it on the next accepted connection. Hot.
    PushChainBindings {
        chain_bindings: mirage_core::mirage::mesh::ChainBindings,
    },
    /// Authoritative anonymous-credential verification params for the
    /// data-leg authz pillar. The node hot-swaps these into its runtime
    /// (`credential_params` ArcSwap) and verifies client credentials on
    /// every direct-exit accept. `generation` lets the node ignore a
    /// stale/duplicate push. Empty `params.epochs` ⇒ nothing to verify
    /// against (node stays in open/transition mode). Forward-compat: old
    /// nodes that predate this variant tolerate it via their `#[serde(other)]`
    /// arm — deploy nodes BEFORE the monitor starts pushing it.
    PushCredentialParams {
        generation: u64,
        params: mirage_core::crypto::CredentialParams,
    },
    /// Authoritative full subscriber-entrance set for this node — the
    /// back-office automated-issuance transport
    /// (`docs/mirage/plans/2026-09-23-backoffice-automated-issuance.md` §2).
    /// Full-set replace only — never a delta, matching the box-local
    /// `subscriber-keys.json` file's own contract
    /// (`mirage2node::core::subscriber_keys` module doc, "File shape"): an
    /// empty `entries` revokes every subscriber on this node at once.
    /// `generation` lets the node drop a stale/duplicate push, same idiom
    /// as [`Self::PushCredentialParams`].
    PushSubscriberKeys {
        generation: u64,
        entries: Vec<mirage_core::entrance_wire::SubscriberKeyWireEntry>,
    },
    Ping {
        ts_ms: u64,
    },
}

/// Self-contained listener entry inside a `PushListenerSet` frame.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PushListenerEntry {
    pub listener_id: String,
    pub spec: serde_json::Value,
    pub fingerprint_hex: String,
}

/// One entry in a node→monitor `ListenerSnapshot` frame. Describes a
/// single listener the node has bound locally and that the monitor
/// reflects in its RAM mirror.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListenerSnapshotEntry {
    pub listener_id: String,
    /// Actual port the listener bound on.
    pub bind_port: u16,
    pub bound_addr: String,
    /// `"bound" | "binding" | "failed"`.
    pub state: String,
    /// `None` if the listener belongs to no chain (legacy / direct).
    #[serde(default)]
    pub chain_id: Option<String>,
    /// Empty for single-hop / direct exit.
    #[serde(default)]
    pub chain_node_ids: Vec<String>,
    /// `None` for failed entries.
    #[serde(default)]
    pub fingerprint_hex: Option<String>,
    #[serde(default)]
    pub bytes_in: u64,
    #[serde(default)]
    pub bytes_out: u64,
    #[serde(default)]
    pub active_conns: u32,
    /// L1.3 slice 2b: hex Ed25519 signature over
    /// `mirage_core::fact_signing::listener_state_signing_bytes(...)`, computed
    /// by the node's box-signing key over this entry's fields plus the
    /// enclosing `ListenerSnapshot.timestamp_ms`. `None` on unsigned (legacy)
    /// nodes. The monitor folds it into the gossiped `ListenerStateUpsert`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sig_hex: Option<String>,
}

/// One peer-to-peer Mirage dial probe result from the node prober.
///
/// `status` mirrors the sentry convention: `"ok" | "refused" | "timeout"`.
///
/// # Why there are two verdicts and not one
///
/// `status`/`rtt_ms` describe a STREAM dial to the peer's `:19444`. They say
/// nothing about whether the same edge carries datagrams, and until
/// 2026-09-09 nothing did — the topology picker read this one verdict and
/// used it to build chains for every transport.
///
/// Measured on a lab mesh that day, `ru-hostkey-203.0.113.15` to
/// `us-example-203.0.113.25`: TCP `:80` connected in 228ms and TCP `:443`
/// in 198ms, while UDP datagrams to its chain face never arrived at all. The
/// matrix reported that edge `ok`, so datagram chains were routed across it
/// and died mid-handshake — 4-hop chains always, 3-hop chains whenever the
/// picker's reshuffle happened to draw it.
///
/// So the datagram verdict is carried separately, and `None` means "not
/// probed" rather than "down": a peer that publishes no datagram face, and a
/// node too old to probe one, are both absences, not failures. Reading
/// absence as failure would condemn every stream-only box in the fleet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeEgressObservation {
    pub to_node_id: String,
    /// `"ok"` | `"refused"` | `"timeout"` — the STREAM dial's verdict.
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rtt_ms: Option<u32>,
    /// `"ok"` | `"fail"` for the peer's datagram chain face. `None` when the
    /// peer publishes no such face, or when the reporting node predates this
    /// field — both are "not probed", never "down". See the type doc.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dgram_status: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dgram_rtt_ms: Option<u32>,
    /// When the datagram probe last ran, ms since epoch. Separate from the
    /// stream probe's timing because the two run concurrently and either can
    /// be the stale one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dgram_probe_ms: Option<u64>,
}

/// One subscriber's reported bandwidth consumption inside a
/// `SubscriberConsumptionReport` frame.
///
/// `consumed_bytes_since_last_report` is a DELTA, not a running total —
/// mirrors `ListenerActivityReport`'s own point-in-time-snapshot shape
/// rather than a cumulative counter the monitor would have to reconcile
/// against node restarts. `subscriber_key_hex` identifies the subscriber
/// the exact same way the node identifies them internally
/// (`core::bandwidth_cap`/`core::subscriber_keys`'s hex-encoded static
/// X25519 public key) — nothing else about the subscriber ever rides this
/// frame, and this key is never logged on either side, only ever stored or
/// read back as a lookup key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubscriberConsumptionObservation {
    pub subscriber_key_hex: String,
    pub consumed_bytes_since_last_report: u64,
    /// Whether this subscriber is currently degraded to the monthly-volume
    /// floor rate (`core::bandwidth_cap::MonthlyVolume`'s degrade state) —
    /// mirrored here so the monitor's read side (and eventually the panel)
    /// doesn't need a second round trip to know why a subscriber's traffic
    /// slowed.
    pub degraded: bool,
}

/// node → monitor frames.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum NodeToMonitor {
    ListenerBound {
        listener_id: String,
        bound_addr: String,
        /// Actual port the node bound on. Older nodes encoded the port
        /// inside `bound_addr`; kept `Option` for one-window forward-
        /// compat.
        #[serde(default)]
        bind_port: Option<u16>,
        /// L1.3 slice 2b: node-stamped emit time (ms). Signed; the monitor
        /// preserves it as the gossiped fact's `updated_at_ms`. Defaults to
        /// `0` from legacy nodes that don't stamp it (those take the
        /// unsigned monitor-stamped path).
        #[serde(default)]
        updated_at_ms: u64,
        /// L1.3 slice 2b: hex Ed25519 signature over
        /// `listener_state_signing_bytes(...)`. `None` on unsigned (legacy)
        /// nodes — those facts gossip via the legacy unsigned path.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        sig_hex: Option<String>,
    },
    ListenerError {
        listener_id: String,
        reason: String,
        /// L1.3 slice 2b: node-stamped emit time (ms). See `ListenerBound`.
        #[serde(default)]
        updated_at_ms: u64,
        /// L1.3 slice 2b: hex Ed25519 signature. See `ListenerBound`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        sig_hex: Option<String>,
    },
    /// A chain listener (`ListenerRegistry::register_chain_spec`) came up
    /// as a routing entry with no socket — see `nemo/mirage2node/CLAUDE.md`
    /// "Chain hops bind no port". `ListenerBound` cannot report this: it
    /// requires a `bound_addr`, and a chain hop has none BY DESIGN, so a
    /// fabricated address would tell the monitor something false. This
    /// variant is the same signed shape as `ListenerBound` minus the
    /// address and port — there is no socket to describe.
    ListenerRegistered {
        listener_id: String,
        /// L1.3 slice 2b: node-stamped emit time (ms). See `ListenerBound`.
        #[serde(default)]
        updated_at_ms: u64,
        /// L1.3 slice 2b: hex Ed25519 signature over
        /// `listener_state_signing_bytes(...)` with `state = "registered"`,
        /// `bound_addr = None`, `bind_port = None`. `None` on unsigned
        /// (legacy) nodes — those facts gossip via the legacy unsigned path.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        sig_hex: Option<String>,
    },
    ListenerStats {
        listener_id: String,
        bytes_in: u64,
        bytes_out: u64,
        active_conns: u32,
    },
    /// Bulk per-(node, listener) report sent by a node right after WS
    /// reconnect — used by the monitor to rebuild its RAM
    /// `chain_bindings` / `node_reported_state` mirrors without waiting
    /// for the node to re-bind everything.
    ListenerSnapshot {
        timestamp_ms: u64,
        listeners: Vec<ListenerSnapshotEntry>,
    },
    /// D1: active liveness reply. `ts_ms` echoes the `Ping.ts_ms` this
    /// answers, so the monitor can validate it is measuring THIS ping's
    /// rtt rather than a stale one (belt-and-suspenders on top of the
    /// "only one ping outstanding per interval" ordering guarantee already
    /// implicit in the control channel's single `tokio::select!` loop).
    /// `#[serde(default)]` — additive/rolling-upgrade-safe: old nodes that
    /// don't echo it send a bare `{"type":"pong"}`, deserialised as
    /// `ts_ms: 0`; the monitor falls back to its own locally-tracked
    /// ping-send time for the rtt calc in that case.
    Pong {
        #[serde(default)]
        ts_ms: u64,
    },
    /// Periodic report of per-listener dial activity timestamps. The
    /// monitor stores `last_dial_ms` in `desired_listeners` so the
    /// idle reaper can distinguish genuinely unused chains from chains
    /// that had no `last_used_ms` bump.
    ///
    /// `listeners`: map from `listener_id` → `last_dial_ms` (UNIX ms
    /// of the most recent client dial on that listener). Absent
    /// entries are not touched — partial reports are safe.
    ListenerActivityReport {
        timestamp_ms: u64,
        #[serde(default)]
        listeners: HashMap<String, u64>,
    },
    /// Sent on reconnect after the node lost its session_token (e.g.
    /// process crashed before persisting it). The monitor responds by
    /// closing the socket and letting the node `POST /register` again.
    RegisterRequest,
    /// Periodic node-to-node Mirage-native reachability probe results.
    ///
    /// Each observation is a real Mirage V5 handshake attempt to the
    /// peer's `:19444`. The monitor folds these into
    /// `MeshState.node_egress` keyed by
    /// `(from_node_id=authenticated_ws_node_id, to_node_id)`.
    ///
    /// NOTE: `from_node_id` is NOT in this payload — the monitor uses
    /// the WS session's authenticated `node_id` to prevent impersonation.
    NodeEgressReport {
        probed_at_ms: u64,
        observations: Vec<NodeEgressObservation>,
    },
    /// Periodic report of per-subscriber bandwidth consumption for the
    /// commercial subscriber entrance (`core::bandwidth_cap`). Sent from
    /// the SAME loop and on the SAME ~60s cadence as `ListenerActivityReport`
    /// — see `node_control_client.rs`'s reconcile loop — never per chunk.
    /// A node with no subscriber traffic since its last report (including
    /// every node that has no bandwidth cap configured at all) sends
    /// nothing: `subscribers` is only ever non-empty when there is
    /// something new to report, matching `ListenerActivityReport`'s own
    /// "skip the frame entirely when the snapshot is empty" behaviour.
    ///
    /// This is a commercial fact, not mesh state — the monitor stores it in
    /// its own RAM ring and does NOT gossip it to sibling monitors (see
    /// `mesh_state::MeshState::subscriber_consumption`'s doc).
    SubscriberConsumptionReport {
        reported_at_ms: u64,
        #[serde(default)]
        subscribers: Vec<SubscriberConsumptionObservation>,
    },
    /// Unknown variant — tolerated on old monitors during rolling deploy.
    /// Deploy monitor before nodes to avoid hitting this path.
    #[serde(other)]
    Unknown,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn monitor_to_node_ping_roundtrip() {
        let frame = MonitorToNode::Ping { ts_ms: 1_700_000_000_000 };
        let s = serde_json::to_string(&frame).unwrap();
        assert!(s.contains(r#""type":"ping""#));
        let back: MonitorToNode = serde_json::from_str(&s).unwrap();
        match back {
            MonitorToNode::Ping { ts_ms } => assert_eq!(ts_ms, 1_700_000_000_000),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn push_credential_params_roundtrip() {
        use mirage_core::crypto::{CredentialParams, CredentialScheme, EpochEntry};
        let frame = MonitorToNode::PushCredentialParams {
            generation: 7,
            params: CredentialParams::single(
                7,
                CredentialScheme::EpochHmac,
                vec![EpochEntry::with_secret(42, 1_700_000_000_000, [3u8; 32])],
            ),
        };
        let s = serde_json::to_string(&frame).unwrap();
        assert!(s.contains(r#""type":"push_credential_params""#));
        let back: MonitorToNode = serde_json::from_str(&s).unwrap();
        match back {
            MonitorToNode::PushCredentialParams { generation, params } => {
                assert_eq!(generation, 7);
                assert_eq!(params.authorities[0].epochs.len(), 1);
                assert_eq!(params.authorities[0].epochs[0].epoch_id, 42);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn push_subscriber_keys_roundtrip() {
        use mirage_core::entrance_wire::SubscriberKeyWireEntry;
        let frame = MonitorToNode::PushSubscriberKeys {
            generation: 3,
            entries: vec![
                SubscriberKeyWireEntry {
                    public_key_hex: "aa".repeat(32),
                    personal_mesh_id: Some("sub-1".to_string()),
                    caps: None,
                    egress_country: Some("nl".to_string()),
                },
                SubscriberKeyWireEntry {
                    public_key_hex: "bb".repeat(32),
                    personal_mesh_id: None,
                    caps: None,
                    egress_country: None,
                },
            ],
        };
        let s = serde_json::to_string(&frame).unwrap();
        assert!(s.contains(r#""type":"push_subscriber_keys""#));
        let back: MonitorToNode = serde_json::from_str(&s).unwrap();
        match back {
            MonitorToNode::PushSubscriberKeys { generation, entries } => {
                assert_eq!(generation, 3);
                assert_eq!(entries.len(), 2);
                assert_eq!(entries[0].public_key_hex, "aa".repeat(32));
                assert_eq!(entries[0].personal_mesh_id.as_deref(), Some("sub-1"));
                assert_eq!(entries[0].egress_country.as_deref(), Some("nl"));
                assert_eq!(entries[1].public_key_hex, "bb".repeat(32));
                assert!(entries[1].personal_mesh_id.is_none());
            }
            _ => panic!("wrong variant"),
        }
    }

    /// An empty `entries` vec — the "revoke everyone" full-set replace —
    /// round-trips: `Vec::is_empty` must not be treated as "field absent"
    /// on the way back in, and the frame must not collapse into a
    /// different variant.
    #[test]
    fn push_subscriber_keys_empty_entries_round_trips_as_revoke_everyone() {
        let frame = MonitorToNode::PushSubscriberKeys {
            generation: 9,
            entries: Vec::new(),
        };
        let s = serde_json::to_string(&frame).unwrap();
        assert!(s.contains(r#""entries":[]"#));
        let back: MonitorToNode = serde_json::from_str(&s).unwrap();
        match back {
            MonitorToNode::PushSubscriberKeys { generation, entries } => {
                assert_eq!(generation, 9);
                assert!(entries.is_empty());
            }
            _ => panic!("wrong variant"),
        }
    }

    /// A frame minted before `PushSubscriberKeys` existed (any neighbouring
    /// `MonitorToNode` variant, e.g. `Ping`) still decodes under the enum
    /// that now carries the new variant — adding a variant to an internally
    /// tagged enum does not disturb decoding of a JSON payload tagged with
    /// a DIFFERENT, pre-existing variant.
    #[test]
    fn old_shape_frame_without_the_new_variant_still_decodes() {
        let old_shape_json = r#"{"type":"ping","ts_ms":1700000000000}"#;
        let frame: MonitorToNode = serde_json::from_str(old_shape_json).unwrap();
        match frame {
            MonitorToNode::Ping { ts_ms } => assert_eq!(ts_ms, 1_700_000_000_000),
            _ => panic!("wrong variant"),
        }

        let old_listener_set_json =
            r#"{"type":"push_listener_set","generation":1,"listeners":[]}"#;
        let frame2: MonitorToNode = serde_json::from_str(old_listener_set_json).unwrap();
        match frame2 {
            MonitorToNode::PushListenerSet { generation, listeners } => {
                assert_eq!(generation, 1);
                assert!(listeners.is_empty());
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn node_to_monitor_listener_bound() {
        let json = r#"{"type":"listener_bound","listener_id":"L1","bound_addr":"0.0.0.0:4700","bind_port":4700}"#;
        let frame: NodeToMonitor = serde_json::from_str(json).unwrap();
        match frame {
            NodeToMonitor::ListenerBound { listener_id, bind_port, .. } => {
                assert_eq!(listener_id, "L1");
                assert_eq!(bind_port, Some(4700));
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn node_to_monitor_listener_registered_roundtrip() {
        let frame = NodeToMonitor::ListenerRegistered {
            listener_id: "L-chain-1".into(),
            updated_at_ms: 1_700_000_000_000,
            sig_hex: Some("ab".repeat(64)),
        };
        let s = serde_json::to_string(&frame).unwrap();
        assert!(s.contains(r#""type":"listener_registered""#));
        assert!(!s.contains("bound_addr"));
        assert!(!s.contains("bind_port"));
        let back: NodeToMonitor = serde_json::from_str(&s).unwrap();
        match back {
            NodeToMonitor::ListenerRegistered {
                listener_id,
                updated_at_ms,
                sig_hex,
            } => {
                assert_eq!(listener_id, "L-chain-1");
                assert_eq!(updated_at_ms, 1_700_000_000_000);
                assert_eq!(sig_hex, Some("ab".repeat(64)));
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn node_to_monitor_listener_registered_minimal_json() {
        // Node with no signing key configured omits sig_hex and can omit
        // updated_at_ms (defaults to 0) — must still deserialize cleanly.
        let json = r#"{"type":"listener_registered","listener_id":"L1"}"#;
        let frame: NodeToMonitor = serde_json::from_str(json).unwrap();
        match frame {
            NodeToMonitor::ListenerRegistered { listener_id, updated_at_ms, sig_hex } => {
                assert_eq!(listener_id, "L1");
                assert_eq!(updated_at_ms, 0);
                assert_eq!(sig_hex, None);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn snapshot_entry_optional_chain_id() {
        let s = r#"{"listener_id":"L","bind_port":1,"bound_addr":"x","state":"bound"}"#;
        let e: ListenerSnapshotEntry = serde_json::from_str(s).unwrap();
        assert!(e.chain_id.is_none());
        assert!(e.chain_node_ids.is_empty());
    }

    #[test]
    fn pong_roundtrip_with_ts_ms() {
        let frame = NodeToMonitor::Pong { ts_ms: 1_700_000_000_123 };
        let s = serde_json::to_string(&frame).unwrap();
        assert!(s.contains(r#""type":"pong""#));
        let back: NodeToMonitor = serde_json::from_str(&s).unwrap();
        match back {
            NodeToMonitor::Pong { ts_ms } => assert_eq!(ts_ms, 1_700_000_000_123),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn pong_ts_ms_defaults_when_absent() {
        // Legacy node (pre-D1) sends a bare `{"type":"pong"}` with no
        // `ts_ms` field — must deserialize with `ts_ms` defaulting to 0,
        // not error (rolling-upgrade safety).
        let s = r#"{"type":"pong"}"#;
        let frame: NodeToMonitor = serde_json::from_str(s).unwrap();
        match frame {
            NodeToMonitor::Pong { ts_ms } => assert_eq!(ts_ms, 0),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn node_egress_report_roundtrip() {
        let frame = NodeToMonitor::NodeEgressReport {
            probed_at_ms: 1_700_000_000_000,
            observations: vec![
                NodeEgressObservation {
                    to_node_id: "peer1".into(),
                    status: "ok".into(),
                    rtt_ms: Some(25),
                    dgram_status: None,
                    dgram_rtt_ms: None,
                    dgram_probe_ms: None,
                },
                NodeEgressObservation {
                    to_node_id: "peer2".into(),
                    status: "timeout".into(),
                    rtt_ms: None,
                    dgram_status: None,
                    dgram_rtt_ms: None,
                    dgram_probe_ms: None,
                },
            ],
        };
        let s = serde_json::to_string(&frame).unwrap();
        assert!(s.contains(r#""type":"node_egress_report""#));
        assert!(s.contains("peer1"));
        assert!(s.contains("peer2"));
        // rtt_ms absent for timeout observation
        let peer2_pos = s.find("peer2").unwrap();
        let after_peer2 = &s[peer2_pos..];
        assert!(!after_peer2.contains("\"rtt_ms\""));
        let back: NodeToMonitor = serde_json::from_str(&s).unwrap();
        match back {
            NodeToMonitor::NodeEgressReport { probed_at_ms, observations } => {
                assert_eq!(probed_at_ms, 1_700_000_000_000);
                assert_eq!(observations.len(), 2);
                assert_eq!(observations[0].rtt_ms, Some(25));
                assert_eq!(observations[1].rtt_ms, None);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn subscriber_consumption_report_roundtrip() {
        let frame = NodeToMonitor::SubscriberConsumptionReport {
            reported_at_ms: 1_700_000_000_000,
            subscribers: vec![
                SubscriberConsumptionObservation {
                    subscriber_key_hex: "ab".repeat(32),
                    consumed_bytes_since_last_report: 12_345,
                    degraded: false,
                },
                SubscriberConsumptionObservation {
                    subscriber_key_hex: "cd".repeat(32),
                    consumed_bytes_since_last_report: 0,
                    degraded: true,
                },
            ],
        };
        let s = serde_json::to_string(&frame).unwrap();
        assert!(s.contains(r#""type":"subscriber_consumption_report""#));
        let back: NodeToMonitor = serde_json::from_str(&s).unwrap();
        match back {
            NodeToMonitor::SubscriberConsumptionReport {
                reported_at_ms,
                subscribers,
            } => {
                assert_eq!(reported_at_ms, 1_700_000_000_000);
                assert_eq!(subscribers.len(), 2);
                assert_eq!(subscribers[0].consumed_bytes_since_last_report, 12_345);
                assert!(!subscribers[0].degraded);
                assert!(subscribers[1].degraded);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn subscriber_consumption_report_empty_subscribers_defaults() {
        // A node with nothing to report sends only the tag + timestamp; the
        // monitor must still parse `subscribers` as empty rather than error.
        let json = r#"{"type":"subscriber_consumption_report","reported_at_ms":5}"#;
        let frame: NodeToMonitor = serde_json::from_str(json).unwrap();
        match frame {
            NodeToMonitor::SubscriberConsumptionReport {
                reported_at_ms,
                subscribers,
            } => {
                assert_eq!(reported_at_ms, 5);
                assert!(subscribers.is_empty());
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn unknown_variant_deserializes_gracefully() {
        // Old monitor receiving a new unknown NodeToMonitor variant.
        let json = r#"{"type":"future_unknown_frame","some_field":42}"#;
        let frame: NodeToMonitor = serde_json::from_str(json).unwrap();
        assert!(matches!(frame, NodeToMonitor::Unknown));
    }

    #[test]
    fn node_egress_observation_ok_has_rtt() {
        let obs = NodeEgressObservation {
            to_node_id: "x".into(),
            status: "ok".into(),
            rtt_ms: Some(12),
                    dgram_status: None,
                    dgram_rtt_ms: None,
                    dgram_probe_ms: None,
                };
        let s = serde_json::to_string(&obs).unwrap();
        let back: NodeEgressObservation = serde_json::from_str(&s).unwrap();
        assert_eq!(back.rtt_ms, Some(12));
        assert_eq!(back.status, "ok");
    }

    #[test]
    fn node_egress_observation_fail_no_rtt() {
        let obs = NodeEgressObservation {
            to_node_id: "y".into(),
            status: "timeout".into(),
            rtt_ms: None,
                    dgram_status: None,
                    dgram_rtt_ms: None,
                    dgram_probe_ms: None,
                };
        let s = serde_json::to_string(&obs).unwrap();
        // skip_serializing_if = None means rtt_ms key absent
        assert!(!s.contains("rtt_ms"));
    }
}
