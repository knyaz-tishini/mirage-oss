//! `mirage-core` — shared types for the stack on Mirage VPS nodes.
//!
//! - [`mirage`] — native Mirage chain stack. Has its own wire plane
//!   (RelayMode/ExitMode/Camouflage/AEAD), mesh plane (MeshId, NodeId,
//!   ChainId, PeerTable, ChainBinding), and ListenerSpec.
//!
//! (The former `standalone` foreign-wire branch — AWG / Trojan /
//! Shadowsocks / VLESS-Reality / ShadowTLS / Hysteria2-native /
//! QUIC-xray / Websocket-xray — was hard-deleted; Mirage's own wire
//! plane is the only branch left.)

pub mod mirage;

// ── Strongly-typed identifiers ────────────────────────────────────────
//
// Replaces the prior `String` typing of mesh_id / lm_id / monitor_id /
// node_id everywhere. Mixing different id types is a compile error,
// which catches the bugs the previous string-everywhere approach hid
// (e.g. comparing `lm_id` with `responsible_monitor_id` when the two
// shapes silently diverged).
pub mod ids;

// Machine metadata reader (`nemo/inventory.toml`).
pub mod inventory;

// ── Shared monitor↔node control plane ─────────────────────────────────
// Envelope types used by the node's WS client. NodeFrame lives here.
pub mod control;

// ── Crypto + frame primitives (used by both branches but not branch-specific) ─
pub mod crypto;
pub mod frame;

// Re-export the blind-token issuance/verification primitive so consumers that
// may only depend on `mirage-core` (e.g. operator-box) reach it without taking
// a direct dependency on the leaf crate. The 0x03 verify path uses it internally
// (see crypto::credential); issuers reach issuer_keygen / blind_sign here.
pub use mirage_blindtoken;

// ── Independent helpers ──────────────────────────────────────────────
pub mod dns;
pub mod error;
pub mod routing;
pub mod sealed_secret;
pub mod identity;
pub mod box_signing;
pub mod dk_delivery;

// Identity capsules — the sealed, RAM-only replacement for baked identity.
// Same envelope as `dk_delivery`, but the plaintext is a whole identity
// instead of one key, and the trust anchor is dual (operator OR the FROST
// group key carried in an operator-signed charter).
pub mod capsule;

// The capsule's country table in its compact, portable form (gzip +
// base64). The compressed bytes ride inside the signed preimage of the
// gossiped `service_config` anchor, so the compressor is pinned to an
// exact version — see the module doc for why.
pub mod country_table;

// The append-only, signed record of who the mesh has admitted — the half of
// quorum issuance that is independent of FROST. `capsule` already VERIFIES a
// group-signed capsule; this is what the quorum says while producing one.
pub mod quorum;

// The one credential that stays on disk: a per-machine key whose only power is
// to make a boot announce credible. It is what lets the quorum admit a rebooted
// box without the operator, and it is a different asset class from anything in
// `capsule` — it decrypts nothing and joins nothing.
pub mod attestation;

// The operator's reversible, fleet-wide on/off switch for one machine — a
// SIBLING fact to `attestation` (same signature-verification model, an
// independent LWW clock), not a field folded into it. See the module doc for
// why the two must stay separate.
pub mod machine_park;

// Operator-signed, gossiped `service_config` — lets any monitor source a
// subject's `CapsuleServiceConfig` when minting a capsule, not only the
// subject's own box. Sibling fact to `machine_park`, same signing shape,
// operator-only (no quorum authority — see the module doc for why).
pub mod service_config_anchor;

// There is NO per-mesh exit-selection policy fact here any more.
//
// The module that used to live at this slot (`mesh_policy`) carried three
// operator-settable knobs — an exit-authorisation mode, a region blacklist
// mode and a same-region mode — plus the operator-signed fact that gossiped
// them to the monitors. It is GONE, deliberately, not dormant: the owner
// re-thought the rule on 2026-10-23 and it collapsed to ONE rule with no
// knobs at all.
//
//   * auto  — the exit must NOT be in the CLIENT's own country.
//   * manual — the client named an exit region; the mesh honours it verbatim.
//
// The knobs that went with it were answers to questions the new rule does not
// ask. "Which regions may be exits?" is now "which region may this client's
// exit be in?", and the answer lives on the CLIENT's registration
// (`ClientRegistration.country`), not in an operator fact. "Should a banned
// region be excluded, penalised or preferred?" is now "may the exit be in the
// client's own country at all?" — and the answer is always "no", so there is
// nothing to tune.
//
// A future reader who wants a policy fact back should know what it cost: the
// fact made the rule per-MESH and operator-settable, and in exchange it made
// the rule INERT whenever the operator did not issue it (the default mode was
// fail-open), so the fleet silently served the exits the rule was supposed to
// forbid. The rule now has no configuration surface, which means it cannot be
// switched off by omission.

// The `Unidentified -> announce -> capsule -> Identified` boot state machine
// every service shares. One implementation, so the identity cross-checks the
// baked path did by hand in seven places happen in exactly one place.
pub mod identity_boot;

// A box minting its own full machine identity from `attestation` alone — no
// operator, no quorum, no network. Sibling to `identity_boot` rather than
// folded into it: that module owns the announce/capsule EXCHANGE, this one
// owns the one box-local case where nothing is exchanged at all.
pub mod self_issue;
/// Per-box perimeter persona — the deterministic face list a box publishes.
/// Shared because both the operator and the box's own warden must derive
/// the SAME surface; see the module doc for what went wrong while only one
/// of them could.
pub mod persona;

// Self-collected platform facts for a boot announce's attestation-bound
// PlatformFingerprint (admission gate 4) — what BootSession::with_platform
// attaches. See its own module doc for the read-or-nothing gather rule.
pub mod platform_probe;

// This box's own network-interface addresses, read from the kernel — the
// shared fact behind "does an address belong to this box". Used by
// `mirage-secd`'s never-ban-self guard and by `mirage-mesh-client`'s
// monitor-dial self-check; see the module doc for why the enumeration lives
// here rather than in either of those crates.
pub mod local_interface_addrs;

pub mod shared_store;

// Log-on-change gate for CONFIRMATION/REJECTION spam — see module doc.
pub mod log_state;

// ── arc2.9 operator→warden graceful-restart command envelope ───────────
// Moved here (verbatim) from `mirage-secd::pair` so platform-neutral
// consumers (opbox, Windows dev box) can build a signed OperatorCommand
// without depending on mirage-secd (Linux-only). mirage-secd::pair
// re-exports this module's items so every `mirage_secd::pair::*` path
// keeps resolving.
pub mod operator_cmd;

/// Map a [`identity::ServiceRole`] to its on-disk / DB slug. Shared so
/// every callsite uses the same canonical string for table keys and
/// state-dir suffixes.
pub fn role_slug_for(role: &identity::ServiceRole) -> &'static str {
    use identity::ServiceRole;
    use ids::NodeEpoch;
    match role {
        ServiceRole::Node { epoch: NodeEpoch::V1 } => "node-v1",
        ServiceRole::Node { epoch: NodeEpoch::V2 } => "node-v2",
        ServiceRole::Node { epoch: NodeEpoch::V3 } => "node-v3",
        ServiceRole::Monitor => "monitor",
        ServiceRole::Sentry => "sentry",
        ServiceRole::Mshd => "mshd",
        ServiceRole::Sentinel => "sentinel",
        ServiceRole::Secd => "secd",
        ServiceRole::DbWorker => "db-worker",
        ServiceRole::Warden => "warden",
        ServiceRole::Operator => "operator",
        ServiceRole::Perimeter => "perimeter",
        ServiceRole::Edge => "edge",
        ServiceRole::BackOffice => "back-office",
    }
}

// ── Split-tunnel typed policy (monitor→client wire) ──────────────────
pub mod split_policy;

// ── mshd zero-trust blob delivery ───────────────────────────────────────────
pub mod mshd_blob;

// ── Flow-metadata contract (instructions DOWN / metadata UP) ─────────
pub mod metadata;
pub use metadata::{ClientMetadataReport, FlowObservation, MetadataPolicy};

// ── Per-fact signing helpers (canonical byte layouts for sign+verify) ───────
pub mod fact_signing;

// ── D0 (arc3 Foundation, docs/mirage/plans/
// arc3-foundation-d0-sentry-d1-prober-2026-07-24.md §1): sentry live box
// inventory typed data model (process/listener/outbound/log-level facts +
// the transition journal). Signing-bytes fns + verify_* counterparts live
// in `fact_signing` alongside every other fact's canonical byte layout.
pub mod box_inventory;

// Flat exe_path + systemd unit_name allowlist shared between
// `mirage-secd::protected_units` (kill/scrape enforcement) and
// `mirage2sentry::box_inventory` (MainPID-based process classification) —
// extracted so the two lists cannot drift (D0 plan §1.3).
pub mod mirage_units;

/// The supervisor's typed answer to "which binary is running, since when" —
/// see the module doc for why this replaces every consumer scraping /proc.
pub mod unit_state;

/// The warden's structured answer to an operator-signed `RetireUnit` command
/// (remove a unit from a box) — see the module doc.
pub mod unit_retire;

// ── Who owns a listening socket ─────────────────────────────────────────────
// `sock_diag` asks the kernel which CGROUP owns each socket (netlink
// `INET_DIAG_CGROUP_ID`, not ptrace-gated, so it answers for processes our
// own Tier-2 refuses to let anything read), and `cgroup_units` turns that
// integer into a systemd unit name by inode. Together they are the only way
// on this fleet to say "who is listening on this port" without a privileged
// `/proc/<pid>/fd` walk that Tier-2 denies for exactly the protected
// processes worth asking about.
//
// They lived in `mirage2sentry` until 2026-08-29, when secd needed the same
// answer to decide whether an ADMITTED port is held by the perimeter or by
// something else. One fact, one implementation — a second copy in secd would
// be a second opinion about the same kernel, which is the shape of defect
// this arc keeps finding.
pub mod cgroup_units;
pub mod sock_diag;

// ── secd control directives (operator→secd typed, signed, pull-delivered) ────
pub mod secd_directive;

// ── secd typed policy — orthogonal, capability-gated defense axes ───────────
pub mod secd_policy;

// ── Perimeter → arbiter shared observation contract (arc3 de-root split) ────
// The typed fact a perimeter component (decoy, and later jail/honeypot)
// reports about an inbound touch. Lives here — not in `mirage-perimeter`,
// not in `mirage-secd` — because it is the shared vocabulary both planes
// must name without either depending on the other. See that module's doc.
pub mod local_security_event;
pub mod perimeter_observation;

// What the WAF tells an inward destination about the connection it hands
// over — the real peer, the face, the verdict, the deciding bytes. Replaces
// the arbiter's reassembly of an address from two timing-correlated reports;
// see the module doc.
pub mod perimeter_preamble;

// ── Box-local transport: every channel that never leaves the box ────────────
// One `cfg` for the whole tree — unix socket on unix, loopback TCP on
// Windows — plus the `SO_PEERCRED` identity, the unlink-before-bind, and the
// directory grant that three services had each written for themselves. See
// `docs/mirage/plans/local-transport-unix-sockets-2026-08-15.md`.
pub mod local_endpoint;

// The datagram counterpart to `local_endpoint`: a message-preserving
// box-local channel (`SOCK_DGRAM` unix socket / Windows loopback UDP) for
// carriage that must not be reassembled into a byte stream — the U0 UDP
// front-door plan's local splice. See the module doc for the one open gap
// it deliberately does not close (§3.4 of
// `docs/mirage/plans/udp-front-door-u0-2026-09-05.md`).
pub mod local_dgram_endpoint;

// The one framing every typed box-local channel speaks: magic, version,
// length, body. Generalised from `perimeter_preamble`'s frame rather than
// grown as a third encoding. There is no HTTP and no `curl` in this plane —
// see the module doc for why that is a rule and not a preference.
pub mod local_rpc;

// What the perimeter answers when something on the box asks it a question.
// Here, not in `mirage-perimeter`, because these shapes were defined TWICE —
// once in the producer and once in the operator's reader — and had already
// drifted in both directions.
pub mod perimeter_query;

// What the keeper (`mirage-warden`) answers on the slice-serving socket —
// every supervised service asks for its own role's slice out of the current
// machine capsule. Here, not in `mirage-warden`, for the same reason
// `perimeter_query` lives here: one definition, compiled into the keeper and
// every consumer.
pub mod machine_identity_query;

// What the keeper and mshd say to each other while carrying one machine's
// identity to the mesh and back — `FetchAnnounce` / `DeliverSealed`. A
// SEPARATE protocol and a separate socket from `machine_identity_query`: the
// transport must not be able to ask for a slice, and a service must not be
// able to deliver an envelope.
pub mod machine_identity_handover;

// What db-worker answers about this box's own stored state — the DK backend
// it achieved, secd's durable desired state, a role's self-enable flag.
// Replaces a hand-rolled HTTP server on `127.0.0.1:19446` and four `reqwest`
// readers that each re-derived the shape from JSON.
pub mod local_dbworker;

// ── Internal serde helpers ───────────────────────────────────────────
pub mod hex_fixed;
pub mod b64_serde;

// ── Legacy modules (to retire in Phase 1.6 once consumers migrate).
// These still expose the pre-v3 wire shape — kept so the wider workspace
// keeps compiling during the cutover. ─────────────────────────────────
pub mod config;

// ── Back-office automated issuance (2026-09-23) ─────────────────────────
// docs/mirage/plans/2026-09-23-backoffice-automated-issuance.md §2/§6.2.
pub mod entrance_wire;
pub mod entrance_grant;
