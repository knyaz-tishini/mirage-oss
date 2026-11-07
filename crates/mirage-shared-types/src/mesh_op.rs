//! Monitor-originated durable-store RPC contract (`MeshOp`).
//!
//! Lives here — not in `mirage2dbworker`'s `proto.rs` — because BOTH sides
//! of this wire need the type: the monitor CONSTRUCTS a [`MeshRequest`],
//! db-worker DESERIALISES and dispatches one. Neither crate depends on the
//! other; both already depend on `mirage-shared-types` + `mirage-core`, so
//! this is the natural shared home (mirrors the doc plan
//! `docs/mirage/plans/storage-consolidation-2026-07-02.md` §2.4/§3 Phase 0).
//!
//! ## Trust domain — separate from `DbOp`
//!
//! `mirage2dbworker::proto::DbOp`/`DbRequest` is the OPERATOR-debug raw-SQL
//! surface: `operator_sig` verifies against the fleet-wide pinned operator
//! Ed25519 pubkey (`operator_pinned` table), and `DbOp::Exec` runs
//! unrestricted SQL under that trust.
//!
//! `MeshOp`/`MeshRequest` here is the MONITOR-originated typed surface. Its
//! trust boundary is the transport, not an app-layer signature: monitor and
//! db-worker talk over the db-worker control WS on loopback, and that WS is
//! already mutually authenticated at handshake (operator-signed
//! `DeclaredIdentity` + X25519 static-key + `SenderProof` DH-MAC, verified
//! against the pinned operator pubkey). A `MeshRequest` frame arriving on
//! that WS is provably from the monitor at the other end of the connection —
//! db-worker derives the real caller identity from the authenticated WS
//! session, never from a field inside the request body. The monitor is not a
//! fact-signer (excluded from `role_signs_facts`) and holds no box-signing
//! key to sign requests with, so there is no per-request signature to check.
//!
//! These two surfaces MUST NEVER be merged: `MeshOp` stays a fixed whitelist
//! of typed operations dispatched only to callers on the authenticated
//! monitor-side WS; `DbOp::Exec`'s unrestricted SQL surface stays gated on
//! the separate operator-key check. `db-worker`'s dispatcher (Phase 0:
//! `handle_mesh_op`) only ever executes the whitelisted `MeshOp` variants
//! below — never raw SQL.
//!
//! ## Phase 0 scope
//!
//! The enum below is the FULL contract per plan §2.4 (all variants, so the
//! wire type is complete and later phases are additive-only). db-worker's
//! Phase 0 dispatcher implements only the two boot-seed reads
//! (`ListMonitors` / `ListPeers`); every other
//! variant returns a typed `not_implemented_phase0` error, never a silent
//! stub success.

use serde::{Deserialize, Serialize};

/// Which gossip-replicated CIDR list a `ListSinceCidr` call targets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CidrKind {
    Live,
    External,
}

/// Monitor-originated durable-store operations. Trust comes from the
/// authenticated db-worker control WS the request arrives on, not from any
/// field inside the request itself — see the module-level doc comment.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum MeshOp {
    // ── boot-time identity seed (cold, once per monitor process start) ──
    ListMonitors,
    /// Node identity rows (peer_table durable mirror).
    ListPeers,
    // ── client / sentry / mshd registries (cold, register+heartbeat rate) ──
    UpsertClient {
        client_id: String,
        reg_json: String,
        registered_at: String,
        updated_at_ms: u64,
        origin_lm_id: String,
    },
    SaveClientHeartbeat {
        client_id: String,
        heartbeat_json: String,
        at: String,
        updated_at_ms: u64,
        origin_lm_id: String,
    },
    DeleteClient {
        client_id: String,
    },
    UpsertSentry {
        sentry_id: String,
        machine_id: Option<String>,
        role: Option<String>,
        shortname: Option<String>,
        now_ms: u64,
    },
    SaveSentryHeartbeat {
        sentry_id: String,
        load_json: Option<String>,
        now_ms: u64,
    },
    UpsertMshd {
        mshd_id: String,
        machine_id: Option<String>,
        role: Option<String>,
        shortname: Option<String>,
        now_ms: u64,
    },
    SaveMshdHeartbeat {
        mshd_id: String,
        now_ms: u64,
    },
    UpsertDbWorker {
        worker_id: String,
        machine_id: Option<String>,
        shortname: Option<String>,
        now_ms: u64,
    },

    // ── mshd blob staging (cold, per-blob not per-connection) ──
    UpsertMshdBlobManifest {
        manifest_json: String,
    },
    UpsertMshdBlobChunk {
        blob_id: String,
        idx: u32,
        nonce: [u8; 12],
        ct: Vec<u8>,
    },
    GetMshdBlobManifest {
        blob_id: String,
    },
    ListPendingBlobsFor {
        mshd_id: String,
    },
    GetMshdBlobChunk {
        blob_id: String,
        idx: u32,
    },
    /// Mirrors `RelayStore::list_mshd_blob_chunks_for`
    /// (`mirage2monitor/crates/monitor/src/store.rs:502`). Returns ALL
    /// chunks for `blob_id`, ordered by `idx` — distinct from
    /// `GetMshdBlobChunk`'s single-chunk-by-index lookup. Used by the
    /// one-shot `GET /relay/mshd/blob/{blob_id}` fetch path, which ships
    /// the whole blob (manifest + every chunk) in one response.
    ListMshdBlobChunksFor {
        blob_id: String,
    },
    MarkMshdBlobDelivered {
        blob_id: String,
        delivered_at_ms: u64,
    },
    /// Mirrors `RelayStore::get_mshd_blob_delivered_at`
    /// (`mirage2monitor/crates/monitor/src/store.rs:565`). Returns the
    /// `delivered_at_ms` for a blob, or `None` if not delivered / not
    /// found — used by the peer-gossip LWW apply path
    /// (`api.rs::apply_incoming_peer_event::MshdBlobDelivered`) to decide
    /// whether an incoming delivery tombstone is newer than the local row.
    GetMshdBlobDeliveredAt {
        blob_id: String,
    },
    /// Mirrors `RelayStore::list_expired_mshd_blobs`
    /// (`mirage2monitor/crates/monitor/src/store.rs:582`). Lists blobs
    /// past hard TTL or past grace-after-delivery, for the blob TTL
    /// reaper (`main.rs` Etape 6 background task).
    ListExpiredMshdBlobs {
        now_ms: u64,
        hard_ttl_ms: u64,
        grace_ms: u64,
    },
    /// Mirrors `RelayStore::delete_mshd_blob`
    /// (`mirage2monitor/crates/monitor/src/store.rs:551`). Hard-deletes a
    /// blob and all its chunks. Returns `true` if a row was deleted.
    DeleteMshdBlob {
        blob_id: String,
    },

    // ── gossip-replicated LWW state (cold, sub-Hz apply rate) ──
    UpsertLiveCidrLww {
        cidr: String,
        source_lm_id: String,
        first_seen_ms: u64,
        last_seen_ms: u64,
        updated_at_ms: u64,
    },
    UpsertExternalCidrLww {
        list_id: String,
        cidr: String,
        label: Option<String>,
        updated_at_ms: u64,
    },
    UpsertAppSplitConfigLww {
        scope_id: String,
        config_key: String,
        config_json: String,
        updated_at_ms: u64,
    },
    ListSinceCidr {
        kind: CidrKind,
        since_ms: u64,
    },

    // ── signed facts (cold, seconds-to-minutes cadence) ──
    UpsertMachineStateLww {
        row_json: String,
    },
    UpsertSecurityPostureLww {
        row_json: String,
    },
    ListMachineState,
    ListSecurityPosture,

    // ── service_config (cold, node-boot rate) ──
    GetServiceConfig {
        role: String,
    },
    /// Mirrors the monitor's admin write path
    /// (`mirage2monitor api.rs::handle_admin_put_service_config`, currently
    /// raw `INSERT OR REPLACE INTO service_config`). No LWW guard — same
    /// last-writer-wins semantics as the handler it replaces; `updated_at_ms`
    /// is server-computed by the CALLER (the monitor), not db-worker, exactly
    /// as today.
    PutServiceConfig {
        role: String,
        config_json: String,
        updated_at_ms: i64,
    },

    // ── arc2.7: secd desired-state (durable, LWW by updated_at_ms) ──
    /// Mirrors `mirage2dbworker::store::get_secd_desired_state`. Returns
    /// every `secd_desired_state` row for `machine_id` (at most one per
    /// `kind` — `'set_policy'` | `'set_patch_schedule'`); db-worker's
    /// dispatch arm serializes the list as `{"rows": [[kind, blob_b64,
    /// updated_at_ms], ...]}`.
    GetSecdDesiredState {
        machine_id: String,
    },
    /// Mirrors `mirage2dbworker::store::put_secd_desired_state`. LWW:
    /// db-worker skips the write when the stored `updated_at_ms` is already
    /// `>=` the incoming value. `directive_blob` is the whole signed
    /// `mirage_core::secd_directive::SecdDirective`, `serde_json`-serialized
    /// to bytes — never decoded scalars, so the reader can re-run the exact
    /// `apply_directive` dispatch (operator-sig re-verify).
    PutSecdDesiredState {
        machine_id: String,
        kind: String,
        directive_blob: Vec<u8>,
        updated_at_ms: i64,
    },
    /// WAVE 2 (fleet gossip peer-reseed): mirrors db-worker's
    /// `store::list_secd_desired_state_since`. Returns every
    /// `secd_desired_state` row (across ALL machines, unlike
    /// `GetSecdDesiredState` which is scoped to one `machine_id`) with
    /// `updated_at_ms > since_ms`, for the monitor's `/peers/pull` gap-fill
    /// path. db-worker's dispatch arm serializes the list as `{"rows":
    /// [[machine_id, kind, blob_b64, updated_at_ms], ...]}`.
    ListSecdDesiredStateSince {
        since_ms: i64,
    },

    // ── audit ──
    AppendAuditLog {
        entry_json: String,
    },
    /// Mirrors `RelayStore::list_audit_log` (`store.rs:1614`). Cold,
    /// operator-only, low frequency — `GET /relay/audit/log`.
    ListAuditLog {
        since_ms: u64,
        limit: usize,
        role: Option<String>,
    },
    /// Runs the audit-log hash-chain walk entirely db-worker-side and
    /// returns the RESULT of the walk, not the raw rows — mirrors
    /// `RelayStore::list_audit_log_for_verify` (`store.rs:1657`) plus the
    /// break-detection algorithm the monitor's `get_audit_verify` handler
    /// used to run in-process (`api.rs:1607-1676`). Kept result-only so a
    /// large audit_log is never shipped whole over the control WS.
    VerifyAuditChain {},

    // ── Stage D: chain_owners / port_assignments (cold durable) ──
    /// Mirrors `store.rs::upsert_chain_owner` (~3012) — `ON CONFLICT(chain_id)
    /// DO UPDATE`, so a full-row opaque payload isn't needed: all three
    /// scalar params map 1:1 onto the SQL bind list.
    UpsertChainOwner {
        chain_id: String,
        client_id: String,
        requester_role: String,
    },
    /// Mirrors `store.rs::get_chain_owner` (~3032).
    GetChainOwner {
        chain_id: String,
    },
    /// Mirrors `store.rs::list_chain_owners_for_client` (~3055).
    ListChainOwnersForClient {
        client_id: String,
    },
    /// Mirrors `store.rs::delete_chain_owner` (~3078).
    DeleteChainOwner {
        chain_id: String,
    },

    /// Mirrors `store.rs::insert_chain_port_assignment` (~2896). **CAS
    /// semantics**: fails on UNIQUE violation (allocator must have already
    /// checked `used_ports_on_node` — this is the last-line collision
    /// guard). db-worker's dispatch arm MUST surface that failure via
    /// `MeshResponse::error_kind = Some(MeshErrorKind::UniqueViolation)`,
    /// never collapse it into a generic string error.
    InsertChainPortAssignment {
        chain_id: String,
        hop_position: u8,
        node_id: String,
        bind_port: u16,
        kind: String,
    },
    /// Mirrors `store.rs::release_chain_port_assignments` (~2917).
    ReleaseChainPortAssignments {
        chain_id: String,
    },
    /// Mirrors `store.rs::used_ports_on_node` (~2932). Note: the monitor
    /// method also unions in `desired_listeners.spec_json` bind ports on
    /// the same connection — db-worker's dispatch arm reproduces that same
    /// two-table union server-side (single param here, same as the source
    /// method's signature).
    UsedPortsOnNode {
        node_id: String,
    },
    /// Mirrors `store.rs::list_chain_port_assignments` (~2984).
    ListChainPortAssignments {
        chain_id: String,
    },
}

/// Sent monitor → db-worker over the existing db-worker control WS
/// (monitor-originated direction, additive to the operator-originated
/// `DbRequest`/`DbResponse` flow already carried on that same connection).
///
/// Authentication is entirely at the transport level: the control WS this
/// request travels on is already mutually authenticated at handshake, so
/// there is no per-request signature field here. See the module-level doc
/// comment for the full trust-domain writeup.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeshRequest {
    /// Caller-chosen correlation id; echoed on the response.
    pub cmd_id: String,
    /// Unix-seconds after which db-worker must reject the request.
    pub expires_at_unix: i64,
    /// The op itself + its parameters.
    #[serde(flatten)]
    pub op: MeshOp,
    /// The calling monitor's `DeclaredIdentity.self_id` (UUID string),
    /// carried for logging / diagnostics only. NOT trusted for
    /// authentication — the trust boundary is the authenticated control WS
    /// this request arrives on; db-worker derives the real caller identity
    /// from that WS session, never from this field.
    pub caller_monitor_id: String,
}

/// Typed discriminator for [`MeshResponse::error_kind`]. Added so a caller
/// (e.g. the chain-port-assignment allocator) can distinguish a specific
/// failure class from a generic error without string-matching the
/// human-readable [`MeshResponse::error`] text across the wire.
///
/// Additive: unknown-to-an-older-binary variants never appear on the wire
/// today (this is the first variant), and the field itself is `Option` so
/// old responses that never set it still deserialize fine (see
/// `MeshResponse::error_kind`'s `skip_serializing_if`/default-`None` path).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MeshErrorKind {
    /// SQLite UNIQUE constraint violation — used as the CAS "slot already
    /// taken" signal by `InsertChainPortAssignment` (`store.rs:2894`
    /// comment: "Fails on UNIQUE violation — allocator must check
    /// `used_ports_on` first").
    UniqueViolation,
    /// The request's `expires_at_unix` was in the past when db-worker
    /// received it.
    Expired,
    /// The op is recognised but not yet implemented by this db-worker
    /// build (Phase-0-style rollout gap).
    NotImplemented,
}

/// Response shape, structurally identical to
/// `mirage2dbworker::proto::DbResponse` — kept as its own type here since
/// `mirage-shared-types` cannot depend on the db-worker binary crate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeshResponse {
    /// Echo of the request `cmd_id`.
    pub cmd_id: String,
    /// `true` if the op completed without error.
    pub ok: bool,
    /// On success: the result JSON (rows / table list / etc.).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    /// On failure: human-readable error string.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// On failure: typed discriminator, when the failure maps onto a known
    /// class (see [`MeshErrorKind`]). `None` for both success responses and
    /// failures that don't fit a typed category (falls back to `error`'s
    /// free-text message) — old wire producers that never set this field
    /// deserialize as `None` here, so this is backward-compatible.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub error_kind: Option<MeshErrorKind>,
}

impl MeshResponse {
    pub fn ok(cmd_id: String, result: serde_json::Value) -> Self {
        Self { cmd_id, ok: true, result: Some(result), error: None, error_kind: None }
    }

    pub fn err(cmd_id: String, error: String) -> Self {
        Self { cmd_id, ok: false, result: None, error: Some(error), error_kind: None }
    }

    /// Same as [`MeshResponse::err`], plus a typed discriminator so the
    /// caller can branch without parsing `error`'s free text (e.g. the
    /// chain-port-assignment allocator telling "port taken" apart from
    /// "transport/db error").
    pub fn err_kind(cmd_id: String, error: String, kind: MeshErrorKind) -> Self {
        Self { cmd_id, ok: false, result: None, error: Some(error), error_kind: Some(kind) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mesh_response_roundtrip() {
        let r = MeshResponse::ok("c1".into(), serde_json::json!({"n": 1}));
        let s = serde_json::to_string(&r).unwrap();
        let parsed: MeshResponse = serde_json::from_str(&s).unwrap();
        assert!(parsed.ok);
        assert_eq!(parsed.cmd_id, "c1");
        assert_eq!(parsed.error_kind, None);
    }

    #[test]
    fn mesh_response_err_kind_roundtrip() {
        let r = MeshResponse::err_kind(
            "c2".into(),
            "port 10101 already assigned on node n-1".into(),
            MeshErrorKind::UniqueViolation,
        );
        let s = serde_json::to_string(&r).unwrap();
        let parsed: MeshResponse = serde_json::from_str(&s).unwrap();
        assert!(!parsed.ok);
        assert_eq!(parsed.error_kind, Some(MeshErrorKind::UniqueViolation));
        assert_eq!(parsed.error.as_deref(), Some("port 10101 already assigned on node n-1"));
    }

    #[test]
    fn mesh_response_old_wire_shape_without_error_kind_still_deserializes() {
        // Simulates a response produced by a pre-Stage-D db-worker binary
        // that never emits `error_kind` on the wire at all — proves the
        // new field is backward-compatible, not just "works when present".
        let old_wire_json = serde_json::json!({
            "cmd_id": "c3",
            "ok": false,
            "error": "not_implemented_phase0"
        });
        let parsed: MeshResponse = serde_json::from_value(old_wire_json).unwrap();
        assert!(!parsed.ok);
        assert_eq!(parsed.error_kind, None);
        assert_eq!(parsed.error.as_deref(), Some("not_implemented_phase0"));
    }
}
