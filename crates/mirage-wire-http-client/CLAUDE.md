# mirage-wire-http-client — agent rules

Wire-HTTP-over-V9 client for a **non-opbox** process. Lets any process that
holds its own operator-signed `DeclaredIdentity` + static X25519 keypair —
today: `mirage2panel`'s automated-issuance back-office (owner's ruling,
2026-09-23, `docs/mirage/plans/2026-09-23-backoffice-automated-issuance.md`
§9 Brief 8) — dial a Mirage monitor's HTTP routes over the V9 wire with the
same V9 sender-proof headers opbox's own `wire_http::wire_request` already
builds, without depending on `operator-box` (which is opbox-only: local
inventory, sqlite, SSH, provider APIs — none of that belongs in a
back-office process, and none of it is in this crate's dependency graph).

## Public API

```rust
pub struct WireFace {
    pub host: String,
    pub port: u16,
    pub camouflage: mirage_core::mirage::wire::TransportCamouflage,
    pub static_pubkey_hex: String,
}

pub struct WireHttpClient { /* .. */ }

impl WireHttpClient {
    pub fn new(identity: DeclaredIdentity, priv_key: [u8; 32], mesh_id: impl Into<String>, faces: Vec<WireFace>) -> Self;
    pub fn with_timeouts(self, connect: Duration, handshake: Duration, recv_idle: Duration) -> Self;
    pub async fn request(&self, method: &str, path: &str, body: Option<&[u8]>) -> Result<(u16, Vec<u8>), WireHttpError>;
}
```

`request` tries every face in `faces`, in order, with a bounded per-face
connect timeout (default 3s) and handshake timeout (default 5s) — see
`DEFAULT_FACE_CONNECT_TIMEOUT` / `DEFAULT_FACE_HANDSHAKE_TIMEOUT`. A face
that fails is recorded (`FaceAttempt { face, error }`) and the walk moves
to the next; total failure returns `WireHttpError::AllFacesFailed(attempts)`
naming every face tried and why, never just the last one.

## What this mirrors from opbox, function by function

Source of truth read (read-only, never edited by this crate's author):
`mirage2operator/crates/operator-box/src/wire_http.rs`.

| opbox (`operator-box::wire_http`) | This crate | What changed |
|---|---|---|
| `wire_request` / `wire_request_inner` | `WireHttpClient::request` / `try_one_face` | No `OperatorState`, no `MachineRow`, no session pool (`wire_reqresp_pool`) — every call dials fresh. See "Session reuse" below. |
| `dial_first_answering` + `build_dial_order` | `WireHttpClient::request`'s face loop | No `WireStats`-backed "preferred face" memory across calls (opbox remembers which face answered last, process-lifetime) — this crate always walks `faces` in the order the caller supplied. No `Progress`/telemetry reporting. |
| `resolve_monitor_wire_params` + `resolve_face_candidates` | *(caller's job)* | This crate takes an already-resolved `Vec<WireFace>` — it does not read any inventory, capsule or `service_config` to build one. The caller (the panel's `entrance_relay_client.rs`, Brief 8b) is responsible for turning a `GET /relay/entrance/dial-faces` (or an identity-install payload) response into `WireFace`s. |
| `build_request_head` | `http::build_request_head` | Same HTTP/1.1 status-line + header framing. Ported near-verbatim. |
| `run_one_exchange` / `read_http_response` / `read_chunked_body` / `recv_idle` / `find_subslice` | `http::{run_one_exchange, ...}` (same names, `pub(crate)`) | Ported unchanged — pure framing over `&mut dyn Tunnel`, no opbox state was ever in these functions. |
| `MonitorWireParams` / `WireCandidate` / `FaceSource` | `WireFace` | Flattened: opbox's `WireCandidate` is one face of ONE resolved monitor (`MonitorWireParams` carries the shared pubkey); `WireFace` carries its OWN `static_pubkey_hex` per entry, because the automated-issuance plan's own §2 has this crate's caller dial "any monitor" from a flat candidate list, not one resolved target's face set. |
| — (not ported) | — | `wire_session_pool::ReqRespSession` / `wire_stats::{WireStats, Progress, CallOutcome}` — opbox-only telemetry and pooling infrastructure. See "Session reuse" below. |

Sender-proof header construction is **not** duplicated here at all —
`WireHttpClient::sender_proof_headers` calls this crate's own
`sender_proof::build_sender_proof_headers`, the exact function the
monitor's own verifier checks and that opbox's own `wire_http::
build_request_head` mirrors byte-for-byte in its own inlined copy. The
implementation was moved here verbatim from the fleet's mesh-client crate
when the deep libraries were split out into this OSS repository, so that
this layer carries no fleet dependency; the MAC formula is unchanged.

## Session reuse — deliberately not ported

opbox's `wire_reqresp_pool` keeps one already-authenticated tunnel per
machine alive across calls, because opbox makes MANY calls to the SAME
small fleet in a tight loop (mesh fan-out, `/relay/*` polling). The
back-office's own call pattern (Brief 8b/9: one put or one read per
customer action) does not have that shape, and pooling needs a place to
live BETWEEN calls — this crate is stateless beyond one `WireHttpClient`
value, deliberately, so it carries no `Arc<Mutex<..>>` pool and no
process-lifetime cache. If a future caller's call volume justifies it,
adding a pool here is a `WireHttpClient`-internal change (a `HashMap<face
label, Session>` behind an `Arc<tokio::sync::Mutex<_>>>`, mirroring
`wire_session_pool`'s own shape) — it does not change the public
`request` signature.

## No opbox state types

This crate depends on `mirage-core`, `mirage-protocol` only. No
`mirage-operator`/`operator-box` dependency, and none of
`OperatorState`, `MachineRow`, `sqlite`, `WireStats`, `Progress` appear
anywhere in this crate — confirmed by construction (nothing in this
crate's `Cargo.toml` path-deps on `operator-box`). It depends on NO fleet
crate either: the sender-proof primitive it used to borrow from the
fleet's mesh-client crate now lives in `src/sender_proof.rs`.

## Switching opbox to call this crate (a later step, not done here)

Not done in this change — opbox is untouched. When it happens, it is
mechanical against the table above:

1. `operator-box` adds a path-dep on `mirage-wire-http-client`.
2. `resolve_monitor_wire_params`/`resolve_face_candidates` keep their job
   (opbox still resolves faces from its OWN inventory/capsule state) but
   their OUTPUT gets adapted into `Vec<WireFace>` instead of
   `MonitorWireParams`/`Vec<WireCandidate>`.
3. `wire_request`'s body becomes a call to
   `WireHttpClient::new(op_identity.declared, op_identity.priv_key, mesh_id,
   faces).request(method, path, body)`.
4. `wire_session_pool`/`wire_stats` stay in `operator-box` UNCHANGED —
   either wrapped around the new call (pool per-machine `WireHttpClient`
   instances, since a fresh dial per `request` costs one V9 handshake) or
   left as the next increment once the pool is ported into this crate per
   the "Session reuse" section above.

## Tests

- `http::tests` — request-head framing (method upper-cased, sender-proof
  headers present, `Content-Length`/`Content-Type` only when a body is
  present) and full request/response exchange round-trips (content-length,
  chunked, non-2xx status, malformed response) against an in-memory
  `MockTunnel`.
- `client::tests::sender_proof_mac_verifies_by_x25519_symmetry_with_the_documented_formula`
  — **no standalone sender-proof verifier function exists anywhere in the
  `mirage2web` workspace to import** (confirmed by grep across the tree
  before writing this test — `MonitorSenderVerifier::verify` lives only in
  `mirage2monitor`, a different subgit this crate must not depend on). The
  test instead proves the MAC by X25519's symmetry: this crate's own
  `sender_proof_headers` (which calls the shared, non-duplicated
  `build_sender_proof_headers`) computes `shared = X25519(client_priv,
  monitor_pub)`; the test independently recomputes `shared' =
  X25519(monitor_priv, client_pub)` — the SAME secret by construction — and
  hashes it with the exact formula documented (identically) in both
  `monitor_dial::build_sender_proof_headers` and opbox's
  `wire_http::build_request_head`. If a shared verifier crate is ever
  extracted into `mirage2web` (out of scope here), point this test at it
  directly and delete the recomputation.
- `client::tests::request_walks_every_face_in_order_after_the_first_fails` —
  two bind-then-drop loopback listeners (real `ECONNREFUSED`, no live
  peer), proving `request` tries BOTH faces, in order, rather than stopping
  after the first failure.
