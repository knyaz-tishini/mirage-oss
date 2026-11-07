//! [`WireHttpClient`] — dial a Mirage monitor's HTTP routes over the V9
//! wire with a caller-owned `DeclaredIdentity` + X25519 keypair, trying an
//! ordered list of [`WireFace`]s until one answers.
//!
//! Generalises `mirage2operator/crates/operator-box/src/wire_http.rs`'s
//! `wire_request` / `dial_first_answering` for a caller that is not opbox:
//! no `OperatorState`, no sqlite, no `WireStats`/`Progress` telemetry, and
//! no session pool (see this crate's own CLAUDE.md for what that drops and
//! why it is a later, separable addition). Sender-proof header
//! construction lives in this crate's own `sender_proof` module — the
//! protocol-level primitive, moved here verbatim from the fleet's
//! mesh-client crate so that this OSS layer stays free of fleet
//! dependencies.

use std::net::SocketAddr;
use std::time::Duration;

use mirage_core::config::{AuthMode, MirageEndpointConfig, TransportKind};
use mirage_core::identity::DeclaredIdentity;
use mirage_protocol::driver::run_client_tcp_v9_with_timeouts;

use crate::error::{FaceAttempt, WireHttpError};
use crate::face::WireFace;
use crate::http::{build_request_head, run_one_exchange};

/// Per-face TCP connect bound — mirrors `wire_http::FACE_CONNECT_TIMEOUT`.
pub const DEFAULT_FACE_CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
/// Per-face Mirage handshake bound — mirrors `wire_http::FACE_HANDSHAKE_TIMEOUT`.
pub const DEFAULT_FACE_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
/// Idle bound on a single response `recv()` — mirrors `wire_http::RESPONSE_RECV_IDLE`.
pub const DEFAULT_RESPONSE_RECV_IDLE: Duration = Duration::from_secs(8);

/// A wire-HTTP client for one caller identity, dialling an ordered list of
/// monitor faces.
///
/// Built from exactly the three things a non-opbox process holds: its own
/// signed [`DeclaredIdentity`] + matching X25519 private key, the mesh it
/// was admitted into, and the faces it is allowed to try (read from a
/// monitor's dial-faces route, or handed down at identity-install time —
/// see the automated-issuance plan's §2/§3, Brief 8).
pub struct WireHttpClient {
    identity: DeclaredIdentity,
    priv_key: [u8; 32],
    mesh_id: String,
    faces: Vec<WireFace>,
    connect_timeout: Duration,
    handshake_timeout: Duration,
    recv_idle: Duration,
}

impl WireHttpClient {
    /// `faces` is tried in order on every [`Self::request`] call — no
    /// learned/preferred-face memory across calls (unlike
    /// `wire_http::build_dial_order`'s `WireStats`-backed one), since this
    /// crate carries no state to remember it in. A caller that wants that
    /// property reorders `faces` itself between calls.
    pub fn new(
        identity: DeclaredIdentity,
        priv_key: [u8; 32],
        mesh_id: impl Into<String>,
        faces: Vec<WireFace>,
    ) -> Self {
        Self {
            identity,
            priv_key,
            mesh_id: mesh_id.into(),
            faces,
            connect_timeout: DEFAULT_FACE_CONNECT_TIMEOUT,
            handshake_timeout: DEFAULT_FACE_HANDSHAKE_TIMEOUT,
            recv_idle: DEFAULT_RESPONSE_RECV_IDLE,
        }
    }

    /// Override the per-face connect / handshake bounds and the response
    /// idle-recv bound. Defaults mirror opbox's own measured values
    /// (`wire_http`'s constants) — see this module's own `DEFAULT_*` docs.
    pub fn with_timeouts(mut self, connect: Duration, handshake: Duration, recv_idle: Duration) -> Self {
        self.connect_timeout = connect;
        self.handshake_timeout = handshake;
        self.recv_idle = recv_idle;
        self
    }

    /// Issue one HTTP request to a monitor, trying [`Self::faces`] in
    /// order. Returns the first face's response on success.
    ///
    /// Every attempt dials fresh — no session reuse across calls or across
    /// faces (see this crate's own CLAUDE.md, "Session reuse"). A caller
    /// that expects to make many requests to the same monitor should build
    /// one `WireHttpClient` and call `request` repeatedly; the cost of that
    /// is one fresh V9 handshake per call, same as opbox before its own
    /// session pool landed.
    pub async fn request(&self, method: &str, path: &str, body: Option<&[u8]>) -> Result<(u16, Vec<u8>), WireHttpError> {
        if self.faces.is_empty() {
            return Err(WireHttpError::NoFaces);
        }

        let mut attempts = Vec::with_capacity(self.faces.len());
        for face in &self.faces {
            match self.try_one_face(face, method, path, body).await {
                Ok(resp) => return Ok(resp),
                Err(e) => {
                    tracing::debug!(face = %face.label(), error = %e, "[WIRE-HTTP] face failed, trying the next");
                    attempts.push(FaceAttempt { face: face.label(), error: e });
                }
            }
        }
        Err(WireHttpError::AllFacesFailed(attempts))
    }

    async fn try_one_face(
        &self,
        face: &WireFace,
        method: &str,
        path: &str,
        body: Option<&[u8]>,
    ) -> Result<(u16, Vec<u8>), String> {
        let server_static_pub = decode_pubkey(&face.static_pubkey_hex)
            .ok_or_else(|| format!("static_pubkey_hex is not 32 bytes: '{}'", face.static_pubkey_hex))?;
        let server_addr: SocketAddr = format!("{}:{}", face.host, face.port)
            .parse()
            .map_err(|e| format!("addr parse '{}:{}': {e}", face.host, face.port))?;

        let config = MirageEndpointConfig {
            transport: TransportKind::Tcp,
            auth: AuthMode::Blake3,
            camouflage: face.camouflage.clone(),
            byte_cipher: None,
            byte_cipher_mode: None,
        };

        let mut tunnel = run_client_tcp_v9_with_timeouts(
            &config,
            server_addr,
            &server_static_pub,
            &self.priv_key,
            &face.host,
            self.mesh_id.as_bytes(),
            None, // control-plane dial carries no anonymous credential
            self.connect_timeout,
            self.handshake_timeout,
        )
        .await
        .map_err(|e| format!("dial: {e}"))?;

        let (identity_b64, mac_hex, ts_ms) = self.sender_proof_headers(face)?;

        let content_len = body.map(<[u8]>::len).unwrap_or(0);
        let head = build_request_head(&face.host, &identity_b64, &mac_hex, ts_ms, method, path, content_len);

        let result = run_one_exchange(&mut *tunnel, &head, body.unwrap_or(&[]), self.recv_idle).await;
        // No session pool: every exchange closes its own tunnel regardless
        // of outcome, see the module doc's "Session reuse" note.
        let _ = tunnel.close().await;
        result.map(|resp| (resp.status, resp.body))
    }

    /// Build the three V9 sender-proof header values for one face. Not
    /// re-implemented — delegates to `crate::sender_proof`, the exact
    /// primitive the monitor's own verifier and opbox's
    /// `wire_http::build_request_head` already implement for the identical
    /// purpose (see this crate's module doc). Split out of
    /// [`Self::try_one_face`] so the header construction itself is
    /// unit-testable without a live V9 dial.
    fn sender_proof_headers(&self, face: &WireFace) -> Result<(String, String, u64), String> {
        crate::sender_proof::build_sender_proof_headers(
            Some(&self.identity),
            &self.priv_key,
            &face.static_pubkey_hex,
        )
        .map_err(|e| format!("build sender-proof headers: {e}"))?
        .ok_or_else(|| "build_sender_proof_headers returned None for a present identity".to_string())
    }
}

fn decode_pubkey(hex_str: &str) -> Option<[u8; 32]> {
    hex::decode(hex_str.trim()).ok()?.try_into().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;
    use ed25519_dalek::SigningKey;
    use mirage_core::identity::{RolePublicKeys, ServiceRole};
    use mirage_core::ids::{MachineId, MeshId};
    use mirage_core::mirage::wire::TransportCamouflage;

    /// Build a `DeclaredIdentity` whose `BackOffice` role wire key is
    /// `pub_hex` — enough for `sender_proof_headers`, which only reads the
    /// identity to embed it in the header and never checks its own
    /// signature (the receiving monitor does that; out of this crate's
    /// scope, see the crate CLAUDE.md).
    fn identity_with_pubkey(pub_hex: &str) -> DeclaredIdentity {
        let op = SigningKey::from_bytes(&[9u8; 32]);
        DeclaredIdentity::sign_new(
            uuid::Uuid::from_u128(42),
            MachineId::new("admin-back-office").expect("machine id"),
            MeshId::new("v3-staging").expect("mesh id"),
            vec![ServiceRole::BackOffice],
            vec![RolePublicKeys {
                role: ServiceRole::BackOffice,
                wire_pubkey_hex: pub_hex.to_string(),
                signing_pubkey_hex: None,
            }],
            1_700_000_000_000,
            &op,
        )
    }

    fn face(host: &str, port: u16, pubkey_hex: &str) -> WireFace {
        WireFace::new(host, port, TransportCamouflage::None, pubkey_hex)
    }

    // ── sender-proof headers verify with the formula the monitor's own
    //    verifier implements ──────────────────────────────────────────────
    //
    // `MonitorSenderVerifier::verify` (`mirage2monitor/crates/monitor/src/
    // mesh_receiver.rs`) is the actual receiver of these headers, and it
    // lives in a DIFFERENT subgit this crate must not depend on (per
    // `mirage2operator/CLAUDE.md`, "No dependency on mirage2monitor" — and
    // mirage2web itself carries no such dependency either; confirmed by
    // grep, nothing in this workspace re-exports that verifier). So this
    // test proves the header MAC the same way the monitor's own verifier
    // would arrive at its answer — by X25519's symmetry: the client side
    // (this crate, via `build_sender_proof_headers`) computes
    // `shared = X25519(client_priv, monitor_pub)`; the monitor side
    // computes `shared' = X25519(monitor_priv, client_pub)`. Those are the
    // SAME secret by construction, so recomputing the identical documented
    // formula (`sender_proof::build_sender_proof_headers`'s own doc, which
    // matches `wire_http.rs`'s copy byte-for-byte) from the monitor's own
    // key pair must reproduce the exact MAC the client sent. The MAC
    // formula itself is not re-implemented here beyond that recomputation —
    // it is the one function already shared by every wire-HTTP caller in
    // this codebase.
    #[test]
    fn sender_proof_mac_verifies_by_x25519_symmetry_with_the_documented_formula() {
        let monitor_priv = [11u8; 32];
        let monitor_pub = x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(monitor_priv));
        let monitor_pub_hex = hex::encode(monitor_pub.as_bytes());

        let client_priv = [22u8; 32];
        let client_pub = x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(client_priv));
        let client_pub_hex = hex::encode(client_pub.as_bytes());

        let identity = identity_with_pubkey(&client_pub_hex);
        let client = WireHttpClient::new(identity.clone(), client_priv, "v3-staging", vec![face("m.example", 443, &monitor_pub_hex)]);

        let (identity_b64, mac_hex, ts_ms) = client
            .sender_proof_headers(&client.faces[0])
            .expect("headers build for a present identity");

        // The identity travelling in the header must decode back to the
        // SAME client pubkey the monitor would extract to compute its own
        // half of the DH — proves the envelope round-trips, not just the MAC.
        let decoded: DeclaredIdentity =
            serde_json::from_slice(&base64::engine::general_purpose::STANDARD.decode(&identity_b64).expect("valid base64"))
                .expect("identity round-trips through the header");
        assert_eq!(
            decoded.wire_pubkey_for(&ServiceRole::BackOffice),
            Some(client_pub_hex.as_str())
        );

        // The monitor-side recomputation — independent of `build_sender_proof_headers`,
        // using ITS OWN private key and the CLIENT's pubkey read back out of
        // the header, exactly as `MonitorSenderVerifier::verify` does.
        let shared_at_monitor = x25519_dalek::StaticSecret::from(monitor_priv)
            .diffie_hellman(&x25519_dalek::PublicKey::from(client_pub.to_bytes()));
        let expected_mac: [u8; 32] = {
            let mut h = blake3::Hasher::new();
            h.update(b"MIRAGE-SENDER-PROOF-V1");
            h.update(shared_at_monitor.as_bytes());
            h.update(monitor_pub_hex.as_bytes());
            h.update(&ts_ms.to_be_bytes());
            *h.finalize().as_bytes()
        };
        assert_eq!(mac_hex, hex::encode(expected_mac), "monitor-side recomputation must match the header's MAC");
    }

    #[test]
    fn sender_proof_headers_carry_a_fresh_timestamp_each_call() {
        let identity = identity_with_pubkey(&"aa".repeat(32));
        let client = WireHttpClient::new(identity, [3u8; 32], "v3-staging", vec![face("m.example", 443, &"bb".repeat(32))]);
        let (_, mac_a, ts_a) = client.sender_proof_headers(&client.faces[0]).expect("headers");
        std::thread::sleep(Duration::from_millis(2));
        let (_, mac_b, ts_b) = client.sender_proof_headers(&client.faces[0]).expect("headers");
        assert!(ts_b >= ts_a, "timestamp must not go backwards between calls");
        if ts_b != ts_a {
            assert_ne!(mac_a, mac_b, "a changed timestamp must change the MAC");
        }
    }

    // ── face fallback order on a failed first face ──────────────────────
    //
    // Two bind-then-drop loopback listeners: `TcpListener::bind` reserves
    // the port, then the listener is immediately dropped, so a subsequent
    // connect gets a real, fast `ECONNREFUSED` — the same technique the
    // fleet's own dial-faces tests use. Both faces
    // refuse, so `request` must return `AllFacesFailed` naming BOTH faces,
    // IN ORDER — proving the walk did not stop after the first failure.
    #[tokio::test]
    async fn request_walks_every_face_in_order_after_the_first_fails() {
        let first_addr = reserve_and_drop_loopback_port().await;
        let second_addr = reserve_and_drop_loopback_port().await;

        let identity = identity_with_pubkey(&"aa".repeat(32));
        let faces = vec![
            face(&first_addr.ip().to_string(), first_addr.port(), &"cc".repeat(32)),
            face(&second_addr.ip().to_string(), second_addr.port(), &"dd".repeat(32)),
        ];
        let client = WireHttpClient::new(identity, [4u8; 32], "v3-staging", faces.clone())
            .with_timeouts(Duration::from_millis(500), Duration::from_millis(500), Duration::from_millis(500));

        let err = client
            .request("GET", "/relay/entrance/dial-faces", None)
            .await
            .expect_err("nothing listens on either dropped port");

        match err {
            WireHttpError::AllFacesFailed(attempts) => {
                assert_eq!(attempts.len(), 2, "both faces must have been tried, not just the first");
                assert_eq!(attempts[0].face, faces[0].label(), "face order is preserved: first face attempted first");
                assert_eq!(attempts[1].face, faces[1].label(), "face order is preserved: second face attempted second");
            }
            other => panic!("expected AllFacesFailed, got {other}"),
        }
    }

    #[tokio::test]
    async fn request_refuses_with_no_faces_before_dialling_anything() {
        let identity = identity_with_pubkey(&"aa".repeat(32));
        let client = WireHttpClient::new(identity, [5u8; 32], "v3-staging", vec![]);
        let err = client.request("GET", "/x", None).await.expect_err("empty face list");
        assert!(matches!(err, WireHttpError::NoFaces));
    }

    async fn reserve_and_drop_loopback_port() -> SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind ephemeral loopback port");
        let addr = listener.local_addr().expect("local_addr of a bound listener");
        drop(listener); // stale now: a real, immediate ECONNREFUSED, no live peer
        addr
    }
}
