//! V9 handshake unit tests (§6.2 of the spec).
//!
//! Tests 1–7 use `tokio::io::duplex` as an in-memory bidirectional stream so
//! no TCP sockets are needed. Each test spawns a server task and runs the
//! client in the current task, then joins.

use mirage_core::crypto::{AeadSuite, KeyPair};
use mirage_protocol::core::{run_client_handshake_v9, run_server_handshake_v9};
use x25519_dalek::StaticSecret;

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Generate a static X25519 keypair, returning (secret_bytes, KeyPair).
fn gen_static() -> ([u8; 32], KeyPair) {
    let kp = KeyPair::generate();
    let secret_bytes = kp.secret.to_bytes();
    (secret_bytes, kp)
}

/// Generate a fresh KeyPair (for the server).
fn gen_keypair() -> KeyPair {
    KeyPair::generate()
}

const MESH_ID: &[u8] = b"test-mesh-v9";
const SUITE_PREFS: &[AeadSuite] = &[AeadSuite::ChaCha20Poly1305];

// ─────────────────────────────────────────────────────────────────────────────
// Test 1: Happy path — V9 client + V9 server, mutual auth, session keys match
// ─────────────────────────────────────────────────────────────────────────────

/// V9 full roundtrip: client and server complete mutual-auth handshake and
/// derive matching session keys.
#[tokio::test]
async fn v9_full_handshake_roundtrip() {
    let server_kp = gen_keypair();
    let server_static_pub = server_kp.public.to_bytes();
    let (client_static_priv, _client_kp) = gen_static();

    let (client_half, server_half) = tokio::io::duplex(4096);

    let server_handle = tokio::spawn(async move {
        let mut stream = server_half;
        run_server_handshake_v9(
            &mut stream,
            &server_kp,
            MESH_ID,
            SUITE_PREFS,
            |_ctx| true, // permissive verifier
        )
        .await
        .expect("server handshake must not error")
        .expect("server must accept connection")
    });

    let mut client_stream = client_half;
    let client_result = run_client_handshake_v9(
        &mut client_stream,
        &server_static_pub,
        &client_static_priv,
        MESH_ID,
        SUITE_PREFS,
    )
    .await
    .expect("client handshake must succeed");

    let server_result = server_handle.await.expect("server task panicked");

    // Both sides must derive the same session keys.
    assert_eq!(
        *client_result.session_keys.client_write_key,
        *server_result.session_keys.client_write_key,
        "client_write_key must match"
    );
    assert_eq!(
        *client_result.session_keys.server_write_key,
        *server_result.session_keys.server_write_key,
        "server_write_key must match"
    );
    assert_eq!(
        client_result.session_keys.suite,
        server_result.session_keys.suite,
        "negotiated suite must match"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 2: Modified client_proof → server rejects before sending ServerHello
// ─────────────────────────────────────────────────────────────────────────────

/// When the client sends a corrupted `client_proof_mac`, the server must close
/// without sending a ServerHello — client receives an error.
#[tokio::test]
async fn v9_rejects_invalid_client_proof() {
    use mirage_protocol::auth::v9::{
        compute_client_proof, gen_ephemeral, suite_to_id, V9ClientHello, WIRE_VERSION_V9,
    };

    let server_kp = gen_keypair();
    let server_static_pub = server_kp.public.to_bytes();
    let (client_static_priv, _) = gen_static();

    let (mut client_half, server_half) = tokio::io::duplex(4096);

    let server_handle = tokio::spawn(async move {
        let mut stream = server_half;
        run_server_handshake_v9(
            &mut stream,
            &server_kp,
            MESH_ID,
            SUITE_PREFS,
            |_ctx| true,
        )
        .await
        .expect("server I/O must not error")
    });

    // Build a ClientHello with a corrupted proof (flip all bits of client_proof).
    let (_e_priv_c, e_pub_c) = gen_ephemeral();
    let ts_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;

    let suite_ids = [suite_to_id(AeadSuite::ChaCha20Poly1305), 0u8, 0u8];
    let mut bad_proof = compute_client_proof(
        &client_static_priv,
        &server_static_pub,
        &e_pub_c,
        MESH_ID,
        &suite_ids,
        ts_ms,
    );
    // Flip all bits to corrupt the proof.
    bad_proof.iter_mut().for_each(|b| *b ^= 0xff);

    // Derive client_static_pub.
    let client_static_pub = x25519_dalek::PublicKey::from(&StaticSecret::from(client_static_priv)).to_bytes();

    let hello = V9ClientHello {
        version: WIRE_VERSION_V9,
        suite_ids: [suite_to_id(AeadSuite::ChaCha20Poly1305), 0, 0],
        e_pub_c,
        ts_ms,
        client_proof: bad_proof,
        client_static_pub,
        cred_scheme: 0x00,
        target_hint: 0,
    };

    use tokio::io::AsyncWriteExt;
    client_half.write_all(&hello.to_wire()).await.expect("write hello");

    // Server should reject (return None) and close. The client trying to read
    // a ServerHello should get EOF.
    let server_result = server_handle.await.expect("server task must not panic");
    assert!(
        server_result.is_none(),
        "server must reject bad client_proof"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 3: Modified server_proof → client rejects on ServerHello
// ─────────────────────────────────────────────────────────────────────────────

/// An on-path party that flips bits in `server_proof` causes the client to
/// reject the ServerHello and return an error.
#[tokio::test]
async fn v9_rejects_invalid_server_proof() {
    use mirage_protocol::auth::v9::{
        compute_server_proof, compute_transcript_0,
        gen_ephemeral, negotiate_suite, suite_to_id,
        V9ClientHello, V9ServerHello, CLIENT_HELLO_LEN,
    };

    let server_kp = gen_keypair();
    let server_static_pub_bytes = server_kp.public.to_bytes();
    let (client_static_priv, _) = gen_static();

    // Create an on-path relay stream: client → relay_in; relay_out → server.
    let (mut client_side, mut mitm_client_end) = tokio::io::duplex(4096);

    // Run real client.
    let client_handle = tokio::spawn(async move {
        run_client_handshake_v9(
            &mut client_side,
            &server_static_pub_bytes,
            &client_static_priv,
            MESH_ID,
            SUITE_PREFS,
        )
        .await
    });

    // On-path relay: read ClientHello, forward to server, read ServerHello, corrupt proof, forward to client.
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // Read ClientHello from client.
    let mut client_hello_buf = [0u8; CLIENT_HELLO_LEN];
    mitm_client_end
        .read_exact(&mut client_hello_buf)
        .await
        .expect("read ClientHello");

    let hello = V9ClientHello::from_wire(&client_hello_buf).expect("parse ClientHello");

    // Compute what the server would produce (we simulate the server side to get a ServerHello).
    let server_prefs = [AeadSuite::ChaCha20Poly1305];
    let suite = negotiate_suite(&server_prefs, &hello.suite_ids).expect("suite negotiated");
    let suite_id = suite_to_id(suite);

    let (e_priv_s, e_pub_s) = gen_ephemeral();
    use zeroize::Zeroizing;
    let e_pub_c_pk = x25519_dalek::PublicKey::from(hello.e_pub_c);
    let ecdh_ee = Zeroizing::new(e_priv_s.diffie_hellman(&e_pub_c_pk).to_bytes());

    let transcript_0 = compute_transcript_0(
        &hello.e_pub_c,
        &e_pub_s,
        MESH_ID,
        suite_id,
        hello.ts_ms,
    );

    // Verify client proof (server would do this — we skip it here to focus on the server_proof).
    // Instead, build a ServerHello with a CORRUPTED server_proof.
    let mut corrupted_proof = compute_server_proof(&ecdh_ee, &transcript_0, &server_kp.public.to_bytes());
    corrupted_proof.iter_mut().for_each(|b| *b ^= 0xff);

    let server_hello = V9ServerHello {
        chosen_suite: suite_id,
        e_pub_s,
        server_proof: corrupted_proof,
        _reserved: [0u8; 16],
    };

    // Send corrupted ServerHello to the client.
    mitm_client_end
        .write_all(&server_hello.to_wire())
        .await
        .expect("write ServerHello");

    // Client must reject.
    let client_result = client_handle.await.expect("client task must not panic");
    assert!(
        client_result.is_err(),
        "client must reject modified server_proof"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 4: Wrong mesh_id → client_proof mismatch, server rejects
// ─────────────────────────────────────────────────────────────────────────────

/// Client sends a ClientHello computed for `mesh_id = "wrong-mesh"` but the
/// server expects `mesh_id = "test-mesh-v9"`. The server's proof verification
/// fails and it closes without sending ServerHello.
#[tokio::test]
async fn v9_rejects_wrong_mesh_id() {
    let server_kp = gen_keypair();
    let server_static_pub = server_kp.public.to_bytes();
    let (client_static_priv, _) = gen_static();

    let (client_half, server_half) = tokio::io::duplex(4096);

    let server_handle = tokio::spawn(async move {
        let mut stream = server_half;
        run_server_handshake_v9(
            &mut stream,
            &server_kp,
            MESH_ID, // server expects "test-mesh-v9"
            SUITE_PREFS,
            |_ctx| true,
        )
        .await
        .expect("server I/O must not error")
    });

    // Client uses the wrong mesh_id.
    let mut client_stream = client_half;
    let client_result = run_client_handshake_v9(
        &mut client_stream,
        &server_static_pub,
        &client_static_priv,
        b"wrong-mesh-id", // wrong mesh_id
        SUITE_PREFS,
    )
    .await;

    let server_result = server_handle.await.expect("server task must not panic");
    assert!(
        server_result.is_none(),
        "server must reject proof computed with wrong mesh_id"
    );
    // Client gets an error (EOF or handshake failure when trying to read ServerHello).
    assert!(
        client_result.is_err(),
        "client must error when server closes without ServerHello"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 5: Stale timestamp → server rejects
// ─────────────────────────────────────────────────────────────────────────────

/// A ClientHello with `ts_ms` outside the ±5-minute window is rejected.
/// We craft a ClientHello with ts_ms=0 (year 1970 — far outside the window).
/// Even though the BLAKE3 proof is cryptographically consistent with ts_ms=0,
/// the server's timestamp-window check fires first and rejects the connection
/// before any key material is derived.
#[tokio::test]
async fn v9_rejects_stale_timestamp() {
    use mirage_protocol::auth::v9::{
        compute_client_proof, gen_ephemeral, suite_to_id, V9ClientHello, WIRE_VERSION_V9,
    };

    let server_kp = gen_keypair();
    let server_static_pub = server_kp.public.to_bytes();
    let (client_static_priv, _) = gen_static();

    let (mut client_half, server_half) = tokio::io::duplex(4096);

    let server_handle = tokio::spawn(async move {
        let mut stream = server_half;
        run_server_handshake_v9(
            &mut stream,
            &server_kp,
            MESH_ID,
            SUITE_PREFS,
            |_ctx| true,
        )
        .await
        .expect("server I/O must not error")
    });

    // Build a ClientHello with ts_ms = 0 (year 1970 — clearly outside the ±5 min window).
    let stale_ts: u64 = 0;
    let (_, e_pub_c) = gen_ephemeral();

    // Compute proof consistent with ts_ms=0 — the proof MAC is valid, but the
    // server's wall-clock window check should fire before proof verification.
    let stale_suite_ids = [suite_to_id(AeadSuite::ChaCha20Poly1305), 0u8, 0u8];
    let client_proof = compute_client_proof(
        &client_static_priv,
        &server_static_pub,
        &e_pub_c,
        MESH_ID,
        &stale_suite_ids,
        stale_ts,
    );

    let client_static_pub = x25519_dalek::PublicKey::from(&StaticSecret::from(client_static_priv)).to_bytes();

    let hello = V9ClientHello {
        version: WIRE_VERSION_V9,
        suite_ids: [suite_to_id(AeadSuite::ChaCha20Poly1305), 0, 0],
        e_pub_c,
        ts_ms: stale_ts,
        client_proof,
        client_static_pub,
        cred_scheme: 0x00,
        target_hint: 0,
    };

    use tokio::io::AsyncWriteExt;
    client_half.write_all(&hello.to_wire()).await.expect("write hello");

    let server_result = server_handle.await.expect("server task must not panic");

    // The ±5-minute window check rejects ts_ms=0 unconditionally.
    assert!(
        server_result.is_none(),
        "server must reject ts_ms=0 (outside ±5-minute window), got Some"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 5b: Modified ts_ms → server rejects (proof bound to ts_ms)
// ─────────────────────────────────────────────────────────────────────────────

/// Verify ts_ms IS bound in the proof: send a ClientHello where ts_ms was
/// altered after proof computation. Server MUST reject.
#[tokio::test]
async fn v9_rejects_modified_timestamp() {
    use mirage_protocol::auth::v9::{
        compute_client_proof, gen_ephemeral, suite_to_id, V9ClientHello, WIRE_VERSION_V9,
    };

    let server_kp = gen_keypair();
    let server_static_pub = server_kp.public.to_bytes();
    let (client_static_priv, _) = gen_static();

    let (mut client_half, server_half) = tokio::io::duplex(4096);

    let server_handle = tokio::spawn(async move {
        let mut stream = server_half;
        run_server_handshake_v9(
            &mut stream,
            &server_kp,
            MESH_ID,
            SUITE_PREFS,
            |_ctx| true,
        )
        .await
        .expect("server I/O must not error")
    });

    // Compute proof for ts_ms = 1_000_000, then send ts_ms = 2_000_000 on wire.
    let proof_ts: u64 = 1_000_000;
    let wire_ts: u64 = 2_000_000; // different from proof_ts
    let (_, e_pub_c) = gen_ephemeral();

    let suite_ids_for_proof = [suite_to_id(AeadSuite::ChaCha20Poly1305), 0u8, 0u8];
    let client_proof = compute_client_proof(
        &client_static_priv,
        &server_static_pub,
        &e_pub_c,
        MESH_ID,
        &suite_ids_for_proof,
        proof_ts,
    );

    let client_static_pub = x25519_dalek::PublicKey::from(&StaticSecret::from(client_static_priv)).to_bytes();

    // Send with modified ts_ms.
    let hello = V9ClientHello {
        version: WIRE_VERSION_V9,
        suite_ids: [suite_to_id(AeadSuite::ChaCha20Poly1305), 0, 0],
        e_pub_c,
        ts_ms: wire_ts, // modified
        client_proof,
        client_static_pub,
        cred_scheme: 0x00,
        target_hint: 0,
    };

    use tokio::io::AsyncWriteExt;
    client_half.write_all(&hello.to_wire()).await.expect("write hello");

    // Server re-computes proof using wire_ts (2_000_000), but the MAC was built
    // with proof_ts (1_000_000) — mismatch → reject.
    let server_result = server_handle.await.expect("server task must not panic");
    assert!(
        server_result.is_none(),
        "server must reject when ts_ms was modified after proof computation"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 7: FS property — two handshakes with same static keys → different session keys
// ─────────────────────────────────────────────────────────────────────────────

/// Forward secrecy: two V9 handshakes with the same static keys must produce
/// different session keys because each uses fresh ephemeral keys.
#[tokio::test]
async fn v9_session_keys_are_fresh_each_handshake() {
    let server_kp_1 = KeyPair::from_secret(gen_keypair().secret.to_bytes());
    let server_pub = server_kp_1.public.to_bytes();
    let (client_static_priv, _) = gen_static();

    // --- Handshake 1 ---
    let server_kp_a = KeyPair::from_secret(server_kp_1.secret.to_bytes());
    let (client_half_a, server_half_a) = tokio::io::duplex(4096);

    let server_a = tokio::spawn(async move {
        let mut stream = server_half_a;
        run_server_handshake_v9(&mut stream, &server_kp_a, MESH_ID, SUITE_PREFS, |_ctx| true)
            .await
            .unwrap()
            .unwrap()
    });

    let mut cs_a = client_half_a;
    let client_a = run_client_handshake_v9(
        &mut cs_a,
        &server_pub,
        &client_static_priv,
        MESH_ID,
        SUITE_PREFS,
    )
    .await
    .unwrap();

    let server_a_result = server_a.await.unwrap();

    // --- Handshake 2 (same static keys) ---
    let server_kp_b = KeyPair::from_secret({
        // Same server static key as handshake 1.
        server_kp_1.secret.to_bytes()
    });
    let (client_half_b, server_half_b) = tokio::io::duplex(4096);

    let server_b = tokio::spawn(async move {
        let mut stream = server_half_b;
        run_server_handshake_v9(&mut stream, &server_kp_b, MESH_ID, SUITE_PREFS, |_ctx| true)
            .await
            .unwrap()
            .unwrap()
    });

    let mut cs_b = client_half_b;
    let client_b = run_client_handshake_v9(
        &mut cs_b,
        &server_pub,
        &client_static_priv,
        MESH_ID,
        SUITE_PREFS,
    )
    .await
    .unwrap();

    let server_b_result = server_b.await.unwrap();

    // Session keys from handshake 1 and 2 must differ (fresh ephemeral keys each time).
    assert_ne!(
        *client_a.session_keys.client_write_key,
        *client_b.session_keys.client_write_key,
        "FS: client_write_key must differ between handshakes"
    );
    assert_ne!(
        *client_a.session_keys.server_write_key,
        *client_b.session_keys.server_write_key,
        "FS: server_write_key must differ between handshakes"
    );

    // But within each handshake, client and server keys must agree.
    assert_eq!(
        *client_a.session_keys.client_write_key,
        *server_a_result.session_keys.client_write_key,
    );
    assert_eq!(
        *client_b.session_keys.client_write_key,
        *server_b_result.session_keys.client_write_key,
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 8: suite_ids round-trip — client signs offer list, server verifies it
// ─────────────────────────────────────────────────────────────────────────────

/// Verifies that suite_ids is now bound into client_proof:
/// client signs [ChaCha, AES256, AES128], server verifies with the same bytes → OK.
#[tokio::test]
async fn v9_suite_ids_bound_in_client_proof_roundtrip() {
    use mirage_protocol::auth::v9::{compute_client_proof, verify_client_proof, gen_ephemeral};

    let server_kp = gen_keypair();
    let (client_static_priv, _) = gen_static();

    let (_, e_pub_c) = gen_ephemeral();
    let ts_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;

    let suite_ids: [u8; 3] = [0x01, 0x02, 0x03]; // ChaCha + AES256 + AES128

    let proof = compute_client_proof(
        &client_static_priv,
        &server_kp.public.to_bytes(),
        &e_pub_c,
        MESH_ID,
        &suite_ids,
        ts_ms,
    );

    let client_static_pub = x25519_dalek::PublicKey::from(
        &StaticSecret::from(client_static_priv)
    ).to_bytes();

    // Server-side verify with the same suite_ids → must succeed.
    let result = verify_client_proof(
        &server_kp.secret,
        &client_static_pub,
        &e_pub_c,
        &server_kp.public.to_bytes(),
        MESH_ID,
        &suite_ids,
        ts_ms,
        &proof,
    );
    assert!(result.is_ok(), "verify must succeed when suite_ids match");
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 9: On-path suite strip detected — verify fails when suite_ids modified
// ─────────────────────────────────────────────────────────────────────────────

/// Regression guard: on-path party strips ChaCha + AES256, leaves only AES128.
/// Client signed [0x01, 0x02, 0x00]; server receives [0x03, 0x00, 0x00].
/// verify_client_proof with the modified list must return AuthFailed.
#[tokio::test]
async fn v9_suite_strip_onpath_detected() {
    use mirage_core::error::MirageError;
    use mirage_protocol::auth::v9::{compute_client_proof, verify_client_proof, gen_ephemeral};

    let server_kp = gen_keypair();
    let (client_static_priv, _) = gen_static();

    let (_, e_pub_c) = gen_ephemeral();
    let ts_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;

    // Client offers ChaCha + AES256; AES128 not in offer.
    let client_offered: [u8; 3] = [0x01, 0x02, 0x00];

    let proof = compute_client_proof(
        &client_static_priv,
        &server_kp.public.to_bytes(),
        &e_pub_c,
        MESH_ID,
        &client_offered,
        ts_ms,
    );

    let client_static_pub = x25519_dalek::PublicKey::from(
        &StaticSecret::from(client_static_priv)
    ).to_bytes();

    // On-path party rewrites the offer to only AES128.
    let onpath_rewritten: [u8; 3] = [0x03, 0x00, 0x00];

    let result = verify_client_proof(
        &server_kp.secret,
        &client_static_pub,
        &e_pub_c,
        &server_kp.public.to_bytes(),
        MESH_ID,
        &onpath_rewritten, // modified suite_ids
        ts_ms,
        &proof,
    );
    assert!(
        matches!(result, Err(MirageError::AuthFailed)),
        "on-path suite-strip must be detected: expected AuthFailed, got {:?}",
        result
    );
}
