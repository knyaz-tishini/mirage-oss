//! Core ECDH handshake primitives.
//!
//! Both sides use ephemeral X25519 keys.  The `AuthMode` dispatch determines how
//! the key material is authenticated.  After a successful handshake both sides
//! hold matching `SessionKeys`.
//!
//! ## V8 Flow (default)
//! ```text
//! CLIENT                           SERVER
//!   gen e_priv, e_pub
//!   ecdh = ECDH(server_static_pub, e_priv)
//!   msg  = auth.build_client_msg(e_pub, ecdh)
//!   send msg ─────────────────────────────▶  recv msg
//!                                            e_pub = auth.verify_server(msg, keypair, mesh_id)
//!                                            ecdh  = ECDH(server_priv, e_pub)
//!                                            keys  = SessionKeys::derive(ecdh, e_pub)
//!                                            confirm = auth.build_server_confirm(ecdh, s_pub, mesh_id)
//!                                 ◀───────── send confirm (32 bytes)
//!   recv confirm
//!   auth.verify_client_confirm(confirm, ecdh, s_pub, mesh_id)
//!   keys = SessionKeys::derive(ecdh, e_pub)
//! ```
//!
//! ## V9 Flow (version probe — first byte 0x09)
//!
//! `run_server_handshake` reads the first byte to detect version. If 0x09 it
//! routes to `run_server_handshake_v9`. Otherwise it falls back to the legacy
//! V8 path, prepending the already-read byte to reconstruct the full 64-byte
//! client message — V8 behaviour is byte-identical.
//!
//! `run_client_handshake_v9` is available for direct use in tests and future
//! V9 client activation. The default `run_client_handshake` always uses V8 so
//! existing callers are unchanged.

use mirage_core::{
    crypto::{AeadSuite, KeyPair, SessionKeys},
    error::MirageError,
};
use rand::rngs::OsRng;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::auth::{
    dispatch_build_server_confirm, dispatch_client_msg, dispatch_client_msg_len,
    dispatch_verify_client_confirm, dispatch_verify_server, AuthMode,
};
use crate::auth::v9::{
    compute_client_proof, compute_server_proof, compute_transcript_0, derive_v9_keys,
    gen_ephemeral, id_to_suite, negotiate_suite, suite_to_id, verify_client_proof,
    verify_server_proof, TargetHint, V9ClientHello, V9ServerHello, CLIENT_HELLO_LEN,
    SERVER_HELLO_LEN, VERSION_REJECT, WIRE_VERSION_V9,
};

// ─────────────────────────────────────────────────────────────────────────────
// ClientAuthContext — credential context passed to client_auth closures
// ─────────────────────────────────────────────────────────────────────────────

/// Context passed to the V9 `client_auth` closure on the server side.
///
/// Built after `client_proof` is verified and (when `scheme_byte != 0x00`) after
/// the credential frame is read. The closure receives this context and returns
/// `true` to accept or `false` to reject the connection.
///
/// The credential bytes are opaque to `mirage-protocol` — cryptographic
/// verification (e.g. calling `mirage_core::crypto::verify_credential`) is the
/// responsibility of the caller's closure.
pub struct ClientAuthContext<'a> {
    /// Client's static X25519 public key (32 bytes, from ClientHello bytes 60..92).
    pub static_pub: &'a [u8; 32],
    /// Millisecond UTC timestamp from the ClientHello (replay-window checked before
    /// this context is built).
    pub ts_ms: u64,
    /// Client ephemeral X25519 public key (from ClientHello bytes 4..36).
    pub e_pub_c: &'a [u8; 32],
    /// Credential scheme wire byte at ClientHello position 92.
    ///
    /// `0x00` = legacy / no credential present. Non-zero identifies the scheme
    /// used for the credential bytes in `credential`.
    pub scheme_byte: u8,
    /// Raw credential bytes received in the `[2B len BE][token]` frame that
    /// follows the 97B hello when `scheme_byte != 0x00`. Empty when
    /// `scheme_byte == 0x00`.
    pub credential: &'a [u8],
}

/// Maximum credential frame payload length. Enforced before allocation so a
/// pre-auth peer cannot trigger an unbounded read.
///
/// `pub(crate)` — reused as-is by `crate::core::udp_handshake` so datagram
/// carriage caps a credential at the exact same size as the stream path
/// rather than inventing a second number for the same kind of data.
pub(crate) const MAX_CREDENTIAL_LEN: usize = 1024;

// ─────────────────────────────────────────────────────────────────────────────
// Result types
// ─────────────────────────────────────────────────────────────────────────────

/// Result of a successful client-side handshake.
pub struct ClientHandshakeResult {
    pub session_keys: SessionKeys,
    /// Server's static public key (echoed or verified, depending on `AuthMode`).
    pub remote_s_pub: [u8; 32],
}

/// Result of a successful server-side handshake.
pub struct ServerHandshakeResult {
    pub session_keys: SessionKeys,
    /// Client's ephemeral public key (V8) or client's static pubkey (V9).
    pub remote_e_pub: [u8; 32],
}

// ─────────────────────────────────────────────────────────────────────────────
// Client-side handshake (V8 default — unchanged behaviour)
// ─────────────────────────────────────────────────────────────────────────────

/// Perform the client side of the Mirage ECDH handshake.
///
/// `mesh_id` — mesh identifier bytes baked into the Blake3 confirm label.
/// Both client and server must supply the same `mesh_id`; a mismatch causes
/// `verify_client_confirm` to return `Err(MirageError::Handshake)`.
///
/// Default mode: V8. Existing callers are unchanged.
/// For V9 use `run_client_handshake_v9` directly.
pub async fn run_client_handshake<S>(
    stream: &mut S,
    server_pubkey: &[u8; 32],
    auth: &AuthMode,
    mesh_id: &[u8],
    suite: AeadSuite,
) -> Result<ClientHandshakeResult, MirageError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // Generate ephemeral key pair.
    let e_priv = EphemeralSecret::random_from_rng(OsRng);
    let e_pub = PublicKey::from(&e_priv);
    let e_pub_bytes = e_pub.to_bytes();

    // ECDH against server's static public key.
    let server_pk = PublicKey::from(*server_pubkey);
    let ecdh_bytes = e_priv.diffie_hellman(&server_pk).to_bytes();

    // Build and send the client handshake message (V3: mesh_id bound into hint).
    let msg = dispatch_client_msg(auth, &e_pub_bytes, &ecdh_bytes, mesh_id);
    stream.write_all(&msg).await?;

    // Read the 32-byte server confirmation.
    let mut confirm = [0u8; 32];
    stream.read_exact(&mut confirm).await?;

    // Verify server confirmation with mesh_id binding.
    dispatch_verify_client_confirm(auth, &confirm, &ecdh_bytes, server_pubkey, mesh_id)?;

    let session_keys = SessionKeys::derive(&ecdh_bytes, &e_pub_bytes, suite);

    Ok(ClientHandshakeResult {
        session_keys,
        remote_s_pub: *server_pubkey,
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Client-side handshake (V9 — forward-secret + mutual auth)
// ─────────────────────────────────────────────────────────────────────────────

/// Perform the client side of the V9 forward-secret mutual-auth handshake.
///
/// Sends a 97-byte ClientHello (version = 0x09, suite preference, ephemeral pub,
/// timestamp, 16-byte client proof). Verifies the 81-byte ServerHello's
/// `server_proof` before deriving session keys.
///
/// # Arguments
/// - `server_static_pub` — server's declared static X25519 pubkey.
/// - `client_static_priv` — client's own static X25519 private key (for proof).
/// - `suite_prefs` — client's ordered AEAD suite preferences.
pub async fn run_client_handshake_v9<S>(
    stream: &mut S,
    server_static_pub: &[u8; 32],
    client_static_priv: &[u8; 32],
    mesh_id: &[u8],
    suite_prefs: &[AeadSuite],
) -> Result<ClientHandshakeResult, MirageError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // Generate client ephemeral key pair.
    let (e_priv_c, e_pub_c) = gen_ephemeral();

    // Timestamp for replay protection.
    let ts_ms = current_ts_ms();

    // Preferred suite IDs — pack up to 3, pad with zeros.
    let mut suite_ids = [0u8; 3];
    for (i, &s) in suite_prefs.iter().take(3).enumerate() {
        suite_ids[i] = suite_to_id(s);
    }
    // Primary suite for client_proof binding (first preference).
    let primary_suite_id = suite_ids[0];

    // Compute client proof (binds to server_static_pub, e_pub_c, mesh_id, suite_ids, ts_ms).
    // suite_ids is the exact 3-byte offered list that will appear at ClientHello[1..4],
    // preventing an on-path party from stripping strong suites from the offer undetectably.
    let client_proof = compute_client_proof(
        client_static_priv,
        server_static_pub,
        &e_pub_c,
        mesh_id,
        &suite_ids,
        ts_ms,
    );

    // Derive client_static_pub from client_static_priv so the server can verify the proof.
    let client_static_pub = {
        let secret = StaticSecret::from(*client_static_priv);
        PublicKey::from(&secret).to_bytes()
    };

    // Build and send ClientHello (97 bytes).
    // cred_scheme = 0x00: legacy path, no credential frame follows.
    let hello = V9ClientHello {
        version: WIRE_VERSION_V9,
        suite_ids,
        e_pub_c,
        ts_ms,
        client_proof,
        client_static_pub,
        cred_scheme: 0x00,
        // No sender in this codebase sets a non-legacy target hint yet —
        // see `mirage_protocol::auth::v9::TargetHint`'s own doc. Routing on
        // this connection stays exactly what the face's declared purpose
        // says, precisely as it did before this field existed.
        target_hint: TargetHint::Legacy.to_byte(),
    };
    stream.write_all(&hello.to_wire()).await?;

    // Read ServerHello (81 bytes) or VersionReject (1 byte = 0xFF).
    let mut first_byte = [0u8; 1];
    stream.read_exact(&mut first_byte).await?;
    if first_byte[0] == VERSION_REJECT {
        return Err(MirageError::Handshake(
            "V9: server rejected version (VersionReject 0xFF)".into(),
        ));
    }

    // Read remaining 80 bytes of ServerHello.
    let mut rest = [0u8; SERVER_HELLO_LEN - 1];
    stream.read_exact(&mut rest).await?;
    let mut buf = [0u8; SERVER_HELLO_LEN];
    buf[0] = first_byte[0];
    buf[1..].copy_from_slice(&rest);

    let server_hello = V9ServerHello::from_wire(&buf)?;

    // Resolve negotiated suite from server's choice.
    let suite = id_to_suite(server_hello.chosen_suite).ok_or_else(|| {
        MirageError::Handshake(format!(
            "V9: unknown suite_id 0x{:02x} in ServerHello",
            server_hello.chosen_suite
        ))
    })?;

    // Compute ecdh_ee — ephemeral×ephemeral. Zeroize on drop.
    let e_pub_s = PublicKey::from(server_hello.e_pub_s);
    let ecdh_ee = Zeroizing::new(e_priv_c.diffie_hellman(&e_pub_s).to_bytes());

    // Recompute transcript_0 with the now-known e_pub_s.
    let transcript_0 = compute_transcript_0(
        &e_pub_c,
        &server_hello.e_pub_s,
        mesh_id,
        server_hello.chosen_suite,
        ts_ms,
    );

    // Verify server proof — proves server holds the static key corresponding to
    // the operator-signed DeclaredIdentity.
    verify_server_proof(&ecdh_ee, &transcript_0, server_static_pub, &server_hello.server_proof)?;

    // Derive session keys after mutual auth.
    let session_keys = derive_v9_keys(&ecdh_ee, &transcript_0, suite);

    // Primary suite from our prefs is what we sent; confirm server agrees.
    let _ = primary_suite_id;

    Ok(ClientHandshakeResult {
        session_keys,
        remote_s_pub: *server_static_pub,
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Server-side handshake (version-probing entry point)
// ─────────────────────────────────────────────────────────────────────────────

/// Perform the server side of the Mirage ECDH handshake.
///
/// **Version probe:** reads the first byte of the stream. If it is `0x09`, routes
/// to the V9 path (`run_server_handshake_v9`). Otherwise, prepends the
/// already-read byte to the remaining 63 bytes of the V8 64-byte client message
/// and continues with the V8 path — byte-identical behaviour.
///
/// `mesh_id` — mesh identifier bytes baked into the Blake3 confirm label.
/// Must match the `mesh_id` the connecting client uses.
///
/// `allow_legacy_v8` — when `false`, any non-V9 first byte causes the server to
/// send `VERSION_REJECT (0xFF)` and return `Ok(None)`. Set to `true` to preserve
/// the current permissive behaviour (accepts V8 dials).
///
/// Returns `None` when authentication fails — the caller should use
/// `AcceptResult::Fallback` to forward the connection to a camouflage backend.
///
/// The `client_auth` closure is only invoked on the V9 path. For V8,
/// pass `|_| true` (or any closure — it will not be called).
///
/// # INVARIANT: parser never reached until `Ok(Some(_))` is returned.
#[must_use = "caller must check Option — None means auth rejected, do not proceed"]
pub async fn run_server_handshake<S>(
    stream: &mut S,
    keypair: &KeyPair,
    auth: &AuthMode,
    mesh_id: &[u8],
    suite: AeadSuite,
    allow_legacy_v8: bool,
) -> Result<Option<ServerHandshakeResult>, MirageError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    run_server_handshake_with_auth(stream, keypair, auth, mesh_id, suite, |_ctx| true, allow_legacy_v8).await
}

/// Version of `run_server_handshake` that accepts a `client_auth` closure for
/// the V9 path.
///
/// The `client_auth` closure receives a [`ClientAuthContext`] containing the
/// client's static public key, timestamp, ephemeral key, credential scheme byte,
/// and raw credential bytes. It returns `true` to accept or `false` to reject.
/// Called **before** session keys are derived and before `ServerHello` is sent.
///
/// `allow_legacy_v8` — when `false`, any non-V9 first byte causes the server to
/// send `VERSION_REJECT (0xFF)` and return `Ok(None)`. Set to `true` to preserve
/// the current permissive behaviour (accepts V8 dials).
///
/// # INVARIANT: parser never reached until `Ok(Some(_))` is returned.
#[must_use = "caller must check Option — None means auth rejected, do not proceed"]
pub async fn run_server_handshake_with_auth<S, F>(
    stream: &mut S,
    keypair: &KeyPair,
    auth: &AuthMode,
    mesh_id: &[u8],
    suite: AeadSuite,
    client_auth: F,
    allow_legacy_v8: bool,
) -> Result<Option<ServerHandshakeResult>, MirageError>
where
    S: AsyncRead + AsyncWrite + Unpin,
    F: for<'a> Fn(&ClientAuthContext<'a>) -> bool,
{
    // Read 1 byte to probe the version.
    let mut version_probe = [0u8; 1];
    stream.read_exact(&mut version_probe).await?;

    match version_probe[0] {
        WIRE_VERSION_V9 => {
            // V9 path: read the remaining 96 bytes of the ClientHello.
            let mut rest = [0u8; CLIENT_HELLO_LEN - 1];
            stream.read_exact(&mut rest).await?;
            let mut buf = [0u8; CLIENT_HELLO_LEN];
            buf[0] = WIRE_VERSION_V9;
            buf[1..].copy_from_slice(&rest);

            run_server_handshake_v9_inner(stream, keypair, mesh_id, suite, client_auth, &buf).await
        }
        _ if !allow_legacy_v8 => {
            // TCP servers set allow_legacy_v8=false: any non-V9 first byte →
            // send VersionReject and close. Single-hop TCP V8 handshake removed.
            let _ = auth; // not used in this branch
            let _ = stream.write_all(&[VERSION_REJECT]).await;
            tracing::warn!(
                first_byte = format!("0x{:02x}", version_probe[0]),
                "[HS-V9] server refused: first byte is not a V9 hello and legacy V8 is off"
            );
            Ok(None)
        }
        first_byte => {
            // V8 legacy path — UDP servers set allow_legacy_v8=true to support
            // existing V8 UDP clients (run_client_udp uses run_client_handshake).
            // The first byte is already consumed — prepend it to reconstruct
            // the full client message.
            let msg_len = dispatch_client_msg_len(auth);
            let mut rest = vec![0u8; msg_len.saturating_sub(1)];
            stream.read_exact(&mut rest).await?;
            let mut msg = Vec::with_capacity(msg_len);
            msg.push(first_byte);
            msg.extend_from_slice(&rest);

            run_server_handshake_v8_inner(stream, keypair, auth, mesh_id, suite, &msg).await
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Server-side handshake (V8 inner — UDP legacy path)
// ─────────────────────────────────────────────────────────────────────────────

/// V8 inner path — takes the already-assembled client message.
/// Only reached when `allow_legacy_v8=true` (UDP server path).
/// Single-hop TCP V8 is removed; this function is UDP-only.
async fn run_server_handshake_v8_inner<S>(
    stream: &mut S,
    keypair: &KeyPair,
    auth: &AuthMode,
    mesh_id: &[u8],
    suite: AeadSuite,
    msg: &[u8],
) -> Result<Option<ServerHandshakeResult>, MirageError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    use mirage_core::crypto::shared_secret;

    // Verify and extract the client's ephemeral public key.
    let e_pub_bytes = match dispatch_verify_server(auth, msg, keypair, mesh_id) {
        Ok(pub_bytes) => pub_bytes,
        Err(e) => {
            tracing::warn!(error = %e, "[HS-V9] server refused: V8 auth verify failed");
            return Ok(None); // Auth failed → signal fallback.
        }
    };

    // Complete ECDH using server's static secret against client's ephemeral pub.
    let client_e_pub = PublicKey::from(e_pub_bytes);
    let ecdh_bytes = shared_secret(&keypair.secret, &client_e_pub);

    // Server's static public key bytes (used in confirm).
    let s_pub_bytes = keypair.public.to_bytes();

    // Build and send the 32-byte confirmation with mesh_id binding.
    let confirm = dispatch_build_server_confirm(auth, &ecdh_bytes, &s_pub_bytes, mesh_id);
    stream.write_all(&confirm).await?;

    let session_keys = SessionKeys::derive(&ecdh_bytes, &e_pub_bytes, suite);

    Ok(Some(ServerHandshakeResult {
        session_keys,
        remote_e_pub: e_pub_bytes,
    }))
}

// ─────────────────────────────────────────────────────────────────────────────
// Server-side handshake (V9 — forward-secret + mutual auth)
// ─────────────────────────────────────────────────────────────────────────────

/// Perform the server side of the V9 forward-secret mutual-auth handshake.
///
/// The `client_auth` closure receives a [`ClientAuthContext`] containing the
/// client's static public key, timestamp, ephemeral key, credential scheme byte,
/// and raw credential bytes. Returns `true` to accept or `false` to reject.
/// Called BEFORE session keys are derived or ServerHello is sent.
///
/// Returns `None` when the client is rejected by `client_auth` or when the
/// `client_proof_mac` fails verification.
///
/// # INVARIANT: parser never reached until `Ok(Some(_))` is returned.
#[must_use = "caller must check Option — None means auth rejected, do not proceed"]
pub async fn run_server_handshake_v9<S, F>(
    stream: &mut S,
    keypair: &KeyPair,
    mesh_id: &[u8],
    suite_prefs: &[AeadSuite],
    client_auth: F,
) -> Result<Option<ServerHandshakeResult>, MirageError>
where
    S: AsyncRead + AsyncWrite + Unpin,
    F: for<'a> Fn(&ClientAuthContext<'a>) -> bool,
{
    let mut buf = [0u8; CLIENT_HELLO_LEN];
    stream.read_exact(&mut buf).await?;
    run_server_handshake_v9_inner(stream, keypair, mesh_id, suite_prefs[0], client_auth, &buf).await
}

/// Inner V9 server handshake — takes the already-read 97-byte buffer.
async fn run_server_handshake_v9_inner<S, F>(
    stream: &mut S,
    keypair: &KeyPair,
    mesh_id: &[u8],
    _default_suite: AeadSuite,
    client_auth: F,
    buf: &[u8; CLIENT_HELLO_LEN],
) -> Result<Option<ServerHandshakeResult>, MirageError>
where
    S: AsyncRead + AsyncWrite + Unpin,
    F: for<'a> Fn(&ClientAuthContext<'a>) -> bool,
{
    let hello = match V9ClientHello::from_wire(buf) {
        Ok(h) => h,
        Err(e) => {
            tracing::warn!(error = %e, buf_len = buf.len(),
                "[HS-V9] server refused: client hello did not parse");
            return Ok(None);
        }
    };

    // Server preference list defaults to ChaCha20 first.
    let server_prefs = [
        AeadSuite::ChaCha20Poly1305,
        AeadSuite::Aes256Gcm,
        AeadSuite::Aes128Gcm,
    ];
    let suite = match negotiate_suite(&server_prefs, &hello.suite_ids) {
        Some(s) => s,
        None => {
            // No overlap — send VersionReject and close.
            let _ = stream.write_all(&[VERSION_REJECT]).await;
            tracing::warn!(
                offered = ?hello.suite_ids,
                "[HS-V9] server refused: no AEAD suite in common with the client"
            );
            return Ok(None);
        }
    };
    let suite_id = suite_to_id(suite);

    // Generate server ephemeral key pair.
    let (e_priv_s, e_pub_s) = gen_ephemeral();

    // Compute ecdh_ee — ephemeral×ephemeral. Zeroize on drop.
    let e_pub_c_pk = PublicKey::from(hello.e_pub_c);
    let ecdh_ee = Zeroizing::new(e_priv_s.diffie_hellman(&e_pub_c_pk).to_bytes());

    // transcript_0 uses the actual e_pub_s.
    let transcript_0 = compute_transcript_0(
        &hello.e_pub_c,
        &e_pub_s,
        mesh_id,
        suite_id,
        hello.ts_ms,
    );

    // client_static_pub is transmitted in bytes 60..92 of the ClientHello.
    let client_static_pub = hello.client_static_pub;

    // Reject stale or reused ClientHellos before any key material is touched.
    // A 5-minute window (both directions) tolerates reasonable clock skew while
    // preventing indefinite reuse of a captured ClientHello.
    if !ts_within_window(current_ts_ms(), hello.ts_ms) {
        let now = current_ts_ms();
        tracing::warn!(
            client_ts_ms = hello.ts_ms,
            server_ts_ms = now,
            skew_ms = (now as i64) - (hello.ts_ms as i64),
            client_static_pub = %hex::encode(&hello.client_static_pub[..8]),
            "[HS-V9] server refused: client hello timestamp outside the accepted window"
        );
        return Ok(None);
    }

    // Verify client proof before any session key derivation or server response.
    // suite_ids is hello.suite_ids — the offered list as received on the wire at [1..4],
    // byte-identical to what the client signed. If an on-path party stripped suites, this fails.
    // INVARIANT: parser never reached until this returns Ok.
    if verify_client_proof(
        &keypair.secret,
        &client_static_pub,
        &hello.e_pub_c,
        &keypair.public.to_bytes(),
        mesh_id,
        &hello.suite_ids,
        hello.ts_ms,
        &hello.client_proof,
    ).is_err() {
        // Reject — do NOT send ServerHello.
        tracing::warn!(
            client_static_pub = %hex::encode(&client_static_pub[..8]),
            server_static_pub = %hex::encode(&keypair.public.to_bytes()[..8]),
            mesh_id = %String::from_utf8_lossy(mesh_id),
            suites = ?hello.suite_ids,
            ts_ms = hello.ts_ms,
            "[HS-V9] server refused: client proof did not verify — the client signed against              a different static key, mesh_id or suite list than this server holds"
        );
        return Ok(None);
    }

    // Read the credential frame when scheme_byte != 0x00.
    // Frame format: [2B len big-endian][len bytes].
    // DoS cap: MAX_CREDENTIAL_LEN enforced before allocation; the credential
    // read happens only after proof-verify + the accept semaphore bounds it.
    let cred_bytes: Vec<u8> = if hello.cred_scheme != 0x00 {
        let mut len_buf = [0u8; 2];
        stream.read_exact(&mut len_buf).await?;
        let len = u16::from_be_bytes(len_buf) as usize;
        if len > MAX_CREDENTIAL_LEN {
            // Reject — oversized credential frame; do NOT send ServerHello.
            tracing::warn!(len, cap = MAX_CREDENTIAL_LEN,
                "[HS-V9] server refused: credential frame over the cap");
            return Ok(None);
        }
        let mut bytes = vec![0u8; len];
        stream.read_exact(&mut bytes).await?;
        bytes
    } else {
        Vec::new()
    };

    // Build the auth context and invoke the client_auth closure.
    let ctx = ClientAuthContext {
        static_pub: &client_static_pub,
        ts_ms: hello.ts_ms,
        e_pub_c: &hello.e_pub_c,
        scheme_byte: hello.cred_scheme,
        credential: &cred_bytes,
    };
    if !client_auth(&ctx) {
        tracing::warn!(
            client_static_pub = %hex::encode(&client_static_pub[..8]),
            scheme = hello.cred_scheme,
            "[HS-V9] server refused: the caller's client_auth closure rejected this client"
        );
        return Ok(None);
    }

    // Compute server proof.
    let server_static_pub = keypair.public.to_bytes();
    let server_proof = compute_server_proof(&ecdh_ee, &transcript_0, &server_static_pub);

    // Build and send ServerHello.
    let server_hello = V9ServerHello {
        chosen_suite: suite_id,
        e_pub_s,
        server_proof,
        _reserved: [0u8; 16],
    };
    stream.write_all(&server_hello.to_wire()).await?;

    // Derive session keys.
    let session_keys = derive_v9_keys(&ecdh_ee, &transcript_0, suite);

    Ok(Some(ServerHandshakeResult {
        session_keys,
        remote_e_pub: client_static_pub,
    }))
}

// ─────────────────────────────────────────────────────────────────────────────
// Timestamp helper
// ─────────────────────────────────────────────────────────────────────────────

/// Return the current UTC time in milliseconds since the Unix epoch.
pub(crate) fn current_ts_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// Replay-window check: `ts_ms` is acceptable when it is within
/// `MAX_HANDSHAKE_SKEW_MS` of `now_ms` in either direction.
///
/// A client slightly ahead of the server passes; a captured hello from
/// more than 5 minutes ago (or implausibly far in the future) fails.
const MAX_HANDSHAKE_SKEW_MS: u64 = 300_000; // 5 minutes

pub(crate) fn ts_within_window(now_ms: u64, ts_ms: u64) -> bool {
    now_ms.abs_diff(ts_ms) <= MAX_HANDSHAKE_SKEW_MS
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::{ts_within_window, MAX_HANDSHAKE_SKEW_MS};

    #[test]
    fn ts_window_rejects_epoch_zero() {
        let now_ms = 1_700_000_000_000u64; // arbitrary "now" far from epoch
        assert!(!ts_within_window(now_ms, 0), "epoch-zero must be rejected");
    }

    #[test]
    fn ts_window_accepts_exact_boundary() {
        let now_ms = 1_700_000_000_000u64;
        assert!(ts_within_window(now_ms, now_ms));
        assert!(ts_within_window(now_ms, now_ms - MAX_HANDSHAKE_SKEW_MS));
        assert!(ts_within_window(now_ms, now_ms + MAX_HANDSHAKE_SKEW_MS));
    }

    #[test]
    fn ts_window_rejects_six_minutes_old() {
        let now_ms = 1_700_000_000_000u64;
        let six_min_ms = 360_000u64;
        assert!(!ts_within_window(now_ms, now_ms - six_min_ms), "6-min-old must be rejected");
    }

    #[test]
    fn ts_window_rejects_six_minutes_future() {
        let now_ms = 1_700_000_000_000u64;
        let six_min_ms = 360_000u64;
        assert!(!ts_within_window(now_ms, now_ms + six_min_ms), "6-min-future must be rejected");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // V9 credential wire tests (tokio duplex in-memory pipe)
    // ─────────────────────────────────────────────────────────────────────────

    use std::sync::{Arc, atomic::{AtomicBool, AtomicU8, Ordering}};
    use mirage_core::crypto::{AeadSuite, KeyPair};
    use super::{
        run_server_handshake_v9, run_client_handshake_v9, ClientAuthContext,
    };

    fn test_keypair() -> KeyPair {
        let secret = x25519_dalek::StaticSecret::from([0xABu8; 32]);
        let public = x25519_dalek::PublicKey::from(&secret);
        KeyPair { secret, public }
    }

    fn client_priv() -> [u8; 32] {
        [0xCDu8; 32]
    }

    fn mesh_id() -> Vec<u8> {
        b"test-mesh".to_vec()
    }

    /// Helper: run the client+server pair via tokio::io::duplex.
    /// Returns (server_result, client_result).
    async fn handshake_pair<F>(
        cred: Option<(u8, Vec<u8>)>,
        auth_fn: F,
    ) -> (
        Result<Option<super::ServerHandshakeResult>, mirage_core::error::MirageError>,
        Result<super::ClientHandshakeResult, mirage_core::error::MirageError>,
    )
    where
        F: for<'a> Fn(&ClientAuthContext<'a>) -> bool + Send + 'static,
    {
        let keypair = test_keypair();
        let server_pub = keypair.public.to_bytes();
        let client_priv = client_priv();
        let mesh = mesh_id();

        let (client_io, server_io) = tokio::io::duplex(4096);

        let server_keypair = keypair.clone();
        let server_mesh = mesh.clone();
        let server_handle = tokio::spawn(async move {
            let mut s = server_io;
            run_server_handshake_v9(
                &mut s,
                &server_keypair,
                &server_mesh,
                &[AeadSuite::ChaCha20Poly1305],
                auth_fn,
            )
            .await
        });

        let client_handle = tokio::spawn(async move {
            let mut c = client_io;
            // Write the credential frame after the 97B hello if present.
            use crate::auth::v9::{
                compute_client_proof, gen_ephemeral, suite_to_id, TargetHint, V9ClientHello,
                WIRE_VERSION_V9,
            };
            use tokio::io::{AsyncWriteExt, AsyncReadExt};
            use x25519_dalek::{PublicKey, StaticSecret};

            if let Some((scheme, token)) = cred {
                // Build hello manually so we can set cred_scheme.
                let (_e_priv_c, e_pub_c) = gen_ephemeral();
                let ts_ms = super::current_ts_ms();
                let mut suite_ids = [0u8; 3];
                suite_ids[0] = suite_to_id(AeadSuite::ChaCha20Poly1305);

                let client_static_pub = {
                    let s = StaticSecret::from(client_priv);
                    PublicKey::from(&s).to_bytes()
                };
                let proof = compute_client_proof(
                    &client_priv,
                    &server_pub,
                    &e_pub_c,
                    &mesh,
                    &suite_ids,
                    ts_ms,
                );
                let hello = V9ClientHello {
                    version: WIRE_VERSION_V9,
                    suite_ids,
                    e_pub_c,
                    ts_ms,
                    client_proof: proof,
                    client_static_pub,
                    cred_scheme: scheme,
                    target_hint: TargetHint::Legacy.to_byte(),
                };
                c.write_all(&hello.to_wire()).await.unwrap();
                // Write [2B len BE][token].
                let len = token.len() as u16;
                c.write_all(&len.to_be_bytes()).await.unwrap();
                c.write_all(&token).await.unwrap();
                // Now read the server response so the duplex doesn't deadlock.
                let mut srv_buf = [0u8; 81];
                let _ = c.read_exact(&mut srv_buf).await;
                Ok(super::ClientHandshakeResult {
                    session_keys: mirage_core::crypto::SessionKeys {
                        client_write_key: zeroize::Zeroizing::new([0u8; 32]),
                        server_write_key: zeroize::Zeroizing::new([0u8; 32]),
                        client_nonce_counter: 0,
                        server_nonce_counter: 0,
                        suite: AeadSuite::ChaCha20Poly1305,
                    },
                    remote_s_pub: server_pub,
                })
            } else {
                run_client_handshake_v9(
                    &mut c,
                    &server_pub,
                    &client_priv,
                    &mesh,
                    &[AeadSuite::ChaCha20Poly1305],
                )
                .await
            }
        });

        let (sr, cr) = tokio::join!(server_handle, client_handle);
        (sr.unwrap(), cr.unwrap())
    }

    /// Client sends an EpochHmac-shaped credential (scheme=1, 52 bytes).
    /// Server closure asserts scheme_byte==1, credential.len()==52, accepts.
    #[tokio::test]
    async fn v9_credential_frame_accepted() {
        let saw_cred = Arc::new(AtomicBool::new(false));
        let saw_cred2 = Arc::clone(&saw_cred);
        let saw_len = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let saw_len2 = Arc::clone(&saw_len);

        let token = vec![0xBEu8; 52];
        let (server_res, _client_res) = handshake_pair(
            Some((0x01, token)),
            move |ctx| {
                saw_cred2.store(true, Ordering::Relaxed);
                saw_len2.store(ctx.credential.len(), Ordering::Relaxed);
                ctx.scheme_byte == 0x01 && ctx.credential.len() == 52
            },
        )
        .await;

        assert!(saw_cred.load(Ordering::Relaxed), "client_auth must have been called");
        assert_eq!(saw_len.load(Ordering::Relaxed), 52, "credential length must be 52");
        assert!(
            server_res.is_ok() && server_res.unwrap().is_some(),
            "server must accept when closure returns true"
        );
    }

    /// Legacy client (no credential, scheme=0x00).
    /// Server closure sees scheme_byte==0, credential.is_empty(), accepts.
    #[tokio::test]
    async fn v9_legacy_no_credential() {
        let saw_scheme = Arc::new(AtomicU8::new(0xFF));
        let saw_scheme2 = Arc::clone(&saw_scheme);
        let saw_empty = Arc::new(AtomicBool::new(false));
        let saw_empty2 = Arc::clone(&saw_empty);

        let (server_res, client_res) = handshake_pair(
            None,
            move |ctx| {
                saw_scheme2.store(ctx.scheme_byte, Ordering::Relaxed);
                saw_empty2.store(ctx.credential.is_empty(), Ordering::Relaxed);
                true
            },
        )
        .await;

        assert_eq!(saw_scheme.load(Ordering::Relaxed), 0x00, "scheme_byte must be 0 for legacy");
        assert!(saw_empty.load(Ordering::Relaxed), "credential must be empty for legacy");
        assert!(server_res.is_ok() && server_res.unwrap().is_some());
        assert!(client_res.is_ok());
    }

    /// Client sends scheme=1 credential but closure returns false → Ok(None).
    #[tokio::test]
    async fn v9_credential_rejected_by_closure() {
        let token = vec![0xAAu8; 52];
        let (server_res, _) = handshake_pair(
            Some((0x01, token)),
            |_ctx| false,
        )
        .await;

        assert!(
            matches!(server_res, Ok(None)),
            "server must return Ok(None) when closure rejects"
        );
    }

    /// Client sends scheme=1 with oversized credential (>1024 bytes) → Ok(None).
    #[tokio::test]
    async fn v9_oversized_credential_rejected() {
        // Build the hello + oversized credential frame directly.
        use crate::auth::v9::{
            compute_client_proof, gen_ephemeral, suite_to_id, TargetHint, V9ClientHello,
            WIRE_VERSION_V9,
        };
        use tokio::io::{AsyncWriteExt, AsyncReadExt};
        use x25519_dalek::{PublicKey, StaticSecret};

        let keypair = test_keypair();
        let server_pub = keypair.public.to_bytes();
        let client_priv_bytes = client_priv();
        let mesh = mesh_id();

        let (client_io, server_io) = tokio::io::duplex(8192);

        let server_keypair = keypair.clone();
        let server_mesh = mesh.clone();
        let server_handle = tokio::spawn(async move {
            let mut s = server_io;
            run_server_handshake_v9(
                &mut s,
                &server_keypair,
                &server_mesh,
                &[AeadSuite::ChaCha20Poly1305],
                |_ctx| true,
            )
            .await
        });

        let client_handle = tokio::spawn(async move {
            let mut c = client_io;
            let (_e_priv_c, e_pub_c) = gen_ephemeral();
            let ts_ms = super::current_ts_ms();
            let mut suite_ids = [0u8; 3];
            suite_ids[0] = suite_to_id(AeadSuite::ChaCha20Poly1305);
            let client_static_pub = {
                let s = StaticSecret::from(client_priv_bytes);
                PublicKey::from(&s).to_bytes()
            };
            let proof = compute_client_proof(
                &client_priv_bytes,
                &server_pub,
                &e_pub_c,
                &mesh,
                &suite_ids,
                ts_ms,
            );
            let hello = V9ClientHello {
                version: WIRE_VERSION_V9,
                suite_ids,
                e_pub_c,
                ts_ms,
                client_proof: proof,
                client_static_pub,
                cred_scheme: 0x01,
                target_hint: TargetHint::Legacy.to_byte(),
            };
            c.write_all(&hello.to_wire()).await.unwrap();
            // Write oversized frame: len=1025.
            let oversized_len: u16 = 1025;
            c.write_all(&oversized_len.to_be_bytes()).await.unwrap();
            let big = vec![0xFFu8; 1025];
            c.write_all(&big).await.unwrap();
            // Drain any server response (may get nothing if server closed).
            let mut drain = [0u8; 1];
            let _ = c.read_exact(&mut drain).await;
        });

        let (sr, _) = tokio::join!(server_handle, client_handle);
        assert!(
            matches!(sr.unwrap(), Ok(None)),
            "server must return Ok(None) for oversized credential"
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // UDP V9 handshake tests
    //
    // These tests verify the V9 protocol at the handshake level using
    // `tokio::io::duplex` in-memory pipes — no real UDP socket involved.
    // The handshake code is identical whether the stream came from a real UDP
    // camouflage adapter or from an in-memory duplex; the camouflage layer
    // is hidden below the `AsyncRead + AsyncWrite` boundary.
    // ─────────────────────────────────────────────────────────────────────────

    /// V9 round-trip without any credential.
    /// Both sides succeed; server closure always accepts.
    #[tokio::test]
    async fn udp_v9_roundtrip_no_credential() {
        let (server_res, client_res) = handshake_pair(None, |_| true).await;
        assert!(
            server_res.is_ok() && server_res.unwrap().is_some(),
            "server must return Ok(Some(_)) with no credential"
        );
        assert!(client_res.is_ok(), "client must succeed with no credential");
    }

    /// V9 round-trip with an EpochHmac credential (scheme=1, 52-byte token).
    /// Server closure asserts scheme_byte==1, credential.len()==52.
    #[tokio::test]
    async fn udp_v9_roundtrip_with_credential() {
        let saw_scheme = Arc::new(AtomicU8::new(0xFF));
        let saw_scheme2 = Arc::clone(&saw_scheme);
        let saw_len = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let saw_len2 = Arc::clone(&saw_len);

        let token = vec![0xABu8; 52];
        let (server_res, _client_res) = handshake_pair(
            Some((0x01, token)),
            move |ctx| {
                saw_scheme2.store(ctx.scheme_byte, Ordering::Relaxed);
                saw_len2.store(ctx.credential.len(), Ordering::Relaxed);
                ctx.scheme_byte == 0x01 && ctx.credential.len() == 52
            },
        )
        .await;

        assert_eq!(saw_scheme.load(Ordering::Relaxed), 0x01, "scheme_byte must be 1");
        assert_eq!(saw_len.load(Ordering::Relaxed), 52, "credential length must be 52");
        assert!(
            server_res.is_ok() && server_res.unwrap().is_some(),
            "server must accept when closure returns true"
        );
    }

    /// Server with `allow_legacy_v8=false` rejects a non-V9 hello.
    /// The server sends VERSION_REJECT and returns Ok(None).
    #[tokio::test]
    async fn udp_v9_rejects_v8_when_allow_legacy_false() {
        use tokio::io::AsyncWriteExt;

        let keypair = test_keypair();
        let mesh = mesh_id();

        let (client_io, server_io) = tokio::io::duplex(4096);

        let server_keypair = keypair.clone();
        let server_mesh = mesh.clone();
        let server_handle = tokio::spawn(async move {
            let mut s = server_io;
            // Use run_server_handshake_with_auth with allow_legacy_v8=false.
            super::run_server_handshake_with_auth(
                &mut s,
                &server_keypair,
                &crate::auth::AuthMode::Blake3,
                &server_mesh,
                AeadSuite::ChaCha20Poly1305,
                |_ctx| true,
                false, // allow_legacy_v8=false
            )
            .await
        });

        let client_handle = tokio::spawn(async move {
            let mut c = client_io;
            // Send a V8-style hello: first byte is NOT 0x09.
            // A minimal 64-byte V8 hello is sufficient to trigger the reject path.
            let v8_hello = [0x01u8; 64];
            let _ = c.write_all(&v8_hello).await;
            // Read server response — expect VERSION_REJECT (0xFF).
            use tokio::io::AsyncReadExt;
            let mut buf = [0u8; 1];
            let _ = c.read_exact(&mut buf).await;
            buf[0]
        });

        let (sr, cr) = tokio::join!(server_handle, client_handle);
        assert!(
            matches!(sr.unwrap(), Ok(None)),
            "server must return Ok(None) when allow_legacy_v8=false and client sends V8 hello"
        );
        assert_eq!(
            cr.unwrap(),
            crate::auth::v9::VERSION_REJECT,
            "client must receive VERSION_REJECT byte (0xFF)"
        );
    }
}
