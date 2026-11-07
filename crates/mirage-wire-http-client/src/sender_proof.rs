//! Sender-proof header construction — the V9 HTTP-layer authz headers a
//! wire-HTTP client presents to a monitor.
//!
//! The primitive lives here, and not in the fleet's mesh-client crate,
//! because this repository is the OSS layer: it must not depend on any
//! fleet crate. The implementation below is the fleet's
//! `monitor_dial::build_sender_proof_headers` moved verbatim — same MAC
//! formula, same byte order, same error behaviour — so a header built by
//! this crate verifies against a monitor exactly as it did before the
//! deep libraries were split out of the fleet repository.
//!
//! The MAC formula, byte-for-byte:
//!
//! ```text
//! MAC = BLAKE3("MIRAGE-SENDER-PROOF-V1" || X25519(node_priv, server_pub)
//!             || server_pubkey_hex.as_bytes() || ts_ms.to_be_bytes())
//! ```
//!
//! It matches the monitor's own `MonitorSenderVerifier::verify` and the
//! inlined copy in operator-box's `wire_http::build_request_head`.

use mirage_core::identity::DeclaredIdentity;

/// Build the three SenderProof HTTP headers for a Mirage-over-WS upgrade.
///
/// Returns `Ok(None)` when `identity` is absent — legacy nodes that lack
/// an operator-signed identity skip the proof; the monitor still accepts
/// them via session-token Bearer (defense-in-depth, SenderProof is additive
/// this phase).
///
/// Returns `Ok(Some((identity_b64, mac_hex, ts_ms)))` on success.
///
/// The MAC formula EXACTLY matches `MonitorSenderVerifier::verify` on the
/// monitor side:
///
///   `MAC = BLAKE3("MIRAGE-SENDER-PROOF-V1" || X25519(node_priv, server_pub)
///               || server_pubkey_hex.as_bytes() || ts_ms.to_be_bytes())`
pub(crate) fn build_sender_proof_headers(
    identity: Option<&DeclaredIdentity>,
    node_priv: &[u8; 32],
    monitor_pubkey_hex: &str,
) -> Result<Option<(String, String, u64)>, Box<dyn std::error::Error + Send + Sync>> {
    let identity = match identity {
        Some(id) => id,
        None => return Ok(None),
    };

    // The monitor's OWN wire key, handed in by the caller, which got it from
    // the monitor's signed identity via `monitor_faces::target_from_identity`
    // (`wire_pubkey_for(ServiceRole::Monitor)`).
    //
    // It used to be looked up in the `PeerTable`, keyed by the binding's exit
    // node_id, and that stopped being the monitor's key on 2026-08-17.
    // `351c568` made every wire key ROLE-specific while the peer table kept
    // one row per MACHINE with a single `pubkey_hex` — and that column carries
    // the NODE role's key (`node_control_api`'s register path stores
    // `node_pubkey_hex`). So on any full box this resolved a sibling role's
    // key, the DH secret differed from the one the monitor derives with its
    // own private key, and the MAC could not match.
    //
    // Taking the key as a parameter also drops this function's dependency on
    // the peer table entirely, which is worth having on its own: that table
    // is RAM-only, so a monitor restart emptied it and a self-issued capsule
    // never had one, and both cases used to fail here with `peer_table miss`
    // before a socket was ever dialled.
    let server_pub_bytes: [u8; 32] = hex::decode(monitor_pubkey_hex)
        .map_err(|e| format!("decode monitor pubkey_hex: {e}"))?
        .try_into()
        .map_err(|_| "monitor pubkey_hex must be 32 bytes".to_owned())?;

    let ts_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);

    // DH shared secret: X25519(node_priv, server_pub)
    let own_secret = x25519_dalek::StaticSecret::from(*node_priv);
    let server_pub = x25519_dalek::PublicKey::from(server_pub_bytes);
    let shared = zeroize::Zeroizing::new(own_secret.diffie_hellman(&server_pub).to_bytes());

    // MAC = BLAKE3("MIRAGE-SENDER-PROOF-V1" || shared || server_pubkey_hex.as_bytes() || ts_be)
    let mac: [u8; 32] = {
        let mut h = blake3::Hasher::new();
        h.update(b"MIRAGE-SENDER-PROOF-V1");
        h.update(&*shared);
        h.update(monitor_pubkey_hex.as_bytes());
        h.update(&ts_ms.to_be_bytes());
        *h.finalize().as_bytes()
    };

    let identity_bytes = serde_json::to_vec(identity)?;
    use base64::Engine as _;
    let identity_b64 = base64::engine::general_purpose::STANDARD.encode(&identity_bytes);
    let mac_hex = hex::encode(mac);

    Ok(Some((identity_b64, mac_hex, ts_ms)))
}
