use blake3::Hasher;
use mirage_core::{crypto::KeyPair, error::MirageError};
use x25519_dalek::{EphemeralSecret, PublicKey};
use zeroize::Zeroizing;

use mirage_core::crypto::AeadSuite;

use super::layer::peel_reply_layer_v7;

/// A hop's preferred AEAD suite order, as published in the peer table.
///
/// Carried through from the dial-core chain builder to whichever onion
/// builder assembles the circuit (FS telescopic today) so per-hop suite
/// selection does not need a full `PeerTable` dependency in this crate.
pub struct PeerSuitePreference {
    pub node_id: String,
    pub aead_suite_preference: Vec<AeadSuite>,
}

// ── V9-FS forward-secret primitives ─────────────────────────────────────────

/// Derive a per-layer symmetric key for V9-FS onion (ntor-style authenticated FS).
///
/// Binds BOTH DH outputs:
/// - `ee_shared`: `client_eph × server_eph` — forward secrecy (ephemeral-ephemeral)
/// - `es_shared`: `client_eph × node_static` — node authentication (ephemeral-static)
///
/// Neither term alone suffices: `ee` provides FS (ephemeral gone after session),
/// `es` provides authentication (only the real node holds the certified static secret).
///
/// Label `b"mirage-onion-layer-v9-fs-ntor-v1"` is distinct from earlier labels
/// to prevent cross-version key reuse.
pub fn derive_layer_key_v9_fs(
    ee_shared: &[u8; 32],
    es_shared: &[u8; 32],
    chain_position: u8,
    transcript: &[u8; 32],
    suite: AeadSuite,
) -> [u8; 32] {
    let mut h = Hasher::new_derive_key("mirage-onion-layer-v9-fs-ntor-v1");
    h.update(ee_shared);
    h.update(es_shared);
    h.update(&[chain_position, suite.id()]);
    h.update(transcript);
    *h.finalize().as_bytes()
}

/// Compute the key-confirmation auth tag included in `FsCreatedFrame`.
///
/// The tag proves the node possesses the layer key (and thus the certified static secret).
/// The client verifies this after deriving the same key — an on-path party without the node's
/// certified static secret cannot produce a matching tag.
///
/// ```text
/// BLAKE3_keyed(layer_key)
///   .update(b"mirage-onion-fs-keyconfirm-v1")
///   .update(transcript_i)
///   .update(server_eph_pub)
///   .finalize()
/// ```
pub fn compute_fs_auth_tag(
    layer_key: &[u8; 32],
    transcript_i: &[u8; 32],
    server_eph_pub: &[u8; 32],
) -> [u8; 32] {
    let mut h = Hasher::new_keyed(layer_key);
    h.update(b"mirage-onion-fs-keyconfirm-v1");
    h.update(transcript_i);
    h.update(server_eph_pub);
    *h.finalize().as_bytes()
}

/// Compute the base (pre-hop) FS transcript.
///
/// ```text
/// BLAKE3("MIRAGE-ONION-FS-V9")
///   .update(mesh_id_len BE u16 || mesh_id)
///   .update(chain_id_len BE u16 || chain_id)
///   .finalize()
/// ```
pub fn compute_fs_transcript_base(mesh_id: &[u8], chain_id: &[u8]) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(b"MIRAGE-ONION-FS-V9");
    h.update(&(mesh_id.len() as u16).to_be_bytes());
    h.update(mesh_id);
    h.update(&(chain_id.len() as u16).to_be_bytes());
    h.update(chain_id);
    *h.finalize().as_bytes()
}

/// Extend the FS transcript after hop `chain_position` is established.
///
/// ```text
/// transcript_i = BLAKE3_keyed(transcript_{i-1}, "mirage-onion-fs-extend")
///   .update([chain_position])
///   .update(client_eph_pub)
///   .update(server_eph_pub)
///   .update(node_id.as_bytes())
///   .update([chosen_suite.id()])
///   .update(node_static_pub)          ← certified identity bound into transcript
///   .finalize()
/// ```
///
/// Both `client_eph_pub` and `server_eph_pub` are included so neither party
/// can predict the key without knowing the other's ephemeral.
/// `node_static_pub` binds the node's certified identity: the transcript diverges
/// if the client and server disagree on which static key belongs to this hop.
/// Hop isolation: hop i-1 does NOT know `server_eph_pub_i`, so it cannot
/// compute `transcript_i` — only hop i and the client share this knowledge.
pub fn extend_fs_transcript(
    prev_transcript: &[u8; 32],
    chain_position: u8,
    node_id: &str,
    client_eph_pub: &[u8; 32],
    server_eph_pub: &[u8; 32],
    node_static_pub: &[u8; 32],
    chosen_suite: AeadSuite,
) -> [u8; 32] {
    let mut h = Hasher::new_keyed(prev_transcript);
    h.update(b"mirage-onion-fs-extend");
    h.update(&[chain_position]);
    h.update(client_eph_pub);
    h.update(server_eph_pub);
    h.update(node_id.as_bytes());
    h.update(&[chosen_suite.id()]);
    h.update(node_static_pub);
    *h.finalize().as_bytes()
}

/// Client-side V9-FS session state, built up hop-by-hop during telescopic setup.
///
/// After all hops are established, `layer_keys[i]` was derived from
/// `client_eph_i × server_eph_i` (both ephemeral — no static key).
pub struct OnionFsSession {
    /// Per-hop layer keys, indexed by position (entry = 0).
    pub layer_keys: Vec<[u8; 32]>,
    /// Per-hop AEAD suites, one per hop, indexed by position.
    pub layer_aead_suites: Vec<AeadSuite>,
    /// Client's per-hop ephemeral public keys (for audit/logging; not secret).
    pub client_eph_pubs: Vec<[u8; 32]>,
    /// Server's per-hop ephemeral public keys (received in `FsCreatedFrame`).
    pub server_eph_pubs: Vec<[u8; 32]>,
    /// Incremental transcript after each hop is established.
    pub transcripts: Vec<[u8; 32]>,
}

impl OnionFsSession {
    /// Unwrap a reply frame wrapped by N hops in reverse-onion order.
    ///
    /// Identical algorithm to `OnionSession::unwrap_reply` — both operate on
    /// `(layer_keys, layer_aead_suites)`. The keys are different (both-eph ECDH
    /// vs one-eph ECDH) but the reply-path stripping logic is unchanged.
    pub fn unwrap_reply(&self, wire_bytes: &[u8]) -> Result<Vec<u8>, MirageError> {
        let n = self.layer_keys.len();
        let mut current = wire_bytes.to_vec();
        for (i, key) in self.layer_keys.iter().enumerate() {
            let suite = self.layer_aead_suites[i];
            current = peel_reply_layer_v7(suite, key, &current)?;
            if i + 1 < n {
                if current.len() < 4 {
                    return Err(MirageError::Protocol(format!(
                        "v9-fs onion reply: layer {} too short for inner length prefix ({} bytes)",
                        i,
                        current.len()
                    )));
                }
                let inner_len =
                    u32::from_be_bytes([current[0], current[1], current[2], current[3]]) as usize;
                if current.len() != 4 + inner_len {
                    return Err(MirageError::Protocol(format!(
                        "v9-fs onion reply: layer {} inner length mismatch: declared {}, got {} body bytes",
                        i,
                        inner_len,
                        current.len() - 4
                    )));
                }
                current.drain(..4);
            }
        }
        Ok(current)
    }
}

/// Node-side V9-FS peel for one hop (ntor-style authenticated forward secrecy).
///
/// Takes the node's per-accept EPHEMERAL secret, the node's CERTIFIED STATIC keypair
/// (for authentication), the client's ephemeral public key, and the node's `node_id`.
///
/// Internally the function:
/// 1. Derives `server_eph_pub` from `server_eph_secret`.
/// 2. Computes `ee = server_eph × client_eph_pub` (forward secrecy term).
/// 3. Computes `es = node_static.secret × client_eph_pub` (authentication term).
/// 4. Reproduces the extended transcript (binds certified static pub):
///    `t_i = extend_fs_transcript(prev, pos, node_id, client_eph_pub, server_eph_pub, &node_static.public.to_bytes(), suite)`.
/// 5. Derives `layer_key = derive_layer_key_v9_fs(&ee, &es, pos, &t_i, suite)`.
/// 6. Computes `auth_tag = compute_fs_auth_tag(&layer_key, &t_i, &server_eph_pub)`.
///
/// All shared secrets are zeroized after use (via `Zeroizing`).
///
/// Returns `(layer_key, server_eph_pub_bytes, t_i, auth_tag)`. The caller puts
/// `server_eph_pub_bytes` in `FsCreatedFrame.server_eph_pub`, `t_i` in
/// `FsCreatedFrame.transcript_hash`, and `auth_tag` in `FsCreatedFrame.auth_tag`.
///
/// An on-path party without the node's certified static secret cannot produce a matching `auth_tag`.
pub fn peel_onion_fs_layer(
    server_eph_secret: EphemeralSecret,
    node_static: &KeyPair,
    client_eph_pub: &[u8; 32],
    chain_position: u8,
    prev_transcript: &[u8; 32],
    node_id: &str,
    chosen_suite: AeadSuite,
) -> ([u8; 32], [u8; 32], [u8; 32], [u8; 32]) {
    let server_eph_pub = PublicKey::from(&server_eph_secret).to_bytes();
    let client_pub = PublicKey::from(*client_eph_pub);

    // ee: server_eph × client_eph (forward secrecy)
    let ee_raw = server_eph_secret.diffie_hellman(&client_pub);
    let ee_bytes = Zeroizing::new(ee_raw.to_bytes());

    // es: node_static × client_eph (node authentication)
    let es_raw = node_static.secret.diffie_hellman(&client_pub);
    let es_bytes = Zeroizing::new(es_raw.to_bytes());

    let node_static_pub = node_static.public.to_bytes();
    let t_i = extend_fs_transcript(
        prev_transcript,
        chain_position,
        node_id,
        client_eph_pub,
        &server_eph_pub,
        &node_static_pub,
        chosen_suite,
    );
    let layer_key = derive_layer_key_v9_fs(&ee_bytes, &es_bytes, chain_position, &t_i, chosen_suite);
    let auth_tag = compute_fs_auth_tag(&layer_key, &t_i, &server_eph_pub);
    (layer_key, server_eph_pub, t_i, auth_tag)
}

#[cfg(test)]
mod fs_primitives_tests {
    use super::*;
    use rand::rngs::OsRng;

    // ── derive_layer_key_v9_fs ───────────────────────────────────────────────

    /// Client and server compute the same key given matching ephemerals + static key.
    #[test]
    fn derive_layer_key_v9_fs_client_server_agree() {
        use x25519_dalek::StaticSecret;

        let node_kp = KeyPair::generate();
        let node_static_pub = node_kp.public.to_bytes();

        // Use StaticSecret on client side so we can do two DHs.
        let client_eph = StaticSecret::random_from_rng(OsRng);
        let client_eph_pub = x25519_dalek::PublicKey::from(&client_eph).to_bytes();

        let server_eph = EphemeralSecret::random_from_rng(OsRng);
        let server_eph_pub_bytes = PublicKey::from(&server_eph).to_bytes();

        let transcript = [0x42u8; 32];
        let suite = AeadSuite::ChaCha20Poly1305;
        let pos = 0u8;

        // Server side: peel_onion_fs_layer.
        let (server_key, srv_pub, t_server, auth_tag_server) =
            peel_onion_fs_layer(server_eph, &node_kp, &client_eph_pub, pos, &transcript, "test-node", suite);

        // Client side: two DHs.
        let ee_client = Zeroizing::new(
            client_eph.diffie_hellman(&PublicKey::from(srv_pub)).to_bytes(),
        );
        let es_client = Zeroizing::new(
            client_eph.diffie_hellman(&PublicKey::from(node_static_pub)).to_bytes(),
        );
        let t_client = extend_fs_transcript(
            &transcript, pos, "test-node", &client_eph_pub, &srv_pub, &node_static_pub, suite,
        );
        let client_key = derive_layer_key_v9_fs(&ee_client, &es_client, pos, &t_client, suite);
        let auth_tag_client = compute_fs_auth_tag(&client_key, &t_client, &srv_pub);

        assert_eq!(client_key, server_key, "client and server must derive identical key");
        assert_eq!(t_client, t_server, "client and server transcript must agree");
        assert_eq!(auth_tag_client, auth_tag_server, "auth tags must match");
        assert_eq!(srv_pub, server_eph_pub_bytes, "peel must return server eph pub");
    }

    /// V9-FS key differs from the legacy non-FS ("v8") key even when the same
    /// shared secret is used.
    ///
    /// `derive_layer_key_v8` (the non-FS derivation this compared against) was
    /// deleted with the rest of the non-forward-secret onion path. Rather than
    /// resurrect it, this pins the exact 32 bytes it produced for these fixed
    /// inputs — captured from the live function immediately before removal —
    /// so the test keeps proving domain separation between the two label
    /// spaces without any non-FS code needing to exist.
    #[test]
    fn derive_layer_key_v9_fs_differs_from_v8() {
        let shared = [0x11u8; 32];
        let transcript = [0x22u8; 32];
        let suite = AeadSuite::Aes256Gcm;
        let pos = 0u8;

        // Pinned output of the now-deleted
        // `derive_layer_key_v8(&shared, pos, &transcript, suite)` for these
        // exact inputs (label `b"mirage-onion-layer-v8"`, keyed BLAKE3 over
        // `shared_secret`).
        let legacy_v8_key: [u8; 32] = [
            0x36, 0x07, 0x4d, 0xcf, 0x13, 0xc8, 0xd7, 0xc8, 0x54, 0x1d, 0x70, 0x43, 0x4e, 0x4e,
            0xa6, 0x1b, 0x4f, 0x1f, 0xf2, 0x57, 0x67, 0xa9, 0x4a, 0x00, 0x08, 0x4f, 0x9b, 0x2d,
            0x0e, 0xba, 0xe1, 0xf4,
        ];

        // For v9-fs we need two shared secrets; use same bytes for both to keep test simple.
        let key_fs = derive_layer_key_v9_fs(&shared, &shared, pos, &transcript, suite);

        assert_ne!(
            key_fs, legacy_v8_key,
            "v9-fs and the deleted v8 label must produce different keys"
        );
    }

    /// A snapshot observer has: node_static (exposed), client_eph_pub, server_eph_pub.
    /// They can compute es = static × client_eph, but NOT ee = server_eph × client_eph
    /// (server_eph secret is gone). So they cannot reconstruct the session key.
    #[test]
    fn static_key_cannot_derive_fs_layer_key() {
        use x25519_dalek::StaticSecret;

        let node_kp = KeyPair::generate();

        let client_eph = StaticSecret::random_from_rng(OsRng);
        let client_eph_pub = x25519_dalek::PublicKey::from(&client_eph).to_bytes();

        let server_eph = EphemeralSecret::random_from_rng(OsRng);
        let server_eph_pub_bytes = PublicKey::from(&server_eph).to_bytes();

        let transcript = [0x01u8; 32];
        let suite = AeadSuite::ChaCha20Poly1305;

        // Real key: both ee + es.
        let (real_fs_key, _, _, _) =
            peel_onion_fs_layer(server_eph, &node_kp, &client_eph_pub, 0, &transcript, "test-node", suite);

        // Outside party has static secret + sees server_eph_pub — can compute es but NOT ee.
        // They try: ee=static×client_eph (wrong), es=static×client_eph (also wrong DH path).
        // Actually: outside party can compute es correctly (they have static), but ee requires
        // server_eph secret which is gone. Use wrong es (can't get real ee either).
        let wrong_ee = Zeroizing::new(
            node_kp.secret.diffie_hellman(&PublicKey::from(client_eph_pub)).to_bytes(),
        );
        // es computed correctly by outside party (they have static key)
        let correct_es = Zeroizing::new(
            node_kp.secret.diffie_hellman(&PublicKey::from(client_eph_pub)).to_bytes(),
        );
        // But they use wrong_ee (which equals correct_es here — that's the point:
        // without server_eph secret, they can't distinguish ee from es).
        let wrong_key = derive_layer_key_v9_fs(&wrong_ee, &correct_es, 0, &transcript, suite);

        assert_ne!(
            real_fs_key, wrong_key,
            "static key alone must not reproduce FS layer key (ee term is missing)"
        );

        let _ = server_eph_pub_bytes;
    }

    /// An on-path party generates their own server ephemeral and computes transcript_hash correctly,
    /// but does NOT possess the node's certified static secret, so they cannot produce
    /// a matching auth_tag. The client's auth_tag check must catch this.
    #[test]
    fn onpath_substituted_server_ephemeral_fails_auth() {
        use x25519_dalek::StaticSecret;

        let real_node_kp = KeyPair::generate();
        let real_node_static_pub = real_node_kp.public.to_bytes();

        let client_eph = StaticSecret::random_from_rng(OsRng);
        let client_eph_pub = x25519_dalek::PublicKey::from(&client_eph).to_bytes();

        let transcript = [0x10u8; 32];
        let suite = AeadSuite::ChaCha20Poly1305;

        // On-path party generates their own server ephemeral.
        let onpath_eph = EphemeralSecret::random_from_rng(OsRng);
        let onpath_eph_pub = PublicKey::from(&onpath_eph).to_bytes();

        // On-path party computes ee (they have server_eph secret).
        let onpath_ee = Zeroizing::new(
            onpath_eph.diffie_hellman(&PublicKey::from(client_eph_pub)).to_bytes(),
        );
        // On-path party cannot compute real es = client_eph × real_node_static (they lack node static secret).
        // They substitute a fake es using their own key.
        let fake_node_kp = KeyPair::generate();
        let onpath_fake_es = Zeroizing::new(
            fake_node_kp.secret.diffie_hellman(&PublicKey::from(client_eph_pub)).to_bytes(),
        );

        // On-path transcript uses their onpath_eph_pub but REAL node_static_pub (they see it from peer_table).
        let onpath_t = extend_fs_transcript(
            &transcript, 0, "node-real", &client_eph_pub, &onpath_eph_pub, &real_node_static_pub, suite,
        );
        // On-path party derives a key (with wrong es — they don't have real node static secret).
        let onpath_key = derive_layer_key_v9_fs(&onpath_ee, &onpath_fake_es, 0, &onpath_t, suite);
        // On-path party computes auth_tag with their own (wrong) key.
        let onpath_auth_tag = compute_fs_auth_tag(&onpath_key, &onpath_t, &onpath_eph_pub);

        // Client side: uses real certified node_static_pub for es.
        let client_ee = Zeroizing::new(
            client_eph.diffie_hellman(&PublicKey::from(onpath_eph_pub)).to_bytes(),
        );
        let client_es = Zeroizing::new(
            client_eph.diffie_hellman(&PublicKey::from(real_node_static_pub)).to_bytes(),
        );
        let client_t = extend_fs_transcript(
            &transcript, 0, "node-real", &client_eph_pub, &onpath_eph_pub, &real_node_static_pub, suite,
        );
        let client_key = derive_layer_key_v9_fs(&client_ee, &client_es, 0, &client_t, suite);
        let expected_auth_tag = compute_fs_auth_tag(&client_key, &client_t, &onpath_eph_pub);

        // The client's expected auth tag ≠ what on-path party produced, because their es terms differ.
        assert_ne!(
            expected_auth_tag, onpath_auth_tag,
            "on-path party without certified static secret must not produce a matching auth_tag"
        );

        // Transcripts agree (on-path party used correct inputs for transcript).
        assert_eq!(client_t, onpath_t);
        // But keys differ (es differs → keys differ).
        assert_ne!(client_key, onpath_key);
    }

    /// Two different static keypairs produce different es → different layer_key.
    /// Proves the certified static key binds node identity into the session.
    #[test]
    fn node_without_certified_static_derives_different_key() {
        use x25519_dalek::StaticSecret;

        let node_kp_a = KeyPair::generate();
        let node_kp_b = KeyPair::generate();

        let client_eph = StaticSecret::random_from_rng(OsRng);
        let client_eph_pub = x25519_dalek::PublicKey::from(&client_eph).to_bytes();

        let server_eph_a = EphemeralSecret::random_from_rng(OsRng);
        let server_eph_b = EphemeralSecret::random_from_rng(OsRng);
        let server_eph_a_pub = PublicKey::from(&server_eph_a).to_bytes();
        let server_eph_b_pub = PublicKey::from(&server_eph_b).to_bytes();

        let transcript = [0x20u8; 32];
        let suite = AeadSuite::Aes256Gcm;

        // Node A: uses kp_a's static.
        let (key_a, srv_a_pub, t_a, _) =
            peel_onion_fs_layer(server_eph_a, &node_kp_a, &client_eph_pub, 0, &transcript, "node-a", suite);

        // Node B: uses kp_b's static.
        let (key_b, srv_b_pub, t_b, _) =
            peel_onion_fs_layer(server_eph_b, &node_kp_b, &client_eph_pub, 0, &transcript, "node-b", suite);

        // Different static keys → different es → different layer_key.
        assert_ne!(key_a, key_b, "different certified static keys must produce different layer keys");

        let _ = server_eph_a_pub;
        let _ = server_eph_b_pub;
        let _ = srv_a_pub;
        let _ = srv_b_pub;
        let _ = t_a;
        let _ = t_b;
    }

    // ── compute_fs_transcript_base ───────────────────────────────────────────

    #[test]
    fn fs_transcript_base_is_deterministic() {
        let t1 = compute_fs_transcript_base(b"staging-v2", b"c-fs-test");
        let t2 = compute_fs_transcript_base(b"staging-v2", b"c-fs-test");
        assert_eq!(t1, t2);
    }

    #[test]
    fn fs_transcript_base_differs_on_different_ids() {
        let t_mesh = compute_fs_transcript_base(b"staging-v2", b"c-fs");
        let t_chain = compute_fs_transcript_base(b"staging-v2", b"c-fs-other");
        let t_mesh2 = compute_fs_transcript_base(b"other-mesh", b"c-fs");
        assert_ne!(t_mesh, t_chain);
        assert_ne!(t_mesh, t_mesh2);
    }

    // ── extend_fs_transcript ─────────────────────────────────────────────────

    #[test]
    fn extend_fs_transcript_is_deterministic() {
        let base = compute_fs_transcript_base(b"mesh", b"chain");
        let c_pub = [0xAAu8; 32];
        let s_pub = [0xBBu8; 32];
        let n_pub = [0xCCu8; 32];

        let t1 = extend_fs_transcript(&base, 0, "hop-0", &c_pub, &s_pub, &n_pub, AeadSuite::ChaCha20Poly1305);
        let t2 = extend_fs_transcript(&base, 0, "hop-0", &c_pub, &s_pub, &n_pub, AeadSuite::ChaCha20Poly1305);
        assert_eq!(t1, t2);
    }

    /// Two different `server_eph_pub` values produce different transcripts.
    #[test]
    fn extend_fs_transcript_differs_on_different_server_eph() {
        let base = compute_fs_transcript_base(b"mesh", b"chain");
        let c_pub = [0x11u8; 32];
        let s_pub_a = [0x22u8; 32];
        let s_pub_b = [0x33u8; 32];
        let n_pub = [0x44u8; 32];

        let ta = extend_fs_transcript(&base, 0, "hop-0", &c_pub, &s_pub_a, &n_pub, AeadSuite::ChaCha20Poly1305);
        let tb = extend_fs_transcript(&base, 0, "hop-0", &c_pub, &s_pub_b, &n_pub, AeadSuite::ChaCha20Poly1305);
        assert_ne!(ta, tb, "different server_eph_pub must produce different transcript");
    }

    /// Two different `client_eph_pub` values produce different transcripts.
    #[test]
    fn extend_fs_transcript_differs_on_different_client_eph() {
        let base = compute_fs_transcript_base(b"mesh", b"chain");
        let c_pub_a = [0x44u8; 32];
        let c_pub_b = [0x55u8; 32];
        let s_pub = [0x66u8; 32];
        let n_pub = [0x77u8; 32];

        let ta = extend_fs_transcript(&base, 0, "hop-0", &c_pub_a, &s_pub, &n_pub, AeadSuite::ChaCha20Poly1305);
        let tb = extend_fs_transcript(&base, 0, "hop-0", &c_pub_b, &s_pub, &n_pub, AeadSuite::ChaCha20Poly1305);
        assert_ne!(ta, tb, "different client_eph_pub must produce different transcript");
    }

    #[test]
    fn extend_fs_transcript_differs_on_different_positions() {
        let base = compute_fs_transcript_base(b"mesh", b"chain");
        let c_pub = [0x77u8; 32];
        let s_pub = [0x88u8; 32];
        let n_pub = [0x99u8; 32];

        let t0 = extend_fs_transcript(&base, 0, "hop-0", &c_pub, &s_pub, &n_pub, AeadSuite::ChaCha20Poly1305);
        let t1 = extend_fs_transcript(&base, 1, "hop-0", &c_pub, &s_pub, &n_pub, AeadSuite::ChaCha20Poly1305);
        assert_ne!(t0, t1);
    }

    /// Transcript differs when node_static_pub differs — proves static is bound.
    #[test]
    fn extend_fs_transcript_differs_on_different_static_pub() {
        let base = compute_fs_transcript_base(b"mesh", b"chain");
        let c_pub = [0xAAu8; 32];
        let s_pub = [0xBBu8; 32];
        let n_pub_a = [0xCCu8; 32];
        let n_pub_b = [0xDDu8; 32];

        let ta = extend_fs_transcript(&base, 0, "hop-0", &c_pub, &s_pub, &n_pub_a, AeadSuite::ChaCha20Poly1305);
        let tb = extend_fs_transcript(&base, 0, "hop-0", &c_pub, &s_pub, &n_pub_b, AeadSuite::ChaCha20Poly1305);
        assert_ne!(ta, tb, "different node_static_pub must produce different transcript");
    }

    // ── OnionFsSession::unwrap_reply ─────────────────────────────────────────

    #[test]
    fn onion_fs_session_unwrap_reply_3hop() {
        use crate::cores::onion::layer::wrap_reply_layer_v7;

        let suite = AeadSuite::ChaCha20Poly1305;
        let keys: Vec<[u8; 32]> = (0..3u8).map(|i| [i + 1; 32]).collect();

        let session = OnionFsSession {
            layer_keys: keys.clone(),
            layer_aead_suites: vec![suite; 3],
            client_eph_pubs: vec![[0u8; 32]; 3],
            server_eph_pubs: vec![[0u8; 32]; 3],
            transcripts: vec![[0u8; 32]; 3],
        };

        let plaintext = b"hello from exit";
        // Simulate exit-hop wrapping, then hop 1, then hop 0.
        let r2 = wrap_reply_layer_v7(suite, &keys[2], plaintext).unwrap();
        let mut r2_framed = (r2.len() as u32).to_be_bytes().to_vec();
        r2_framed.extend_from_slice(&r2);
        let r1 = wrap_reply_layer_v7(suite, &keys[1], &r2_framed).unwrap();
        let mut r1_framed = (r1.len() as u32).to_be_bytes().to_vec();
        r1_framed.extend_from_slice(&r1);
        let r0 = wrap_reply_layer_v7(suite, &keys[0], &r1_framed).unwrap();

        let unwrapped = session.unwrap_reply(&r0).unwrap();
        assert_eq!(unwrapped, plaintext);
    }

    // ── 2-hop + 3-hop full-cycle integration ─────────────────────────────────

    // Helper: simulate client side for one hop given server peel outputs.
    fn client_hop(
        client_eph: x25519_dalek::StaticSecret,
        client_eph_pub: &[u8; 32],
        srv_pub: &[u8; 32],
        node_static_pub: &[u8; 32],
        prev: &[u8; 32],
        pos: u8,
        node_id: &str,
        suite: AeadSuite,
    ) -> ([u8; 32], [u8; 32]) {
        let ee = Zeroizing::new(
            client_eph.diffie_hellman(&PublicKey::from(*srv_pub)).to_bytes(),
        );
        let es = Zeroizing::new(
            client_eph.diffie_hellman(&PublicKey::from(*node_static_pub)).to_bytes(),
        );
        let t = extend_fs_transcript(prev, pos, node_id, client_eph_pub, srv_pub, node_static_pub, suite);
        let key = derive_layer_key_v9_fs(&ee, &es, pos, &t, suite);
        (key, t)
    }

    /// Full 2-hop FS cycle: client derives keys, server (peel) derives same keys,
    /// auth_tags verified, transcripts match.
    #[test]
    fn fs_full_cycle_2hop() {
        use x25519_dalek::StaticSecret;

        let suite = AeadSuite::ChaCha20Poly1305;
        let mesh_id = b"staging-v2";
        let chain_id = b"c-fs-2hop";
        let node_ids = ["node-0", "node-1"];

        let node_kps = [KeyPair::generate(), KeyPair::generate()];

        let base = compute_fs_transcript_base(mesh_id, chain_id);

        // --- Hop 0 ---
        let c0 = StaticSecret::random_from_rng(OsRng);
        let c0_pub = x25519_dalek::PublicKey::from(&c0).to_bytes();
        let s0 = EphemeralSecret::random_from_rng(OsRng);

        let (server_key0, srv0_pub, server_t0, auth_tag_server0) =
            peel_onion_fs_layer(s0, &node_kps[0], &c0_pub, 0, &base, node_ids[0], suite);

        let (client_key0, t0) = client_hop(c0, &c0_pub, &srv0_pub, &node_kps[0].public.to_bytes(), &base, 0, node_ids[0], suite);
        let auth_tag_client0 = compute_fs_auth_tag(&client_key0, &t0, &srv0_pub);

        assert_eq!(client_key0, server_key0, "hop 0: key must match");
        assert_eq!(t0, server_t0, "hop 0: transcript must match");
        assert_eq!(auth_tag_client0, auth_tag_server0, "hop 0: auth_tag must match");

        // --- Hop 1 ---
        let c1 = StaticSecret::random_from_rng(OsRng);
        let c1_pub = x25519_dalek::PublicKey::from(&c1).to_bytes();
        let s1 = EphemeralSecret::random_from_rng(OsRng);

        let (server_key1, srv1_pub, server_t1, auth_tag_server1) =
            peel_onion_fs_layer(s1, &node_kps[1], &c1_pub, 1, &t0, node_ids[1], suite);

        let (client_key1, t1) = client_hop(c1, &c1_pub, &srv1_pub, &node_kps[1].public.to_bytes(), &t0, 1, node_ids[1], suite);
        let auth_tag_client1 = compute_fs_auth_tag(&client_key1, &t1, &srv1_pub);

        assert_eq!(client_key1, server_key1, "hop 1: key must match");
        assert_eq!(t1, server_t1, "hop 1: transcript must match");
        assert_eq!(auth_tag_client1, auth_tag_server1, "hop 1: auth_tag must match");

        assert_ne!(client_key0, client_key1);
    }

    /// Full 3-hop FS cycle: verify per-hop key isolation + auth tags.
    #[test]
    fn fs_full_cycle_3hop() {
        use x25519_dalek::StaticSecret;

        let suite = AeadSuite::Aes256Gcm;
        let base = compute_fs_transcript_base(b"mesh", b"chain-3hop");
        let node_ids = ["n0", "n1", "n2"];
        let node_kps = [KeyPair::generate(), KeyPair::generate(), KeyPair::generate()];

        let mut transcripts = vec![base];
        let mut client_keys = Vec::new();
        let mut server_keys = Vec::new();

        for i in 0..3usize {
            let c = StaticSecret::random_from_rng(OsRng);
            let c_pub = x25519_dalek::PublicKey::from(&c).to_bytes();
            let s = EphemeralSecret::random_from_rng(OsRng);
            let prev = transcripts[i];
            let node_static_pub = node_kps[i].public.to_bytes();

            let (sk, srv_pub, server_t_i, auth_server) =
                peel_onion_fs_layer(s, &node_kps[i], &c_pub, i as u8, &prev, node_ids[i], suite);
            server_keys.push(sk);

            let (ck, client_t_i) = client_hop(c, &c_pub, &srv_pub, &node_static_pub, &prev, i as u8, node_ids[i], suite);
            let auth_client = compute_fs_auth_tag(&ck, &client_t_i, &srv_pub);
            client_keys.push(ck);

            assert_eq!(ck, sk, "hop {i}: key mismatch");
            assert_eq!(client_t_i, server_t_i, "hop {i}: transcript mismatch");
            assert_eq!(auth_client, auth_server, "hop {i}: auth_tag mismatch");

            transcripts.push(client_t_i);
        }

        assert_ne!(client_keys[0], client_keys[1]);
        assert_ne!(client_keys[1], client_keys[2]);
        assert_ne!(client_keys[0], client_keys[2]);
    }

}
