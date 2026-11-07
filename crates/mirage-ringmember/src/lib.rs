//! Merkle ring-membership credential (scheme 0x04).
//!
//! Proves that a client belongs to an authorised member set (identified by a
//! Merkle root) without contacting the issuer at dial time.  A DLEQ nullifier
//! makes the proof single-use per epoch and ties it to the member's secret key
//! so a public-only observer cannot forge a valid token.
//!
//! Role split:
//! - **Issuer** (opbox, Phase 3): calls [`issuer_build_tree`] → distributes
//!   `member_sk + path` to each member; publishes the root in `EpochEntry`.
//! - **Member** (client, Phase 4): calls [`prove_membership`] at dial time.
//! - **Verifier** (node, Phase 2): calls [`verify_membership`]; uses returned
//!   [`Nullifier`] for SpentSet replay tracking.
//!
//! # Wire layout (token body — scheme byte 0x04 is the credential layer)
//!
//! ```text
//! [ 4B epoch_id_le | 4B nf_index_le | 32B member_pk | 32B nullifier
//!   | 32B dleq_c | 32B dleq_s
//!   | 2B depth_le | depth × 33B path_step(32B sibling + 1B is_right) ]
//! ```
//!
//! `nf_index` selects one of `max_dials` distinct per-epoch nullifiers
//! (`nf_i = sk · H_e(epoch, i)`), so a member with a concurrent connection pool
//! can hold several live dials at once without any two presenting the same
//! nullifier (which the verifier's SpentSet would reject as a replay). The
//! verifier rejects `nf_index >= max_dials`; `max_dials == 1` is the strict
//! single-use regime.

use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT,
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
    traits::VartimeMultiscalarMul,
};
use sha2::Sha512;
use zeroize::{Zeroize, ZeroizeOnDrop};

// ── domain-separation tags ────────────────────────────────────────────────────

const TAG_LEAF: &[u8] = b"mirage-ringmember-leaf-v1";
const TAG_NODE: &[u8] = b"mirage-ringmember-node-v1";
const TAG_EPOCHGEN: &[u8] = b"mirage-ringmember-epochgen-v1";
const TAG_DLEQ: &[u8] = b"mirage-ringmember-dleq-v1";

// ── fixed-size type aliases ───────────────────────────────────────────────────

/// Compressed ristretto point representing a member's public key (32 bytes).
pub type MemberPk = [u8; 32];

/// Merkle root (32 bytes, BLAKE3 output).
pub type MerkleRoot = [u8; 32];

/// A single Merkle path step: (sibling hash, is_right).
///
/// `is_right = true` means the sibling is on the right; the current node is
/// the left child at this level.
pub type PathStep = ([u8; 32], bool);

/// Compressed ristretto nullifier (32 bytes).  Returned by [`verify_membership`]
/// for the caller's SpentSet.
pub type Nullifier = [u8; 32];

// ── error type ────────────────────────────────────────────────────────────────

#[derive(thiserror::Error, Debug)]
pub enum RingError {
    #[error("empty member set — cannot build tree")]
    EmptyMemberSet,

    #[error("token byte slice has wrong length: expected at least {min}, got {got}")]
    BadLength { min: usize, got: usize },

    #[error("invalid compressed ristretto point")]
    BadPoint,

    #[error("Merkle path does not reconstruct the expected root")]
    MerkleRootMismatch,

    #[error("DLEQ proof is invalid")]
    DleqInvalid,

    #[error("nullifier index {index} exceeds the epoch dial budget (max_dials={max_dials})")]
    DialBudgetExceeded { index: u32, max_dials: u32 },

    #[error("wire token is malformed: {0}")]
    MalformedToken(&'static str),
}

// ── member secret ─────────────────────────────────────────────────────────────

/// Client-held member secret (ristretto scalar).
///
/// Zeroized on drop.  Never log or transmit this value.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct MemberSecret(Scalar);

impl std::fmt::Debug for MemberSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MemberSecret(<redacted>)")
    }
}

impl MemberSecret {
    /// Serialize the scalar to 32 canonical bytes (little-endian).
    ///
    /// Used by the issuer to seal per-member secrets to disk without
    /// exposing the internal `Scalar` type.  The bytes are the canonical
    /// Ristretto scalar encoding.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    /// Deserialize from 32 bytes produced by [`to_bytes`].
    ///
    /// Returns `None` when `bytes` do not represent a canonical scalar
    /// (i.e. the value is >= the group order).  Callers must treat a
    /// `None` return as a corrupt or tampered secret and refuse to use it.
    pub fn from_bytes(bytes: [u8; 32]) -> Option<Self> {
        Scalar::from_canonical_bytes(bytes)
            .into_option()
            .map(MemberSecret)
    }
}

// ── wire token (parsed) ───────────────────────────────────────────────────────

/// Decoded membership token body (scheme 0x04 byte not included here).
#[derive(Debug, Clone)]
pub struct MembershipToken {
    pub epoch_id: u32,
    /// Per-epoch nullifier index — selects the `H_e(epoch, nf_index)` generator.
    /// Lets a member hold `max_dials` concurrent dials, each with a distinct
    /// nullifier. `0` is the single-use default.
    pub nf_index: u32,
    pub member_pk: MemberPk,
    pub nullifier: Nullifier,
    pub dleq_c: [u8; 32],
    pub dleq_s: [u8; 32],
    /// Merkle inclusion path (leaf → root).
    pub path: Vec<PathStep>,
}

// ── wire encode / decode ──────────────────────────────────────────────────────

/// Fixed header bytes before the variable-length path.
const HEADER_LEN: usize = 4 + 4 + 32 + 32 + 32 + 32 + 2; // 138

impl MembershipToken {
    /// Encode to wire bytes.
    pub fn encode(&self) -> Vec<u8> {
        let depth = self.path.len();
        let mut out = Vec::with_capacity(HEADER_LEN + depth * 33);
        out.extend_from_slice(&self.epoch_id.to_le_bytes());
        out.extend_from_slice(&self.nf_index.to_le_bytes());
        out.extend_from_slice(&self.member_pk);
        out.extend_from_slice(&self.nullifier);
        out.extend_from_slice(&self.dleq_c);
        out.extend_from_slice(&self.dleq_s);
        out.extend_from_slice(&(depth as u16).to_le_bytes());
        for (sibling, is_right) in &self.path {
            out.extend_from_slice(sibling);
            out.push(u8::from(*is_right));
        }
        out
    }

    /// Decode from wire bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, RingError> {
        if bytes.len() < HEADER_LEN {
            return Err(RingError::BadLength {
                min: HEADER_LEN,
                got: bytes.len(),
            });
        }
        let epoch_id = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
        let nf_index = u32::from_le_bytes(bytes[4..8].try_into().unwrap());
        let member_pk: MemberPk = bytes[8..40].try_into().unwrap();
        let nullifier: Nullifier = bytes[40..72].try_into().unwrap();
        let dleq_c: [u8; 32] = bytes[72..104].try_into().unwrap();
        let dleq_s: [u8; 32] = bytes[104..136].try_into().unwrap();
        let depth = u16::from_le_bytes(bytes[136..138].try_into().unwrap()) as usize;

        let required = HEADER_LEN + depth * 33;
        if bytes.len() < required {
            return Err(RingError::BadLength {
                min: required,
                got: bytes.len(),
            });
        }

        let mut path = Vec::with_capacity(depth);
        let mut pos = HEADER_LEN;
        for _ in 0..depth {
            let sibling: [u8; 32] = bytes[pos..pos + 32].try_into().unwrap();
            let is_right = bytes[pos + 32] != 0;
            path.push((sibling, is_right));
            pos += 33;
        }

        Ok(MembershipToken {
            epoch_id,
            nf_index,
            member_pk,
            nullifier,
            dleq_c,
            dleq_s,
            path,
        })
    }
}

// ── internal helpers ──────────────────────────────────────────────────────────

/// `BLAKE3("mirage-ringmember-leaf-v1" || pk_bytes)`.
fn leaf_hash(pk: &MemberPk) -> [u8; 32] {
    let mut h = blake3::Hasher::new_derive_key(unsafe {
        std::str::from_utf8_unchecked(TAG_LEAF)
    });
    h.update(pk);
    *h.finalize().as_bytes()
}

/// `BLAKE3("mirage-ringmember-node-v1" || left || right)`.
fn node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut h = blake3::Hasher::new_derive_key(unsafe {
        std::str::from_utf8_unchecked(TAG_NODE)
    });
    h.update(left.as_ref());
    h.update(right.as_ref());
    *h.finalize().as_bytes()
}

/// Hash a byte slice to a ristretto scalar (BLAKE3 → 64 bytes → wide reduce).
///
/// BLAKE3 produces 32 bytes.  We need 64 for `from_bytes_mod_order_wide`.
/// We derive two 32-byte lanes with domain-separated inputs:
///   lane0 = BLAKE3(b"\x00" || data)
///   lane1 = BLAKE3(b"\x01" || data)
fn blake3_to_scalar(data: &[u8]) -> Scalar {
    let mut out = [0u8; 64];

    let mut h0 = blake3::Hasher::new();
    h0.update(b"\x00");
    h0.update(data);
    out[..32].copy_from_slice(h0.finalize().as_bytes());

    let mut h1 = blake3::Hasher::new();
    h1.update(b"\x01");
    h1.update(data);
    out[32..].copy_from_slice(h1.finalize().as_bytes());

    Scalar::from_bytes_mod_order_wide(&out)
}

/// DLEQ challenge scalar.
///
/// `BLAKE3_scalar(TAG_DLEQ || pk || nf || A || B || transcript)`
fn dleq_challenge(
    pk_bytes: &[u8; 32],
    nf_bytes: &[u8; 32],
    a_bytes: &[u8; 32],
    b_bytes: &[u8; 32],
    transcript: &[u8],
) -> Scalar {
    let mut buf = Vec::with_capacity(
        TAG_DLEQ.len() + 32 + 32 + 32 + 32 + transcript.len(),
    );
    buf.extend_from_slice(TAG_DLEQ);
    buf.extend_from_slice(pk_bytes);
    buf.extend_from_slice(nf_bytes);
    buf.extend_from_slice(a_bytes);
    buf.extend_from_slice(b_bytes);
    buf.extend_from_slice(transcript);
    blake3_to_scalar(&buf)
}

/// Derive the per-dial epoch generator point `H_e(epoch_id, nf_index)`.
///
/// Each `nf_index` yields an independent generator, so `nf_i = sk · H_e_i` are
/// distinct unlinkable-to-each-other nullifiers for the same member within one
/// epoch. The verifier recomputes the generator from the token's `nf_index`, so
/// tampering with the index breaks the DLEQ (recomputed `B'` diverges).
fn epoch_generator(epoch_id: u32, nf_index: u32) -> RistrettoPoint {
    let mut input = Vec::with_capacity(TAG_EPOCHGEN.len() + 8);
    input.extend_from_slice(TAG_EPOCHGEN);
    input.extend_from_slice(&epoch_id.to_le_bytes());
    input.extend_from_slice(&nf_index.to_le_bytes());
    RistrettoPoint::hash_from_bytes::<Sha512>(&input)
}

// ── Merkle tree ───────────────────────────────────────────────────────────────

/// Build a Merkle tree from a set of member public keys.
///
/// Returns `(root, proofs)` where `proofs[i]` is the inclusion path for
/// `members[i]`.  Leaves are the BLAKE3 commitments of each `MemberPk`,
/// sorted before tree construction so the root is deterministic regardless
/// of the order members are passed.
///
/// Odd-node convention: when a level has an odd number of nodes, the last
/// node carries up unchanged (i.e. it is promoted without pairing).
pub fn issuer_build_tree(
    members: &[MemberPk],
) -> Result<(MerkleRoot, Vec<Vec<PathStep>>), RingError> {
    if members.is_empty() {
        return Err(RingError::EmptyMemberSet);
    }

    // Compute leaf hashes and sort them; track original member → sorted index.
    let mut leaves_with_idx: Vec<([u8; 32], usize)> = members
        .iter()
        .enumerate()
        .map(|(i, pk)| (leaf_hash(pk), i))
        .collect();
    leaves_with_idx.sort_by_key(|(h, _)| *h);

    let n = leaves_with_idx.len();
    let sorted_leaves: Vec<[u8; 32]> = leaves_with_idx.iter().map(|(h, _)| *h).collect();

    // Build tree bottom-up; for each level store the nodes.
    // We also record at each level how each original leaf maps to a position.
    let mut levels: Vec<Vec<[u8; 32]>> = vec![sorted_leaves.clone()];
    let mut current = sorted_leaves.clone();
    while current.len() > 1 {
        let mut next = Vec::new();
        let mut i = 0;
        while i < current.len() {
            if i + 1 < current.len() {
                next.push(node_hash(&current[i], &current[i + 1]));
            } else {
                // Odd node: carry up unchanged.
                next.push(current[i]);
            }
            i += 2;
        }
        levels.push(next.clone());
        current = next;
    }

    let root: MerkleRoot = current[0];

    // Build inclusion proof for each original member.
    // Proof is built for sorted position, then stored back via original index.
    let mut proofs_sorted: Vec<Vec<PathStep>> = vec![Vec::new(); n];
    let mut positions: Vec<usize> = (0..n).collect(); // current positions at each level

    for level_idx in 0..levels.len().saturating_sub(1) {
        let level = &levels[level_idx];
        let level_len = level.len();
        for leaf_pos in 0..n {
            let pos = positions[leaf_pos];
            // Determine sibling position and whether sibling is to the right.
            let (sibling_pos, is_right) = if pos % 2 == 0 {
                // Current node is a left child; sibling is to the right.
                if pos + 1 < level_len {
                    (pos + 1, true)
                } else {
                    // Odd node: no sibling, carries up; skip recording a step.
                    // Mark with sentinel: we'll push a zero step only to track
                    // that this is the "carry up" case — but actually the fold
                    // must replicate this too.  Instead of a dummy step, we
                    // skip: the odd node is its own parent.
                    // We do NOT push a path step for an odd node.
                    positions[leaf_pos] = pos / 2;
                    continue;
                }
            } else {
                // Current node is a right child; sibling is to the left.
                (pos - 1, false)
            };

            let sibling = level[sibling_pos];
            proofs_sorted[leaf_pos].push((sibling, is_right));
            // Advance position to parent.
            positions[leaf_pos] = pos / 2;
        }
    }

    // Map proofs back to original member order.
    let mut proofs = vec![Vec::new(); n];
    for (sorted_pos, &(_, orig_idx)) in leaves_with_idx.iter().enumerate() {
        proofs[orig_idx] = proofs_sorted[sorted_pos].clone();
    }

    Ok((root, proofs))
}

/// Verify an inclusion proof.
///
/// Folds the path from the leaf commitment upward and checks that the result
/// equals `expected_root`.
pub fn verify_inclusion(
    member_pk: &MemberPk,
    path: &[PathStep],
    expected_root: &MerkleRoot,
) -> Result<(), RingError> {
    let mut current = leaf_hash(member_pk);
    for (sibling, is_right) in path {
        current = if *is_right {
            // Sibling is to the right; current is the left child.
            node_hash(&current, sibling)
        } else {
            // Sibling is to the left; current is the right child.
            node_hash(sibling, &current)
        };
    }
    if &current == expected_root {
        Ok(())
    } else {
        Err(RingError::MerkleRootMismatch)
    }
}

// ── member keygen ─────────────────────────────────────────────────────────────

/// Generate a fresh member key pair.
///
/// Returns `(secret, public_key)`.  The secret stays with the member client;
/// the public key is given to the issuer to include in the member set.
pub fn member_keygen() -> (MemberSecret, MemberPk) {
    use rand_core::OsRng;
    let sk = Scalar::random(&mut OsRng);
    let pk = (RISTRETTO_BASEPOINT_POINT * sk).compress();
    (MemberSecret(sk), *pk.as_bytes())
}

// ── prove_membership ──────────────────────────────────────────────────────────

/// Produce a membership token for one dial.
///
/// - `member_sk`: the member's secret from [`member_keygen`].
/// - `leaf_path`: the inclusion proof returned by [`issuer_build_tree`].
/// - `epoch_id`: current epoch identifier (must match the verifier's epoch).
/// - `transcript`: dial context bytes (e.g. `epoch_id || chain_id`); bound
///   into the DLEQ challenge so the proof cannot be lifted to a different dial.
/// - `nf_index`: which of the member's `max_dials` per-epoch nullifiers to
///   mint. Use a distinct index per concurrent dial (e.g. a monotonic counter
///   over the connection pool) so no two live dials replay the same nullifier.
///   `0` is the strict single-use value.
pub fn prove_membership(
    member_sk: &MemberSecret,
    leaf_path: &[PathStep],
    epoch_id: u32,
    transcript: &[u8],
    nf_index: u32,
) -> MembershipToken {
    use rand_core::OsRng;

    let sk = &member_sk.0;
    let g = RISTRETTO_BASEPOINT_POINT;

    // Public key.
    let pk_point = g * sk;
    let pk_bytes: MemberPk = *pk_point.compress().as_bytes();

    // Per-dial epoch generator and nullifier.
    let h_e = epoch_generator(epoch_id, nf_index);
    let nf_point = h_e * sk;
    let nf_bytes: Nullifier = *nf_point.compress().as_bytes();

    // DLEQ Chaum-Pedersen proof.
    // k ← random scalar; A = k·G; B = k·H_e
    let k = Scalar::random(&mut OsRng);
    let a_point = g * k;
    let b_point = h_e * k;
    let a_bytes: [u8; 32] = *a_point.compress().as_bytes();
    let b_bytes: [u8; 32] = *b_point.compress().as_bytes();

    // c = BLAKE3-scalar(TAG_DLEQ || pk || nf || A || B || transcript)
    let c = dleq_challenge(&pk_bytes, &nf_bytes, &a_bytes, &b_bytes, transcript);
    // s = k + c·sk
    let s = k + c * sk;

    let dleq_c: [u8; 32] = *c.as_bytes();
    let dleq_s: [u8; 32] = *s.as_bytes();

    MembershipToken {
        epoch_id,
        nf_index,
        member_pk: pk_bytes,
        nullifier: nf_bytes,
        dleq_c,
        dleq_s,
        path: leaf_path.to_vec(),
    }
}

// ── verify_membership ─────────────────────────────────────────────────────────

/// Verify a membership token wire body.
///
/// Checks in order:
/// 1. `nf_index < max_dials` (per-epoch dial budget).
/// 2. Merkle path reconstructs `root`.
/// 3. DLEQ proof is valid (nullifier correctly derived from the same sk as pk
///    under the `H_e(epoch, nf_index)` generator the token names).
///
/// Returns the [`Nullifier`] on success; the caller is responsible for SpentSet
/// tracking (replay enforcement — each distinct `nf_index` yields a distinct
/// nullifier, so a member may hold up to `max_dials` live dials at once).
///
/// `transcript` must match what the prover used in [`prove_membership`].
/// `max_dials` is the epoch's published dial budget (`1` = strict single-use).
pub fn verify_membership(
    token_bytes: &[u8],
    root: &MerkleRoot,
    epoch_id: u32,
    transcript: &[u8],
    max_dials: u32,
) -> Result<Nullifier, RingError> {
    let token = MembershipToken::decode(token_bytes)?;

    if token.epoch_id != epoch_id {
        return Err(RingError::DleqInvalid);
    }

    // Step 0: dial-budget bound. A member may mint nullifiers 0..max_dials;
    // anything at or beyond the budget is rejected before any curve work.
    if token.nf_index >= max_dials {
        return Err(RingError::DialBudgetExceeded {
            index: token.nf_index,
            max_dials,
        });
    }

    // Step 1: Merkle inclusion.
    verify_inclusion(&token.member_pk, &token.path, root)?;

    // Step 2: DLEQ verification.
    //
    // Recompute A' = s·G − c·pk,  B' = s·H_e − c·nf,
    // then recompute the challenge from (pk, nf, A', B', transcript) and
    // check it equals the c in the token.

    let pk_point = CompressedRistretto(token.member_pk)
        .decompress()
        .ok_or(RingError::BadPoint)?;
    let nf_point = CompressedRistretto(token.nullifier)
        .decompress()
        .ok_or(RingError::BadPoint)?;

    // Canonicalise c and s as scalars.
    let c = Scalar::from_canonical_bytes(token.dleq_c)
        .into_option()
        .ok_or(RingError::DleqInvalid)?;
    let s = Scalar::from_canonical_bytes(token.dleq_s)
        .into_option()
        .ok_or(RingError::DleqInvalid)?;

    let g = RISTRETTO_BASEPOINT_POINT;
    let h_e = epoch_generator(epoch_id, token.nf_index);

    // A' = s·G − c·pk
    let a_prime = RistrettoPoint::vartime_multiscalar_mul(
        [s, -c],
        [g, pk_point],
    );
    // B' = s·H_e − c·nf
    let b_prime = RistrettoPoint::vartime_multiscalar_mul(
        [s, -c],
        [h_e, nf_point],
    );

    let a_prime_bytes: [u8; 32] = *a_prime.compress().as_bytes();
    let b_prime_bytes: [u8; 32] = *b_prime.compress().as_bytes();

    let c_prime = dleq_challenge(
        &token.member_pk,
        &token.nullifier,
        &a_prime_bytes,
        &b_prime_bytes,
        transcript,
    );

    if c_prime != c {
        return Err(RingError::DleqInvalid);
    }

    Ok(token.nullifier)
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // Helper: build a 4-member tree and return (root, proofs, members).
    fn build_4(
        members: &[(MemberSecret, MemberPk)],
    ) -> (MerkleRoot, Vec<Vec<PathStep>>) {
        let pks: Vec<MemberPk> = members.iter().map(|(_, pk)| *pk).collect();
        issuer_build_tree(&pks).unwrap()
    }

    // ── happy path ────────────────────────────────────────────────────────────

    /// Full flow: keygen → build tree → prove → encode → decode → verify.
    #[test]
    fn happy_path() {
        let members: Vec<(MemberSecret, MemberPk)> =
            (0..4).map(|_| member_keygen()).collect();
        let (root, proofs) = build_4(&members);
        let epoch_id: u32 = 42;
        let transcript = b"epoch42-chain-xyz";

        for (i, (sk, _pk)) in members.iter().enumerate() {
            let token = prove_membership(sk, &proofs[i], epoch_id, transcript, 0);
            let encoded = token.encode();
            let nf =
                verify_membership(&encoded, &root, epoch_id, transcript, 1).unwrap();
            assert_eq!(nf, token.nullifier, "nullifier mismatch for member {i}");
        }
    }

    // ── bounded budget: distinct indices → distinct nullifiers ─────────────────

    /// One member minting two different `nf_index` values produces two distinct
    /// nullifiers, both of which verify under a budget that admits them. This is
    /// the property that lets a connection pool hold concurrent dials without the
    /// SpentSet rejecting the later ones as replays.
    #[test]
    fn distinct_index_distinct_nullifier() {
        let members: Vec<(MemberSecret, MemberPk)> =
            (0..4).map(|_| member_keygen()).collect();
        let (root, proofs) = build_4(&members);
        let epoch_id: u32 = 9;
        let transcript = b"pool-dials";
        let (sk, _pk) = &members[0];

        let t0 = prove_membership(sk, &proofs[0], epoch_id, transcript, 0);
        let t1 = prove_membership(sk, &proofs[0], epoch_id, transcript, 1);

        assert_ne!(
            t0.nullifier, t1.nullifier,
            "distinct nf_index must yield distinct nullifiers"
        );

        let nf0 = verify_membership(&t0.encode(), &root, epoch_id, transcript, 4).unwrap();
        let nf1 = verify_membership(&t1.encode(), &root, epoch_id, transcript, 4).unwrap();
        assert_ne!(nf0, nf1, "verified nullifiers must differ across indices");
    }

    // ── bounded budget: index at/over budget rejected ─────────────────────────

    /// `nf_index >= max_dials` is rejected; the last in-budget index passes.
    #[test]
    fn index_beyond_budget_rejected() {
        let members: Vec<(MemberSecret, MemberPk)> =
            (0..2).map(|_| member_keygen()).collect();
        let (root, proofs) = build_4(&members);
        let epoch_id: u32 = 11;
        let transcript = b"budget";
        let (sk, _pk) = &members[0];

        // max_dials = 3 admits indices 0,1,2.
        let ok = prove_membership(sk, &proofs[0], epoch_id, transcript, 2);
        verify_membership(&ok.encode(), &root, epoch_id, transcript, 3).unwrap();

        // index 3 is out of budget.
        let over = prove_membership(sk, &proofs[0], epoch_id, transcript, 3);
        let res = verify_membership(&over.encode(), &root, epoch_id, transcript, 3);
        assert!(
            matches!(res, Err(RingError::DialBudgetExceeded { index: 3, max_dials: 3 })),
            "index 3 with max_dials 3 must be rejected as over-budget, got {res:?}"
        );
    }

    /// An index tampered after proving (without re-proving) breaks the DLEQ:
    /// the verifier recomputes `H_e` from the token's index, so `B'` diverges.
    #[test]
    fn tampered_index_rejected() {
        let members: Vec<(MemberSecret, MemberPk)> =
            (0..2).map(|_| member_keygen()).collect();
        let (root, proofs) = build_4(&members);
        let epoch_id: u32 = 13;
        let transcript = b"tamper";
        let (sk, _pk) = &members[0];

        let mut token = prove_membership(sk, &proofs[0], epoch_id, transcript, 0);
        token.nf_index = 1; // tamper: keep nf/c/s but claim a different index
        let res = verify_membership(&token.encode(), &root, epoch_id, transcript, 4);
        assert!(res.is_err(), "tampered nf_index must break DLEQ verification");
    }

    // ── leaf-replay forgery ───────────────────────────────────────────────────

    /// A public observer knows (member_pk, path) but lacks member_sk.
    /// They attach a random nullifier + random DLEQ — must be rejected.
    #[test]
    fn leaf_replay_forgery_rejected() {
        use rand_core::{OsRng, RngCore};

        let members: Vec<(MemberSecret, MemberPk)> =
            (0..4).map(|_| member_keygen()).collect();
        let (root, proofs) = build_4(&members);
        let epoch_id: u32 = 1;
        let transcript = b"some-dial";

        // Take member 0's public info but forge with random nf and DLEQ.
        let (_sk0, pk0) = &members[0];
        let path0 = proofs[0].clone();

        let mut random_nf = [0u8; 32];
        let mut random_c = [0u8; 32];
        let mut random_s = [0u8; 32];
        OsRng.fill_bytes(&mut random_nf);
        OsRng.fill_bytes(&mut random_c);
        OsRng.fill_bytes(&mut random_s);

        let forged = MembershipToken {
            epoch_id,
            nf_index: 0,
            member_pk: *pk0,
            nullifier: random_nf,
            dleq_c: random_c,
            dleq_s: random_s,
            path: path0,
        };

        let encoded = forged.encode();
        let result = verify_membership(&encoded, &root, epoch_id, transcript, 1);
        assert!(
            result.is_err(),
            "forged token with random DLEQ must be rejected"
        );
    }

    // ── double-spend: same epoch = same nullifier ─────────────────────────────

    /// Same member + same epoch → the two tokens carry identical nullifiers
    /// (deterministic DLEQ).  A second distinct valid nullifier is unforgeable.
    #[test]
    fn double_spend_same_nullifier() {
        let members: Vec<(MemberSecret, MemberPk)> =
            (0..2).map(|_| member_keygen()).collect();
        let (root, proofs) = build_4(&members);
        let epoch_id: u32 = 7;
        let transcript = b"dial-transcript";

        let (sk, _pk) = &members[0];
        let t1 = prove_membership(sk, &proofs[0], epoch_id, transcript, 0);
        let t2 = prove_membership(sk, &proofs[0], epoch_id, transcript, 0);

        // Both must verify.
        verify_membership(&t1.encode(), &root, epoch_id, transcript, 1).unwrap();
        verify_membership(&t2.encode(), &root, epoch_id, transcript, 1).unwrap();

        // Nullifiers are identical (deterministic per (sk, epoch, nf_index)).
        assert_eq!(
            t1.nullifier, t2.nullifier,
            "nullifier must be deterministic for same (sk, epoch, nf_index)"
        );
    }

    // ── epoch binding ─────────────────────────────────────────────────────────

    /// A token proved for epoch A fails DLEQ verification under epoch B's H_e.
    #[test]
    fn epoch_binding() {
        let members: Vec<(MemberSecret, MemberPk)> =
            (0..2).map(|_| member_keygen()).collect();
        let (root, proofs) = build_4(&members);
        let transcript = b"same-transcript";

        let (sk, _pk) = &members[0];
        let token_a = prove_membership(sk, &proofs[0], 100, transcript, 0);

        // Verify under epoch 100 — ok.
        verify_membership(&token_a.encode(), &root, 100, transcript, 1).unwrap();

        // Verify under epoch 101 — must fail (H_e differs → DLEQ invalid).
        let res = verify_membership(&token_a.encode(), &root, 101, transcript, 1);
        assert!(res.is_err(), "token from epoch 100 must fail under epoch 101");
    }

    // ── transcript binding ────────────────────────────────────────────────────

    /// Token proved for transcript T1 fails verification under T2.
    #[test]
    fn transcript_binding() {
        let members: Vec<(MemberSecret, MemberPk)> =
            (0..2).map(|_| member_keygen()).collect();
        let (root, proofs) = build_4(&members);
        let epoch_id: u32 = 5;

        let (sk, _pk) = &members[0];
        let token = prove_membership(sk, &proofs[0], epoch_id, b"transcript-T1", 0);

        verify_membership(&token.encode(), &root, epoch_id, b"transcript-T1", 1).unwrap();

        let res =
            verify_membership(&token.encode(), &root, epoch_id, b"transcript-T2", 1);
        assert!(res.is_err(), "token for T1 must fail under T2");
    }

    // ── multi-root isolation ──────────────────────────────────────────────────

    /// A proof valid under root A must be rejected under root B.
    #[test]
    fn multi_root_isolation() {
        let set_a: Vec<(MemberSecret, MemberPk)> =
            (0..2).map(|_| member_keygen()).collect();
        let set_b: Vec<(MemberSecret, MemberPk)> =
            (0..2).map(|_| member_keygen()).collect();

        let (root_a, proofs_a) = build_4(&set_a);
        let (root_b, _proofs_b) = build_4(&set_b);

        let epoch_id: u32 = 3;
        let transcript = b"any";

        let (sk_a, _) = &set_a[0];
        let token_a = prove_membership(sk_a, &proofs_a[0], epoch_id, transcript, 0);

        // Valid under root A.
        verify_membership(&token_a.encode(), &root_a, epoch_id, transcript, 1).unwrap();

        // Invalid under root B (Merkle path mismatch).
        let res = verify_membership(&token_a.encode(), &root_b, epoch_id, transcript, 1);
        assert!(res.is_err(), "token for root A must fail under root B");
    }

    // ── wire encode/decode round-trip ─────────────────────────────────────────

    #[test]
    fn wire_roundtrip() {
        let members: Vec<(MemberSecret, MemberPk)> =
            (0..4).map(|_| member_keygen()).collect();
        let (_, proofs) = build_4(&members);
        let (sk, _pk) = &members[1];
        let token = prove_membership(sk, &proofs[1], 99, b"wire-test", 7);

        let encoded = token.encode();
        let decoded = MembershipToken::decode(&encoded).unwrap();

        assert_eq!(decoded.epoch_id, token.epoch_id);
        assert_eq!(decoded.nf_index, token.nf_index);
        assert_eq!(decoded.nf_index, 7);
        assert_eq!(decoded.member_pk, token.member_pk);
        assert_eq!(decoded.nullifier, token.nullifier);
        assert_eq!(decoded.dleq_c, token.dleq_c);
        assert_eq!(decoded.dleq_s, token.dleq_s);
        assert_eq!(decoded.path.len(), token.path.len());
        for (i, (a, b)) in token.path.iter().zip(decoded.path.iter()).enumerate() {
            assert_eq!(a, b, "path step {i} mismatch");
        }
    }

    // ── Merkle known-answer vector (pins odd-node convention) ─────────────────

    /// Single-member tree: root = leaf hash (no pairing needed).
    #[test]
    fn merkle_single_member() {
        let (_, pk) = member_keygen();
        let (root, proofs) = issuer_build_tree(&[pk]).unwrap();
        assert_eq!(root, leaf_hash(&pk));
        assert!(proofs[0].is_empty(), "no path steps for single-member tree");
        verify_inclusion(&pk, &proofs[0], &root).unwrap();
    }

    /// Three-member tree: pins the odd-node carry-up at the second level.
    ///
    /// Members A, B, C → sorted leaves [L0, L1, L2].
    /// Level 0: [L0, L1, L2]
    /// Level 1: [H(L0,L1), L2]   ← L2 carries up unchanged
    /// Level 2 (root): H(H(L0,L1), L2)
    #[test]
    fn merkle_three_member_known_answer() {
        // Use fixed byte arrays so the test is deterministic.
        let pk_a: MemberPk = [0x01u8; 32];
        let pk_b: MemberPk = [0x02u8; 32];
        let pk_c: MemberPk = [0x03u8; 32];

        let (root, proofs) = issuer_build_tree(&[pk_a, pk_b, pk_c]).unwrap();

        // Verify all three members' proofs reconstruct the root.
        verify_inclusion(&pk_a, &proofs[0], &root).unwrap();
        verify_inclusion(&pk_b, &proofs[1], &root).unwrap();
        verify_inclusion(&pk_c, &proofs[2], &root).unwrap();

        // Manually compute expected root to pin the odd-node convention.
        let leaves = {
            let mut v = vec![leaf_hash(&pk_a), leaf_hash(&pk_b), leaf_hash(&pk_c)];
            v.sort();
            v
        };
        let level1_left = node_hash(&leaves[0], &leaves[1]);
        // Odd node: leaves[2] carries up unchanged.
        let expected_root = node_hash(&level1_left, &leaves[2]);

        assert_eq!(root, expected_root, "odd-node convention mismatch");
    }

    // ── MemberSecret byte serialisation ──────────────────────────────────────

    /// `to_bytes` → `from_bytes` round-trip preserves the secret.
    /// The recovered secret must produce the same public key as the original.
    #[test]
    fn member_secret_bytes_roundtrip() {
        let (sk, pk) = member_keygen();
        let bytes = sk.to_bytes();
        let sk2 = MemberSecret::from_bytes(bytes)
            .expect("canonical scalar must deserialise");
        // Re-derive public key from recovered secret.
        let pk2 = *(RISTRETTO_BASEPOINT_POINT * sk2.0).compress().as_bytes();
        assert_eq!(pk, pk2, "recovered secret must reproduce the same public key");
    }

    /// All-zero bytes (0 scalar) is canonical but still accepted;
    /// 32 bytes of 0xFF are NOT canonical (> group order) and must return None.
    #[test]
    fn member_secret_from_bytes_rejects_non_canonical() {
        let too_large = [0xFFu8; 32];
        assert!(
            MemberSecret::from_bytes(too_large).is_none(),
            "non-canonical scalar must return None"
        );
    }

    // ── absent member cannot dial ─────────────────────────────────────────────

    /// A member not in the set cannot produce a proof that passes Merkle check,
    /// even if they have a valid sk.
    #[test]
    fn absent_member_rejected() {
        let members: Vec<(MemberSecret, MemberPk)> =
            (0..4).map(|_| member_keygen()).collect();
        let (root, proofs) = build_4(&members);
        let epoch_id: u32 = 1;
        let transcript = b"t";

        // Generate a fresh key pair not in the set.
        let (outsider_sk, _outsider_pk) = member_keygen();

        // Use member 0's path but the outsider's sk.
        let token =
            prove_membership(&outsider_sk, &proofs[0], epoch_id, transcript, 0);
        let res = verify_membership(&token.encode(), &root, epoch_id, transcript, 1);

        // The Merkle check must fail (token.member_pk is outsider's pk, not in tree).
        assert!(
            res.is_err(),
            "outsider using member path with own pk must be rejected"
        );
    }
}
