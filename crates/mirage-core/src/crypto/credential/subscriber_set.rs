//! `SubscriberSet` — the edge's own issuer-signed subscriber allowlist.
//!
//! See `docs/mirage/plans/2026-09-25-subscription-bound-credentials.md`,
//! "Coordinator decision (2026-09-25)" — that section OVERRIDES the plan
//! body's client-carried `SubscriberCredential` design. Under the decision
//! actually shipped, the customer device carries nothing: the **edge**
//! holds one issuer-signed set naming every device it currently admits, and
//! the V9 handshake's own already-authenticated static key is looked up in
//! that set — no credential ever rides `EdgeHello`.
//!
//! # Shape
//!
//! One [`SubscriberSet`] is exactly the file `mirage-edge`'s existing
//! box-local subscriber-keys store already carries (same push mechanism,
//! `opbox` `POST /mshd/put/subscriber-key`, same hot-reload) — this module
//! only adds the issuer signature and the per-entry expiry/scope fields the
//! coordinator decision asks for: `{device_pubkey, scope: public | edge:
//! <machine>, not_after_ms = paid-through, subscription_ref}`, plus the
//! set's own `issued_at_ms` and `issuer_sig_hex`.
//!
//! # Canonical signing bytes are independent of entry order
//!
//! [`SubscriberSet`] derives `serde` so it can ride the existing JSON
//! file/push path unchanged, but the JSON array order of `entries` is
//! **not** part of what gets signed. [`sign`] and [`verify`] both compute
//! the signing preimage from a **freshly sorted copy** of `entries` (by
//! `device_pubkey_hex`, then by scope — see [`entry_sort_key`]), never from
//! `serde_json`'s own (order-preserving, but otherwise unspecified-stable)
//! map/array encoding. Two [`SubscriberSet`]s that carry the same entries in
//! a different JSON array order therefore produce the SAME preimage and the
//! SAME valid signature — reordering entries in transit (e.g. a
//! byte-for-byte-non-canonicalising relay) can never invalidate a
//! legitimately issued set.
//!
//! # Enforcement
//!
//! The edge admits a live V9 handshake's static key ([`VerifiedSubscriberSet::admit`])
//! only when: the key is present in the set, its entry has not expired
//! against `now_ms`, and its `scope` matches this edge box's own configured
//! scope ([`EdgeScopeView`]) — a `Public` entry only at a public edge, an
//! `Edge { machine_id }` entry only at the one box named. Nothing here
//! decides *when* to re-check a live session — [`VerifiedSubscriberSet::next_expiry_after`]
//! hands the caller the timestamp to arm its own timer against, so a session
//! is cut the moment its entry expires, not only at the next handshake.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;

// ── Constants ────────────────────────────────────────────────────────────

/// Domain label for [`canonical_signing_bytes`]'s preimage.
const SUBSCRIBER_SET_LABEL: &[u8] = b"MIRAGE-SUBSCRIBER-SET-V1\0";

/// The only version this module knows how to sign or verify today.
pub const SUBSCRIBER_SET_VERSION: u8 = 1;

/// Safety cap on how many entries one signed set may carry. Bounds decode-time
/// memory/CPU against a corrupt or adversarial file; real fleet-wide
/// subscriber counts per box are orders of magnitude below this.
pub const MAX_ENTRIES: usize = 100_000;

/// `device_pubkey_hex` must be exactly this many hex characters — a 32-byte
/// X25519 static public key, hex-encoded.
pub const DEVICE_PUBKEY_HEX_LEN: usize = 64;

/// Upper bound on `SubscriberScope::Edge`'s `machine_id`.
pub const MAX_MACHINE_ID_LEN: usize = 256;

/// Upper bound on `subscription_ref` — opaque to this module, but still
/// bounded so a malformed/adversarial file cannot carry an unbounded string.
pub const MAX_SUBSCRIPTION_REF_LEN: usize = 256;

// ── Types ────────────────────────────────────────────────────────────────

/// Where one entry's device key is admitted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SubscriberScope {
    /// Valid on every edge box configured as a public entrance.
    Public,
    /// Valid only on the edge box whose own `machine_id` matches.
    Edge { machine_id: String },
}

/// One admitted device inside a [`SubscriberSet`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubscriberSetEntry {
    /// X25519 static public key, lower-case hex, [`DEVICE_PUBKEY_HEX_LEN`]
    /// characters — the SAME key the V9 handshake already authenticated.
    pub device_pubkey_hex: String,
    pub scope: SubscriberScope,
    /// `== subscription.period_end_ms` at issue/reissue time. No grace baked
    /// in here — see this module's own doc.
    pub not_after_ms: u64,
    /// Opaque to every edge — correlates issuance/revocation on the panel
    /// side only, never interpreted here.
    pub subscription_ref: String,
}

/// The edge's own issuer-signed subscriber allowlist. See this module's own
/// doc for the shape and the enforcement model.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubscriberSet {
    /// Wire/schema version — [`SUBSCRIBER_SET_VERSION`] today.
    pub v: u8,
    pub issued_at_ms: u64,
    pub entries: Vec<SubscriberSetEntry>,
    /// Hex-encoded Ed25519 signature over [`canonical_signing_bytes`]'s
    /// preimage of `(v, issued_at_ms, entries)`.
    pub issuer_sig_hex: String,
}

// ── Errors ───────────────────────────────────────────────────────────────

/// Everything [`SubscriberSet::decode`] / [`verify`] can reject a set for.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum SubscriberSetError {
    /// The issuer signature over the canonical preimage does not verify —
    /// the set was tampered with, or never really issued by the pinned
    /// subscriber-issuer key.
    #[error("subscriber_set: issuer signature does not verify")]
    BadIssuerSig,
    /// More entries than [`MAX_ENTRIES`] — refused before any crypto runs.
    #[error("subscriber_set: too many entries ({count}, max {max})")]
    TooManyEntries { count: usize, max: usize },
    /// Entry `index`'s `device_pubkey_hex` is not exactly
    /// [`DEVICE_PUBKEY_HEX_LEN`] lower-case hex characters.
    #[error("subscriber_set: entry {index} has a malformed device_pubkey_hex (must be {expected} hex characters)")]
    BadDevicePubkeyHex { index: usize, expected: usize },
    /// Entry `index`'s named `field` exceeds its bound.
    #[error("subscriber_set: entry {index} field '{field}' is too long ({len}, max {max})")]
    FieldTooLong { index: usize, field: &'static str, len: usize, max: usize },
    /// The set's bytes are structurally malformed — bad JSON, bad hex
    /// signature encoding, or any other decode-time precondition this module
    /// refuses to silently paper over. Never a panic.
    #[error("subscriber_set: {0}")]
    Malformed(String),
}

/// Everything [`VerifiedSubscriberSet::admit`] can refuse a presented device
/// key for. Independently reachable, independently tested.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum AdmitRefusal {
    /// No entry in the set names this device key at all.
    #[error("subscriber_set: device not present in the signed set")]
    NotInSet,
    /// The device's entry exists but `now_ms` is past its `not_after_ms`.
    #[error("subscriber_set: entry expired (not_after_ms={not_after_ms})")]
    Expired { not_after_ms: u64 },
    /// The device's entry exists and has not expired, but its `scope` does
    /// not match this edge box's own configured scope.
    #[error("subscriber_set: entry scope does not match this edge's own scope")]
    ScopeMismatch,
}

// ── What one edge box is configured to admit ────────────────────────────

/// Resolved once, at boot, from the edge box's own provisioning config. An
/// edge is never both — mirrors the plan's own `EdgeScope`/`EdgeConfig`
/// split, kept as its own type here rather than reusing [`SubscriberScope`]
/// so "what one entry in the set claims" and "what this box is configured
/// as" can never be silently conflated at a call site.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EdgeScopeView {
    Public,
    Edge { machine_id: String },
}

// ── Sign / verify ────────────────────────────────────────────────────────

/// Issuer side (opbox only — the subscriber-issuer private key never leaves
/// it). Builds a fresh signed set from `entries` — callers are responsible
/// for keeping each entry's own fields within this module's published
/// bounds; [`verify`]/[`SubscriberSet::decode`] enforce them independently
/// on every read, so a bound violation here is caught the moment the set is
/// next read, not silently trusted forever.
pub fn sign(entries: Vec<SubscriberSetEntry>, issued_at_ms: u64, issuer_signing_key: &SigningKey) -> SubscriberSet {
    let preimage = canonical_signing_bytes(SUBSCRIBER_SET_VERSION, issued_at_ms, &entries);
    let sig = issuer_signing_key.sign(&preimage);
    SubscriberSet {
        v: SUBSCRIBER_SET_VERSION,
        issued_at_ms,
        entries,
        issuer_sig_hex: hex::encode(sig.to_bytes()),
    }
}

/// A [`SubscriberSet`] whose issuer signature has already been checked.
/// Borrows the set it was built from — [`admit`](Self::admit) and
/// [`next_expiry_after`](Self::next_expiry_after) hand back references into
/// it, never a copy.
#[derive(Debug, Clone, Copy)]
pub struct VerifiedSubscriberSet<'a> {
    set: &'a SubscriberSet,
}

impl SubscriberSet {
    /// Edge/verifier side: check the issuer signature over the canonical
    /// (order-independent) preimage of this set's own fields.
    ///
    /// Runs bounds validation first — a set that fails [`SubscriberSetError`]
    /// bounds checks is rejected before the Ed25519 verify ever runs.
    pub fn verify(&self, issuer_pub: &VerifyingKey) -> Result<VerifiedSubscriberSet<'_>, SubscriberSetError> {
        self.validate_bounds()?;

        let preimage = canonical_signing_bytes(self.v, self.issued_at_ms, &self.entries);
        let sig_bytes = hex::decode(&self.issuer_sig_hex).map_err(|_| SubscriberSetError::BadIssuerSig)?;
        let sig_arr: [u8; 64] = sig_bytes.try_into().map_err(|_| SubscriberSetError::BadIssuerSig)?;
        let sig = Signature::from_bytes(&sig_arr);
        issuer_pub
            .verify(&preimage, &sig)
            .map_err(|_| SubscriberSetError::BadIssuerSig)?;

        Ok(VerifiedSubscriberSet { set: self })
    }

    /// Decode a set from its wire (JSON) bytes and enforce every bound in
    /// this module (entry count, field lengths, hex shape) — independent of,
    /// and always run before, any signature check. Never a panic on
    /// malformed/adversarial input.
    pub fn decode(bytes: &[u8]) -> Result<Self, SubscriberSetError> {
        let set: SubscriberSet =
            serde_json::from_slice(bytes).map_err(|e| SubscriberSetError::Malformed(e.to_string()))?;
        set.validate_bounds()?;
        Ok(set)
    }

    /// Encode to wire (JSON) bytes.
    pub fn encode(&self) -> Result<Vec<u8>, SubscriberSetError> {
        serde_json::to_vec(self).map_err(|e| SubscriberSetError::Malformed(e.to_string()))
    }

    fn validate_bounds(&self) -> Result<(), SubscriberSetError> {
        if self.entries.len() > MAX_ENTRIES {
            return Err(SubscriberSetError::TooManyEntries { count: self.entries.len(), max: MAX_ENTRIES });
        }
        for (index, entry) in self.entries.iter().enumerate() {
            let hex_ok = entry.device_pubkey_hex.len() == DEVICE_PUBKEY_HEX_LEN
                && entry.device_pubkey_hex.bytes().all(|b| b.is_ascii_hexdigit());
            if !hex_ok {
                return Err(SubscriberSetError::BadDevicePubkeyHex { index, expected: DEVICE_PUBKEY_HEX_LEN });
            }
            if entry.subscription_ref.len() > MAX_SUBSCRIPTION_REF_LEN {
                return Err(SubscriberSetError::FieldTooLong {
                    index,
                    field: "subscription_ref",
                    len: entry.subscription_ref.len(),
                    max: MAX_SUBSCRIPTION_REF_LEN,
                });
            }
            if let SubscriberScope::Edge { machine_id } = &entry.scope {
                if machine_id.len() > MAX_MACHINE_ID_LEN {
                    return Err(SubscriberSetError::FieldTooLong {
                        index,
                        field: "machine_id",
                        len: machine_id.len(),
                        max: MAX_MACHINE_ID_LEN,
                    });
                }
            }
        }
        Ok(())
    }
}

impl<'a> VerifiedSubscriberSet<'a> {
    /// Look up `device_pubkey_hex` (the V9 handshake's own already-verified
    /// static key, presented as lower-case hex) and decide whether this edge
    /// box, presenting `own_scope`, admits it at `now_ms`.
    ///
    /// Checks run in the order a caller can name a distinct refusal for:
    /// presence first ([`AdmitRefusal::NotInSet`]), then expiry
    /// ([`AdmitRefusal::Expired`]), then scope
    /// ([`AdmitRefusal::ScopeMismatch`]) — matching this module's own
    /// published refusal set one-for-one.
    pub fn admit(
        &self,
        device_pubkey_hex: &str,
        now_ms: u64,
        own_scope: &EdgeScopeView,
    ) -> Result<&'a SubscriberSetEntry, AdmitRefusal> {
        let entry = self
            .set
            .entries
            .iter()
            .find(|e| e.device_pubkey_hex.eq_ignore_ascii_case(device_pubkey_hex))
            .ok_or(AdmitRefusal::NotInSet)?;

        if now_ms > entry.not_after_ms {
            return Err(AdmitRefusal::Expired { not_after_ms: entry.not_after_ms });
        }

        let scope_ok = match (&entry.scope, own_scope) {
            (SubscriberScope::Public, EdgeScopeView::Public) => true,
            (SubscriberScope::Edge { machine_id }, EdgeScopeView::Edge { machine_id: own_id }) => {
                machine_id == own_id
            }
            _ => false,
        };
        if !scope_ok {
            return Err(AdmitRefusal::ScopeMismatch);
        }

        Ok(entry)
    }

    /// The latest `not_after_ms` among this device's own entries that is
    /// still ahead of `now_ms`, or `None` if the device has no entry, or
    /// every entry it has is already at or past `now_ms` — so the caller can
    /// arm a session timer that cuts a live connection the moment its entry
    /// expires, not only at the next handshake.
    ///
    /// Takes the maximum rather than [`admit`](Self::admit)'s single
    /// scope-matched entry deliberately: a device can appear more than once
    /// across a subscription-scope transition, and the caller wants to know
    /// the LATEST moment this key remains admissible under ANY of its
    /// entries, not just the one that happened to admit the current session.
    pub fn next_expiry_after(&self, now_ms: u64, device_pubkey_hex: &str) -> Option<u64> {
        self.set
            .entries
            .iter()
            .filter(|e| e.device_pubkey_hex.eq_ignore_ascii_case(device_pubkey_hex))
            .map(|e| e.not_after_ms)
            .filter(|&t| t > now_ms)
            .max()
    }
}

// ── Preimage ─────────────────────────────────────────────────────────────

fn scope_wire_byte(scope: &SubscriberScope) -> u8 {
    match scope {
        SubscriberScope::Public => 0x00,
        SubscriberScope::Edge { .. } => 0x01,
    }
}

/// Deterministic sort key: `device_pubkey_hex` (case-folded), then scope
/// (`Public` before `Edge`, then by `machine_id`) — see this module's own
/// doc, "Canonical signing bytes are independent of entry order".
fn entry_sort_key(entry: &SubscriberSetEntry) -> (String, u8, String) {
    let machine_id = match &entry.scope {
        SubscriberScope::Public => String::new(),
        SubscriberScope::Edge { machine_id } => machine_id.clone(),
    };
    (entry.device_pubkey_hex.to_ascii_lowercase(), scope_wire_byte(&entry.scope), machine_id)
}

/// The signing preimage: domain label, then `(v, issued_at_ms, entries)`
/// with `entries` sorted by [`entry_sort_key`] — deliberately NOT
/// `serde_json`'s own encoding of `self`, so entry order in the JSON array
/// never affects the signature. See this module's own doc.
fn canonical_signing_bytes(v: u8, issued_at_ms: u64, entries: &[SubscriberSetEntry]) -> Vec<u8> {
    let mut sorted: Vec<&SubscriberSetEntry> = entries.iter().collect();
    sorted.sort_by_key(|entry| entry_sort_key(entry));

    let mut buf = Vec::new();
    buf.extend_from_slice(SUBSCRIBER_SET_LABEL);
    buf.push(v);
    buf.extend_from_slice(&issued_at_ms.to_be_bytes());
    buf.extend_from_slice(&(sorted.len() as u32).to_be_bytes());
    for entry in sorted {
        write_len_prefixed(&mut buf, entry.device_pubkey_hex.as_bytes());
        buf.push(scope_wire_byte(&entry.scope));
        if let SubscriberScope::Edge { machine_id } = &entry.scope {
            write_len_prefixed(&mut buf, machine_id.as_bytes());
        }
        buf.extend_from_slice(&entry.not_after_ms.to_be_bytes());
        write_len_prefixed(&mut buf, entry.subscription_ref.as_bytes());
    }
    buf
}

fn write_len_prefixed(buf: &mut Vec<u8>, bytes: &[u8]) {
    buf.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    buf.extend_from_slice(bytes);
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    const NOW: u64 = 1_800_000_000_000;

    fn hexkey(byte: u8) -> String {
        hex::encode([byte; 32])
    }

    fn make_entries() -> Vec<SubscriberSetEntry> {
        vec![
            SubscriberSetEntry {
                device_pubkey_hex: hexkey(0x11),
                scope: SubscriberScope::Public,
                not_after_ms: NOW + 3_600_000,
                subscription_ref: "sub-public".to_string(),
            },
            SubscriberSetEntry {
                device_pubkey_hex: hexkey(0x22),
                scope: SubscriberScope::Edge { machine_id: "box-1".to_string() },
                not_after_ms: NOW + 7_200_000,
                subscription_ref: "sub-private".to_string(),
            },
        ]
    }

    fn make_issuer() -> SigningKey {
        SigningKey::generate(&mut OsRng)
    }

    // ── Sign / verify round trip ─────────────────────────────────────────

    #[test]
    fn sign_then_verify_round_trips() {
        let issuer = make_issuer();
        let set = sign(make_entries(), NOW, &issuer);

        let verified = set.verify(&issuer.verifying_key()).expect("a freshly signed set must verify");
        assert!(verified.admit(&hexkey(0x11), NOW, &EdgeScopeView::Public).is_ok());
    }

    #[test]
    fn wire_round_trip_still_verifies() {
        let issuer = make_issuer();
        let set = sign(make_entries(), NOW, &issuer);
        let wire = set.encode().expect("encode");
        let decoded = SubscriberSet::decode(&wire).expect("decode");

        decoded.verify(&issuer.verifying_key()).expect("decoded set must still verify");
    }

    // ── Tamper detection ─────────────────────────────────────────────────

    #[test]
    fn a_changed_entry_fails_verification() {
        let issuer = make_issuer();
        let mut set = sign(make_entries(), NOW, &issuer);
        set.entries[0].not_after_ms += 1;

        let result = set.verify(&issuer.verifying_key());
        assert_eq!(result.unwrap_err(), SubscriberSetError::BadIssuerSig);
    }

    #[test]
    fn reordering_entries_does_not_break_the_signature() {
        let issuer = make_issuer();
        let mut set = sign(make_entries(), NOW, &issuer);
        set.entries.reverse();

        set.verify(&issuer.verifying_key())
            .expect("canonical signing bytes must be order-independent");
    }

    #[test]
    fn a_signature_minted_over_a_different_set_fails() {
        let issuer = make_issuer();
        let set_a = sign(make_entries(), NOW, &issuer);
        let mut set_b = sign(make_entries(), NOW + 1, &issuer); // different issued_at_ms
        set_b.issuer_sig_hex = set_a.issuer_sig_hex.clone();

        let result = set_b.verify(&issuer.verifying_key());
        assert_eq!(result.unwrap_err(), SubscriberSetError::BadIssuerSig);
    }

    // ── admit() ───────────────────────────────────────────────────────────

    #[test]
    fn admit_refuses_a_device_not_in_the_set() {
        let issuer = make_issuer();
        let set = sign(make_entries(), NOW, &issuer);
        let verified = set.verify(&issuer.verifying_key()).expect("verify");

        let result = verified.admit(&hexkey(0xEE), NOW, &EdgeScopeView::Public);
        assert_eq!(result.unwrap_err(), AdmitRefusal::NotInSet);
    }

    #[test]
    fn admit_refuses_an_expired_entry() {
        let issuer = make_issuer();
        let set = sign(make_entries(), NOW, &issuer);
        let verified = set.verify(&issuer.verifying_key()).expect("verify");

        let past_expiry = NOW + 3_600_000 + 1;
        let result = verified.admit(&hexkey(0x11), past_expiry, &EdgeScopeView::Public);
        assert_eq!(result.unwrap_err(), AdmitRefusal::Expired { not_after_ms: NOW + 3_600_000 });
    }

    #[test]
    fn admit_accepts_a_public_entry_at_a_public_edge() {
        let issuer = make_issuer();
        let set = sign(make_entries(), NOW, &issuer);
        let verified = set.verify(&issuer.verifying_key()).expect("verify");

        let entry = verified
            .admit(&hexkey(0x11), NOW, &EdgeScopeView::Public)
            .expect("public entry at a public edge must be admitted");
        assert_eq!(entry.subscription_ref, "sub-public");
    }

    #[test]
    fn admit_refuses_a_public_entry_at_a_private_edge() {
        let issuer = make_issuer();
        let set = sign(make_entries(), NOW, &issuer);
        let verified = set.verify(&issuer.verifying_key()).expect("verify");

        let own = EdgeScopeView::Edge { machine_id: "box-1".to_string() };
        let result = verified.admit(&hexkey(0x11), NOW, &own);
        assert_eq!(result.unwrap_err(), AdmitRefusal::ScopeMismatch);
    }

    #[test]
    fn admit_accepts_an_edge_entry_on_its_own_machine() {
        let issuer = make_issuer();
        let set = sign(make_entries(), NOW, &issuer);
        let verified = set.verify(&issuer.verifying_key()).expect("verify");

        let own = EdgeScopeView::Edge { machine_id: "box-1".to_string() };
        let entry = verified
            .admit(&hexkey(0x22), NOW, &own)
            .expect("edge entry must be admitted on its own machine");
        assert_eq!(entry.subscription_ref, "sub-private");
    }

    #[test]
    fn admit_refuses_an_edge_entry_on_a_different_machine() {
        let issuer = make_issuer();
        let set = sign(make_entries(), NOW, &issuer);
        let verified = set.verify(&issuer.verifying_key()).expect("verify");

        let other = EdgeScopeView::Edge { machine_id: "box-2".to_string() };
        let result = verified.admit(&hexkey(0x22), NOW, &other);
        assert_eq!(result.unwrap_err(), AdmitRefusal::ScopeMismatch);
    }

    // ── next_expiry_after() ───────────────────────────────────────────────

    #[test]
    fn next_expiry_after_reports_the_entrys_own_expiry() {
        let issuer = make_issuer();
        let set = sign(make_entries(), NOW, &issuer);
        let verified = set.verify(&issuer.verifying_key()).expect("verify");

        assert_eq!(verified.next_expiry_after(NOW, &hexkey(0x11)), Some(NOW + 3_600_000));
    }

    #[test]
    fn next_expiry_after_is_none_once_past_it() {
        let issuer = make_issuer();
        let set = sign(make_entries(), NOW, &issuer);
        let verified = set.verify(&issuer.verifying_key()).expect("verify");

        assert_eq!(verified.next_expiry_after(NOW + 3_600_001, &hexkey(0x11)), None);
    }

    #[test]
    fn next_expiry_after_is_none_for_an_unknown_device() {
        let issuer = make_issuer();
        let set = sign(make_entries(), NOW, &issuer);
        let verified = set.verify(&issuer.verifying_key()).expect("verify");

        assert_eq!(verified.next_expiry_after(NOW, &hexkey(0xEE)), None);
    }

    // ── Bounds / named decode errors ─────────────────────────────────────

    #[test]
    fn decode_refuses_too_many_entries() {
        let issuer = make_issuer();
        let mut entries = Vec::with_capacity(MAX_ENTRIES + 1);
        for i in 0..(MAX_ENTRIES + 1) {
            entries.push(SubscriberSetEntry {
                device_pubkey_hex: hex::encode((i as u32).to_be_bytes().repeat(8)),
                scope: SubscriberScope::Public,
                not_after_ms: NOW + 1,
                subscription_ref: "s".to_string(),
            });
        }
        let set = sign(entries, NOW, &issuer);
        let wire = set.encode().expect("encode");

        let result = SubscriberSet::decode(&wire);
        assert_eq!(
            result.unwrap_err(),
            SubscriberSetError::TooManyEntries { count: MAX_ENTRIES + 1, max: MAX_ENTRIES }
        );
    }

    #[test]
    fn decode_refuses_a_malformed_device_pubkey_hex() {
        let issuer = make_issuer();
        let entries = vec![SubscriberSetEntry {
            device_pubkey_hex: "not-hex".to_string(),
            scope: SubscriberScope::Public,
            not_after_ms: NOW + 1,
            subscription_ref: "s".to_string(),
        }];
        let set = sign(entries, NOW, &issuer);
        let wire = set.encode().expect("encode");

        let result = SubscriberSet::decode(&wire);
        assert_eq!(
            result.unwrap_err(),
            SubscriberSetError::BadDevicePubkeyHex { index: 0, expected: DEVICE_PUBKEY_HEX_LEN }
        );
    }

    #[test]
    fn decode_refuses_an_oversized_subscription_ref() {
        let issuer = make_issuer();
        let entries = vec![SubscriberSetEntry {
            device_pubkey_hex: hexkey(0x11),
            scope: SubscriberScope::Public,
            not_after_ms: NOW + 1,
            subscription_ref: "x".repeat(MAX_SUBSCRIPTION_REF_LEN + 1),
        }];
        let set = sign(entries, NOW, &issuer);
        let wire = set.encode().expect("encode");

        let result = SubscriberSet::decode(&wire);
        assert_eq!(
            result.unwrap_err(),
            SubscriberSetError::FieldTooLong {
                index: 0,
                field: "subscription_ref",
                len: MAX_SUBSCRIPTION_REF_LEN + 1,
                max: MAX_SUBSCRIPTION_REF_LEN,
            }
        );
    }

    #[test]
    fn decode_refuses_an_oversized_machine_id() {
        let issuer = make_issuer();
        let entries = vec![SubscriberSetEntry {
            device_pubkey_hex: hexkey(0x22),
            scope: SubscriberScope::Edge { machine_id: "m".repeat(MAX_MACHINE_ID_LEN + 1) },
            not_after_ms: NOW + 1,
            subscription_ref: "s".to_string(),
        }];
        let set = sign(entries, NOW, &issuer);
        let wire = set.encode().expect("encode");

        let result = SubscriberSet::decode(&wire);
        assert_eq!(
            result.unwrap_err(),
            SubscriberSetError::FieldTooLong {
                index: 0,
                field: "machine_id",
                len: MAX_MACHINE_ID_LEN + 1,
                max: MAX_MACHINE_ID_LEN,
            }
        );
    }

    #[test]
    fn decode_refuses_malformed_json_without_panicking() {
        let result = SubscriberSet::decode(b"not json at all");
        assert!(matches!(result, Err(SubscriberSetError::Malformed(_))));
    }

    // ── Fixed test vector ────────────────────────────────────────────────
    //
    // A hardcoded key + 2-entry set, so opbox and the edge can cross-check
    // the canonical preimage bytes and the resulting signature independently
    // of this module's own round-trip tests above.

    #[test]
    fn fixed_test_vector_preimage_and_signature() {
        // Fixed Ed25519 seed — test-only, never a real issuer key.
        let issuer = SigningKey::from_bytes(&[0x01u8; 32]);

        let entries = vec![
            SubscriberSetEntry {
                device_pubkey_hex: "11".repeat(32),
                scope: SubscriberScope::Public,
                not_after_ms: 1_700_000_000_000,
                subscription_ref: "sub-aaa".to_string(),
            },
            SubscriberSetEntry {
                device_pubkey_hex: "22".repeat(32),
                scope: SubscriberScope::Edge { machine_id: "box-1".to_string() },
                not_after_ms: 1_800_000_000_000,
                subscription_ref: "sub-bbb".to_string(),
            },
        ];
        let issued_at_ms = 1_690_000_000_000u64;

        const EXPECTED_PREIMAGE_HEX: &str = "4d49524147452d535542534352494245522d5345542d56310001000001897bd98400000000020000004031313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131000000018bcfe56800000000077375622d61616100000040323232323232323232323232323232323232323232323232323232323232323232323232323232323232323232323232323232323232323232323232323232320100000005626f782d31000001a3185c5000000000077375622d626262";

        let preimage = canonical_signing_bytes(SUBSCRIBER_SET_VERSION, issued_at_ms, &entries);
        assert_eq!(hex::encode(&preimage), EXPECTED_PREIMAGE_HEX);

        const EXPECTED_ISSUER_SIG_HEX: &str = "15726cd22aeb153f8d86ddff82635490b95f294cdc352fc17c447ffa1498eb065c4825a1e5f01e7dc95c4737345c5d6e09c6638f3640ba2abc2b10840bd8bf07";

        let set = sign(entries, issued_at_ms, &issuer);
        assert_eq!(set.issuer_sig_hex, EXPECTED_ISSUER_SIG_HEX);
        let verified = set.verify(&issuer.verifying_key()).expect("fixed test vector must verify");
        assert!(verified.admit("11".repeat(32).as_str(), 1_690_000_000_001, &EdgeScopeView::Public).is_ok());
    }
}
