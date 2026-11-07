//! Operator-signed authority for the back-office's automated-issuance role
//! to write/read one edge machine's subscriber-key set.
//!
//! See `docs/mirage/plans/2026-09-23-backoffice-automated-issuance.md` §3
//! ("Q2 — Scoped authority") and §6.2 ("The provisioning trigger"). An
//! `EntranceGrant` is the thing a monitor checks — alongside
//! `AuthRole::BackOffice` and a live `ServiceRole::Edge` declared identity
//! for the target — before honouring a `POST /relay/entrance/subscriber-key`
//! or `GET /relay/entrance/dial-faces` call: "role BackOffice **and** a live
//! `EntranceGrant` for `(self_id, machine_id)` **and** `machine_id` carries
//! `ServiceRole::Edge`" (§3's verb table). That monitor-side enforcement, the
//! `PeerEvent::EntranceGrantUpsert` gossip wiring, and the opbox-side mint
//! step are later briefs (4/5/6) — this module carries only the type, its
//! signing-bytes layout, and its verify.
//!
//! # Shape, following [`crate::identity::DeclaredIdentity`]'s own precedent
//!
//! One operator-signed row names exactly one `(back_office_self_id,
//! machine_id)` pair — a grant is never a wildcard and never covers more
//! than one edge. `revoked`/`revoked_at_ms` sit OUTSIDE the signed bytes,
//! exactly the way `DeclaredIdentity::revoked`/`revoked_at_ms` do (see that
//! struct's own field docs): they default to `false`/`None` at mint time and
//! are the local, gossiped-LWW-cache fields a monitor flips after processing
//! a revocation, not something the operator re-signs on every toggle. What
//! IS signed — `grant_id`, `back_office_self_id`, `machine_id`,
//! `issued_at_ms`, `not_after_ms` — is exactly the set a relay must not be
//! able to forge or extend: which back-office, which one edge, and the
//! window it is authorised for.

use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

use crate::identity::{IdentityError, SignatureHex};
use crate::ids::MachineId;

/// Domain prefix for `EntranceGrant` signing bytes — see
/// [`EntranceGrant::signing_bytes`].
const DOMAIN_ENTRANCE_GRANT: &[u8] = b"mirage-entrance-grant-v1\0";

/// Operator-signed authority for one back-office identity to reach one edge
/// machine's subscriber-entrance gate through a monitor relay.
///
/// `operator_sig` covers [`Self::signing_bytes`] — see that function's doc
/// for the exact layout. Gossiped fleet-wide the same way `declared_identities`
/// already is (per the plan's §6.2), so any monitor a back-office dials can
/// verify a grant without asking opbox at request time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntranceGrant {
    /// Revocation-friendly identifier for this grant — lets a grant be
    /// revoked/re-gossiped by id without re-deriving it from
    /// `(back_office_self_id, machine_id)`, mirroring
    /// [`crate::identity::DeclaredIdentity::self_id`]'s own role.
    pub grant_id: Uuid,
    /// Which back-office identity this grant authorises — the
    /// [`crate::identity::DeclaredIdentity::self_id`] of the
    /// `ServiceRole::BackOffice`-role identity minted for the panel.
    pub back_office_self_id: Uuid,
    /// The single edge machine this grant covers. A grant never names more
    /// than one machine — the monitor-side check in §3 is a lookup keyed on
    /// exactly `(back_office_self_id, machine_id)`, not a prefix or a set.
    pub machine_id: MachineId,
    /// Unix-ms when the operator minted this grant.
    pub issued_at_ms: u64,
    /// Unix-ms after which this grant MUST NOT be honoured. Bound into the
    /// operator signature so a relay cannot silently extend a back-office's
    /// authority over an edge past what was actually granted.
    pub not_after_ms: u64,
    /// `true` once the operator revokes this grant and the tombstone has
    /// been gossiped. **Not** part of [`Self::signing_bytes`] — see this
    /// struct's own doc for why, mirroring
    /// [`crate::identity::DeclaredIdentity::revoked`] exactly.
    #[serde(default)]
    pub revoked: bool,
    /// Unix-ms of revocation (`None` while live).
    #[serde(default)]
    pub revoked_at_ms: Option<u64>,
    /// Ed25519 signature over [`Self::signing_bytes`].
    pub operator_sig: SignatureHex,
}

impl EntranceGrant {
    /// Canonical byte form used as the signing input.
    ///
    /// ```text
    /// DOMAIN                     24 bytes + NUL = 25 bytes
    /// grant_id                   16 bytes big-endian UUID
    /// back_office_self_id        16 bytes big-endian UUID
    /// machine_id UTF-8 NUL       variable + 1
    /// issued_at_ms               8 bytes big-endian u64
    /// not_after_ms               8 bytes big-endian u64
    /// ```
    ///
    /// `revoked`/`revoked_at_ms` are deliberately absent — see the struct
    /// doc. Any field added later MUST be appended as a domain-separated
    /// tail (the same discipline `DeclaredIdentity::signing_bytes` uses for
    /// `expires_at_ms`/`public_addr`/`faces`) so a grant minted before the
    /// addition keeps verifying byte-for-byte.
    pub fn signing_bytes(
        grant_id: Uuid,
        back_office_self_id: Uuid,
        machine_id: &MachineId,
        issued_at_ms: u64,
        not_after_ms: u64,
    ) -> Vec<u8> {
        let mut buf = Vec::with_capacity(
            DOMAIN_ENTRANCE_GRANT.len()
                + 16 // grant_id
                + 16 // back_office_self_id
                + machine_id.to_string().len()
                + 1 // NUL
                + 8 // issued_at_ms
                + 8, // not_after_ms
        );
        buf.extend_from_slice(DOMAIN_ENTRANCE_GRANT);
        buf.extend_from_slice(grant_id.as_bytes());
        buf.extend_from_slice(back_office_self_id.as_bytes());
        buf.extend_from_slice(machine_id.to_string().as_bytes());
        buf.push(0);
        buf.extend_from_slice(&issued_at_ms.to_be_bytes());
        buf.extend_from_slice(&not_after_ms.to_be_bytes());
        buf
    }

    /// Construct + sign in one call (operator-box use).
    pub fn sign_new(
        grant_id: Uuid,
        back_office_self_id: Uuid,
        machine_id: MachineId,
        issued_at_ms: u64,
        not_after_ms: u64,
        signing_key: &SigningKey,
    ) -> Self {
        let bytes = Self::signing_bytes(
            grant_id,
            back_office_self_id,
            &machine_id,
            issued_at_ms,
            not_after_ms,
        );
        let sig = signing_key.sign(&bytes);
        Self {
            grant_id,
            back_office_self_id,
            machine_id,
            issued_at_ms,
            not_after_ms,
            revoked: false,
            revoked_at_ms: None,
            operator_sig: SignatureHex::from_signature(&sig),
        }
    }

    /// Verify the signature against an operator pinned verifying key.
    pub fn verify(&self, operator_pub: &VerifyingKey) -> Result<(), EntranceGrantError> {
        let bytes = Self::signing_bytes(
            self.grant_id,
            self.back_office_self_id,
            &self.machine_id,
            self.issued_at_ms,
            self.not_after_ms,
        );
        let sig = self.operator_sig.to_signature().map_err(|e| match e {
            IdentityError::BadHex(h) => EntranceGrantError::BadHex(h),
            IdentityError::BadSignatureLen(n) => EntranceGrantError::BadSignatureLen(n),
            IdentityError::BadSignature
            | IdentityError::NoMachineAnchor(_)
            | IdentityError::MachineAnchorMismatch { .. } => EntranceGrantError::BadSignature,
        })?;
        operator_pub
            .verify(&bytes, &sig)
            .map_err(|_| EntranceGrantError::BadSignature)
    }

    /// `true` when `now_ms` is at or past [`Self::not_after_ms`].
    pub fn is_expired(&self, now_ms: u64) -> bool {
        now_ms >= self.not_after_ms
    }
}

/// Errors verifying an [`EntranceGrant`]'s signature.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum EntranceGrantError {
    #[error("invalid hex in signature: {0}")]
    BadHex(String),
    #[error("signature must be 64 bytes, got {0}")]
    BadSignatureLen(usize),
    #[error("operator signature did not verify")]
    BadSignature,
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    fn op_key() -> SigningKey {
        SigningKey::generate(&mut OsRng)
    }

    fn sample_grant(op: &SigningKey) -> EntranceGrant {
        EntranceGrant::sign_new(
            Uuid::new_v4(),
            Uuid::new_v4(),
            MachineId::new("nl-example-203.0.113.32").unwrap(),
            1_700_000_000_000,
            1_700_086_400_000,
            op,
        )
    }

    #[test]
    fn sign_verify_good_path() {
        let op = op_key();
        let grant = sample_grant(&op);
        grant.verify(&op.verifying_key()).expect("must verify");
        assert!(!grant.revoked);
        assert!(grant.revoked_at_ms.is_none());
    }

    #[test]
    fn tampered_machine_id_fails_verify() {
        let op = op_key();
        let mut grant = sample_grant(&op);
        grant.machine_id = MachineId::new("ru-hostkey-999.99").unwrap();
        let err = grant.verify(&op.verifying_key()).unwrap_err();
        assert_eq!(err, EntranceGrantError::BadSignature);
    }

    #[test]
    fn tampered_expiry_fails_verify() {
        let op = op_key();
        let mut grant = sample_grant(&op);
        grant.not_after_ms += 1_000_000;
        let err = grant.verify(&op.verifying_key()).unwrap_err();
        assert_eq!(err, EntranceGrantError::BadSignature);
    }

    #[test]
    fn wrong_operator_key_rejected() {
        let op = op_key();
        let wrong_key = op_key();
        let grant = sample_grant(&op);
        let err = grant.verify(&wrong_key.verifying_key()).unwrap_err();
        assert_eq!(err, EntranceGrantError::BadSignature);
    }

    #[test]
    fn grant_round_trips_through_json_and_still_verifies() {
        let op = op_key();
        let grant = sample_grant(&op);
        let json = serde_json::to_string(&grant).expect("serialize");
        let back: EntranceGrant = serde_json::from_str(&json).expect("deserialize");
        back.verify(&op.verifying_key())
            .expect("round-tripped grant must still verify");
        assert_eq!(back.grant_id, grant.grant_id);
        assert_eq!(back.machine_id, grant.machine_id);
    }

    #[test]
    fn is_expired_reads_not_after_ms() {
        let op = op_key();
        let grant = sample_grant(&op);
        assert!(!grant.is_expired(grant.not_after_ms - 1));
        assert!(grant.is_expired(grant.not_after_ms));
        assert!(grant.is_expired(grant.not_after_ms + 1));
    }

    /// A grant naming a different `back_office_self_id` produces a
    /// different signature — the signed identity binding cannot be swapped
    /// onto a different back-office's grant undetected.
    #[test]
    fn different_back_office_self_id_changes_the_signature() {
        let grant_id = Uuid::new_v4();
        let machine_id = MachineId::new("nl-example-203.0.113.32").unwrap();
        let a = EntranceGrant::signing_bytes(
            grant_id,
            Uuid::new_v4(),
            &machine_id,
            1_700_000_000_000,
            1_700_086_400_000,
        );
        let b = EntranceGrant::signing_bytes(
            grant_id,
            Uuid::new_v4(),
            &machine_id,
            1_700_000_000_000,
            1_700_086_400_000,
        );
        assert_ne!(a, b);
    }
}
