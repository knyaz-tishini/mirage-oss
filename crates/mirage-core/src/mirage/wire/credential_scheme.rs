//! Per-connection anonymous-credential scheme selection.
//!
//! Mirrors `aead_suite.rs` in structure and doctrine.
//! **Wire id is forever — never reuse a number.**

use serde::{Deserialize, Serialize};

use crate::error::{MirageError, Result};

/// Anonymous-credential scheme used for data-plane untrusted-peer authz.
///
/// A node configured to require credentials rejects `Legacy`; nodes in open-relay
/// mode (transition default) accept it. Higher variants are privacy-preserving.
///
/// Adding a new scheme: append a variant, assign the next u8, implement arms in
/// `verify_credential`. **Wire id is forever — never reuse a number.**
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[repr(u8)]
pub enum CredentialScheme {
    /// No anonymous credential — legacy open-relay path. Transition default; a
    /// node configured to REQUIRE credentials rejects this.
    Legacy = 0x00,
    /// HMAC-SHA256(epoch_secret, nonce). ~1-3µs. Verifier-unlinkable,
    /// issuer-linkable. The light arm.
    EpochHmac = 0x01,
    /// Ed25519-signed single-use capability token. Asymmetric: only the issuer
    /// (opbox) can mint; nodes hold only the per-epoch Ed25519 verifying key
    /// and can verify but cannot fabricate tokens. Verifier-unlinkable (node sees
    /// only a random nonce + signature). Wire byte 0x02 — preserved from the
    /// retired `PrivacyPassVoprf` slot.
    SignedCapability = 0x02,
    /// RFC 9474 publicly-verifiable blind RSA token, single-use within a batch.
    /// Authority holds the RSA private key; nodes hold only the RSA public key
    /// (verify-only). Unlinkable: the issuer cannot correlate a token to its use.
    BlindRsaBatch = 0x03,
    /// Accumulator/Merkle ring-membership proof. Constant-size verify; no central
    /// issuer needed at use time. Reserved — verify path lands in a later phase.
    RingMembership = 0x04,
    /// Operator/group-signed role identity, self-presented and self-vouched:
    /// the credential holder (an operator-admitted, non-relay role — an Edge
    /// box today) is also the authority that signed the identity excerpt it
    /// presents, plus a per-dial signature by that role's own signing key,
    /// bound to the exit's node id and a fresh nonce/timestamp. See
    /// `mirage-core::crypto::credential::role_signed` and
    /// `docs/mirage/plans/2026-09-24-edge-as-entry.md`, "Credentials — the
    /// exit admits an edge-owned chain by the edge's own operator-signed
    /// identity". Owner-approved name and wire byte, 2026-09-24.
    RoleSigned = 0x05,
}

impl CredentialScheme {
    pub const DEFAULT: Self = CredentialScheme::Legacy;

    /// Wire byte for negotiation / token header.
    pub fn id(self) -> u8 {
        self as u8
    }

    /// Wire byte (same as `id`, kept for API parity).
    pub fn as_u8(self) -> u8 {
        self as u8
    }

    /// Parse the wire byte. Unknown ids reject — never silently fall back.
    pub fn from_byte(b: u8) -> Result<Self> {
        match b {
            0x00 => Ok(CredentialScheme::Legacy),
            0x01 => Ok(CredentialScheme::EpochHmac),
            0x02 => Ok(CredentialScheme::SignedCapability),
            0x03 => Ok(CredentialScheme::BlindRsaBatch),
            0x04 => Ok(CredentialScheme::RingMembership),
            0x05 => Ok(CredentialScheme::RoleSigned),
            other => Err(MirageError::Protocol(format!(
                "CredentialScheme: unknown id 0x{:02x}",
                other
            ))),
        }
    }

    /// Soft parse — `None` on unknown id.
    pub fn try_from_u8(b: u8) -> Option<Self> {
        Self::from_byte(b).ok()
    }

    /// Pretty name for logging.
    pub fn name(self) -> &'static str {
        match self {
            CredentialScheme::Legacy => "Legacy",
            CredentialScheme::EpochHmac => "EpochHmac",
            CredentialScheme::SignedCapability => "SignedCapability",
            CredentialScheme::BlindRsaBatch => "BlindRsaBatch",
            CredentialScheme::RingMembership => "RingMembership",
            CredentialScheme::RoleSigned => "RoleSigned",
        }
    }

    /// snake_case wire label (matches the JSON serialisation).
    pub fn as_str(self) -> &'static str {
        match self {
            CredentialScheme::Legacy => "legacy",
            CredentialScheme::EpochHmac => "epoch_hmac",
            CredentialScheme::SignedCapability => "signed_capability",
            CredentialScheme::BlindRsaBatch => "blind_rsa_batch",
            CredentialScheme::RingMembership => "ring_membership",
            CredentialScheme::RoleSigned => "role_signed",
        }
    }
}

impl Default for CredentialScheme {
    fn default() -> Self {
        Self::DEFAULT
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credential_scheme_byte_roundtrip() {
        let variants = [
            CredentialScheme::Legacy,
            CredentialScheme::EpochHmac,
            CredentialScheme::SignedCapability,
            CredentialScheme::BlindRsaBatch,
            CredentialScheme::RingMembership,
            CredentialScheme::RoleSigned,
        ];
        for v in variants {
            let b = v.as_u8();
            assert_eq!(CredentialScheme::from_byte(b).unwrap(), v);
        }
    }

    #[test]
    fn credential_scheme_unknown_byte_rejects() {
        // 0x03, 0x04 and 0x05 are now valid; test truly unknown bytes.
        assert!(CredentialScheme::from_byte(0x03).is_ok());
        assert!(CredentialScheme::from_byte(0x04).is_ok());
        assert!(CredentialScheme::from_byte(0x05).is_ok());
        assert!(CredentialScheme::from_byte(0x06).is_err());
        assert!(CredentialScheme::from_byte(0xff).is_err());
        assert!(CredentialScheme::try_from_u8(0x42).is_none());
    }

    #[test]
    fn role_signed_is_byte_0x05() {
        // Wire byte 0x05 — owner-approved 2026-09-24, next free id after
        // RingMembership's 0x04.
        assert_eq!(CredentialScheme::RoleSigned.as_u8(), 0x05);
    }

    #[test]
    fn credential_scheme_default_is_legacy() {
        assert_eq!(CredentialScheme::default(), CredentialScheme::Legacy);
    }

    #[test]
    fn signed_capability_is_byte_0x02() {
        // Wire byte 0x02 is preserved from the retired PrivacyPassVoprf slot.
        assert_eq!(CredentialScheme::SignedCapability.as_u8(), 0x02);
    }
}
