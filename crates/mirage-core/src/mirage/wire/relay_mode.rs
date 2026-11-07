//! Relay mode for Entry/Hop nodes. There is one.
//!
//! [`RelayMode::OnionPeel`] — per-connection ECDH (client ephemeral × node
//! static X25519) + BLAKE3 transcript + AEAD layer key.
//!
//! # Why the other two are gone (2026-09-02)
//!
//! This was three variants. `Transparent` was a blind `copy_bidirectional`
//! after the camouflage strip, and `CryptoVerify` peeled one static-keyed
//! [`ByteCipherMode`] skin and then piped. Neither terminated the tunnel,
//! which is what made them relays a client could trust — and neither had any
//! way to know WHICH listener a connection belonged to, because the bind port
//! answered that. They were the port's shape, not a crypto class.
//!
//! Removing the port removed their addressing, and nothing was left to
//! replace it with: a selector cannot be read by a hop that never terminates.
//! [`RelayMode::OnionPeel`] peels per hop, so it can carry one inside its own
//! layer, per hop, without the hello changing and without anything being in
//! the clear. See `docs/mirage/plans/chain-data-plane-over-faces-2026-09-02.md`
//! §2.5.3.
//!
//! Measured before the deletion rather than assumed: the shipped client asked
//! for `OnionPeel` at all seven of its sites and never named the other two;
//! the only caller that did was the test matrix; the monitor never chose one,
//! it only mapped what a caller asked for; and no store on any box held a
//! single chain binding to lose.
//!
//! **[`ByteCipherMode`] did NOT go with them.** It is a separate axis with
//! its own code path on both sides, and it rides the ONION ENTRY hop as a DPI
//! skin on the client→entry link — the one link that outlives the port. See
//! its own doc below.
//!
//! See `docs/plans/mirage-architecture-clean-taxonomy.md` §M-Wire Axis 3.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum RelayMode {
    /// Per-connection ECDH + AEAD layer (the Mirage onion peel). The only
    /// relay mode — see this module's doc for what the other two were and
    /// why they could not survive the port.
    OnionPeel,
}

impl RelayMode {
    pub fn label(&self) -> &'static str {
        match self {
            RelayMode::OnionPeel => "onion_peel",
        }
    }
}

/// Concrete byte-cipher skin variant.
///
/// Set on the onion ENTRY hop when a chain asks for a skin; the entry strips
/// it before reading the envelope. It used to be described as "used by
/// `RelayMode::CryptoVerify`", which was true until that mode was removed on
/// 2026-09-02 — the skin outlived it, and is not tied to a relay mode at all.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ByteCipherMode {
    /// Passthrough — the skin is empty. Kept as the explicit "no skin"
    /// value; it used to be contrasted with `RelayMode::Transparent`, which
    /// no longer exists.
    Raw,
    /// Validate-only: 16-byte magic in the first chunk, then plaintext.
    ValidateFirst {
        #[serde(with = "crate::hex_fixed::hex16")]
        magic: [u8; 16],
    },
    /// Validate + strip 16-byte magic + `junk_size` bytes of junk, then plaintext.
    StripFirst {
        #[serde(with = "crate::hex_fixed::hex16")]
        magic: [u8; 16],
        junk_size: u16,
    },
    /// Whole-stream obfuscation via [`ObfuscationAlgorithm`].
    ObfuscateAll {
        algorithm: ObfuscationAlgorithm,
        #[serde(with = "crate::hex_fixed::hex32")]
        obf_key: [u8; 32],
    },
}

impl ByteCipherMode {
    pub fn label(&self) -> &'static str {
        match self {
            ByteCipherMode::Raw => "raw",
            ByteCipherMode::ValidateFirst { .. } => "validate_first",
            ByteCipherMode::StripFirst { .. } => "strip_first",
            ByteCipherMode::ObfuscateAll { .. } => "obfuscate_all",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObfuscationAlgorithm {
    /// Per-frame `[4B salt][BLAKE3-keystream XOR ciphertext]`.
    XorBlake3,
    /// Per-frame `[8B LE nonce][ChaCha8 keystream XOR ciphertext]`.
    ChaCha8,
}

impl ObfuscationAlgorithm {
    pub fn as_str(self) -> &'static str {
        match self {
            ObfuscationAlgorithm::XorBlake3 => "xor_blake3",
            ObfuscationAlgorithm::ChaCha8 => "chacha8",
        }
    }
}
