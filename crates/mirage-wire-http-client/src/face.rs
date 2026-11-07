//! One dialable face of a monitor — an address, its outer camouflage, and
//! the static X25519 public key that terminates the V9 handshake there.
//!
//! Shape mirrors what a caller outside the mesh is already handed for this
//! exact purpose: `GET /fleet/dial-faces`'s `address + camouflage +
//! static_pubkey_hex` triple
//! (`mirage2operator/crates/operator-box/src/fleet_dial_faces.rs`), and the
//! monitor-native `EntranceDialFace` the automated-issuance plan adds
//! (`docs/mirage/plans/2026-09-23-backoffice-automated-issuance.md` §2). A
//! [`WireFace`] carries its OWN `static_pubkey_hex` rather than sharing one
//! key across a list, because "any monitor the back-office happens to dial"
//! (per that plan's §2) may be a different box with a different wire key —
//! unlike the fleet's own "one target, many faces under one shared key"
//! face set, which is the right shape for a node/secd/sentry dialling a
//! single known monitor by its signed identity, not for a caller trying an
//! arbitrary ordered list of faces that may name different monitors
//! entirely.

use mirage_core::mirage::wire::TransportCamouflage;

/// One dialable face: host + port + camouflage + the static pubkey that
/// terminates the V9 handshake there.
#[derive(Debug, Clone)]
pub struct WireFace {
    /// Host portion only (no port) — SNI and TCP host both.
    pub host: String,
    pub port: u16,
    pub camouflage: TransportCamouflage,
    /// Hex-encoded (64 lowercase chars) X25519 static public key.
    pub static_pubkey_hex: String,
}

impl WireFace {
    pub fn new(
        host: impl Into<String>,
        port: u16,
        camouflage: TransportCamouflage,
        static_pubkey_hex: impl Into<String>,
    ) -> Self {
        Self {
            host: host.into(),
            port,
            camouflage,
            static_pubkey_hex: static_pubkey_hex.into(),
        }
    }

    /// Human label for logs and per-attempt diagnostics.
    pub fn label(&self) -> String {
        format!("{}:{}:{}", self.host, self.port, self.camouflage.label())
    }
}
