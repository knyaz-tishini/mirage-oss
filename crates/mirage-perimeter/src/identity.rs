//! Perimeter identity types + the operator-pubkey anchor read from
//! [`crate::bootstrap`].
//!
//! The perimeter's identity is capsule-delivered at runtime
//! (`crate::capsule_boot::acquire_identity`) — there is no compile-time-
//! baked identity path. [`Identity`] carries the X25519 wire keypair
//! every `strip_tcp_server` camouflage call needs (Reality in particular
//! derives its TLS-mimic session from it; the others ignore it), the
//! [`CapsuleServiceConfig`] that `crate::config::PerimeterConfig::
//! from_capsule` turns into bound listeners, and — since Task #11's
//! second half — an OPTIONAL Ed25519 fact-signing key
//! ([`Identity::signing_keypair`]), used by `crate::face::splice_inward`
//! to sign the PROXY v2 sender-authentication header on the monitor
//! splice (see `mirage_mesh_client::proxy_header`'s module doc, "The
//! header proves who wrote it").
//!
//! `signing_keypair` is `None` on today's fleet: opbox does not yet mint
//! a `signing_privkey` for `ServiceRole::Perimeter`'s capsule (only the
//! X25519 wire key). That is an ISSUER-side decision this crate cannot
//! make for itself — it lives outside `mirage2web` and is not something
//! this repository's code can force. A signing-less capsule is still
//! perfectly usable here: `splice_inward` sends the connection inward
//! with no PROXY preamble at all when it holds no key, which the
//! receiver treats identically to the pre-signing header shape — see
//! that function's own doc.
//!
//! # The standalone identity
//!
//! [`Identity::wire_only`] is the identity a box runs with when it runs
//! the perimeter STANDALONE: no capsule, no operator, no declaration, no
//! charter. It carries the wire keypair and nothing else, and the declared
//! envelope is `None` rather than absent-from-the-type — nothing in this
//! crate reads that field on any path, so a standalone box loses nothing
//! by not having one.

use anyhow::{Context, Result};
use ed25519_dalek::{SigningKey, VerifyingKey};
use mirage_core::capsule::{CapsuleServiceConfig, GroupCharter};
use mirage_core::crypto::KeyPair;
use mirage_core::identity::DeclaredIdentity;

use crate::bootstrap;

/// Fully assembled, VERIFIED perimeter identity for one boot.
pub struct Identity {
    /// Operator-minted UUID for this issuance.
    pub perimeter_id: String,
    /// Mesh identifier (e.g. `"v3-staging"`).
    pub mesh_id: String,
    /// Human label for logs.
    pub shortname: String,
    /// X25519 wire keypair. Consumed by `strip_tcp_server` on every face —
    /// most camouflage variants ignore it, Reality derives its session
    /// from it.
    pub wire_keypair: KeyPair,
    /// The verified, operator-signed envelope for this box's perimeter.
    ///
    /// `None` on the STANDALONE path, where there is no operator and
    /// therefore nobody to sign an envelope: see [`Identity::wire_only`].
    /// Nothing in this crate reads it — the perimeter's own faces need the
    /// wire key and the face list, not a declaration — so a `None` here
    /// costs the standalone path nothing.
    pub declared_identity: Option<DeclaredIdentity>,
    /// Per-box settings — carries `control_plane_endpoints` (the face
    /// list), `perimeter_inner_addr` and `perimeter_stats_bind`. Consumed
    /// by `crate::config::PerimeterConfig::from_capsule`.
    pub service_config: CapsuleServiceConfig,
    /// The mesh's current group charter, if the capsule carried one.
    pub charter: Option<GroupCharter>,
    /// This boot's Ed25519 fact-signing key, when the capsule carried one
    /// (`IdentityCapsule::signing_secret`). `Some` only once opbox mints
    /// one for this role — see this module's doc. Its public half is
    /// always `declared_identity.signing_pubkey_hex` when present:
    /// `mirage_core::identity_boot::check_coherent` refuses any capsule
    /// where the two disagree before this boot ever sees it.
    pub signing_keypair: Option<SigningKey>,
}

/// The id a standalone identity carries in every field that would otherwise
/// name a mesh, a box or an operator.
///
/// The standalone perimeter belongs to no mesh and is signed by no
/// operator, so there is no honest UUID to put there — and an empty string
/// in a log line reads like a bug. One visible word is better: every log
/// line that names this identity then says, out loud, that this box is
/// standing on its own.
pub const STANDALONE_ID: &str = "standalone";

impl Identity {
    /// A WIRE-ONLY identity: the X25519 wire keypair and nothing else.
    ///
    /// No declared identity, no charter, no signing key, no capsule — the
    /// identity a standalone box runs with. The perimeter's faces need the
    /// wire key (Reality derives its TLS-mimic session from it; the other
    /// camouflages ignore it) and the face list, and this crate reads
    /// nothing else off an identity: the declared envelope and the charter
    /// are carried, never consulted, by the face path.
    ///
    /// The `service_config` is left at its default — an empty face list —
    /// because on the standalone path the face list comes from
    /// [`crate::config::PerimeterConfig::from_local_faces`] and never from a
    /// capsule. Nothing reads this field on that path either.
    pub fn wire_only(wire_keypair: KeyPair) -> Self {
        Self {
            perimeter_id: STANDALONE_ID.to_string(),
            mesh_id: STANDALONE_ID.to_string(),
            shortname: STANDALONE_ID.to_string(),
            wire_keypair,
            declared_identity: None,
            service_config: CapsuleServiceConfig::default(),
            charter: None,
            signing_keypair: None,
        }
    }
}

/// What `crate::face` needs to sign a PROXY v2 header's
/// sender-authentication TLV for the co-located monitor — a narrow slice
/// of [`Identity`] built once at boot (`lib.rs::run`) and shared
/// read-only across every face's accept loop.
///
/// A distinct type from `Identity` itself rather than threading
/// `&Identity` through every face/connection function: `Identity` also
/// carries `wire_keypair` and `service_config`, which have their own
/// already-established `Arc`-wrapped threading paths
/// (`run_face`'s `keypair` / `config` parameters) — bundling everything
/// into one `Arc<Identity>` would mean two independent concerns sharing
/// one lock-free handle for no reason beyond "they were both computed at
/// boot".
pub struct SenderSigningIdentity {
    /// This box's own operator-signed `Perimeter` declaration — embedded
    /// wholesale in the header so the receiver can verify it without a
    /// lookup. See `mirage_mesh_client::proxy_header`'s module doc.
    pub declared: DeclaredIdentity,
    /// The key `declared.signing_pubkey_hex` names, when this boot's
    /// capsule carried one. `None` means this splice sends no
    /// sender-authentication header at all — see `crate::face::
    /// splice_inward`'s doc for why that is the honest choice rather than
    /// sending an address claim nothing backs.
    pub signing_key: Option<SigningKey>,
}

/// Decode [`bootstrap::OPERATOR_PUBKEY_HEX`] into a verifying key, refusing
/// the checked-in all-zero placeholder loudly instead of silently handing a
/// degenerate key to a capsule-verification call site.
///
/// The operator pubkey is public, fleet-wide material substituted into this
/// binary at build time — it anchors a capsule's trust independently of
/// whether THIS box has acquired a per-box identity yet, which is exactly
/// why `capsule_boot::acquire_identity` calls this before it has anything
/// else to go on.
pub fn operator_pubkey() -> Result<VerifyingKey> {
    let bytes = hex::decode(bootstrap::OPERATOR_PUBKEY_HEX)
        .context("OPERATOR_PUBKEY_HEX is not valid hex")?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("OPERATOR_PUBKEY_HEX must decode to 32 bytes"))?;
    if arr == [0u8; 32] {
        anyhow::bail!(
            "OPERATOR_PUBKEY_HEX is still the checked-in placeholder — this binary carries no \
             real fleet operator key to anchor a capsule against"
        );
    }
    VerifyingKey::from_bytes(&arr).context("OPERATOR_PUBKEY_HEX is not a valid Ed25519 point")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A wire-only identity carries the wire key and NOTHING else — no
    /// declaration, no charter, no signing key, no capsule.
    ///
    /// This is the whole of what a standalone box has, and it is enough:
    /// the perimeter's faces need the wire key (Reality derives its
    /// TLS-mimic session from it) and the face list, and nothing in this
    /// crate reads a declaration or a charter off an identity.
    #[test]
    fn wire_only_carries_the_wire_key_and_nothing_else() {
        let keypair = KeyPair::generate();
        let identity = Identity::wire_only(keypair.clone());

        assert_eq!(
            identity.wire_keypair.public, keypair.public,
            "the wire key the caller handed in must be the one this identity carries"
        );
        assert!(
            identity.declared_identity.is_none(),
            "a standalone box has no operator, so there is nobody to sign a declaration"
        );
        assert!(identity.charter.is_none(), "a standalone box joins no group");
        assert!(identity.signing_keypair.is_none(), "no capsule, no signing key");
        assert_eq!(identity.mesh_id, STANDALONE_ID);
        assert_eq!(identity.perimeter_id, STANDALONE_ID);
        assert_eq!(identity.shortname, STANDALONE_ID);
    }

    /// The wire-only identity has to be USABLE, not merely constructible:
    /// it must hand the perimeter a face list of its own that is empty
    /// (the standalone path's faces come from the local config, never from
    /// a capsule) rather than a capsule-shaped one waiting to be read.
    #[test]
    fn a_wire_only_identity_carries_no_capsule_faces() {
        let identity = Identity::wire_only(KeyPair::generate());
        assert!(
            identity.service_config.control_plane_endpoints.is_empty(),
            "a wire-only identity has no capsule behind it, so it declares no faces of its own"
        );
    }
}
