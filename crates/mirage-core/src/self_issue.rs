//! A box mints its own FULL machine identity — no operator, no quorum, no
//! network, and nothing waited for.
//!
//! # The doctrine this implements
//!
//! `/run` is tmpfs: a reset box has no capsule and, until now, could only
//! open a delivery window and wait for someone else to seal one — forever,
//! if nobody ever does (`docs/mirage/plans/four-items-2026-08-19.md` item 4,
//! measured on `nl-example-203.0.113.30`: 1820 seconds and climbing). The fix is
//! not a shorter wait — **a self-issued identity blocks nothing.** It is a
//! FULL identity, not a provisional one: every role the box is told to mint
//! for gets a usable slice the instant [`mint_self_issued_capsule`] returns.
//! What acceptance by the operator or quorum changes is mesh access, and
//! only mesh access — never whether the box works.
//!
//! # What this function does and does not decide
//!
//! - **Fresh keys, always.** Every [`RoleSlice`] is freshly generated here
//!   with the ordinary CSPRNG — never derived from `attestation` in any way
//!   (`AttestationKey::derive_subkey` is private-seed-only and, more to the
//!   point, was explicitly rejected for this purpose: a derived role key
//!   would make `attestation.key` a master key for every role key the box
//!   will ever hold, one leak exposing all of them retroactively, none
//!   rotatable without rotating the attestation itself). No key here is
//!   minted at build time and none lives in an ELF.
//! - **`self_id` is freshly minted on every call.** Identity stability
//!   across a reset is explicitly NOT a goal — the box may come back with a
//!   different identity every time; what gets authenticated is the MACHINE,
//!   by the durable attestation key signing the boot announce, not any
//!   particular `self_id`. A caller that wants to EXTEND an
//!   already-self-issued capsule (same boot, approaching its own expiry)
//!   does so by cloning the existing [`MachineCapsule`] and moving its
//!   timestamps — never by calling this function again, which would mint a
//!   second, unrelated identity.
//! - **`db_key` is always `None`.** db-worker's wire fallback
//!   (`await_dk_over_wire`) is the documented path for exactly this case —
//!   a self-minted key would either fail to open an existing SQLCipher file
//!   or silently create a fresh, wrong-keyed one.
//! - **`charter`, `rotation` and `peers` are always empty.** None of them is
//!   knowable locally, and inventing a value for any of them would be
//!   exactly the kind of guess this module refuses to make — see
//!   `docs/mirage/research/self-issued-identity-warden-2026-08-18.md`'s own
//!   accounting of what a box can and cannot know about itself at this
//!   moment.
//! - **Which roles to mint for is the caller's decision, not this
//!   function's.** `roles` is taken as-is; this module does not derive a
//!   role set from anything on disk. See `mirage-warden`'s own call site for
//!   why that derivation is deliberately not made here either.

/// The mesh a box claims when nobody has told it one yet.
///
/// # A box does not know its own mesh
///
/// `/run` is tmpfs, so a rebooted box comes up holding exactly one durable
/// thing: its attestation key, whose entire power is to make one sentence
/// credible — *the announce you are reading came from the machine you think
/// it did*. Which mesh it belongs to is not among the things it can know. It
/// is decided by whoever ADMITS it, every boot, and arrives inside the
/// capsule they issue.
///
/// This is why the mesh is not a compile-time constant. A binary that
/// carried one would be asserting a fact the box has no standing to assert,
/// and the assertion is not even a defence: a box has no independent mesh to
/// check a delivered capsule against, so comparing the capsule to a baked
/// string only compares the issuer's word to the builder's word.
///
/// Measured 2026-08-26: three reinstalled boxes were admitted into a second
/// mesh with correct operator-issued identities, and every one refused its
/// own capsule, because the binaries had been built with the first mesh's
/// name substituted in. Nothing was misconfigured. The build had made a
/// membership claim on the box's behalf and the box then enforced it against
/// the operator.
///
/// So a self-issued capsule carries THIS. It is spelled as a legal mesh id
/// because `MeshId` validates its charset and a bracketed marker will not
/// parse — but it is a RESERVED name, never issued to a real mesh, and
/// [`is_unaffiliated`] is what every reader asks rather than comparing
/// strings. It is the absence of a mesh, stated explicitly rather than
/// guessed. It joins `charter`,
/// `rotation` and `peers` in this module's list of things a self-issuing box
/// refuses to invent.
pub const UNAFFILIATED_MESH_ID: &str = "unaffiliated";

/// Is this the mesh id of a box nobody has admitted yet?
///
/// True for [`UNAFFILIATED_MESH_ID`] and for an empty string — a capsule that
/// names no mesh at all is not in one either.
#[must_use]
pub fn is_unaffiliated(mesh_id: &str) -> bool {
    mesh_id == UNAFFILIATED_MESH_ID || mesh_id.trim().is_empty()
}

use uuid::Uuid;

use crate::attestation::AttestationKey;
use crate::capsule::{CapsuleServiceConfig, MachineCapsule, RoleSlice};
use crate::crypto::KeyPair;
use crate::identity::{DeclaredIdentity, RolePublicKeys, ServiceRole};
use crate::ids::{MachineId, MeshId};

/// Mint a full [`MachineCapsule`] this box grants itself, signed by its own
/// durable [`AttestationKey`] (`declared_identity.signer ==
/// `[`crate::identity::IdentitySigner::Machine`]``). Never sealed — there is
/// no issuer/service split for a box minting its own identity, the
/// plaintext never leaves this process, and [`crate::capsule::SealedCapsule`]
/// exists for transport this call has no need of.
///
/// `machine_id` is read from `attestation.machine_id()` via
/// [`MachineId::from_trusted`] — enrolment already constrained that string
/// to a box name an operator assigned; re-validating it here would only let
/// a malformed enrolment surface as a mint-time panic path instead of the
/// same trust every other reader of [`AttestationKey::machine_id`] already
/// extends it (`identity_boot::BootSession` passes it straight through as a
/// `&str` with no re-check).
///
/// `roles.is_empty()` is not treated as an error here — the caller (see
/// `mirage-warden::machine_store`) already refuses to call this with an
/// empty list, and a capsule naming no role is caught downstream by
/// [`crate::identity_boot::check_coherent_full`]'s own "capsule carries no
/// role slices" refusal regardless, the same defence-in-depth every other
/// mint path in this crate relies on rather than re-asserts.
#[must_use]
pub fn mint_self_issued_capsule(
    attestation: &AttestationKey,
    roles: &[ServiceRole],
    now_ms: u64,
    not_after_ms: u64,
) -> MachineCapsule {
    let machine_id = MachineId::from_trusted(attestation.machine_id());
    let self_id = Uuid::new_v4();

    let mut slices = Vec::with_capacity(roles.len());
    let mut role_keys = Vec::with_capacity(roles.len());
    for &role in roles {
        let wire = KeyPair::generate();
        let wire_pubkey_hex = hex::encode(wire.public.to_bytes());
        let signing = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let signing_pubkey_hex = hex::encode(signing.verifying_key().to_bytes());

        slices.push(RoleSlice {
            role,
            wire_privkey: wire.secret.to_bytes(),
            signing_privkey: Some(signing.to_bytes()),
            wire_pubkey_hex: wire_pubkey_hex.clone(),
            signing_pubkey_hex: Some(signing_pubkey_hex.clone()),
        });
        role_keys.push(RolePublicKeys {
            role,
            wire_pubkey_hex,
            signing_pubkey_hex: Some(signing_pubkey_hex),
        });
    }

    // Not a mesh: the explicit absence of one. See `UNAFFILIATED_MESH_ID`.
    // `from_trusted` is right here precisely because this value is NOT a
    // mesh name and must not be validated as one.
    let mesh_id = MeshId::from_trusted(UNAFFILIATED_MESH_ID);

    let declared_identity = DeclaredIdentity::sign_self_issued(
        self_id,
        machine_id.clone(),
        mesh_id.clone(),
        roles.to_vec(),
        role_keys,
        now_ms,
        Some(not_after_ms),
        attestation,
    );

    // Derived before the struct takes ownership of `machine_id`.
    let persona_faces = crate::persona::persona_for(&machine_id).faces;

    MachineCapsule {
        self_id,
        machine_id,
        mesh_id: mesh_id.clone(),
        slices,
        declared_identity,
        peers: Vec::new(),
        // The box's own persona, derived here rather than left empty.
        //
        // `CapsuleServiceConfig::default()` used to sit here, and the cost
        // was measured on 2026-08-25: a box that self-issued after a reboot
        // handed the perimeter a capsule with no `control_plane_endpoints`,
        // the perimeter refused it ("this box would bind nothing on any
        // public port while reporting healthy; refusing to boot dark") and
        // kept its bare 22/80/443 baseline — no camouflage, no archetype
        // tail. So a box that had lost its identity was distinguishable
        // from one that had not, by port set and by the absence of a
        // disguise, which is precisely the fleet-wide tell
        // `crate::persona` exists to remove.
        //
        // Nothing was stopping it: the derivation is a pure function of the
        // machine id, the machine id is in the attestation key this mint
        // already holds, and the operator derives the SAME faces from the
        // SAME code. The only obstacle was that the code lived in the
        // operator's crate.
        service_config: CapsuleServiceConfig {
            control_plane_endpoints: persona_faces,
            ..CapsuleServiceConfig::default()
        },
        charter: None,
        rotation: None,
        db_key: None,
        issued_at_ms: now_ms,
        not_after_ms,
    }
}

#[cfg(test)]
mod unaffiliated_mesh_tests {
    use super::*;

    /// The whole point: an unsubstituted build must be recognisable, or the
    /// placeholder becomes just another mesh name to converge on.
    #[test]
    fn the_unaffiliated_marker_is_recognised() {
        assert!(is_unaffiliated(UNAFFILIATED_MESH_ID));
    }

    /// Empty counts too — a substitution that wrote nothing is not a mesh
    /// either, and it is the shape a botched `substitute_const` would leave.
    #[test]
    fn an_empty_mesh_id_is_not_a_mesh() {
        assert!(is_unaffiliated(""));
        assert!(is_unaffiliated("   "));
    }

    /// A real mesh must pass, or every gate calling this refuses the fleet.
    #[test]
    fn a_real_mesh_id_passes() {
        assert!(!is_unaffiliated("v3-staging"));
        assert!(!is_unaffiliated("MESH2"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capsule::{CapsuleSigner, CapsuleTrustAnchor, MachineAnchor};
    use crate::identity::IdentitySigner;
    use crate::identity_boot::check_coherent_full;

    fn attestation() -> AttestationKey {
        AttestationKey::generate("ru-hostkey-203.0.113.10")
    }

    fn mesh() -> MeshId {
        MeshId::new("v3-staging").expect("mesh id")
    }

    /// The mechanism the whole self-issuance doctrine rests on: mint, then
    /// pass the exact same check every operator- or group-issued capsule
    /// passes, under the box's own machine anchor.
    #[test]
    fn a_freshly_minted_capsule_passes_check_coherent_full_under_its_own_anchor() {
        let attestation = attestation();
        let roles = [ServiceRole::Warden];
        let capsule =
            mint_self_issued_capsule(&attestation, &roles, 1_000, 1_000 + 3_600_000);

        let operator_pub = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng).verifying_key();
        let anchor = MachineAnchor {
            machine_id: attestation.machine_id(),
            attestation: attestation.verifying_key(),
        };
        check_coherent_full(
            &capsule,
            &operator_pub,
            CapsuleSigner::Machine { machine_id: attestation.machine_id().to_string() },
            1_500,
            Some(&anchor),
        )
        .expect("a freshly self-minted capsule must be coherent under its own anchor");
    }

    /// One slice per named role, no more, no fewer, and none of them shares
    /// key material with another — a fresh generation per role, not one
    /// keypair fanned out.
    #[test]
    fn every_named_role_gets_its_own_freshly_generated_slice() {
        let attestation = attestation();
        let roles = [ServiceRole::Warden, ServiceRole::Secd, ServiceRole::Monitor];
        let capsule = mint_self_issued_capsule(&attestation, &roles, 0, 3_600_000);

        assert_eq!(capsule.slices.len(), 3);
        for role in roles {
            assert!(capsule.slice_for(&role).is_some(), "{role} must have a slice");
        }
        let wire_keys: std::collections::HashSet<_> =
            capsule.slices.iter().map(|s| s.wire_pubkey_hex.clone()).collect();
        assert_eq!(wire_keys.len(), 3, "every role's wire key must be distinct");
    }

    /// Rule handed down explicitly: db-worker takes its documented wire
    /// fallback, never a self-minted key that cannot open an existing
    /// database.
    #[test]
    fn db_key_is_always_none() {
        let attestation = attestation();
        let roles = [ServiceRole::DbWorker];
        let capsule = mint_self_issued_capsule(&attestation, &roles, 0, 3_600_000);
        assert_eq!(capsule.db_key, None);
        assert_eq!(capsule.charter.is_none(), true);
        assert_eq!(capsule.rotation.is_none(), true);
        assert!(capsule.peers.is_empty());
    }

    /// Identity stability across a reset is explicitly not a goal — two
    /// independent mints must never collide on `self_id` or on any role's
    /// keys, even for the identical machine and role set.
    #[test]
    fn two_mints_never_share_a_self_id_or_keys() {
        let attestation = attestation();
        let roles = [ServiceRole::Warden];
        let a = mint_self_issued_capsule(&attestation, &roles, 0, 3_600_000);
        let b = mint_self_issued_capsule(&attestation, &roles, 0, 3_600_000);
        assert_ne!(a.self_id, b.self_id);
        assert_ne!(
            a.slice_for(&ServiceRole::Warden).unwrap().wire_pubkey_hex,
            b.slice_for(&ServiceRole::Warden).unwrap().wire_pubkey_hex,
        );
    }

    /// The declared identity inside the capsule actually claims the machine
    /// signer for THIS box, and would be refused under an anchor for a
    /// different one — proving the capsule's identity and the capsule's
    /// slices agree on which box this is.
    #[test]
    fn the_declared_identity_claims_this_machine_and_no_other() {
        let attestation = attestation();
        let roles = [ServiceRole::Warden];
        let capsule = mint_self_issued_capsule(&attestation, &roles, 0, 3_600_000);
        assert_eq!(
            capsule.declared_identity.signer,
            IdentitySigner::Machine { machine_id: attestation.machine_id().to_string() }
        );

        let operator_pub = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng).verifying_key();
        let wrong_anchor = CapsuleTrustAnchor {
            operator: &operator_pub,
            charter: None,
            machine: Some(MachineAnchor {
                machine_id: "tr-hostkey-203.0.113.20",
                attestation: attestation.verifying_key(),
            }),
        };
        assert!(capsule.declared_identity.verify_with_anchor(&wrong_anchor).is_err());
    }
}
