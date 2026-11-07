//! Epoch identity — the cohabitation primitive.
//!
//! Each running stack (prod / staging / dev) on a single machine lives
//! inside its own `EpochId`. Ports, paths, seal keys, gossip events all
//! key off `(role, generation)`.
//!
//! See the master plan, Stage 4 — Epoch infrastructure, for the
//! deployment semantics. mesh-core only carries the type + the port
//! math primitives.

use std::fmt;

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Stack role within a mesh.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EpochRole {
    Prod,
    Staging,
    Dev,
    /// Operator-controlled scratch ring; ephemeral.
    Scratch,
}

impl fmt::Display for EpochRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            EpochRole::Prod => "prod",
            EpochRole::Staging => "staging",
            EpochRole::Dev => "dev",
            EpochRole::Scratch => "scratch",
        })
    }
}

/// Epoch identity: `(role, generation)`.
///
/// `generation` is a monotonically increasing counter that the operator
/// bumps on cutover.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct EpochId {
    pub role: EpochRole,
    pub generation: u16,
}

impl EpochId {
    pub const fn new(role: EpochRole, generation: u16) -> Self {
        Self { role, generation }
    }

    /// Port encoding: `base_port + generation * STRIDE`.
    ///
    /// Stride is 1000 — fits 60 generations into a typical 60k port
    /// range and keeps the human-readable invariant
    /// `prod-v0:19460, prod-v1:20460, …`.
    pub fn port_for(self, base: u16) -> Result<u16, EpochPortError> {
        let stride: u32 = 1000;
        let offset = (self.generation as u32).saturating_mul(stride);
        let next = (base as u32).checked_add(offset).ok_or(EpochPortError::Overflow)?;
        if next > u16::MAX as u32 {
            return Err(EpochPortError::Overflow);
        }
        Ok(next as u16)
    }

    /// Filesystem path scoping: `/var/lib/mirage/<role>-v<gen>/`.
    pub fn path_segment(self) -> String {
        format!("{}-v{}", self.role, self.generation)
    }
}

impl fmt::Display for EpochId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}-v{}", self.role, self.generation)
    }
}

impl EpochId {
    /// Parse the legacy `"v<N>-<role>"` mesh_id format used in stored config
    /// and signed identities (e.g. `"v3-staging"` → `EpochId{Staging, 3}`).
    ///
    /// Also accepts the canonical `"<role>-v<N>"` Display format
    /// (e.g. `"staging-v3"`), though that form is not yet stored anywhere.
    ///
    /// Returns `None` when the string is unparseable so callers can fall back
    /// gracefully without breaking boot.
    ///
    /// # Format inversion
    ///
    /// The stored legacy string `"v3-staging"` is the INVERSE of `EpochId`'s
    /// `Display` output `"staging-v3"`. These are NOT interchangeable strings.
    /// The stored/signed form must never be changed; this parser bridges them.
    pub fn from_legacy_mesh_id(s: &str) -> Option<EpochId> {
        // Try legacy format first: "v<N>-<role>"
        if let Some(rest) = s.strip_prefix('v') {
            if let Some(dash) = rest.find('-') {
                let gen_str = &rest[..dash];
                let role_str = &rest[dash + 1..];
                if let (Ok(gen), Some(role)) =
                    (gen_str.parse::<u16>(), parse_epoch_role(role_str))
                {
                    return Some(EpochId::new(role, gen));
                }
            }
        }
        // Try canonical format: "<role>-v<N>"
        // Split on "-v" suffix: last occurrence of "-v" separates role from gen.
        if let Some(v_pos) = s.rfind("-v") {
            let role_str = &s[..v_pos];
            let gen_str = &s[v_pos + 2..];
            if let (Some(role), Ok(gen)) =
                (parse_epoch_role(role_str), gen_str.parse::<u16>())
            {
                return Some(EpochId::new(role, gen));
            }
        }
        None
    }
}

impl EpochId {
    /// The epoch of a mesh whose id does NOT name a role and a generation.
    ///
    /// ## Why this exists
    ///
    /// The fleet's mesh ids are `"MESH1"` and `"MESH2"` — operator-chosen
    /// names that carry neither a role nor a generation, so
    /// [`Self::from_legacy_mesh_id`] returns `None` for them. The caller used
    /// to answer that with ONE hardcoded constant, `staging-v3`, for every
    /// such mesh — which is the epoch of the long-dead `v3-staging` mesh, so
    /// every modern mesh silently claimed to BE `v3-staging`. Two different
    /// meshes then shared one substrate namespace, and the logs named the
    /// wrong mesh.
    ///
    /// ## What this does instead
    ///
    /// A mesh id that names no epoch gets one DERIVED from the id itself:
    /// FNV-1a over the id's bytes, folded into the generation field. That
    /// gives the three properties a namespace needs:
    ///
    /// - **stable** — the same mesh id derives the same epoch on every boot,
    ///   on every box, on every host, forever;
    /// - **mesh-specific** — two different mesh ids do not share an epoch
    ///   (except on a 16-bit hash collision, which is a namespace hygiene
    ///   matter, not a security boundary: the substrate's peer set comes from
    ///   operator-signed per-mesh identities, which are mesh-scoped by
    ///   `mesh_id` and not by this epoch);
    /// - **never a hardcoded constant** — no mesh can end up wearing another
    ///   mesh's epoch.
    ///
    /// ## The role is `Staging` by convention, not by meaning
    ///
    /// The role field exists for port arithmetic (`base + generation*1000`)
    /// and for the diagnostic label. Neither is a security boundary, and the
    /// fleet's mesh ids do not say which role they are, so this picks the
    /// neutral one. A mesh that wants a meaningful role should be given a
    /// canonical mesh id (`"prod-v0"`, `"staging-v2"`) — those parse exactly
    /// and take this path never.
    ///
    /// ## Prefer an operator-declared epoch
    ///
    /// This is a derivation, not a declaration. When the operator knows which
    /// stack a mesh belongs to, the right fix is to name the mesh so it
    /// parses (`"prod-v0"`), or to carry an explicit epoch in the capsule's
    /// service config. This function exists so that a mesh with an unmapped
    /// id gets its OWN namespace instead of a shared one.
    #[must_use]
    pub fn from_unmapped_mesh_id(mesh_id: &str) -> EpochId {
        EpochId::new(EpochRole::Staging, fnv1a16(mesh_id.as_bytes()))
    }

    /// The epoch of a mesh, from its id, whatever shape that id has.
    ///
    /// A mesh id that names a role and a generation is taken at its word
    /// ([`Self::from_legacy_mesh_id`]). A mesh id that names neither gets a
    /// derived epoch of its own ([`Self::from_unmapped_mesh_id`]) rather than
    /// a shared fallback.
    #[must_use]
    pub fn for_mesh_id(mesh_id: &str) -> EpochId {
        Self::from_legacy_mesh_id(mesh_id)
            .unwrap_or_else(|| Self::from_unmapped_mesh_id(mesh_id))
    }
}

/// FNV-1a over `bytes`, folded to 16 bits.
///
/// FNV-1a is not a cryptographic hash and is not used as one: this only has
/// to be stable across boots and different for different mesh ids, so that
/// two meshes do not share a substrate namespace by accident. The 16-bit
/// fold is a namespace-hygiene measure — the substrate's actual mesh
/// separation is carried by the operator-signed per-mesh identities, which
/// name their `mesh_id` explicitly.
fn fnv1a16(bytes: &[u8]) -> u16 {
    const OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x0000_0100_0000_01b3;

    let mut hash = OFFSET;
    for b in bytes {
        hash ^= u64::from(*b);
        hash = hash.wrapping_mul(PRIME);
    }
    // Fold the 64-bit state into 16 bits. The high half is folded in too so
    // that ids differing only above the 16th bit still differ below it.
    let folded = (hash ^ (hash >> 16) ^ (hash >> 32) ^ (hash >> 48)) as u16;
    // `0` is the generation of the very first stack and reads as "unset"
    // in a path segment; keep the derived space off it.
    if folded == 0 {
        1
    } else {
        folded
    }
}

fn parse_epoch_role(s: &str) -> Option<EpochRole> {
    match s {
        "prod" => Some(EpochRole::Prod),
        "staging" => Some(EpochRole::Staging),
        "dev" => Some(EpochRole::Dev),
        "scratch" => Some(EpochRole::Scratch),
        _ => None,
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum EpochPortError {
    #[error("epoch port computation overflowed u16")]
    Overflow,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn port_encoding_basic() {
        let e = EpochId::new(EpochRole::Prod, 0);
        assert_eq!(e.port_for(19460).unwrap(), 19460);
        let e1 = EpochId::new(EpochRole::Prod, 1);
        assert_eq!(e1.port_for(19460).unwrap(), 20460);
    }

    #[test]
    fn port_encoding_overflow() {
        let e = EpochId::new(EpochRole::Scratch, 65);
        assert_eq!(e.port_for(60000), Err(EpochPortError::Overflow));
    }

    #[test]
    fn path_segment() {
        let e = EpochId::new(EpochRole::Staging, 2);
        assert_eq!(e.path_segment(), "staging-v2");
        assert_eq!(format!("{e}"), "staging-v2");
    }

    /// Verifies the critical format inversion:
    /// stored mesh_id `"v3-staging"` (legacy `v<N>-<role>`) → `EpochId{Staging, 3}`,
    /// whose Display is `"staging-v3"` (canonical `<role>-v<N>`).
    /// These two strings are NOT interchangeable — the stored form is baked into
    /// signed identities and must never be altered.
    #[test]
    fn from_legacy_mesh_id_v3_staging() {
        let epoch = EpochId::from_legacy_mesh_id("v3-staging")
            .expect("v3-staging must parse");
        assert_eq!(epoch, EpochId::new(EpochRole::Staging, 3));
        // Display is the INVERSE of the stored string — document this explicitly.
        assert_eq!(format!("{epoch}"), "staging-v3");
    }

    #[test]
    fn from_legacy_mesh_id_canonical_form() {
        // Canonical display form also parses correctly.
        let epoch = EpochId::from_legacy_mesh_id("staging-v3")
            .expect("staging-v3 must parse");
        assert_eq!(epoch, EpochId::new(EpochRole::Staging, 3));
    }

    #[test]
    fn from_legacy_mesh_id_other_roles() {
        assert_eq!(
            EpochId::from_legacy_mesh_id("v1-prod"),
            Some(EpochId::new(EpochRole::Prod, 1))
        );
        assert_eq!(
            EpochId::from_legacy_mesh_id("v0-dev"),
            Some(EpochId::new(EpochRole::Dev, 0))
        );
    }

    #[test]
    fn from_legacy_mesh_id_unknown_returns_none() {
        assert_eq!(EpochId::from_legacy_mesh_id("unknown-mesh"), None);
        assert_eq!(EpochId::from_legacy_mesh_id(""), None);
        assert_eq!(EpochId::from_legacy_mesh_id("v-staging"), None);
    }

    /// The regression this exists for: the fleet's mesh ids name no role and
    /// no generation, so they used to fall back to ONE hardcoded constant —
    /// the epoch of the dead `v3-staging` mesh. Two different meshes then
    /// shared one substrate namespace.
    #[test]
    fn an_unmapped_mesh_id_does_not_wear_the_v3_staging_epoch() {
        for mesh_id in ["MESH1", "MESH2", "v3-staging"] {
            let derived = EpochId::from_unmapped_mesh_id(mesh_id);
            assert_ne!(
                derived,
                EpochId::new(EpochRole::Staging, 3),
                "{mesh_id} must not claim the v3-staging epoch"
            );
        }
    }

    /// Two different meshes must not share a namespace.
    #[test]
    fn two_unmapped_meshes_get_different_epochs() {
        assert_ne!(
            EpochId::for_mesh_id("MESH1"),
            EpochId::for_mesh_id("MESH2"),
            "MESH1 and MESH2 must not share a substrate namespace"
        );
    }

    /// The same mesh must get the SAME epoch on every boot, on every box —
    /// otherwise peers of one mesh would not recognise each other.
    #[test]
    fn an_unmapped_mesh_id_is_stable() {
        assert_eq!(
            EpochId::for_mesh_id("MESH2"),
            EpochId::for_mesh_id("MESH2"),
            "the same mesh id must derive the same epoch every time"
        );
    }

    /// A mesh id that DOES name an epoch is taken at its word — the derived
    /// path must not shadow the explicit one.
    #[test]
    fn a_mapped_mesh_id_keeps_its_own_epoch() {
        assert_eq!(
            EpochId::for_mesh_id("v3-staging"),
            EpochId::new(EpochRole::Staging, 3)
        );
        assert_eq!(
            EpochId::for_mesh_id("prod-v0"),
            EpochId::new(EpochRole::Prod, 0)
        );
    }

    /// The derived generation must never be 0 — that is the first stack's
    /// generation and reads as "unset" in a path segment.
    #[test]
    fn a_derived_generation_is_never_zero() {
        assert_ne!(EpochId::from_unmapped_mesh_id("MESH1").generation, 0);
        assert_ne!(EpochId::from_unmapped_mesh_id("MESH2").generation, 0);
    }
}
