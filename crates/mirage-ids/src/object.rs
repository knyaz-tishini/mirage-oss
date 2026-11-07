//! Object identity primitives.
//!
//! `ObjectKind` is a `&'static str` newtype — the registry keys handlers
//! by it. `ObjectId` is `blake3(kind || canonical_spec)` so two monitors
//! that win an auction independently mint the same id (idempotent
//! reconcile, no split-brain).
//!
//! The canonical-spec contract is the handler's responsibility: the
//! handler decides which spec fields are part of identity and feeds the
//! canonical byte form into `ObjectId::derive`.

use std::fmt;

use serde::{Deserialize, Serialize};

/// Object-kind discriminator.
///
/// Convention: lowercase ASCII, dash-separated, e.g. `"chain"`,
/// `"standalone-wire"`, `"node-capability"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ObjectKind(pub &'static str);

impl ObjectKind {
    pub const fn new(s: &'static str) -> Self {
        Self(s)
    }
    pub fn as_str(&self) -> &'static str {
        self.0
    }
}

impl fmt::Display for ObjectKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}

/// Deterministic object identifier: `blake3(kind || canonical_spec)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ObjectId(pub [u8; 32]);

impl ObjectId {
    /// Derive id from a kind tag and a handler-canonical spec blob.
    pub fn derive(kind: ObjectKind, canonical_spec: &[u8]) -> Self {
        let mut h = blake3::Hasher::new();
        h.update(kind.as_str().as_bytes());
        h.update(&[0u8]); // length-of-kind separator; keeps tags injective
        h.update(canonical_spec);
        let out = h.finalize();
        Self(*out.as_bytes())
    }

    pub fn as_hex(&self) -> String {
        let mut s = String::with_capacity(64);
        for b in self.0.iter() {
            use std::fmt::Write;
            let _ = write!(s, "{b:02x}");
        }
        s
    }
}

impl fmt::Display for ObjectId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.as_hex())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_is_deterministic() {
        let k = ObjectKind::new("chain");
        let a = ObjectId::derive(k, b"spec-a");
        let b = ObjectId::derive(k, b"spec-a");
        assert_eq!(a, b);
    }

    #[test]
    fn derive_distinguishes_kinds() {
        let a = ObjectId::derive(ObjectKind::new("chain"), b"x");
        let b = ObjectId::derive(ObjectKind::new("standalone"), b"x");
        assert_ne!(a, b);
    }

    #[test]
    fn hex_roundtrip() {
        let id = ObjectId::derive(ObjectKind::new("k"), b"spec");
        let hex = id.as_hex();
        assert_eq!(hex.len(), 64);
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
    }
}
