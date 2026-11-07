//! Strongly-typed identifiers for the mesh plane.
//!
//! Each is a newtype around `String`. They serialise transparently,
//! so wire format is unaffected — but in code the compiler refuses
//! to mix them up.

use std::fmt;

use serde::{Deserialize, Serialize};

macro_rules! string_newtype {
    ($name:ident, $doc:literal) => {
        #[doc = $doc]
        #[derive(
            Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
        )]
        #[serde(transparent)]
        pub struct $name(pub String);

        impl $name {
            pub fn new(s: impl Into<String>) -> Self {
                Self(s.into())
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl From<String> for $name {
            fn from(s: String) -> Self {
                Self(s)
            }
        }

        impl From<&str> for $name {
            fn from(s: &str) -> Self {
                Self(s.to_string())
            }
        }

        impl AsRef<str> for $name {
            fn as_ref(&self) -> &str {
                &self.0
            }
        }
    };
}

string_newtype!(MeshId, "Logical mesh identity. Canonical scheme: `v3-<env>`.");
string_newtype!(NodeId, "Stable node identity. Survives ephemeral key rotation.");
string_newtype!(ChainId, "Stable chain identity (matches `ListenerSpec.chain_role.chain_id`).");
