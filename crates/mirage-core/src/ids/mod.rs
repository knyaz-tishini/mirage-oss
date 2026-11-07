//! Strongly-typed identifiers — re-exported from `mirage-ids`.
//!
//! All types live in the `mirage-ids` crate. This module is a pure
//! re-export shim so that `mirage_core::ids::X` continues to resolve
//! for existing consumers without any call-site changes.
pub use mirage_ids::*;
