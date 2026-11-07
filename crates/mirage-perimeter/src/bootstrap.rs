//! Universal-build placeholder consts — CHECKED-IN.
//!
//! Mirrors `mirage-secd`/`mirage-warden`'s own `bootstrap.rs` exactly:
//! the perimeter's per-box identity is capsule-delivered at runtime
//! (`capsule_boot`), never compiled in. This file exists purely so
//! operator-box's `POST /universal/build?service=perimeter` (not wired up
//! as part of this task — see this crate's own module doc) has somewhere
//! to substitute one const before every fleet-wide build:
//! [`OPERATOR_PUBKEY_HEX`], genuinely fleet-wide PUBLIC material (not
//! secret, not per-box), and load-bearing: `identity::operator_pubkey`
//! anchors every capsule this process ever accepts against it. `MESH_ID`
//! used to be substituted here too and is gone — the mesh a box belongs to
//! arrives inside the capsule that admits it, every boot.
//!
//! [`PERIMETER_ID`] and [`DECLARED_IDENTITY_JSON`] are kept, byte-for-byte,
//! purely for parity with the other services' `check_is_placeholder`-style
//! build-time safety check, should this service be wired into that
//! pipeline later — nothing in this crate reads either of them today.
//!
//! DO NOT COMMIT THIS FILE WITH REAL VALUES.

/// Nil-UUID sentinel — this crate has no per-box id compiled in (see module
/// doc). Never substituted.
pub const PERIMETER_ID: &str = "00000000-0000-0000-0000-000000000000";

/// Mesh this perimeter belongs to — substituted by
/// `POST /universal/build?service=perimeter` on every fleet-wide build.
// `MESH_ID` was removed here on 2026-08-26. A box does not know its own
// mesh: whoever ADMITS it decides, and says so inside the capsule they
// issue — every boot, because `/run` is tmpfs and nothing is remembered.
// A constant substituted at build time made that the BUILDER's claim
// instead, and this crate then enforced it against the operator. See
// `mirage_core::self_issue::UNAFFILIATED_MESH_ID`.

/// Operator Ed25519 verifying key hex (64 chars) — substituted the same
/// way. Used by [`crate::identity::operator_pubkey`] to verify a capsule's
/// operator signature before this binary trusts anything an issuer offers
/// it.
pub const OPERATOR_PUBKEY_HEX: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

/// Empty-object placeholder. Never substituted — a real per-box
/// `DeclaredIdentity` envelope is capsule-delivered at runtime.
pub const DECLARED_IDENTITY_JSON: &str = r#"{}"#;

// `BOOTSTRAP_ASK_MONITORS` was removed here on 2026-08-27. This binary never
// read it. Since the machine-identity cutover (2026-08-17) the box's keeper
// (`mirage-warden`) is the only party that talks to the mesh for identity;
// every other service takes its slice off a local socket and has no ask path
// left to seed. Sentry and db-worker deleted their copies in that same pass
// and documented why — this finishes the sweep.
//
// Keeping it meant every fleet binary carried a list of OTHER boxes' signed
// `DeclaredIdentity` envelopes that nothing would ever dial. opbox's
// substitution is conditional on the constant still being present
// (`universal_build.rs::render_universal_bootstrap`), so its removal is a
// silent no-op there, not a build break.
