//! Self-collected platform facts for a boot announce's attestation-bound
//! [`crate::fact_signing::PlatformFingerprint`] (admission gate 4,
//! `mirage2monitor::admission::admission_verdict`).
//!
//! Deliberately narrow: only the five fields `PlatformFingerprint` carries.
//! `mirage2sentry::box_profile::collect` reads a much larger set for
//! `BoxProfileRow`'s other columns and is a SEPARATE reader by necessity —
//! `mirage-core` cannot depend on the `mirage2sentry` binary crate. The two
//! agree because both read the same unchanging `/proc` + `/sys` files the
//! same way, not because one calls the other; see that crate's
//! `box_profile.rs` for the pattern this mirrors.
//!
//! Pure gather + return, nothing else — no signing happens here. The
//! [`crate::identity_boot::BootSession`] a caller attaches this to already
//! attests the whole announce, including whichever platform this module
//! hands it, with the box's enrolled attestation key.

use crate::fact_signing::PlatformFingerprint;

/// Gather this box's platform fingerprint from `/proc` and `/sys`, for
/// [`crate::identity_boot::BootSession::with_platform`].
///
/// Reads each of the five fields EXACTLY the way
/// `mirage2sentry::box_profile` reads them for the `BoxProfileRow` that
/// admission gate 4 compares this announce against — the SAME `.trim()`, the
/// SAME first-`model name` line, and crucially the SAME empty-string
/// fallback (`unwrap_or_default`) for a field the box does not expose. A
/// QEMU VPS commonly leaves `/sys/class/dmi/id/board_name` empty, and the
/// sentry stores `""` for it; a fingerprint must reproduce that empty to
/// match the stored row byte for byte. Collapsing the whole struct to `None`
/// instead — a `None` presented against a populated-with-empties
/// `BoxProfileRow` — is EXACTLY the `PlatformFactsEvidenceMissing` refusal
/// this module exists to stop (measured: `board_name` empty on the fleet's
/// QEMU boxes). Only a non-Linux target (the dev box / `cargo test`) yields
/// `None`, from the stub below.
#[cfg(target_os = "linux")]
pub fn collect() -> Option<PlatformFingerprint> {
    Some(PlatformFingerprint {
        cpu_model: read_cpu_model(),
        cpu_arch: std::env::consts::ARCH.to_string(),
        dmi_sys_vendor: read_dmi_field("sys_vendor"),
        dmi_product_name: read_dmi_field("product_name"),
        dmi_board: read_dmi_field("board_name"),
    })
}

/// No `/proc` or `/sys` on this target — nothing to gather. The Windows dev
/// box and `cargo test` both compile through here; a session that never
/// attaches a platform announces exactly as it did before this module
/// existed.
#[cfg(not(target_os = "linux"))]
pub fn collect() -> Option<PlatformFingerprint> {
    None
}

/// The `"model name"` line out of `/proc/cpuinfo` — the same field
/// `mirage2sentry::box_profile::read_cpuinfo` reads for
/// `BoxProfileRow::cpu_model`.
#[cfg(target_os = "linux")]
fn read_cpu_model() -> String {
    let Ok(content) = std::fs::read_to_string("/proc/cpuinfo") else {
        return String::new();
    };
    for line in content.lines() {
        let Some((key, val)) = line.split_once(':') else {
            continue;
        };
        if key.trim() != "model name" {
            continue;
        }
        let val = val.trim();
        if !val.is_empty() {
            return val.to_string();
        }
    }
    String::new()
}

/// One `/sys/class/dmi/id/<field>` value — the same files
/// `mirage2sentry::box_profile::read_dmi` reads.
#[cfg(target_os = "linux")]
fn read_dmi_field(field: &str) -> String {
    std::fs::read_to_string(format!("/sys/class/dmi/id/{field}"))
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}
