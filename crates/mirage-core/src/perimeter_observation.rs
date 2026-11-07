//! The observation a perimeter component reports about an inbound touch —
//! shared vocabulary between the perimeter (de-root, attacker-facing) and
//! the arbiter (secd, root, policy-enforcing) planes described in
//! `docs/mirage/plans/arc3-canon-decomposition-and-renumber-2026-07-24.md`
//! §1-3.
//!
//! # Why this lives in `mirage-core`
//!
//! Both planes already depend on `mirage-core`. `mirage-perimeter` cannot
//! own this type — the arbiter would then have to depend on the periphery
//! just to name the fact it consumes. `mirage-secd` cannot own it either —
//! that keeps the exact coupling this type exists to remove, only pointing
//! the other way (periphery depending on the core instead of the reverse).
//! A type both planes must be able to name belongs to neither plane; it
//! belongs to the shared crate underneath both.
//!
//! # What this is NOT
//!
//! A [`PerimeterObservation`] is a report, never a decision. It carries no
//! ban, no nftables timeout, no enforcement verb of any kind — deciding
//! those is the arbiter's job (`mirage-secd::fw::escalated_ban_ttl_ms` /
//! `ban_for`), and it stays entirely in `mirage-secd`, simply no longer
//! reachable from the perimeter. Consuming a structured row like this one is
//! exactly the "structured signal, not attacker bytes" boundary the arc3
//! canon draws around the arbiter: the arbiter never touches attacker
//! bytes, only typed facts the perimeter derived from them.

use serde::{Deserialize, Serialize};

use crate::fact_signing::AttackerSignalType;


/// One perimeter-side observation of an inbound touch.
///
/// Emitted by perimeter components (today: `mirage-perimeter::decoy`)
/// through a sink supplied at construction — the perimeter crate defines
/// that sink trait and does not implement it. Whatever consumes these
/// observations (the arbiter, once the perimeter is a separate process
/// reaching it over IPC/wire) owns the implementation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PerimeterObservation {
    /// Source IP address string (IPv4 or IPv6) of the touching peer.
    pub ip: String,
    /// The perimeter port/face that received the touch (e.g. a decoy trap
    /// port).
    pub port: u16,
    /// Unix timestamp of the touch, milliseconds since epoch.
    pub ts_ms: u64,
    /// Signal class this touch classifies as — the same closed set the
    /// arbiter already decodes on every other zero-parse signal path
    /// (decoy, tarpit, flood, bomb, ...).
    pub signal_type: AttackerSignalType,
    /// How many times the PERIMETER's own local ledger has seen this IP so
    /// far. This is the perimeter's own accounting for its own future
    /// decisions (e.g. decoy-vs-jail escalation) — NOT the arbiter's ban
    /// engine's offense counter, which is a separate count the arbiter
    /// derives independently once this observation reaches it.
    pub perimeter_touch_count: u32,
    /// Confidence bucket (0-100) for this observation, computed via
    /// [`confidence_bucket`] — a deterministic classification of
    /// `(signal_type, perimeter_touch_count)`, not an enforcement decision.
    pub confidence: u8,
}

/// Confidence bucket for a given signal type + repeat-touch count.
///
/// Deterministic, u8 0-100, a pure classification of an observation's own
/// fields — never consults ban-engine state, never decides an enforcement
/// action, and never depends on anything an attacker sent:
///
/// - `Decoy` (bare tripwire touch): 100 — an unambiguous foe signal by
///   construction (the port has no legitimate use).
/// - `Tarpit` / `Flood` / `Bomb` (a burn mechanism ran): 90 — same
///   unambiguous port-touch signal, slightly discounted vs a pure decoy read
///   since the burn mechanisms are heavier-weight and rarer to trigger
///   spuriously in either direction.
/// - `UnexpectedListener`: 80.
/// - `SshBrute`: scales with `touch_count` — 20 for a lone attempt up to 60
///   for a repeated offender (bounded at `count>=5`).
/// - `KernelPtraceDeny`: 100 — a BPF-LSM deny against a protected cgroup is
///   as unambiguous a foe signal as a decoy touch.
/// - `Honeypot` / `Other`: 50 fallback.
///
/// Shared by both planes so they never compute two different confidence
/// scores for the same kind of observation — moved here (from
/// `mirage-secd::intel`, where it originated) once `mirage-perimeter`
/// started needing the identical classification for its own emitted
/// [`PerimeterObservation`] rows.
#[must_use]
pub fn confidence_bucket(signal_type: AttackerSignalType, touch_count: u32) -> u8 {
    match signal_type {
        AttackerSignalType::Decoy | AttackerSignalType::KernelPtraceDeny => 100,
        AttackerSignalType::Tarpit | AttackerSignalType::Flood | AttackerSignalType::Bomb => 90,
        AttackerSignalType::UnexpectedListener => 80,
        AttackerSignalType::SshBrute => {
            let scaled = 20u32.saturating_add(touch_count.saturating_mul(8));
            scaled.min(60) as u8
        }
        // Seam A. A single failed camouflage strip is the weakest signal the
        // perimeter can emit: a plain HTTP client that does not know a
        // websocket face's path fails it, and so does any crawler. Same
        // shape as `SshBrute` — one touch is nearly nothing, a repeat
        // toucher is a scanner.
        AttackerSignalType::PerimeterCamoFailed => {
            let scaled = 20u32.saturating_add(touch_count.saturating_mul(8));
            scaled.min(60) as u8
        }
        // Seam B. The peer spoke the face's outer protocol correctly and was
        // still neither a V9 hello nor an SSH banner — strictly more
        // deliberate than seam A, so it starts higher and climbs higher, but
        // still short of the unambiguous 100 a decoy touch earns (a decoy
        // port has no legitimate use at all; a face does).
        AttackerSignalType::PerimeterNotWire => {
            let scaled = 40u32.saturating_add(touch_count.saturating_mul(8));
            scaled.min(80) as u8
        }
        AttackerSignalType::Honeypot | AttackerSignalType::Other => 50,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_lone_camo_failure_scores_lower_than_a_lone_not_wire() {
        // Seam A catches browsers and crawlers; seam B catches something
        // that spoke the outer protocol correctly and still was not wire.
        // Flattening the two into one score would hand a crawler the same
        // weight as a probe.
        let seam_a = confidence_bucket(AttackerSignalType::PerimeterCamoFailed, 1);
        let seam_b = confidence_bucket(AttackerSignalType::PerimeterNotWire, 1);
        assert!(seam_a < seam_b, "seam A must start below seam B");
    }

    #[test]
    fn both_perimeter_seams_climb_with_repeats_and_stay_under_a_decoy_touch() {
        for seam in [
            AttackerSignalType::PerimeterCamoFailed,
            AttackerSignalType::PerimeterNotWire,
        ] {
            let once = confidence_bucket(seam, 1);
            let often = confidence_bucket(seam, 20);
            assert!(often > once, "a repeat toucher must score higher");
            assert!(
                often < confidence_bucket(AttackerSignalType::Decoy, 1),
                "a published face is not a decoy port: it has legitimate use, so it                  can never reach the unambiguous score"
            );
        }
    }

    #[test]
    fn confidence_bucket_decoy_is_max() {
        assert_eq!(confidence_bucket(AttackerSignalType::Decoy, 1), 100);
    }

    #[test]
    fn confidence_bucket_ssh_brute_scales_with_touch_count() {
        let single = confidence_bucket(AttackerSignalType::SshBrute, 1);
        let repeated = confidence_bucket(AttackerSignalType::SshBrute, 10);
        assert!(single < repeated, "repeated offender must score higher confidence");
        assert_eq!(repeated, 60, "ssh_brute confidence caps at 60");
    }

    #[test]
    fn confidence_bucket_burn_mechanisms_are_ninety() {
        assert_eq!(confidence_bucket(AttackerSignalType::Tarpit, 1), 90);
        assert_eq!(confidence_bucket(AttackerSignalType::Flood, 1), 90);
        assert_eq!(confidence_bucket(AttackerSignalType::Bomb, 1), 90);
    }

    #[test]
    fn perimeter_observation_round_trips_through_json() {
        let observation = PerimeterObservation {
            ip: "203.0.113.7".to_string(),
            port: 23,
            ts_ms: 1_700_000_000_000,
            signal_type: AttackerSignalType::Tarpit,
            perimeter_touch_count: 3,
            confidence: confidence_bucket(AttackerSignalType::Tarpit, 3),
        };

        let json = serde_json::to_string(&observation).expect("serialize PerimeterObservation");
        let decoded: PerimeterObservation =
            serde_json::from_str(&json).expect("deserialize PerimeterObservation");

        assert_eq!(decoded, observation);
    }
}
