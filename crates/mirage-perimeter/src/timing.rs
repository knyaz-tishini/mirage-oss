//! The splice backstop — a generous, jittered ceiling on how long ONE
//! routed connection may be held, derived from the face's declared
//! [`SessionProfile`]. OBSERVE-ONLY in this step: nothing here cuts a
//! connection. See `crate::face::splice_inward` for the wrap that consumes
//! this, and `docs/mirage/plans/face-behaviour-and-camouflage-2026-09-17.md`
//! for the reasoning this module implements the first real consumer of.
//!
//! # Why generous, and why jittered
//!
//! A mesh chain hop and a customer's mux'd subscriber tunnel are both, by
//! construction, long-held flows — per the 2026-09-16 ruling, a customer
//! shards across whichever of the box's published faces his client chooses,
//! not only the one face structurally designated to carry chain data. So
//! today's live fleet certainly already carries flows that outlive any
//! ceiling this module could name; the numbers below are a first, generous
//! cut whose entire purpose is to produce that measurement
//! (`splice_backstop_observed`, `FaceCounters`) before any enforcement
//! decision is made, not to enforce anything themselves.
//!
//! A single, precise, unjittered cutoff would itself be a fingerprint — an
//! observer who times many sessions on one face and finds them all reported
//! at the identical elapsed wall-clock has learned the constant, the same
//! lesson already drawn for `SampleRate`/delay distributions elsewhere in
//! this crate's camouflage work. [`splice_backstop`] samples a fresh value
//! per connection instead, so many sessions on the same face never share one
//! observable deadline.

use std::time::Duration;

use mirage_core::mirage::wire::camouflage::SessionProfile;
use rand::Rng;

/// Ceiling for a [`SessionProfile::Bursty`] face — real services wearing
/// this shape (a plain TLS request, a one-shot DNS query, an ICMP echo)
/// ordinarily close a connection long before this, so 30 minutes is
/// deliberately generous rather than a tight match to the covered
/// protocol's own typical lifetime. A first-cut number, not an owner-signed
/// one — see this module's own doc; it exists to be measured against, then
/// revisited with real `splice_backstop_observed` data in hand.
pub const BURSTY_SPLICE_BACKSTOP_MS: u64 = 30 * 60 * 1_000;

/// Ceiling for a [`SessionProfile::Sustained`] face — a persistent app/API
/// backend, a real-time channel, an interactive admin session, all of which
/// plausibly hold a connection open for hours. Six hours, for the identical
/// "generous first cut, not an enforced value" reason
/// [`BURSTY_SPLICE_BACKSTOP_MS`]'s doc gives.
pub const SUSTAINED_SPLICE_BACKSTOP_MS: u64 = 6 * 60 * 60 * 1_000;

/// Jitter spread as a fraction of the base, expressed as an integer divisor
/// so the bound is computed without floating point: `base / JITTER_DIVISOR`
/// is ±20% of `base`.
const JITTER_DIVISOR: u64 = 5;

/// This profile's base ceiling before jitter — the value [`splice_backstop`]
/// samples around. Exhaustive, no catch-all: a third [`SessionProfile`]
/// variant is a compile error here, not a silent fallback to one of these
/// two numbers.
const fn base_ms(profile: SessionProfile) -> u64 {
    match profile {
        SessionProfile::Bursty => BURSTY_SPLICE_BACKSTOP_MS,
        SessionProfile::Sustained => SUSTAINED_SPLICE_BACKSTOP_MS,
    }
}

/// The inclusive `[low, high]` band [`splice_backstop`] samples from for a
/// given base — `base ± base/JITTER_DIVISOR`, i.e. ±20%. Split out from
/// [`splice_backstop`] itself so the band can be checked directly in tests
/// without depending on the RNG draw landing inside it by chance.
const fn jitter_bounds_ms(base_ms: u64) -> (u64, u64) {
    let spread = base_ms / JITTER_DIVISOR;
    (base_ms - spread, base_ms + spread)
}

/// A jittered ceiling: `base ± 20%`, sampled once per connection so many
/// sessions on the same face never share one observable cutoff. See this
/// module's own doc for why the base numbers are generous and why the
/// result is jittered at all.
pub fn splice_backstop(profile: SessionProfile) -> Duration {
    let (low, high) = jitter_bounds_ms(base_ms(profile));
    let ms = rand::thread_rng().gen_range(low..=high);
    Duration::from_millis(ms)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A `Sustained` face is plausibly held open far longer than a `Bursty`
    /// one — the ordering the whole module exists to encode. If this ever
    /// flips, every downstream reasoning about "generous enough for a real
    /// mesh/customer flow" in this module's doc is wrong.
    #[test]
    fn sustained_ceiling_is_larger_than_bursty() {
        assert!(SUSTAINED_SPLICE_BACKSTOP_MS > BURSTY_SPLICE_BACKSTOP_MS);
    }

    #[test]
    fn jitter_bounds_are_plus_minus_twenty_percent() {
        let (low, high) = jitter_bounds_ms(1_000_000);
        assert_eq!(low, 800_000);
        assert_eq!(high, 1_200_000);
    }

    /// The property [`splice_backstop`]'s doc claims: every draw, for every
    /// profile, lands inside the computed band — never below it, never
    /// above it. Sampled many times per profile since this is a random
    /// draw; a single sample proves nothing about the distribution's edges.
    #[test]
    fn splice_backstop_stays_within_its_jittered_band_for_every_profile() {
        for profile in [SessionProfile::Bursty, SessionProfile::Sustained] {
            let (low, high) = jitter_bounds_ms(base_ms(profile));
            for _ in 0..500 {
                let ms = splice_backstop(profile).as_millis() as u64;
                assert!(
                    ms >= low && ms <= high,
                    "{:?}: {ms}ms outside [{low}, {high}]",
                    profile
                );
            }
        }
    }

    /// [`base_ms`] is `const fn` and exhaustively matched — this is not a
    /// property test so much as a compile-time guarantee already enforced
    /// by the match itself; this pins the two values it currently returns
    /// so a future edit to either constant is visible as a failing
    /// assertion here, not only in the doc comments above them.
    #[test]
    fn base_ms_matches_the_named_constants() {
        assert_eq!(base_ms(SessionProfile::Bursty), BURSTY_SPLICE_BACKSTOP_MS);
        assert_eq!(base_ms(SessionProfile::Sustained), SUSTAINED_SPLICE_BACKSTOP_MS);
    }
}
