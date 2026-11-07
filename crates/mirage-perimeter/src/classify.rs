//! Wire-vs-not-wire classifier — the decision every face listener makes
//! immediately after camouflage has been stripped and the first
//! [`V9_CLIENT_HELLO_LEN`] bytes have arrived.
//!
//! # This is a ROUTING decision, not an authentication one
//!
//! [`classify_v9_hello`] never touches `client_proof`, never derives a
//! shared secret, and never consults an operator-signed identity. It only
//! asks "does this buffer have the SHAPE of a V9 ClientHello" — version
//! byte, plausible suite ids, a zeroed reserved tail, a timestamp inside
//! the tolerance window. A buffer that passes every check here is routed
//! to the co-located monitor, which still runs the real cryptographic
//! handshake (`mirage_protocol::auth::v9::verify_client_proof`) and rejects
//! it there if the proof does not check out. Nobody downstream may treat a
//! `Verdict::Wire` here as "this peer is authenticated" — it means "this
//! looks enough like Mirage wire to be worth the monitor's time", nothing
//! more.
//!
//! # Why the false-positive rate is negligible
//!
//! Ordinary traffic that lands on a face by mistake or by scan does not
//! produce this shape by accident:
//!
//! - HTTP requests start with an ASCII method byte — `G`/`P`/`H`/… (`0x47`,
//!   `0x50`, `0x48`, …), never `0x09`.
//! - A TLS ClientHello record starts with content-type `0x16`.
//! - SSH identification strings start with `S` (`0x53`) (`"SSH-2.0-…"`).
//! - None of these — nor any other protocol this perimeter is likely to
//!   see probed against it — begins with the single byte `0x09`.
//!
//! A buffer of genuinely random bytes clears every check here with
//! probability on the order of `2^-(8 + 8 + 32) ` for the version byte, a
//! valid first suite id, and the zeroed reserved tail alone (before the
//! timestamp window is even applied) — far below any rate an internet-wide
//! scanner can sustain against one port. The classifier does not need to be
//! cryptographically sound to be operationally decisive; it only needs to
//! be cheap and to almost never let ordinary noise through to the monitor's
//! real handshake code, which [`crate::face`] backs up with the actual
//! per-connection time bounds and the monitor's own auth failure path for
//! anything that slips through.
//!
//! # Interim scope
//!
//! Every [`NotWireReason`] is currently treated identically by
//! [`crate::face`] — the connection is rejected, full stop. The reason is
//! still recorded (see [`crate::stats`]) because the eventual decoy/jail/
//! honeypot dispatch this crate's module doc calls "still genuinely open"
//! will need it to decide where to route a non-wire touch; today nothing
//! reads that decision, only the count.

use mirage_protocol::auth::v9::{id_to_suite, TargetHint, CLIENT_HELLO_LEN, WIRE_VERSION_V9};

/// Wire length of a V9 ClientHello — re-exported under this crate's own
/// name so `face.rs`/`stats.rs` don't have to reach into
/// `mirage_protocol::auth::v9` directly for a single constant.
pub const V9_CLIENT_HELLO_LEN: usize = CLIENT_HELLO_LEN;

/// Byte offset of the target-hint byte within `V9ClientHello`'s reserved
/// tail — see [`TargetHint`]'s own doc for the Stage 2 wire change that
/// carved it out of what used to be four fully-reserved bytes.
const TARGET_HINT_OFFSET: usize = 93;

/// Byte range that must still be all-zero on a genuine hello — the three
/// bytes following [`TARGET_HINT_OFFSET`]. `[93..97]` was the whole
/// reserved tail before Stage 2 of
/// `docs/mirage/plans/every-persona-face-carries-both-2026-09-17.md`; byte
/// 93 is now `target_hint` (validated separately, against [`TargetHint`],
/// not against zero) and only this narrower range remains reserved.
const RESERVED_TAIL_RANGE: std::ops::Range<usize> = 94..97;

/// The fixed prefix every SSH client sends before anything else
/// (RFC 4253 §4.2: the identification string, `SSH-protoversion-...`).
pub const SSH_BANNER_PREFIX: &[u8] = b"SSH-2.0-";

/// How many bytes [`crate::face`] must read before it can tell an SSH client
/// from a Mirage one.
///
/// This exists because the two protocols disagree about who speaks first in a
/// way that would otherwise deadlock the face. A Mirage client sends
/// [`V9_CLIENT_HELLO_LEN`] bytes up front, so the face could simply
/// `read_exact` them. An SSH client sends its identification string — under
/// 30 bytes — and then WAITS for the server's before sending anything more.
/// A face that insisted on 97 bytes first would hold every SSH connection
/// open until the peek timeout fired and then reject it, while the peer sat
/// waiting for a banner that was never coming.
///
/// So the read is staged: this many bytes first, which decides SSH; only if
/// it is not SSH does the face read the rest of the hello.
pub const SSH_DECISION_LEN: usize = SSH_BANNER_PREFIX.len();

/// Does this opening fragment start an SSH connection?
///
/// Shape only, exactly like [`classify_v9_hello`]: this says the peer claims
/// to be an SSH client, and mshd behind it still runs the real key exchange
/// and public-key authentication. A `true` here is not "the operator", it is
/// "worth mshd's time".
#[must_use]
pub fn looks_like_ssh(opening: &[u8]) -> bool {
    opening.starts_with(SSH_BANNER_PREFIX)
}

/// Byte range of the big-endian `ts_ms` field (`V9ClientHello`'s
/// `[36..44]`).
const TS_MS_RANGE: std::ops::Range<usize> = 36..44;

/// The outcome of classifying one buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Shaped like a V9 ClientHello — route to a co-located inward service
    /// for the real (cryptographic) handshake. See this module's doc: NOT
    /// an authentication verdict.
    ///
    /// Carries the hello's parsed and validated [`TargetHint`] — `Legacy`
    /// for every hello that predates Stage 2 of
    /// `docs/mirage/plans/every-persona-face-carries-both-2026-09-17.md`
    /// and every sender in this codebase today (see that type's own doc).
    /// This is the ONLY place a hint is read out of the raw buffer and
    /// validated; a caller that needs it (`crate::face::inward_target`)
    /// takes it from here rather than re-parsing `buf`.
    Wire(TargetHint),
    /// Opened with an SSH identification string — route to the co-located
    /// mshd, which terminates SSH itself. Same disclaimer as [`Self::Wire`]:
    /// a shape, not an identity. mshd still runs key exchange and public-key
    /// auth against the keys its capsule authorised.
    Ssh,
    /// Failed one of the shape checks, in the order they ran.
    NotWire(NotWireReason),
}

/// Why a buffer was not classified as wire, in the order
/// [`classify_v9_hello`] checks them. Carried so [`crate::stats`] can break
/// `rejected_not_wire` down per reason and so the eventual decoy/jail/
/// honeypot dispatch (not built here — see this module's doc) has
/// something to match on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotWireReason {
    /// Fewer than [`V9_CLIENT_HELLO_LEN`] bytes arrived before the peek
    /// timeout or the connection closing. Carries the number of bytes that
    /// DID arrive.
    TooShort(usize),
    /// `buf[0] != WIRE_VERSION_V9`. Carries the byte actually seen.
    BadVersion(u8),
    /// One of `buf[1..4]` is neither `0x00` nor a recognised suite id, OR
    /// `buf[1]` specifically is `0x00` (the first suite slot is never
    /// empty on a genuine hello). Carries the offending byte.
    BadSuite(u8),
    /// `buf[93]` (the target-hint byte) is not one of [`TargetHint`]'s
    /// recognised values, OR `buf[94..97]` (the still-reserved tail past
    /// it) is not all-zero. Before Stage 2 of
    /// `docs/mirage/plans/every-persona-face-carries-both-2026-09-17.md`
    /// this covered `buf[93..97]` as one fully-reserved range; every value
    /// this variant used to catch (any non-zero byte anywhere in
    /// `[93..97]`) is still caught — `0x00` is still the one byte-93 value
    /// that was ever valid before Stage 2, and it remains valid (as
    /// `TargetHint::Legacy`) now.
    ReservedNotZero,
    /// `|now_ms - ts_ms|` exceeds the configured tolerance.
    TimestampSkew { ts_ms: u64, now_ms: u64 },
}

/// Classify `buf` as Mirage V9 wire or not, per this module's doc.
///
/// Checks run in a fixed order — length, version, suite ids, reserved tail,
/// timestamp skew — and return on the first failure, so a caller reading
/// [`NotWireReason`] always sees the FIRST thing wrong, not an arbitrary
/// one.
#[must_use]
pub fn classify_v9_hello(buf: &[u8], now_ms: u64, max_skew_ms: u64) -> Verdict {
    if buf.len() < V9_CLIENT_HELLO_LEN {
        return Verdict::NotWire(NotWireReason::TooShort(buf.len()));
    }

    if buf[0] != WIRE_VERSION_V9 {
        return Verdict::NotWire(NotWireReason::BadVersion(buf[0]));
    }

    // The first suite slot is never empty on a genuine hello — a client
    // that offers zero suites has nothing to negotiate. `id_to_suite`
    // returns `None` for both `0x00` and any unrecognised id, so this one
    // check covers both failure shapes for slot 0.
    if id_to_suite(buf[1]).is_none() {
        return Verdict::NotWire(NotWireReason::BadSuite(buf[1]));
    }
    // The remaining two slots may be legitimately empty (`0x00`) padding.
    for &suite_byte in &buf[2..4] {
        if suite_byte != 0x00 && id_to_suite(suite_byte).is_none() {
            return Verdict::NotWire(NotWireReason::BadSuite(suite_byte));
        }
    }

    // The target-hint byte must name a recognised `TargetHint` — `Legacy`
    // (0x00) included, which is the only value every hello minted before
    // Stage 2 of every-persona-face-carries-both-2026-09-17.md could ever
    // carry here (the whole tail was required zero). Anything outside the
    // three recognised values is exactly as invalid as a non-zero byte
    // anywhere in the old, fully-reserved range was.
    let Some(target_hint) = TargetHint::from_byte(buf[TARGET_HINT_OFFSET]) else {
        return Verdict::NotWire(NotWireReason::ReservedNotZero);
    };

    if buf[RESERVED_TAIL_RANGE].iter().any(|&b| b != 0) {
        return Verdict::NotWire(NotWireReason::ReservedNotZero);
    }

    let ts_bytes: [u8; 8] = buf[TS_MS_RANGE]
        .try_into()
        .expect("range is exactly 8 bytes wide and buf.len() >= V9_CLIENT_HELLO_LEN was checked above");
    let ts_ms = u64::from_be_bytes(ts_bytes);
    if now_ms.abs_diff(ts_ms) > max_skew_ms {
        return Verdict::NotWire(NotWireReason::TimestampSkew { ts_ms, now_ms });
    }

    Verdict::Wire(target_hint)
}

#[cfg(test)]
mod tests {
    use super::*;
    use mirage_protocol::auth::v9::V9ClientHello;

    const NOW: u64 = 1_700_000_000_000;
    const SKEW: u64 = 300_000;

    #[test]
    fn an_ssh_banner_is_recognised_from_its_first_eight_bytes() {
        assert!(looks_like_ssh(b"SSH-2.0-OpenSSH_9.6\r\n"));
        assert!(looks_like_ssh(b"SSH-2.0-"), "the decision needs no more than the prefix");
        assert_eq!(SSH_DECISION_LEN, 8);
    }

    #[test]
    fn a_partial_banner_does_not_decide() {
        // The face reads SSH_DECISION_LEN bytes before asking, so a shorter
        // buffer never reaches this function in production — but it must not
        // claim SSH on a prefix of the prefix either.
        assert!(!looks_like_ssh(b"SSH-2."));
        assert!(!looks_like_ssh(b""));
    }

    #[test]
    fn a_wire_hello_is_not_mistaken_for_ssh() {
        let bytes = hello_bytes(NOW);
        assert!(!looks_like_ssh(&bytes[..SSH_DECISION_LEN]));
    }

    #[test]
    fn ssh_and_wire_openings_cannot_both_match() {
        // The two protocols are separated by their very first byte — 0x53
        // versus 0x09 — which is why one staged read can tell them apart
        // with no ambiguity to resolve later.
        assert_ne!(SSH_BANNER_PREFIX[0], WIRE_VERSION_V9);
    }

    /// Always carries `TargetHint::Legacy` (wire byte `0x00`) — exactly
    /// what every hello minted before Stage 2 of
    /// `docs/mirage/plans/every-persona-face-carries-both-2026-09-17.md`
    /// carried in this position, since it was required all-zero. Tests that
    /// need a different hint mutate `buf[93]` directly (or build their own
    /// hello) — see `a_hint_byte_names_the_carried_target_hint` and
    /// `an_unrecognised_target_hint_byte_rejects` below.
    fn hello_bytes(ts_ms: u64) -> [u8; V9_CLIENT_HELLO_LEN] {
        V9ClientHello {
            version: WIRE_VERSION_V9,
            suite_ids: [0x01, 0x00, 0x00],
            e_pub_c: [0xAA; 32],
            ts_ms,
            client_proof: [0xBB; 16],
            client_static_pub: [0xCC; 32],
            cred_scheme: 0,
            target_hint: TargetHint::Legacy.to_byte(),
        }
        .to_wire()
    }

    #[test]
    fn a_real_hello_classifies_as_wire() {
        let buf = hello_bytes(NOW);
        assert_eq!(classify_v9_hello(&buf, NOW, SKEW), Verdict::Wire(TargetHint::Legacy));
    }

    /// A hello with no `target_hint` set (every hello this codebase sends
    /// today — see [`TargetHint`]'s own doc) classifies as
    /// `Verdict::Wire(TargetHint::Legacy)` — the value that makes
    /// `crate::face::inward_target` fall back to the face's own declared
    /// purpose, unchanged from before this byte existed. This is the "zero
    /// means exactly today's behaviour" property the whole staged roll rests
    /// on, pinned directly rather than inferred from
    /// `a_real_hello_classifies_as_wire` alone.
    #[test]
    fn a_hello_from_a_peer_that_never_heard_of_the_field_still_verifies_as_legacy() {
        // Byte-for-byte what a pre-Stage-2 peer sends: the reserved tail is
        // whatever `hello_bytes` already produces — all-zero, because
        // nothing here has ever set it to anything else.
        let buf = hello_bytes(NOW);
        assert_eq!(buf[93..97], [0x00, 0x00, 0x00, 0x00], "an old peer's hello has a fully-zero tail");
        assert_eq!(classify_v9_hello(&buf, NOW, SKEW), Verdict::Wire(TargetHint::Legacy));
    }

    /// The byte round-trips through the classifier for every recognised
    /// value, and [`Verdict::Wire`] carries exactly the value that was set —
    /// not merely "some `Wire` verdict".
    #[test]
    fn a_hint_byte_names_the_carried_target_hint() {
        for (byte, hint) in [
            (TargetHint::Legacy.to_byte(), TargetHint::Legacy),
            (TargetHint::Monitor.to_byte(), TargetHint::Monitor),
            (TargetHint::Node.to_byte(), TargetHint::Node),
        ] {
            let mut buf = hello_bytes(NOW);
            buf[93] = byte;
            assert_eq!(classify_v9_hello(&buf, NOW, SKEW), Verdict::Wire(hint));
        }
    }

    /// A target-hint byte outside the three recognised values is refused —
    /// the same treatment a non-zero byte anywhere in the old, fully-reserved
    /// tail got before Stage 2 carved this byte out of it.
    #[test]
    fn an_unrecognised_target_hint_byte_rejects() {
        let mut buf = hello_bytes(NOW);
        buf[93] = 0x03;
        assert_eq!(
            classify_v9_hello(&buf, NOW, SKEW),
            Verdict::NotWire(NotWireReason::ReservedNotZero)
        );
    }

    #[test]
    fn a_96_byte_buffer_is_too_short() {
        let buf = [0u8; 96];
        assert_eq!(
            classify_v9_hello(&buf, NOW, SKEW),
            Verdict::NotWire(NotWireReason::TooShort(96))
        );
    }

    #[test]
    fn wrong_version_byte_rejects() {
        let mut buf = hello_bytes(NOW);
        buf[0] = 0x08;
        assert_eq!(
            classify_v9_hello(&buf, NOW, SKEW),
            Verdict::NotWire(NotWireReason::BadVersion(0x08))
        );
    }

    #[test]
    fn an_http_get_prefix_rejects_on_the_version_byte() {
        // "GET / HTTP/1.1" padded to the full hello length — the version
        // check must fire before anything downstream even looks at suites.
        let mut buf = [0u8; V9_CLIENT_HELLO_LEN];
        buf[..14].copy_from_slice(b"GET / HTTP/1.1");
        assert_eq!(
            classify_v9_hello(&buf, NOW, SKEW),
            Verdict::NotWire(NotWireReason::BadVersion(b'G'))
        );
    }

    #[test]
    fn an_empty_first_suite_slot_rejects() {
        let mut buf = hello_bytes(NOW);
        buf[1] = 0x00;
        assert_eq!(
            classify_v9_hello(&buf, NOW, SKEW),
            Verdict::NotWire(NotWireReason::BadSuite(0x00))
        );
    }

    #[test]
    fn an_unrecognised_suite_id_rejects() {
        let mut buf = hello_bytes(NOW);
        buf[1] = 0x7f;
        assert_eq!(
            classify_v9_hello(&buf, NOW, SKEW),
            Verdict::NotWire(NotWireReason::BadSuite(0x7f))
        );
    }

    #[test]
    fn a_nonzero_optional_suite_slot_may_still_be_valid() {
        let mut buf = hello_bytes(NOW);
        buf[2] = 0x02; // second slot: a real (different) suite id — fine.
        assert_eq!(classify_v9_hello(&buf, NOW, SKEW), Verdict::Wire(TargetHint::Legacy));
    }

    #[test]
    fn a_nonzero_reserved_tail_rejects() {
        let mut buf = hello_bytes(NOW);
        buf[96] = 0x01;
        assert_eq!(
            classify_v9_hello(&buf, NOW, SKEW),
            Verdict::NotWire(NotWireReason::ReservedNotZero)
        );
    }

    #[test]
    fn a_stale_timestamp_rejects() {
        let stale_ts = NOW - 1_000_000;
        let buf = hello_bytes(stale_ts);
        assert_eq!(
            classify_v9_hello(&buf, NOW, SKEW),
            Verdict::NotWire(NotWireReason::TimestampSkew {
                ts_ms: stale_ts,
                now_ms: NOW
            })
        );
    }

    #[test]
    fn a_future_timestamp_within_tolerance_is_fine() {
        let buf = hello_bytes(NOW + SKEW);
        assert_eq!(classify_v9_hello(&buf, NOW, SKEW), Verdict::Wire(TargetHint::Legacy));
    }
}
