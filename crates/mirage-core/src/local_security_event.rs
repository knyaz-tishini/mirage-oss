//! The box-local security channel: what the perimeter and mshd tell the
//! arbiter, on one socket, in one typed envelope.
//!
//! # Why an envelope and not a second socket
//!
//! Two producers now report to `mirage-secd`: the perimeter, which sees every
//! inbound connection and its real source address, and mshd, which is the
//! only thing on the box that ever *authenticates* an operator. They report
//! different facts and neither is useful alone — see [`LocalSecurityEvent`]'s
//! variants. One socket means one listener, one set of permissions, one place
//! where a malformed line is dropped and counted.
//!
//! # Why the arbiter needs both halves
//!
//! The perimeter terminates the outer layer and SPLICES the inner connection
//! to `127.0.0.1`, so the daemon that authenticates never sees who it is
//! talking to — its peer is always loopback. And the perimeter, which does
//! know the address, has no idea whether the session that followed
//! authenticated. Neither party can decide "this address is the operator" on
//! its own.
//!
//! # Two authenticators, because Mirage has roles
//!
//! The operator is not "whoever completed a handshake". It is a role with its
//! own signature, and both of the box's inward destinations can recognise it:
//!
//! * **mshd** authenticates the operator's SSH public key against its
//!   authorized keys.
//! * **the monitor** verifies a V9 `SenderProof` whose `DeclaredIdentity`
//!   carries `ServiceRole::Operator` — the root-of-trust control role, which
//!   a client identity (`ServiceRole::Sentinel` → `AuthRole::Client`) can
//!   never present.
//!
//! Both report the same thing: *the operator proved itself on this
//! connection*. Neither reports "somebody finished a handshake", which would
//! be worthless.
//!
//! # The join is gone, and that is the fix
//!
//! This used to be reassembled by the arbiter. The perimeter reported an
//! address keyed by **the loopback ephemeral port** it had dialled from, the
//! destination reported an authentication keyed by the same port, and secd
//! joined the two inside a 60-second window. It worked, and it was a
//! workaround for an address that was never passed: mshd's splice carried
//! nothing at all, so the port was the only thing tying the two halves
//! together.
//!
//! Moving the splice to a unix socket ([`crate::local_endpoint`]) removes the
//! ephemeral port, so the join lost its key — and forced the fix that was
//! owed. The perimeter now sends a typed
//! [`crate::perimeter_preamble::PerimeterPreamble`] WITH the connection, so
//! the destination knows the real address before it authenticates anybody and
//! reports it directly. `PendingRoutes`, `ROUTE_JOIN_WINDOW_MS` and the
//! window's whole failure mode — a port the kernel reused being joined to a
//! different connection's lifetime — are deleted rather than tuned.
//!
//! One consequence worth naming: the RECOVERY DOOR now reports too. It sees a
//! real peer directly (no perimeter in front of it), so it never had a route
//! to join and every authentication through it was dropped at debug level.
//! That is the door the operator uses when the box is in trouble, which is
//! exactly when knowing the operator's current address matters most.
//!
//! # What this is NOT
//!
//! It is not an address list and must never become one. The operator's
//! address drifts constantly; what is stable is the operator's KEY. This
//! channel exists so the box learns the current address as a CONSEQUENCE of a
//! completed public-key authentication, and forgets it on a timer if no
//! further authentication renews it.

use serde::{Deserialize, Serialize};

use crate::perimeter_observation::PerimeterObservation;

/// Unix socket the box-local producers report to and `mirage-secd` listens
/// on — one newline-terminated JSON [`LocalSecurityEvent`] per line.
///
/// Under `/run` because everything it carries is liveness, not history: a
/// reboot starts the counts over, exactly like the nftables state the arbiter
/// derives from them.
pub const LOCAL_EVENT_SOCKET_PATH: &str = "/run/mirage/secd/local-events.sock";

/// Where the perimeter handed a connection.
///
/// # Why this deserializes by hand
///
/// The derived impl would reject a destination it does not know, and a
/// rejection here is not a degraded event — it is a DELETED one: this enum
/// rides inside the preamble written to every inward socket and inside
/// [`LocalSecurityEvent::RoutedInward`], so one unknown value discards the
/// whole record. That is the failure mode this fleet spent a night removing
/// from six other places.
///
/// [`InwardDest::Unknown`] carries the raw string rather than swallowing it.
/// `#[serde(other)]` would have been one line, and it drops the value — a
/// dropped event that cannot name what it dropped is the same defect wearing
/// a different hat.
///
/// # The rule for whoever matches this
///
/// Nothing matches on it today: the perimeter PRODUCES it from its own
/// `InnerKind`, and secd only logs it. A consumer that starts matching must
/// name [`InwardDest::Unknown`] explicitly and must NOT carry a wildcard arm.
/// The Unknown arm disposes exactly as an unknown chain selector does — hold,
/// close, never a byte, and `warn!` with the string it saw. It never routes,
/// and it is never a default.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InwardDest {
    /// The co-located mshd, on an SSH-shaped opening.
    Mshd,
    /// The co-located monitor, on a V9 hello.
    Monitor,
    /// The co-located node, on a V9 hello that arrived at a face the box
    /// declared for chain traffic.
    NodeChain,
    /// A destination this build does not know, verbatim as it arrived.
    Unknown(String),
}

impl InwardDest {
    /// The wire spelling. Round-trips through [`Serialize`]/[`Deserialize`].
    pub fn as_wire(&self) -> &str {
        match self {
            InwardDest::Mshd => "Mshd",
            InwardDest::Monitor => "Monitor",
            InwardDest::NodeChain => "NodeChain",
            InwardDest::Unknown(raw) => raw.as_str(),
        }
    }
}

impl Serialize for InwardDest {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(self.as_wire())
    }
}

impl<'de> Deserialize<'de> for InwardDest {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(d)?;
        Ok(match raw.as_str() {
            "Mshd" => InwardDest::Mshd,
            "Monitor" => InwardDest::Monitor,
            "NodeChain" => InwardDest::NodeChain,
            _ => InwardDest::Unknown(raw),
        })
    }
}

/// How the operator proved itself.
///
/// Recorded so a released ban can be traced to the credential that released
/// it, and so the two paths can be counted apart — during a camouflage or
/// version skew one of them can be failing while the other still works, and
/// that difference is the diagnosis.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OperatorProof {
    /// mshd accepted the operator's SSH public key.
    MshdPublicKey,
    /// The monitor verified a V9 `SenderProof` carrying
    /// `ServiceRole::Operator`.
    WireSenderProof,
}

/// One box-local report. Always a fact the producer observed, never a
/// decision — deciding is the arbiter's job and stays there.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind")]
pub enum LocalSecurityEvent {
    /// The perimeter refused a connection at one of its two seams.
    ///
    /// The least trustworthy input the arbiter has — derived from bytes an
    /// attacker chose — so it may only ever move a counter.
    Observation(PerimeterObservation),

    /// The perimeter ADMITTED a connection and routed it inward.
    ///
    /// It proves nothing about the peer and never did: routing is decided on
    /// the opening bytes, so anything that sends `SSH-2.0-` or a well-shaped
    /// V9 hello produces one of these. What it is now is the WAF's own record
    /// of who was let in and what they were reaching for — which face carried
    /// them, and to which destination. It is no longer half of a join; the
    /// address travels WITH the connection instead (see the module doc).
    RoutedInward {
        /// The real source address, which only the perimeter knows.
        client_ip: String,
        /// The public port the connection arrived on — what the peer was
        /// knocking at, which the destination cannot see.
        face_port: u16,
        dest: InwardDest,
        ts_ms: u64,
    },

    /// An inward destination authenticated the OPERATOR, and knows the
    /// address to say it about.
    ///
    /// THE trustworthy half, and now a complete one. mshd reads the address
    /// off the perimeter's preamble; the recovery door reads it off its own
    /// socket, having no perimeter in front of it; the monitor reads it off
    /// the PROXY v2 header it already receives. None of them is guessing, and
    /// none of them needs a third daemon to correlate anything.
    OperatorAuthenticated {
        /// The client's real address, without a port — trust and ban ledgers
        /// are keyed by address.
        client_ip: String,
        proof: OperatorProof,
        ts_ms: u64,
    },

    /// A wire (V9) handshake rejected the credential it was offered.
    ///
    /// The counterpart, on the wire face, to an SSH credential failure —
    /// see `mirage-secd::banengine`'s module doc for the three-ledger split
    /// this feeds (`docs/mirage/plans/four-items-2026-08-19.md` item 1):
    /// reaching the wire face is free, a REJECTED credential on it is what
    /// counts, and it counts on its own ledger with its own threshold,
    /// never the anonymous-probing one a bare port scan lands on.
    ///
    /// **Named gap, 2026-08-19**: this is the envelope only. Nothing in
    /// `mirage2web` sends it yet — the natural producer is whichever
    /// process runs the real V9 handshake verification behind the
    /// perimeter's wire face (the monitor: `mirage-perimeter`'s own
    /// classifier is explicitly "not an authentication boundary", the real
    /// handshake happens behind it), reporting a rejection over this box's
    /// [`LOCAL_EVENT_SOCKET_PATH`] the same way mshd already reports
    /// [`LocalSecurityEvent::OperatorAuthenticated`]. That producer lives in
    /// a separate repository and is a separate task; this only arms the
    /// receiving side (`mirage-secd::banengine::BanEngineState::
    /// record_wire_credential_failure`) so it is ready the moment it exists.
    WireCredentialRejected {
        /// The peer's real address, as only whichever process ran the
        /// handshake can know it.
        client_ip: String,
        ts_ms: u64,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fact_signing::AttackerSignalType;

    #[test]
    fn every_variant_round_trips_through_the_line_format() {
        let events = vec![
            LocalSecurityEvent::Observation(PerimeterObservation {
                ip: "198.51.100.7".into(),
                port: 443,
                ts_ms: 1,
                signal_type: AttackerSignalType::PerimeterNotWire,
                perimeter_touch_count: 2,
                confidence: 48,
            }),
            LocalSecurityEvent::RoutedInward {
                client_ip: "203.0.113.9".into(),
                face_port: 22,
                dest: InwardDest::Mshd,
                ts_ms: 2,
            },
            LocalSecurityEvent::RoutedInward {
                client_ip: "203.0.113.9".into(),
                face_port: 443,
                dest: InwardDest::Monitor,
                ts_ms: 2,
            },
            LocalSecurityEvent::OperatorAuthenticated {
                client_ip: "203.0.113.9".into(),
                proof: OperatorProof::MshdPublicKey,
                ts_ms: 3,
            },
            LocalSecurityEvent::OperatorAuthenticated {
                client_ip: "2001:db8::5".into(),
                proof: OperatorProof::WireSenderProof,
                ts_ms: 3,
            },
            LocalSecurityEvent::WireCredentialRejected {
                client_ip: "203.0.113.9".into(),
                ts_ms: 4,
            },
        ];
        for e in events {
            let line = serde_json::to_string(&e).expect("serialises");
            assert!(!line.contains('\n'), "a line must not contain a newline");
            let back: LocalSecurityEvent = serde_json::from_str(&line).expect("round trips");
            assert_eq!(back, e);
        }
    }

    #[test]
    fn being_routed_and_being_authenticated_stay_different_facts() {
        // The property the whole design rests on, and it survives the join's
        // deletion: an ADMITTED connection and a PROVEN identity are separate
        // messages about the same address. Collapsing them would mean
        // trusting a routing decision made on the opening bytes, which
        // anything that types `SSH-2.0-` can produce.
        let ip = "203.0.113.9";
        let routed = LocalSecurityEvent::RoutedInward {
            client_ip: ip.into(),
            face_port: 22,
            dest: InwardDest::Mshd,
            ts_ms: 0,
        };
        let authed = LocalSecurityEvent::OperatorAuthenticated {
            client_ip: ip.into(),
            proof: OperatorProof::MshdPublicKey,
            ts_ms: 0,
        };
        assert_ne!(routed, authed, "same address, different claims");
    }

    #[test]
    fn an_unknown_destination_survives_the_round_trip_instead_of_deleting_the_event() {
        // The whole reason `InwardDest` deserializes by hand. A build that
        // meets a destination minted after it must still be able to read the
        // event that carries it — and must be able to SAY what it saw, which
        // is why `Unknown` holds the string rather than swallowing it.
        // Built by serializing a real event and swapping only the
        // destination, so the test cannot drift from the actual envelope
        // shape the way a hand-written literal can.
        let minted_here = LocalSecurityEvent::RoutedInward {
            client_ip: "203.0.113.9".into(),
            face_port: 443,
            dest: InwardDest::Monitor,
            ts_ms: 7,
        };
        let line = serde_json::to_string(&minted_here)
            .expect("serializes")
            .replace("\"Monitor\"", "\"SomethingMintedLater\"");
        let back: LocalSecurityEvent =
            serde_json::from_str(&line).expect("an unknown destination must not fail the parse");
        let LocalSecurityEvent::RoutedInward { dest, face_port, .. } = back else {
            panic!("wrong variant");
        };
        assert_eq!(face_port, 443, "the rest of the event survives intact");
        assert_eq!(dest, InwardDest::Unknown("SomethingMintedLater".into()));
        assert_eq!(dest.as_wire(), "SomethingMintedLater", "and it round-trips out again");
    }

    #[test]
    fn every_known_destination_round_trips_through_its_wire_spelling() {
        for d in [InwardDest::Mshd, InwardDest::Monitor, InwardDest::NodeChain] {
            let json = serde_json::to_string(&d).expect("serializes");
            let back: InwardDest = serde_json::from_str(&json).expect("deserializes");
            assert_eq!(back, d, "{json} did not round-trip");
        }
    }
}
