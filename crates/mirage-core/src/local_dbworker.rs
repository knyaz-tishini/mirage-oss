//! What db-worker answers when something on the box asks it about this
//! box's own stored state.
//!
//! # What this replaces
//!
//! A hand-rolled HTTP/1.1 server on `127.0.0.1:19446` with three GET routes
//! (`/dk/backend`, `/secd/desired-state`, `/self-enable?role=`), and four
//! `reqwest` readers in three other crates, each re-deriving the response
//! shape from JSON with its own `#[derive(Deserialize)]` and its own
//! defaulting rules. The same drift the perimeter's counters already paid
//! for (see [`crate::perimeter_query`]), waiting to happen: db-worker's
//! `/secd/desired-state` body had to be kept "byte-for-byte identical" to a
//! monitor route by hand, and its own doc says so.
//!
//! One definition here, compiled into producer and every consumer. A field
//! renamed is a build error rather than a silent `null`.
//!
//! # Not-ready is a variant, not a status code
//!
//! The HTTP version leaned on 503-vs-200 to separate "the store cannot be
//! read yet" from "the store is open and nothing is staged", and that
//! distinction is load-bearing: secd's boot-seed RETRIES the first and
//! accepts the second as final. Conflating them once already let a rebooted
//! box silently miss its durable state. Here the two are different variants
//! of [`DbWorkerResponse`], so a consumer cannot treat one as the other
//! without writing the arm that says so.
//!
//! [`NotReadyReason`] keeps the split the 503 body carried in prose: a store
//! that is still opening resolves on its own, a box that never received a DK
//! this boot does not resolve at all and a caller polling it is reading a
//! permanent condition as progress.
//!
//! # Every request is a read
//!
//! Nothing on this channel changes db-worker's behaviour or writes a row.
//! Writes ride the authenticated wire to the monitor exactly as before —
//! this is the box-local READ path, and it stays one.

use serde::{Deserialize, Serialize};

use crate::secd_directive::SecdDirective;
use crate::secd_policy::DkBackend;

/// A question for the co-located db-worker.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DbWorkerRequest {
    /// Which DK-storage backend this box's db-worker actually achieved this
    /// boot. secd's axis D reads it instead of hardcoding `Mlock`.
    DkBackend,
    /// This box's own durable `secd_desired_state` rows — secd's boot seed,
    /// read from the local store instead of round-tripping to a monitor.
    SecdDesiredState,
    /// Whether `role`'s `service_config` opts out of the fleet-wide
    /// auto-`systemctl enable` convention.
    SelfEnable { role: String },
}

/// db-worker's answer. One variant per question, matched by shape.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DbWorkerResponse {
    /// `None` when `probe_and_select` has not run — an un-baked box that
    /// never had a DK delivered, reported as absent rather than as a
    /// fabricated default.
    DkBackend(Option<DkBackend>),
    /// The store opened and the read succeeded. Every field may still be
    /// `None`: that is a definitive "nothing staged", not a failure.
    DesiredState(Box<SecdDesiredState>),
    /// The store could not be read. DISTINCT from a `DesiredState` whose
    /// fields are all `None` — see the module doc.
    NotReady(NotReadyReason),
    SelfEnable { self_enable_unit: bool },
}

/// Why db-worker could not answer from the store.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NotReadyReason {
    /// No DK has been delivered to this box this boot, so the store cannot
    /// open at all. **Does not resolve on its own** — with no issuer
    /// reachable a caller polling this waits forever.
    DkNotDelivered,
    /// The DK is present and the store is not readable yet. Transient;
    /// retry.
    StoreOpening,
    /// db-worker has not resolved its own machine identity yet, so it does
    /// not know whose rows to return. Transient, and distinct from the two
    /// above because the store is not the thing that is missing.
    IdentityUnset,
}

impl NotReadyReason {
    /// Whether waiting is expected to help. `false` is the one that matters:
    /// a caller that retries forever on a permanent condition reports it as
    /// progress.
    pub const fn is_transient(self) -> bool {
        match self {
            NotReadyReason::DkNotDelivered => false,
            NotReadyReason::StoreOpening | NotReadyReason::IdentityUnset => true,
        }
    }

    /// One line for a log or an operator's readout.
    pub const fn detail(self) -> &'static str {
        match self {
            NotReadyReason::DkNotDelivered => {
                "no DK has been delivered to this box this boot — the store cannot open at all, \
                 and this does not resolve on its own"
            }
            NotReadyReason::StoreOpening => {
                "the DK is present and the store is not readable yet — transient, retry"
            }
            NotReadyReason::IdentityUnset => {
                "db-worker has not resolved its own machine identity yet — transient, retry"
            }
        }
    }
}

/// This box's durable secd desired state, one directive per kind.
///
/// Shape mirrors the monitor's `GET /relay/secd/{id}/desired-state` because
/// secd applies both through the same code — but it mirrors it as a TYPE
/// now, not as a JSON body two files agree to keep identical by hand.
///
/// `#[serde(default)]` on every field so a peer built before a kind existed
/// reads the rest instead of failing the whole frame: an added kind is
/// additive, exactly like an added directive variant.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecdDesiredState {
    #[serde(default)]
    pub set_policy: Option<SecdDirective>,
    #[serde(default)]
    pub set_patch_schedule: Option<SecdDirective>,
    #[serde(default)]
    pub set_surface_config: Option<SecdDirective>,
    /// axis R — which rung of the fleet-reputation ladder this box is on.
    /// Durable for the same reason the others are: without it a reboot
    /// silently returns the box to `Off`, and a defence that quietly stops
    /// is worse than one that was never enabled.
    #[serde(default)]
    pub set_reputation_mode: Option<SecdDirective>,
}

impl SecdDesiredState {
    /// Nothing staged for any kind. Not an error state — see the module doc.
    pub fn is_empty(&self) -> bool {
        self.set_policy.is_none()
            && self.set_patch_schedule.is_none()
            && self.set_surface_config.is_none()
            && self.set_reputation_mode.is_none()
    }
}

/// The answer every self-enable failure mode resolves to.
///
/// A service must opt OUT explicitly; it is never opted out by omission, a
/// missing row, an unparseable blob, or a db-worker that is not running.
/// The default lives here so all four consumers cannot each pick their own.
pub const SELF_ENABLE_DEFAULT: bool = true;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_not_ready_answer_is_not_an_empty_desired_state() {
        let empty = DbWorkerResponse::DesiredState(Box::default());
        let not_ready = DbWorkerResponse::NotReady(NotReadyReason::StoreOpening);
        assert_ne!(empty, not_ready);
        // And the distinction survives the wire, which is the whole point of
        // it being a variant rather than a status code.
        let encoded = serde_json::to_string(&not_ready).expect("encodes");
        let decoded: DbWorkerResponse = serde_json::from_str(&encoded).expect("decodes");
        assert_eq!(decoded, not_ready);
    }

    #[test]
    fn only_the_undeliverable_dk_is_permanent() {
        assert!(!NotReadyReason::DkNotDelivered.is_transient());
        assert!(NotReadyReason::StoreOpening.is_transient());
        assert!(NotReadyReason::IdentityUnset.is_transient());
    }

    #[test]
    fn a_kind_this_build_does_not_know_leaves_the_others_readable() {
        // A peer built after this one stages a fifth kind. The frame must
        // still decode — an added kind is additive.
        let raw = r#"{"set_policy":null,"set_patch_schedule":null,
                      "set_surface_config":null,"set_reputation_mode":null,
                      "set_something_later":{"whatever":1}}"#;
        let parsed: SecdDesiredState = serde_json::from_str(raw).expect("decodes");
        assert!(parsed.is_empty());
    }

    #[test]
    fn a_request_round_trips_by_name_not_by_position() {
        let req = DbWorkerRequest::SelfEnable {
            role: "sentry".to_string(),
        };
        let encoded = serde_json::to_string(&req).expect("encodes");
        assert!(encoded.contains("self_enable"), "{encoded}");
        assert!(encoded.contains("sentry"), "{encoded}");
        let decoded: DbWorkerRequest = serde_json::from_str(&encoded).expect("decodes");
        assert_eq!(decoded, req);
    }
}
