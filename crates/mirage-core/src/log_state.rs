//! "Log only on state change" — turns a per-key boolean health signal
//! into a transition, so callers emit ONE line when a target recovers or
//! starts failing instead of one line per operation.
//!
//! Motivation: several per-operation hot loops (secd's per-monitor
//! dial/register/submit cycle, the monitor's per-fact originator-identity
//! check) used to log a CONFIRMATION or REJECTION line on every single
//! call. On a small box that produced thousands of near-identical journal
//! lines per boot, burning disk IO/CPU and burying real signal. Owner
//! directive: logs must accumulate only state CHANGES, not confirmations.
//!
//! Process-global by design — the state must survive across the many
//! short-lived tasks/connections that share the same logical target
//! (e.g. "this monitor's V9 wire", "this originator id").

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

/// Result of recording a new observation for a key: `None` means the
/// observation matches the last-recorded state for that key (steady
/// state — nothing worth logging); `Some` means the boolean flipped
/// since the last observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transition {
    /// The key moved from failing (or previously unseen) to healthy.
    Recovered,
    /// The key moved from healthy (or previously unseen) to failing.
    Failed,
}

fn state_map() -> &'static Mutex<HashMap<String, bool>> {
    static STATE: OnceLock<Mutex<HashMap<String, bool>>> = OnceLock::new();
    STATE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Record the current health (`now_ok`) of `key` and report whether this
/// observation is a state change worth logging.
///
/// The first observation for a given `key` always reports a transition —
/// there is no prior state to compare against, so the first known state
/// IS the news (a first success reports `Recovered`, a first failure
/// reports `Failed`). Every subsequent observation with the same boolean
/// as the last one returns `None`; a flip returns `Some(Transition)`.
///
/// Callers own the key namespace — prefix keys per logical channel
/// (e.g. `"register:{monitor_url}"` vs `"posture:{monitor_url}"`) when
/// the same target is tracked along more than one independent axis.
pub fn log_on_change(key: &str, now_ok: bool) -> Option<Transition> {
    let mut map = state_map()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let changed = match map.insert(key.to_string(), now_ok) {
        None => true,
        Some(prev_ok) => prev_ok != now_ok,
    };
    if !changed {
        return None;
    }
    Some(if now_ok {
        Transition::Recovered
    } else {
        Transition::Failed
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_observation_always_transitions() {
        let key = "test:first-ok";
        assert_eq!(log_on_change(key, true), Some(Transition::Recovered));
        let key = "test:first-fail";
        assert_eq!(log_on_change(key, false), Some(Transition::Failed));
    }

    #[test]
    fn steady_state_is_silent() {
        let key = "test:steady";
        assert_eq!(log_on_change(key, true), Some(Transition::Recovered));
        assert_eq!(log_on_change(key, true), None);
        assert_eq!(log_on_change(key, true), None);
    }

    #[test]
    fn flip_reports_transition_both_ways() {
        let key = "test:flip";
        assert_eq!(log_on_change(key, true), Some(Transition::Recovered));
        assert_eq!(log_on_change(key, false), Some(Transition::Failed));
        assert_eq!(log_on_change(key, false), None);
        assert_eq!(log_on_change(key, true), Some(Transition::Recovered));
    }
}
