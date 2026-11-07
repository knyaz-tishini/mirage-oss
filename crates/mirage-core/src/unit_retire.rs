//! The structured answer to
//! [`crate::operator_cmd::OperatorCmdKind::RetireUnit`].
//!
//! Lives in `mirage-core` for the same reason [`crate::unit_state`] does: the
//! warden produces it, but the caller that reads it (opbox, on the Windows dev
//! box, which cannot depend on the Linux-only `mirage-warden`) needs the exact
//! type to decode it.
//!
//! # Wire shape
//!
//! The command channel answers with one string
//! ([`crate::operator_cmd::OperatorCommandResponse::message`]). For
//! `RetireUnit` that string is `"ok: <json>"` when
//! [`RetireReport::succeeded`] and `"error: <json>"` otherwise, where `<json>`
//! is a serialised [`RetireReport`]. A caller strips the prefix and decodes the
//! rest; a refusal or a failure is therefore as structured as a success, never
//! a bare sentence.
//!
//! # What "retired" means
//!
//! The unit file is out of the systemd load path (so the warden's supervision
//! loop, which is keyed on that file existing, no longer considers the unit),
//! nothing of the unit is running, and the unit is disabled. The file is
//! archived rather than deleted, so a retire can be undone by hand.

use serde::{Deserialize, Serialize};

/// One step of the retire sequence, named in the order the warden runs them.
/// A step may appear more than once in [`RetireReport::steps`] (the wait for
/// the unit to disappear is repeated after the SIGKILL fallback).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RetireStep {
    /// Read-only: is the unit file present, is anything of the unit running,
    /// does a copy of the file also sit in a directory this command does not
    /// empty. Nothing has changed on the box while this is the only step.
    Inspect,
    /// Move the unit file (and its `.d` drop-in directory) out of the systemd
    /// load path into the retired archive.
    ArchiveUnitFile,
    /// Open the Tier2 kill-allow-window for the unit's cgroup.
    OpenWindow,
    /// `systemctl stop`.
    Stop,
    /// Wait, bounded, for the unit's main pid and its whole cgroup to be gone.
    WaitGone,
    /// SIGKILL whatever the cgroup still holds after the first wait ran out.
    KillLeftovers,
    /// Re-resolve the protected-cgroup table.
    Rearm,
    /// Close the Tier2 allow-window.
    CloseWindow,
    /// `systemctl disable`.
    Disable,
    /// `systemctl reset-failed`.
    ResetFailed,
    /// `systemctl daemon-reload`.
    DaemonReload,
}

impl RetireStep {
    /// The snake_case name this step carries on the wire.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Inspect => "inspect",
            Self::ArchiveUnitFile => "archive_unit_file",
            Self::OpenWindow => "open_window",
            Self::Stop => "stop",
            Self::WaitGone => "wait_gone",
            Self::KillLeftovers => "kill_leftovers",
            Self::Rearm => "rearm",
            Self::CloseWindow => "close_window",
            Self::Disable => "disable",
            Self::ResetFailed => "reset_failed",
            Self::DaemonReload => "daemon_reload",
        }
    }
}

/// What one step did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StepOutcome {
    /// The step ran and did what it is for.
    Ok,
    /// Nothing to do (the file was already gone, nothing was running).
    Skipped,
    /// The step reported an error but the sequence carried on, because the
    /// end state it serves is decided by a later check (a `systemctl stop`
    /// that errors on a unit that is already gone) or is cosmetic (`disable`
    /// on a unit whose file has just been archived).
    Tolerated,
    /// The step failed and the failure is fatal to the retire.
    Failed,
}

/// One entry of [`RetireReport::steps`], in the order it ran.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StepRecord {
    pub step: RetireStep,
    pub outcome: StepOutcome,
    /// What was observed or what went wrong; empty when there is nothing to add.
    pub detail: String,
}

/// How the whole retire ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RetireStatus {
    /// The unit was running and/or installed; it is now stopped, its file is
    /// archived, and it is disabled.
    Retired,
    /// Nothing to do: the unit file is not in the load path and nothing of the
    /// unit is running. No state was changed.
    AlreadyRetired,
    /// The unit is not on the warden's `RETIRABLE_UNITS` allowlist. No state
    /// was read or changed.
    Refused,
    /// The sequence stopped at [`RetireReport::failed_at`].
    Failed,
}

/// The warden's structured answer to a `RetireUnit` command.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetireReport {
    pub unit: String,
    pub status: RetireStatus,
    /// The first fatal step; `Some` exactly when `status` is
    /// [`RetireStatus::Failed`]. The sequence stops at it, except for the
    /// cleanup that must always run once the allow-window is open (rearm,
    /// close the window) and, after a failure to close the window, the
    /// disable/reload tail — [`Self::steps`] shows everything that ran.
    pub failed_at: Option<RetireStep>,
    /// Why the command was refused, or the one-line summary of a failure.
    pub reason: Option<String>,
    /// Every step that ran, in order, with what it observed.
    pub steps: Vec<StepRecord>,
    /// Where the unit file went (`/var/lib/mirage/retired/<unit>.<unix_ms>`),
    /// set as soon as the archive step succeeded — including on a later
    /// failure, so the operator can put the file back.
    pub archived_unit_file: Option<String>,
    /// Where the unit's `.d` drop-in directory went, if it had one.
    pub archived_drop_in_dir: Option<String>,
    /// Facts the caller should act on that are not step outcomes.
    pub notes: Vec<String>,
}

impl RetireReport {
    /// A report for a command refused before anything was read or changed.
    #[must_use]
    pub fn refused(unit: &str, reason: impl Into<String>) -> Self {
        Self {
            unit: unit.to_string(),
            status: RetireStatus::Refused,
            failed_at: None,
            reason: Some(reason.into()),
            steps: Vec::new(),
            archived_unit_file: None,
            archived_drop_in_dir: None,
            notes: Vec::new(),
        }
    }

    /// A report for a sequence that could not even start (a platform that has
    /// no `systemctl`); recorded as a failure of [`RetireStep::Inspect`].
    #[must_use]
    pub fn failed_at_inspect(unit: &str, detail: impl Into<String>) -> Self {
        let detail = detail.into();
        Self {
            unit: unit.to_string(),
            status: RetireStatus::Failed,
            failed_at: Some(RetireStep::Inspect),
            reason: Some(format!("failed at inspect: {detail}")),
            steps: vec![StepRecord {
                step: RetireStep::Inspect,
                outcome: StepOutcome::Failed,
                detail,
            }],
            archived_unit_file: None,
            archived_drop_in_dir: None,
            notes: Vec::new(),
        }
    }

    /// `true` for [`RetireStatus::Retired`] and [`RetireStatus::AlreadyRetired`]:
    /// the box is in the requested end state.
    #[must_use]
    pub fn succeeded(&self) -> bool {
        matches!(self.status, RetireStatus::Retired | RetireStatus::AlreadyRetired)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn statuses_and_steps_use_the_documented_wire_names() {
        assert_eq!(serde_json::to_string(&RetireStatus::AlreadyRetired).unwrap_or_default(), "\"already_retired\"");
        assert_eq!(serde_json::to_string(&RetireStatus::Retired).unwrap_or_default(), "\"retired\"");
        assert_eq!(serde_json::to_string(&RetireStatus::Refused).unwrap_or_default(), "\"refused\"");
        assert_eq!(serde_json::to_string(&RetireStatus::Failed).unwrap_or_default(), "\"failed\"");
        for step in [
            RetireStep::Inspect,
            RetireStep::ArchiveUnitFile,
            RetireStep::OpenWindow,
            RetireStep::Stop,
            RetireStep::WaitGone,
            RetireStep::KillLeftovers,
            RetireStep::Rearm,
            RetireStep::CloseWindow,
            RetireStep::Disable,
            RetireStep::ResetFailed,
            RetireStep::DaemonReload,
        ] {
            let json = serde_json::to_string(&step).unwrap_or_default();
            assert_eq!(json, format!("\"{}\"", step.as_str()), "as_str must match the serde name");
        }
    }

    #[test]
    fn a_full_report_round_trips_through_json() {
        let report = RetireReport {
            unit: "mirage-node-v2.service".to_string(),
            status: RetireStatus::Failed,
            failed_at: Some(RetireStep::WaitGone),
            reason: Some("failed at wait_gone: 2 processes left".to_string()),
            steps: vec![
                StepRecord { step: RetireStep::Inspect, outcome: StepOutcome::Ok, detail: "installed, running".to_string() },
                StepRecord { step: RetireStep::Stop, outcome: StepOutcome::Tolerated, detail: "timed out".to_string() },
                StepRecord { step: RetireStep::WaitGone, outcome: StepOutcome::Failed, detail: String::new() },
            ],
            archived_unit_file: Some("/var/lib/mirage/retired/mirage-node-v2.service.1700000000000".to_string()),
            archived_drop_in_dir: None,
            notes: vec!["restart the warden to refresh its role set".to_string()],
        };
        let json = serde_json::to_string(&report).unwrap_or_default();
        let back: Result<RetireReport, _> = serde_json::from_str(&json);
        assert_eq!(back.ok(), Some(report));
    }

    #[test]
    fn success_is_retired_or_already_retired_only() {
        let mut r = RetireReport::refused("mirage-secd.service", "not retirable");
        assert!(!r.succeeded());
        r.status = RetireStatus::Failed;
        assert!(!r.succeeded());
        r.status = RetireStatus::Retired;
        assert!(r.succeeded());
        r.status = RetireStatus::AlreadyRetired;
        assert!(r.succeeded());
    }

    #[test]
    fn a_refusal_carries_no_steps_and_no_failed_step() {
        let r = RetireReport::refused("mirage-warden.service", "not on the allowlist");
        assert_eq!(r.status, RetireStatus::Refused);
        assert_eq!(r.failed_at, None);
        assert!(r.steps.is_empty());
        assert_eq!(r.reason.as_deref(), Some("not on the allowlist"));
    }

    #[test]
    fn an_unstartable_sequence_is_a_failure_of_inspect() {
        let r = RetireReport::failed_at_inspect("mirage-node-v2.service", "platform unsupported");
        assert_eq!(r.status, RetireStatus::Failed);
        assert_eq!(r.failed_at, Some(RetireStep::Inspect));
        assert_eq!(r.steps.len(), 1);
        assert_eq!(r.steps[0].outcome, StepOutcome::Failed);
    }
}
