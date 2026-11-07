//! `journal` — sshd auth tail via `journalctl`: ONE follower per process,
//! fanned out to typed failure/success consumers.
//!
//! # Architecture
//!
//! Split for testability, mirroring the `nft` module pattern:
//! - [`parse`] — pure string parser; no `cfg` gate; tests run on every target.
//! - [`tail`] — the follower: a platform-independent fan-out/respawn engine
//!   (`#[cfg(any(target_os="linux", test))]`, unit-tested on every target via
//!   a fake line source — no `journalctl` involved) wired in production to a
//!   `#[cfg(target_os="linux")]` `journalctl --follow` subprocess transport.
//!   Non-Linux (non-test) targets get a stub returning
//!   [`JournalError::PlatformUnsupported`].
//!
//! **Single source**: exactly one `journalctl --follow --unit=sshd.service`
//! process runs per secd instance — see `tail`'s module doc for the fleet
//! finding (two independent tails per process, before 2026-09-23) that made
//! this the rule, not a convention.
//!
//! # Quick start
//!
//! ```ignore
//! let (fail_tx, fail_rx) = std::sync::mpsc::channel();
//! let (success_tx, success_rx) = std::sync::mpsc::channel();
//! let _handle = mirage_hostsec::journal::spawn_sshd_auth_tail(fail_tx, success_tx)?;
//! for failure in fail_rx {
//!     tracing::warn!(ip = %failure.ip, kind = ?failure.kind, "sshd auth failure");
//! }
//! ```

pub mod parse;
pub mod tail;

pub use parse::{AuthFailKind, AuthFailure, AuthSuccess, AuthSuccessKind, parse_auth_success};
pub use tail::{spawn_sshd_auth_tail, JournalHandle};

use thiserror::Error;

/// Errors from the journal subsystem.
#[derive(Debug, Error)]
pub enum JournalError {
    /// `journalctl` could not be spawned (not installed, not on PATH, I/O error).
    #[error("journal: failed to spawn journalctl: {0}")]
    Spawn(#[from] std::io::Error),

    /// The current OS is not Linux — journalctl is unavailable.
    #[error("journal: linux only")]
    PlatformUnsupported,
}
