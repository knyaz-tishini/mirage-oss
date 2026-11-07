//! `nft` — minimal pure-Rust nftables controller via raw netlink.
//!
//! # Architecture
//!
//! Split for testability:
//! - [`wire`] — pure byte serializers (compiles + tests everywhere, no socket).
//! - [`ops`]  — pure message constructors that call `wire` (no socket).
//! - [`sock`] — `#[cfg(target_os="linux")]` netlink socket transport.
//!
//! The public API ([`Nft`]) is `#[cfg(target_os="linux")]`; on other targets
//! every method returns `Err(NftError::PlatformUnsupported)` so Windows
//! `cargo check` / `cargo test` pass cleanly.

pub mod ops;
pub mod surface;
pub mod wire;

pub use surface::{surface_ruleset, BOOT_LOCKDOWN_PORTS, SURFACE_TABLE};

#[cfg(target_os = "linux")]
mod sock;

use std::net::IpAddr;
use thiserror::Error;

/// Errors from the nft subsystem.
#[derive(Debug, Error)]
pub enum NftError {
    /// The current OS is not Linux — netlink is unavailable.
    #[error("nft: linux only")]
    PlatformUnsupported,

    /// A `libc` socket syscall failed with the given errno.
    #[error("nft: socket syscall failed (errno={0})")]
    Syscall(i32),

    /// The kernel returned a netlink error with the given errno.
    #[error("nft: netlink error (errno={0})")]
    Netlink(i32),

    /// One message inside a batch was rejected, and the whole transaction
    /// was therefore rolled back.
    ///
    /// The index is the point of the error: nftables commits a batch
    /// atomically, so "the table was not created" and "rule 7 was malformed"
    /// look identical from the outside unless the position is reported. It
    /// is 1-based over the inner messages, excluding the batch envelope.
    #[error("nft: batch message {index}/{total} rejected (errno={errno})")]
    BatchRejected {
        index: usize,
        total: usize,
        errno: i32,
    },

    /// The ACK reply buffer was malformed or truncated.
    #[error("nft: malformed ACK reply: {0}")]
    BadReply(String),
}

/// Per-element timeout that means "this ban does not expire".
///
/// The top rung of the escalation ladder: an address that keeps coming back
/// after the windowed and long bans have already run their course stops
/// getting a clock at all. Only `unban` (or a reboot, since nftables state is
/// not persisted) clears it — which is exactly why the operator needs a way
/// to list and lift, and why that lever ships with the ladder rather than
/// after it.
pub const PERMANENT_BAN_MS: u64 = 0;

/// High-level nftables controller.
///
/// All methods are idempotent (use `NLM_F_CREATE` without `NLM_F_EXCL`).
/// On non-Linux targets every method returns [`NftError::PlatformUnsupported`].
pub struct Nft;

impl Nft {
    /// Idempotent: create the `inet mirage_ban` table, the `input` base chain
    /// (policy ACCEPT, priority ahead of the surface table), the banned +
    /// trusted sets with per-element timeout, and the four rules that make a
    /// ban a ban — trusted accept, then banned drop.
    ///
    /// Takes no port list on purpose. The box's admitted port set lives in
    /// `inet mirage_surface`, which `mirage-secd` derives continuously from
    /// the perimeter's own live face list (`mirage-secd::
    /// perimeter_admission`); this table decides only WHO, never WHAT. See
    /// [`ops`]'s `TABLE_NAME` doc for what that separation cost when it was
    /// not observed.
    #[cfg(target_os = "linux")]
    pub fn ensure_ban_policy() -> Result<(), NftError> {
        // Flush the chain's rules FIRST, in its own best-effort transaction.
        // `NEWRULE` appends, so without this every restart stacks another
        // four rules behind whatever is already there — including, on a box
        // that ran an older build, a stale pair in the wrong order that
        // would keep deciding ahead of the correct one.
        //
        // Its own transaction because the chain may not exist yet on a first
        // run, and a `DELRULE` against a missing table is an error that
        // would abort the batch that was about to create it.
        //
        // Rules only. The sets — and therefore every live ban and every
        // trusted fleet address — survive untouched.
        // NOT swallowed: a flush that quietly fails leaves the previous
        // rule set in front of the one about to be written, which is the
        // exact failure this call exists to prevent. `ENOENT` on a first run
        // is the one expected outcome and says so.
        match sock::send_batch(&[ops::build_flush_chain()]) {
            Ok(()) => tracing::debug!("[nft] ban chain flushed before re-apply"),
            Err(NftError::Netlink(2)) => {
                tracing::debug!("[nft] no ban chain to flush yet (first run)");
            }
            Err(e) => tracing::warn!(
                error = %e,
                "[nft] ban chain flush FAILED — the previous rules are still in front"
            ),
        }

        let msgs = ops::build_ban_policy();
        sock::send_batch(&msgs)
    }

    #[cfg(not(target_os = "linux"))]
    pub fn ensure_ban_policy() -> Result<(), NftError> {
        Err(NftError::PlatformUnsupported)
    }

    /// axis E — default-deny egress + allowlist (secd master plan §8).
    ///
    /// Flush-then-rebuild: the SEPARATE `fw_egress` table is deleted (best
    /// effort — a missing-table error on first-ever call is swallowed, not
    /// propagated) then fully recreated with the current `allow_ips` set.
    /// This is the correct idempotent shape for a ruleset that is fully
    /// re-derived from live state (mesh topology + monitor + DNS/NTP) on
    /// every `policy_engine` tick, rather than incrementally diffed.
    #[cfg(target_os = "linux")]
    pub fn ensure_egress_policy(allow_ips: &[IpAddr]) -> Result<(), NftError> {
        // Best-effort flush: ignore any error (table may not exist yet on
        // the very first call — that is success, not failure, for an
        // idempotent "ensure" operation).
        let _ = sock::send_batch(&[ops::build_del_egress_table()]);

        let msgs = ops::build_egress_policy(allow_ips);
        sock::send_batch(&msgs)
    }

    #[cfg(not(target_os = "linux"))]
    pub fn ensure_egress_policy(_allow_ips: &[IpAddr]) -> Result<(), NftError> {
        Err(NftError::PlatformUnsupported)
    }

    /// Add `ip` to the appropriate `mirage_banned` set with `timeout_ms`.
    /// Re-banning an already-banned IP silently refreshes the timeout
    /// (kernel behaviour: `NLM_F_CREATE` without `NLM_F_EXCL`).
    ///
    /// `timeout_ms == 0` is [`PERMANENT_BAN_MS`] — an explicit per-element
    /// timeout of zero means "never expires" to the kernel. That is NOT the
    /// same as omitting the attribute, which would make the element inherit
    /// the set's own default timeout, so the permanent tier has to pass the
    /// zero through rather than leave the field off.
    #[cfg(target_os = "linux")]
    pub fn ban(ip: IpAddr, timeout_ms: u64) -> Result<(), NftError> {
        let msg = ops::build_add_elem(ip, timeout_ms);
        sock::send_batch(&[msg])
    }

    #[cfg(not(target_os = "linux"))]
    pub fn ban(_ip: IpAddr, _timeout_ms: u64) -> Result<(), NftError> {
        Err(NftError::PlatformUnsupported)
    }

    /// Remove `ip` from the `mirage_banned` set immediately.
    #[cfg(target_os = "linux")]
    pub fn unban(ip: IpAddr) -> Result<(), NftError> {
        let msg = ops::build_del_elem(ip);
        sock::send_batch(&[msg])
    }

    #[cfg(not(target_os = "linux"))]
    pub fn unban(_ip: IpAddr) -> Result<(), NftError> {
        Err(NftError::PlatformUnsupported)
    }

    /// Add `ip` to the `mirage_trusted` set with `timeout_ms`.
    ///
    /// A trusted IP is accepted before the banned-set lookup and before the
    /// SSH dynset rate-meter, so a cryptographic friend can never be auto-banned.
    /// Call this on every successful V9 wire handshake or opbox auth; entries
    /// are refreshed on each call and GC out after `timeout_ms` of silence.
    #[cfg(target_os = "linux")]
    pub fn trust(ip: IpAddr, timeout_ms: u64) -> Result<(), NftError> {
        let msg = ops::build_add_trusted_elem(ip, timeout_ms);
        sock::send_batch(&[msg])
    }

    #[cfg(not(target_os = "linux"))]
    pub fn trust(_ip: IpAddr, _timeout_ms: u64) -> Result<(), NftError> {
        Err(NftError::PlatformUnsupported)
    }

    /// Remove `ip` from the `mirage_trusted` set immediately.
    #[cfg(target_os = "linux")]
    pub fn untrust(ip: IpAddr) -> Result<(), NftError> {
        let msg = ops::build_del_trusted_elem(ip);
        sock::send_batch(&[msg])
    }

    #[cfg(not(target_os = "linux"))]
    pub fn untrust(_ip: IpAddr) -> Result<(), NftError> {
        Err(NftError::PlatformUnsupported)
    }
}
