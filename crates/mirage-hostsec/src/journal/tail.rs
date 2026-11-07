//! Subprocess transport: tail sshd's systemd journal for auth events.
//!
//! Spawns exactly ONE `journalctl --follow --unit=sshd.service --since=-1min
//! -o cat` process per secd instance and fans its parsed output out to two
//! typed consumers — see [`spawn_sshd_auth_tail`].
//!
//! **Fleet finding (2026-09-23)**: before this module existed in this shape,
//! `mirage-secd::banengine` spawned a SECOND, independent `journalctl
//! --follow --unit=sshd.service` process of its own (for success events),
//! identical to this one. Every box in the fleet ran two of these children
//! under one secd pid. [`super::parse::parse_auth_failure`] and
//! [`super::parse::parse_auth_success`] are mutually exclusive per line (a
//! `Failed ...` line never also matches `Accepted ...`), so the duplication
//! never double-counted a ban-relevant event toward the ban thresholds — it
//! only doubled the process count and the journal read volume. This module
//! is now the single source; `banengine` subscribes to it via the `fail_tx`/
//! `success_tx` channels below instead of spawning its own second
//! `journalctl`.
//!
//! If `journalctl` exits (crash, journald restart, unit rename) the follower
//! respawns it after a fixed backoff rather than leaving the ban engine
//! silently blind. On Linux the child is spawned with
//! `PR_SET_PDEATHSIG=SIGKILL` (see `linux::spawn_journalctl`), so even a hard
//! `SIGKILL` of secd itself — which skips [`JournalHandle`]'s `Drop` entirely
//! — cannot leave an orphaned `journalctl` running: the kernel kills it the
//! instant its parent thread's process exits.
//!
//! `--since=-1min` prevents replaying the entire journal history on daemon
//! start — only the last minute of log lines are replayed, then new entries
//! arrive as they're appended. `-o cat` emits only the raw MESSAGE field,
//! giving the parser a clean input without timestamp/hostname prefixes.
//!
//! **Unit name note**: Ubuntu (22.04+) names the unit `sshd.service`.
//! Older Debian and some distros use `ssh.service`. We follow the fleet's
//! fail2ban `_SYSTEMD_UNIT=sshd.service` match and use `sshd.service`.
//! If a deployment uses `ssh.service`, add `--unit=ssh.service` to the
//! `journalctl` args or adjust the invocation.
//!
//! # Testability
//!
//! The fan-out/respawn engine below (`LineSource`, `KillSwitch`,
//! `run_follower_loop`, `spawn_follower`, `dual_dispatch`) is
//! platform-independent and gated `#[cfg(any(target_os = "linux", test))]` —
//! it compiles and its tests run on every target via a fake, in-memory
//! [`LineSource`], never a real `journalctl`. Only the actual subprocess
//! transport (`linux::spawn_journalctl`) is Linux-only and untested from
//! non-Linux hosts.

use super::JournalError;

#[cfg(any(target_os = "linux", test))]
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(any(target_os = "linux", test))]
use std::sync::{Arc, Mutex};
#[cfg(any(target_os = "linux", test))]
use std::thread::{self, JoinHandle};
#[cfg(any(target_os = "linux", test))]
use std::time::Duration;

// ── Kill/reap handle for the source currently being read ────────────────────

/// Shareable, non-blocking "stop this spawn attempt" handle. Cloned into
/// [`JournalHandle`] so `Drop`/[`JournalHandle::stop`] can interrupt a
/// blocking [`LineSource::next_line`] running on another thread without ever
/// contending with the read itself — the read side never shares a lock with
/// this.
#[cfg(any(target_os = "linux", test))]
trait KillSwitch: Send + Sync {
    /// Must return promptly. Runs on the caller's thread (e.g. `Drop`), never
    /// on the reader thread — it must not itself wait for the transport to
    /// finish exiting (see the real impl's separate reap-on-`Drop`).
    fn kill(&self);
}

// ── Public handle type ───────────────────────────────────────────────────────

/// Handle returned by [`spawn_sshd_auth_tail`].
///
/// Stops respawning, kills the current `journalctl` subprocess, and joins
/// the follower thread on drop, or explicitly via [`JournalHandle::stop`].
pub struct JournalHandle {
    #[cfg(any(target_os = "linux", test))]
    stop: Arc<AtomicBool>,
    #[cfg(any(target_os = "linux", test))]
    current_kill: Arc<Mutex<Option<Arc<dyn KillSwitch>>>>,
    #[cfg(any(target_os = "linux", test))]
    thread: Option<JoinHandle<()>>,
}

impl Drop for JournalHandle {
    fn drop(&mut self) {
        #[cfg(any(target_os = "linux", test))]
        {
            self.stop.store(true, Ordering::SeqCst);
            if let Some(switch) = take_kill_switch(&self.current_kill) {
                switch.kill();
            }
            if let Some(thread) = self.thread.take() {
                let _ = thread.join();
            }
        }
    }
}

impl JournalHandle {
    /// Explicit clean shutdown: stop respawning, kill the subprocess, and
    /// join the thread.
    ///
    /// Equivalent to dropping the handle, but makes intent explicit.
    pub fn stop(self) {
        // Drop runs the shutdown logic via the Drop impl above.
        drop(self);
    }
}

/// Atomically remove whatever kill switch is currently published, releasing
/// the lock BEFORE the caller drops the returned value. The real transport's
/// kill switch reaps its child process in its own `Drop`, which can block
/// briefly (`waitpid`) — that must never happen while this lock is held,
/// since both [`JournalHandle::drop`] and the follower loop itself take it
/// to install/clear the current attempt.
#[cfg(any(target_os = "linux", test))]
fn take_kill_switch(
    current_kill: &Mutex<Option<Arc<dyn KillSwitch>>>,
) -> Option<Arc<dyn KillSwitch>> {
    match current_kill.lock() {
        Ok(mut guard) => guard.take(),
        Err(_) => None,
    }
}

// ── Follower engine (platform-independent, unit-tested on every target) ─────

/// Exclusive read side of one spawn attempt's line stream. Owned solely by
/// the follower's reader thread — never shared — so a blocking read here can
/// never deadlock against [`KillSwitch::kill`] running on another thread.
#[cfg(any(target_os = "linux", test))]
trait LineSource: Send {
    /// Blocks until the next line is available, returns `None` once the
    /// source is exhausted (the underlying process exited), or an I/O error
    /// if the transport itself failed.
    fn next_line(&mut self) -> Option<std::io::Result<String>>;
}

/// Build the dispatch closure [`spawn_follower`] calls per line: parse it as
/// both event kinds (mutually exclusive in practice — see this module's
/// doc) and forward whichever matches to its typed channel. A closed
/// receiver is not an error here; the corresponding forwarder has simply
/// shut down.
#[cfg(any(target_os = "linux", test))]
fn dual_dispatch(
    fail_tx: std::sync::mpsc::Sender<super::parse::AuthFailure>,
    success_tx: std::sync::mpsc::Sender<super::parse::AuthSuccess>,
) -> impl Fn(&str) + Send + 'static {
    move |line: &str| {
        if let Some(f) = super::parse::parse_auth_failure(line) {
            let _ = fail_tx.send(f);
        }
        if let Some(s) = super::parse::parse_auth_success(line) {
            let _ = success_tx.send(s);
        }
    }
}

/// Sleep up to `total`, waking early the moment `stop` flips — so shutdown
/// doesn't have to wait out a full backoff window before the reader thread
/// notices it.
#[cfg(any(target_os = "linux", test))]
fn sleep_respecting_stop(total: Duration, stop: &AtomicBool) {
    const TICK: Duration = Duration::from_millis(10);
    let mut remaining = total;
    while remaining > Duration::ZERO {
        if stop.load(Ordering::SeqCst) {
            return;
        }
        let step = remaining.min(TICK);
        thread::sleep(step);
        remaining = remaining.saturating_sub(step);
    }
}

/// The follower's own loop: spawn a source, read it to exhaustion dispatching
/// every line, then — unless told to stop — back off and respawn.
#[cfg(any(target_os = "linux", test))]
fn run_follower_loop<S, F, D>(
    mut spawn_source: F,
    dispatch: D,
    current_kill: Arc<Mutex<Option<Arc<dyn KillSwitch>>>>,
    stop: Arc<AtomicBool>,
    backoff: Duration,
) where
    S: LineSource,
    F: FnMut() -> Result<(S, Arc<dyn KillSwitch>), JournalError>,
    D: Fn(&str),
{
    while !stop.load(Ordering::SeqCst) {
        let (mut source, kill_switch) = match spawn_source() {
            Ok(pair) => pair,
            Err(_) => {
                sleep_respecting_stop(backoff, &stop);
                continue;
            }
        };

        if let Ok(mut guard) = current_kill.lock() {
            *guard = Some(kill_switch);
        }

        // `stop()` may have fired between the spawn above and here — kill
        // this attempt immediately rather than reading from it at all.
        if stop.load(Ordering::SeqCst) {
            if let Some(switch) = take_kill_switch(&current_kill) {
                switch.kill();
            }
            break;
        }

        loop {
            match source.next_line() {
                Some(Ok(line)) => dispatch(&line),
                Some(Err(_)) | None => break,
            }
        }

        // The source is exhausted (process exited) — clear it so a
        // concurrent `stop()` doesn't try to kill an already-dead handle,
        // and drop it (outside the lock above) so the real transport can
        // reap without holding `current_kill` while it does.
        drop(take_kill_switch(&current_kill));

        if stop.load(Ordering::SeqCst) {
            break;
        }
        sleep_respecting_stop(backoff, &stop);
    }
}

/// Spawn the follower thread: repeatedly call `spawn_source` to obtain one
/// transport attempt at a time, dispatch every line it yields, and back off
/// for `backoff` between attempts (whether the spawn failed or the previous
/// attempt merely ran out).
#[cfg(any(target_os = "linux", test))]
fn spawn_follower<S, F, D>(
    spawn_source: F,
    dispatch: D,
    backoff: Duration,
) -> Result<JournalHandle, JournalError>
where
    S: LineSource + 'static,
    F: FnMut() -> Result<(S, Arc<dyn KillSwitch>), JournalError> + Send + 'static,
    D: Fn(&str) + Send + 'static,
{
    let stop = Arc::new(AtomicBool::new(false));
    let current_kill: Arc<Mutex<Option<Arc<dyn KillSwitch>>>> = Arc::new(Mutex::new(None));

    let stop_bg = Arc::clone(&stop);
    let current_kill_bg = Arc::clone(&current_kill);

    let thread = thread::Builder::new()
        .name("journal-tail".into())
        .spawn(move || {
            run_follower_loop(spawn_source, dispatch, current_kill_bg, stop_bg, backoff);
        })
        .map_err(JournalError::Spawn)?;

    Ok(JournalHandle {
        stop,
        current_kill,
        thread: Some(thread),
    })
}

// ── Linux-only subprocess transport ──────────────────────────────────────────

#[cfg(target_os = "linux")]
mod linux {
    use std::io::{BufRead, BufReader, Lines};
    use std::os::unix::process::CommandExt;
    use std::process::{Child, ChildStdout, Command, Stdio};
    use std::sync::{Arc, Mutex};

    use super::{JournalError, KillSwitch, LineSource};

    /// The real `journalctl --follow` transport — owned exclusively by the
    /// follower's reader thread (see `super::run_follower_loop`), never
    /// shared, so a blocking read here can never contend with
    /// [`ChildKillSwitch::kill`] running on another thread.
    pub(super) struct JournalLineSource {
        lines: Lines<BufReader<ChildStdout>>,
    }

    impl LineSource for JournalLineSource {
        fn next_line(&mut self) -> Option<std::io::Result<String>> {
            self.lines.next()
        }
    }

    /// Shareable kill/reap handle for one spawn attempt's `journalctl`
    /// child. `kill()` only signals — it must never block. Reaping happens
    /// in `Drop`, once this is the last reference (the follower loop clears
    /// its copy from `current_kill` right after the read loop ends): by then
    /// the process is either already gone or has just been signalled to go,
    /// so `wait()` returns promptly.
    struct ChildKillSwitch {
        child: Mutex<Child>,
    }

    impl KillSwitch for ChildKillSwitch {
        fn kill(&self) {
            if let Ok(mut child) = self.child.lock() {
                let _ = child.kill();
            }
        }
    }

    impl Drop for ChildKillSwitch {
        fn drop(&mut self) {
            if let Ok(mut child) = self.child.lock() {
                let _ = child.wait();
            }
        }
    }

    /// Spawn one `journalctl --follow --unit=sshd.service` attempt.
    ///
    /// `PR_SET_PDEATHSIG=SIGKILL` is set in the child between `fork()` and
    /// `exec()` — this is the actual orphan guard. If secd is `SIGKILL`ed
    /// (or crashes) before [`super::JournalHandle`]'s `Drop` ever runs, the
    /// kernel kills this child anyway the instant its parent thread's
    /// process exits — independent of any Rust cleanup path. `kill_on_drop`
    /// (as used elsewhere in this workspace for `tokio::process::Command`)
    /// only covers the graceful-shutdown path; `PDEATHSIG` covers the crash
    /// path too, which is the one that actually produces an orphaned
    /// `journalctl`.
    pub(super) fn spawn_journalctl(
    ) -> Result<(JournalLineSource, Arc<dyn KillSwitch>), JournalError> {
        let mut cmd = Command::new("journalctl");
        cmd.args([
            "--follow",
            "--unit=sshd.service",
            "--since=-1min",
            "-o",
            "cat",
        ])
        .stdout(Stdio::piped())
        // Discard stderr so journal informational messages don't clutter logs.
        .stderr(Stdio::null());

        // SAFETY: `pre_exec` runs in the forked child strictly between
        // `fork()` and `exec()` — only async-signal-safe calls are allowed
        // there. `prctl(PR_SET_PDEATHSIG, SIGKILL)` is a single, well-defined
        // syscall: no allocation, no locks, async-signal-safe.
        unsafe {
            cmd.pre_exec(|| {
                // SAFETY: see the enclosing `unsafe` block's comment.
                let rc = unsafe {
                    libc::prctl(
                        libc::PR_SET_PDEATHSIG,
                        libc::SIGKILL as u64,
                        0_u64,
                        0_u64,
                        0_u64,
                    )
                };
                if rc != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }

        let mut child = cmd.spawn().map_err(JournalError::Spawn)?;

        // Take stdout before handing `child` to the kill switch.
        // SAFETY: stdout is `Stdio::piped()` above; `.take()` on a freshly
        // spawned child always returns `Some` before the first call.
        let stdout: ChildStdout = child
            .stdout
            .take()
            .expect("stdout is piped and has not been taken before");

        let source = JournalLineSource {
            lines: BufReader::new(stdout).lines(),
        };
        let kill_switch: Arc<dyn KillSwitch> = Arc::new(ChildKillSwitch {
            child: Mutex::new(child),
        });

        Ok((source, kill_switch))
    }
}

// ── Public spawn function ────────────────────────────────────────────────────

/// Spawn the ONE `journalctl --follow --unit=sshd.service` process for this
/// secd instance and register both typed consumers on it.
///
/// Every recognised auth-failure line is sent to `fail_tx`; every recognised
/// auth-success line is sent to `success_tx` — mutually exclusive per line,
/// so each consumer sees each event exactly once (see this module's doc for
/// the fleet finding that led to this being a single source).
///
/// The returned [`JournalHandle`] kills the current subprocess, stops
/// respawning, and joins the reader thread when dropped or via
/// [`JournalHandle::stop`].
///
/// # Errors
///
/// Returns [`JournalError::Spawn`] if the follower thread itself cannot be
/// started (an OS-level thread-spawn failure — `journalctl` spawn failures
/// are handled internally by the respawn/backoff loop, not surfaced here).
#[cfg(target_os = "linux")]
pub fn spawn_sshd_auth_tail(
    fail_tx: std::sync::mpsc::Sender<super::parse::AuthFailure>,
    success_tx: std::sync::mpsc::Sender<super::parse::AuthSuccess>,
) -> Result<JournalHandle, JournalError> {
    let dispatch = dual_dispatch(fail_tx, success_tx);
    // journalctl exiting and respawning in a hot loop would just thrash
    // journald/the fork-exec path for no benefit — 2s is enough headroom to
    // matter without meaningfully delaying real recovery.
    spawn_follower(linux::spawn_journalctl, dispatch, Duration::from_secs(2))
}

/// Non-Linux stub — always returns [`JournalError::PlatformUnsupported`];
/// never spawns a subprocess or a thread.
#[cfg(not(target_os = "linux"))]
pub fn spawn_sshd_auth_tail(
    _fail_tx: std::sync::mpsc::Sender<super::parse::AuthFailure>,
    _success_tx: std::sync::mpsc::Sender<super::parse::AuthSuccess>,
) -> Result<JournalHandle, JournalError> {
    Err(JournalError::PlatformUnsupported)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::atomic::AtomicU32;
    use std::sync::mpsc;
    use std::time::Instant;

    /// A canned reader that mimics one `journalctl --follow` run: replays a
    /// fixed queue of lines, then either ends (`None`) — a process that
    /// exited — or blocks until [`FakeKillSwitch::kill`] flips its shared
    /// flag — a process still running when the follower is torn down.
    struct FakeLineSource {
        lines: VecDeque<String>,
        killed: Arc<AtomicBool>,
        block_when_drained: bool,
    }

    impl LineSource for FakeLineSource {
        fn next_line(&mut self) -> Option<std::io::Result<String>> {
            if let Some(line) = self.lines.pop_front() {
                return Some(Ok(line));
            }
            if !self.block_when_drained {
                return None;
            }
            while !self.killed.load(Ordering::SeqCst) {
                thread::sleep(Duration::from_millis(2));
            }
            None
        }
    }

    struct FakeKillSwitch {
        killed: Arc<AtomicBool>,
    }

    impl KillSwitch for FakeKillSwitch {
        fn kill(&self) {
            self.killed.store(true, Ordering::SeqCst);
        }
    }

    /// One fake "spawn attempt": lines to replay, then either EOF or block.
    fn fake_session(lines: Vec<&str>, block_when_drained: bool) -> (FakeLineSource, Arc<dyn KillSwitch>) {
        let killed = Arc::new(AtomicBool::new(false));
        let source = FakeLineSource {
            lines: lines.into_iter().map(str::to_owned).collect(),
            killed: Arc::clone(&killed),
            block_when_drained,
        };
        let switch: Arc<dyn KillSwitch> = Arc::new(FakeKillSwitch { killed });
        (source, switch)
    }

    /// Drain `rx` until `expected` items arrive or `timeout` elapses.
    fn collect_within<T>(rx: &mpsc::Receiver<T>, expected: usize, timeout: Duration) -> Vec<T> {
        let deadline = Instant::now() + timeout;
        let mut out = Vec::new();
        while out.len() < expected {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }
            match rx.recv_timeout(remaining) {
                Ok(item) => out.push(item),
                Err(_) => break,
            }
        }
        out
    }

    #[test]
    fn two_consumers_each_receive_every_relevant_line_exactly_once() {
        // The exact shapes `parse.rs`'s own tests already prove parse
        // correctly — this test is about DELIVERY (fan-out from one source
        // to two typed channels), not parsing.
        let lines = vec![
            "Failed password for root from 192.0.2.5 port 51122 ssh2",
            "Accepted publickey for deploy from 203.0.113.10 port 54321 ssh2: ED25519 SHA256:abc",
            "totally random syslog garbage here",
            "Failed password for invalid user admin from 203.0.113.9 port 4 ssh2",
            "Accepted password for alice from 198.51.100.7 port 1024 ssh2",
        ];

        let (fail_tx, fail_rx) = mpsc::channel();
        let (succ_tx, succ_rx) = mpsc::channel();
        let dispatch = dual_dispatch(fail_tx, succ_tx);

        let mut session = Some(fake_session(lines, false));
        let spawn_source = move || match session.take() {
            Some(s) => Ok(s),
            None => Err(JournalError::PlatformUnsupported),
        };

        let handle = spawn_follower(spawn_source, dispatch, Duration::from_millis(5))
            .expect("test follower spawn must not fail");

        let failures = collect_within(&fail_rx, 2, Duration::from_secs(2));
        let successes = collect_within(&succ_rx, 2, Duration::from_secs(2));

        assert_eq!(failures.len(), 2, "both failure lines must arrive exactly once each");
        assert_eq!(successes.len(), 2, "both success lines must arrive exactly once each");
        assert!(
            fail_rx.recv_timeout(Duration::from_millis(100)).is_err(),
            "no extra/duplicate failure events"
        );
        assert!(
            succ_rx.recv_timeout(Duration::from_millis(100)).is_err(),
            "no extra/duplicate success events"
        );

        handle.stop();
    }

    #[test]
    fn follower_exit_triggers_exactly_one_respawn_after_backoff() {
        let spawn_count = Arc::new(AtomicU32::new(0));
        let spawn_count_bg = Arc::clone(&spawn_count);
        let backoff = Duration::from_millis(15);

        let spawn_source = move || {
            let n = spawn_count_bg.fetch_add(1, Ordering::SeqCst);
            if n == 0 {
                // First attempt: the process exits immediately (EOF), like
                // the fleet's crash-looping journalctl.
                Ok(fake_session(Vec::new(), false))
            } else {
                // Every attempt after: stays "running" until killed, so no
                // THIRD spawn can happen before the test observes and stops.
                Ok(fake_session(Vec::new(), true))
            }
        };

        let (fail_tx, _fail_rx) = mpsc::channel();
        let (succ_tx, _succ_rx) = mpsc::channel();
        let dispatch = dual_dispatch(fail_tx, succ_tx);

        let handle = spawn_follower(spawn_source, dispatch, backoff)
            .expect("test follower spawn must not fail");

        // spawn #1 -> EOF -> backoff -> spawn #2 -> blocks. Generous margin
        // over the 15ms backoff to stay non-flaky.
        thread::sleep(backoff * 10);
        assert_eq!(
            spawn_count.load(Ordering::SeqCst),
            2,
            "exactly one respawn after the backoff"
        );

        handle.stop(); // kills the blocked #2 session
        thread::sleep(backoff * 10);
        assert_eq!(
            spawn_count.load(Ordering::SeqCst),
            2,
            "stop() must not trigger another respawn"
        );
    }
}
