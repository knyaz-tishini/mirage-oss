//! Every channel that never leaves the box, named once, resolved by
//! compilation target.
//!
//! # The rule this module exists to enforce
//!
//! A channel between two processes on the same kernel is a unix socket. On
//! Windows — where no fleet box runs, and which exists here for the client
//! stack and for `cargo test` on the dev box — it is loopback TCP. The choice
//! is made by `cfg`, never by configuration:
//!
//! ```text
//! #[cfg(unix)]    -> AF_UNIX at a path under /run/mirage
//! #[cfg(windows)] -> TCP on 127.0.0.1
//! ```
//!
//! A RUNTIME switch would create a third state — "Linux, configured for
//! ports" — and that is the state that reaches production the first time
//! somebody debugs something. Two states selected by the target are two
//! states that can both be tested. macOS takes the unix arm: `AF_UNIX` is
//! native there, so the Mac client and the Linux fleet share one code path
//! and only Windows differs.
//!
//! # Why, stated once
//!
//! 1. **The listener table is the box's honest surface.** A loopback port is
//!    still a port: it appears in `ss -lnt`, it is one `bind` typo or one
//!    filter edit away from being public, and the fleet has already booted
//!    with every internal port exposed until an operator ran a command. A
//!    unix socket cannot be reached from the network by any mistake of
//!    configuration — the kernel has no route to it.
//! 2. **`SO_PEERCRED` is an identity the caller cannot forge.** Anything
//!    running on the box may connect to `127.0.0.1:19471` and be treated as
//!    the perimeter, because "came from loopback" is the only check
//!    available there. With a socket the receiver reads the peer's uid from
//!    the kernel. That is the difference between a boundary and a habit.
//! 3. **Filesystem permissions are already this fleet's authorisation
//!    vocabulary.** [`crate::identity_boot::role_dir`] says it outright —
//!    the directory's ownership IS the authentication. Three channels
//!    already work this way; the rest are the exception, not the design.
//!
//! # What this module owns, because both have already cost outages
//!
//! - **Unlink before bind, but only when nothing is listening.** `/run` is
//!   tmpfs so a reboot clears it, but an ordinary restart leaves the socket
//!   file behind and the next `bind` fails `EADDRINUSE`. Blindly removing it
//!   is worse: that silently steals the path from a live process. So
//!   [`LocalEndpoint::bind_with`] CONNECTS first — a refusal means the file
//!   is stale and safe to remove, a success means somebody owns it and the
//!   bind fails honestly.
//! - **Directory mode and group, re-applied at every boot.** A hand-`chown`
//!   is lost on the next restart and re-breaks the channel silently; that
//!   defect cost one box a full day of front-door reporting while its logs
//!   said the peer was allowed. The process that opens the socket applies
//!   the grant, every time, from the same resolution that decides the
//!   allowlist.
//!
//! # Root is always admitted — a deliberate deviation from the plan's table
//!
//! `docs/mirage/plans/local-transport-unix-sockets-2026-08-15.md` writes the
//! splice channels as admitting the perimeter's uid **ONLY**. This module
//! admits root as well, on every channel, and the reason is not laxity:
//!
//! - Root on the box can `setuid` to the perimeter's account, `chown` the
//!   socket, or read the keys directly. Excluding it buys nothing. What
//!   defends against a process that is already root is the warden's Tier2,
//!   not a file mode — see that plan's "Root and non-root" section, which
//!   says so in the same breath.
//! - Excluding it COSTS the operator path in exactly the transitional state
//!   the fleet passes through: a box whose perimeter has not been de-rooted
//!   yet, or a fresh onboard before the account exists, would have its SSH
//!   splice refused by a check that was meant to harden it. A fail-closed
//!   check that closes on the state we are migrating THROUGH is how the
//!   perimeter came up binding nothing on 2026-08-14.
//!
//! So the shape is [`crate::identity_boot`]'s and `mirage-secd`'s: root
//! unconditionally, plus the NAMED accounts ([`LocalChannel::peer_accounts`])
//! that the box's own account database resolves. See [`plan_from_resolutions`].
//!
//! # A channel with two de-rooted callers: two groups on one socket
//!
//! Almost every channel names ONE non-root account, and one account is one
//! group, which the ordinary owner/group/other mode bits express exactly:
//! the socket belongs to that group, `0660`, in a directory that is `0710`.
//! [`LocalChannel::MachineIdentity`] is the exception — the keeper serves
//! every supervised role, and the de-rooted ones each run under their OWN
//! account (`mirage-perimeter`, `mirage-edge`), each with its own primary
//! group and no membership in the other's. A file has one owning group, so
//! the mode bits alone cannot reach both.
//!
//! The rest of the grant is a POSIX ACL: the first resolved account's group
//! owns the directory and socket as before, and every further resolved
//! account's group is added as a NAMED-GROUP entry carrying exactly the same
//! permission (`--x` on the directory, `rw-` on the socket). Nothing else
//! changes: others still keep nothing, the directory is still not listable
//! by the grantees, and `SO_PEERCRED` at accept time is still the decider —
//! the ACL only lets the connect reach `accept`, the allowlist and the
//! per-role check behind it still refuse whoever they refuse.
//!
//! Why this and not the alternatives:
//!
//! - **A shared group both units join** (`SupplementaryGroups=`) needs the
//!   group provisioned on every box and a change to every unit that must
//!   join it — the perimeter's unit included, on boxes that are healthy
//!   today. The grant stops being derived from the account resolution and
//!   becomes a second thing that has to be kept in step with it, which is
//!   the failure this module exists to prevent.
//! - **A socket per account** puts a new path in every client and forces a
//!   client redeploy for a defect that lives in the keeper. This grant is
//!   applied by the keeper alone, so rolling the keeper is the whole fix and
//!   a service already waiting on the old path gets through on its next
//!   retry.
//! - **World bits** hand the socket to every local account.
//!
//! Like the mode and the group, the ACL is re-applied on every bind, and a
//! directory left over from a previous boot has any stale named entries
//! removed FIRST, so an account that no longer resolves cannot keep the
//! access it held. Where the filesystem carries no ACL support the extra
//! grant fails with a loud error and the primary grant — the only one this
//! module ever had — is untouched.
//!
//! # Accept enforces; it does not merely report
//!
//! [`LocalListener::accept`] applies the allowlist itself and returns only
//! admitted connections, together with the [`PeerIdentity`] the kernel
//! supplied. Handing the caller an unchecked stream plus a credential to
//! check would make the refusal something eight call sites can each forget
//! once. The identity still comes back because callers have honest uses for
//! it — logging, and attributing an inward splice to the process that made
//! it — and because it is an ENUM: a caller that wants a uid cannot compile
//! without also handling the platform that has none.

use std::io;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// The shared runtime root. Every box-local socket lives under it.
///
/// This module NEVER changes this directory's mode or ownership — it is
/// shared with `warden.sock`, `secd/`, and whatever a later service adds.
/// Per-channel policy is applied to a per-channel subdirectory, and
/// [`LocalChannel::managed_dir`] returns `None` for any channel whose socket
/// sits directly in the root. See [`LocalChannel::managed_dir`]'s doc.
pub const RUN_ROOT: &str = "/run/mirage";

/// Where this process puts its in-box sockets, when it asked to.
///
/// Unset, every path stays under [`RUN_ROOT`]. A process that hosts one box
/// of several on the same kernel sets this to that box's own directory
/// before it binds, so two boxes do not fight over one `/run/mirage` path.
/// The transport stays a unix socket. This is not a switch to TCP.
static RUNTIME_ROOT: OnceLock<std::path::PathBuf> = OnceLock::new();

/// Put this process's in-box sockets under `root`.
///
/// The first call wins. A later call is ignored, so a box cannot move its
/// sockets after another task has already resolved them. Unset, the sockets
/// stay at `/run/mirage/...`.
pub fn set_runtime_root(root: std::path::PathBuf) {
    let _ = RUNTIME_ROOT.set(root);
}

/// The directory [`set_runtime_root`] installed, if any.
pub fn runtime_root() -> Option<&'static Path> {
    RUNTIME_ROOT.get().map(std::path::PathBuf::as_path)
}

/// `logical` rewritten under [`runtime_root`], or `logical` itself when no
/// root was installed. `logical` is a `/run/mirage/...` path.
pub fn resolve_unix_path(logical: &str) -> std::path::PathBuf {
    let logical_path = Path::new(logical);
    match runtime_root() {
        Some(root) => {
            let relative = logical_path
                .strip_prefix(RUN_ROOT)
                .unwrap_or(logical_path);
            root.join(relative)
        }
        None => logical_path.to_path_buf(),
    }
}

/// Parent directory of a resolved socket path, leaked once per `label`.
///
/// [`LocalChannel::managed_dir`] has to return a `'static` path. The
/// overridden directory is not a string constant, so the first lookup keeps
/// it for the life of the process.
pub(crate) fn managed_parent(label: &'static str, resolved: &Path) -> Option<&'static Path> {
    let parent = resolved.parent()?;
    if parent == Path::new(RUN_ROOT) {
        return None;
    }
    static DIRS: OnceLock<Mutex<std::collections::HashMap<&'static str, &'static Path>>> =
        OnceLock::new();
    let map = DIRS.get_or_init(|| Mutex::new(std::collections::HashMap::new()));
    let mut guard = map.lock().unwrap_or_else(|poison| poison.into_inner());
    if let Some(found) = guard.get(label) {
        return Some(*found);
    }
    let leaked: &'static Path = Box::leak(parent.to_path_buf().into_boxed_path());
    guard.insert(label, leaked);
    Some(leaked)
}

/// The system account the perimeter runs as once de-rooted.
///
/// A NAME, never a number. Whatever provisions the account (`useradd
/// --system`, `systemd-sysusers`, `DynamicUser=`) picks the uid from the
/// box's own database, and that number is free to differ box to box. A
/// checked-in number does not fail to compile when it drifts — it quietly
/// admits the wrong process, or none.
pub const PERIMETER_ACCOUNT: &str = "mirage-perimeter";

/// The system account mshd runs as, for the same reason
/// [`PERIMETER_ACCOUNT`] is a name and not a number. Resolved the same way:
/// `NotFound` on a box where mshd has not been de-rooted yet is expected and
/// falls back to root-only, never a hard error.
pub const MSHD_ACCOUNT: &str = "mirage-mshd";

/// The system account the node runs as, for the same reason
/// [`PERIMETER_ACCOUNT`]/[`MSHD_ACCOUNT`] are names and not numbers. Resolved
/// the same way: `NotFound` on a box where the node still runs root (today's
/// default `RunAs` in `mirage2operator/crates/operator-box/src/
/// deploy_spec.rs::node_spec`) is expected and falls back to root-only —
/// root is admitted on every channel regardless (see the module doc), so an
/// unresolved node account costs nothing until the day the node is de-rooted
/// to this name.
pub const NODE_ACCOUNT: &str = "mirage-node";

/// The system account `mirage-edge` runs as (`operator-box`'s
/// `deploy_spec::mirage_edge_spec`, `User=mirage-edge`), for the same reason
/// [`PERIMETER_ACCOUNT`] is a name and not a number. Resolved the same way:
/// `NotFound` on a box that runs no edge is expected and leaves every channel
/// that names it exactly as it was.
pub const EDGE_ACCOUNT: &str = "mirage-edge";

// ── Socket paths ─────────────────────────────────────────────────────────

/// The monitor's local control plane.
///
/// **This path already exists and is already live** —
/// `mirage_mesh_client::local_transport::MIRAGE_LOCAL_SOCKET_PATH`, dialled
/// today by secd's axis-R intel read. The plan named a new
/// `monitor/control.sock`; adopting the existing path instead of renaming it
/// means step 3 does not have to move a channel that already works, and the
/// consumers still on TCP can be moved onto a socket their neighbours are
/// already using.
const MONITOR_CONTROL_SOCK: &str = "/run/mirage/monitor.sock";

/// The perimeter's wire splice into the monitor.
///
/// Deliberately NOT [`MONITOR_CONTROL_SOCK`]. The splice comes from a
/// de-rooted process and carries attacker-controlled bytes; the control
/// plane is root-to-root and carries operator intent. One socket for both
/// would admit the perimeter's uid to the control plane and leave a branch
/// in a handler as the only thing holding it back — the opposite of what
/// de-rooting the perimeter was for. Two sockets make the privilege a
/// property of a FILE, legible in one `ls -l`.
const MONITOR_WIRE_SOCK: &str = "/run/mirage/monitor/wire.sock";

/// db-worker's SQL gate. Root-to-root; no non-root client exists today.
const DBWORKER_SOCK: &str = "/run/mirage/dbworker/sql.sock";

/// node ← perimeter. The CHAIN splice: a connection that arrived on a face
/// the box declared for chain traffic, spliced inward to the node instead of
/// the monitor.
///
/// Its own directory and its own socket for the same reason
/// [`MONITOR_WIRE_SOCK`] is not [`MONITOR_CONTROL_SOCK`]: the node's control
/// plane and the node's attacker-facing ingress must be two files, so which
/// one the perimeter's uid may open is a property visible in `ls -l` rather
/// than a branch in a handler. The node creates the directory; nothing else
/// writes into it.
const NODE_CHAIN_SOCK: &str = "/run/mirage/node/chain.sock";

/// Where the perimeter answers questions about itself — its faces, its
/// health, its counters. See [`crate::perimeter_query`] for the protocol.
///
/// The one channel where the DE-ROOTED process is the listener and root is
/// the client. No group grant is needed in that direction: root traverses
/// filesystem permissions regardless (`CAP_DAC_OVERRIDE`), so a
/// perimeter-owned `0700`/`0600` is both tighter and simpler than a grant.
/// What it DOES need is `RuntimeDirectory=mirage/perimeter` on the unit —
/// `/run/mirage` is `0711 root:root` and uid 997 cannot create a directory
/// in it — which that unit already carries.
///
/// **This directory is also the perimeter's identity role dir** — systemd
/// creates it at `0755` and [`crate::identity_boot`] writes `announce` and
/// the rest capsule into it. Binding this channel therefore tightens it to
/// `0700`, and that is deliberate rather than incidental: at `0755` any local
/// uid could list the perimeter's identity filenames, and the only parties
/// with business there are the perimeter (the owner) and root (the capsule
/// courier, which traverses regardless). It is the perimeter's OWN directory,
/// not the shared root — see [`LocalChannel::managed_dir`] for the one that
/// must never be re-moded.
const PERIMETER_QUERY_SOCK: &str = "/run/mirage/perimeter/query.sock";

/// The perimeter's SSH splice into mshd — the operator's path onto the box.
const MSHD_SSH_SOCK: &str = "/run/mirage/mshd/ssh.sock";

/// The keeper's slice-serving socket — every supervised service dials in as
/// itself and asks for its own role's slice. See
/// [`crate::machine_identity_query`] for the protocol.
///
/// Lives in the same directory as `announce`/`capsule`
/// (`identity_boot::machine_dir`) — that directory has exactly one grant
/// decision to make (this socket's), so it is safe for the raw store files
/// to sit beside it; see [`LocalChannel::MachineIdentityHandover`] for why
/// the OTHER machine-identity socket must NOT share this directory.
///
/// Two de-rooted accounts reach this socket besides root — the perimeter and
/// `mirage-edge` ([`LocalChannel::peer_accounts`]) — each through its own
/// group (see the module doc, "A channel with two de-rooted callers"), and
/// each may take only its OWN role's slice: that is `mirage-warden`'s check
/// behind `SO_PEERCRED`, in `machine_identity.rs`.
const MACHINE_IDENTITY_SOCK: &str = "/run/mirage/machine/keeper.sock";

/// mshd's carrier socket into the keeper: `FetchAnnounce` /
/// `DeliverSealed`. See [`crate::machine_identity_handover`] for the
/// protocol and the module doc above for why this is a second, SEPARATE
/// socket from [`MACHINE_IDENTITY_SOCK`] rather than a second frame on it.
///
/// Deliberately NOT under `/run/mirage/machine/` — that directory's mode and
/// group are already the slice channel's to decide
/// ([`LocalChannel::MachineIdentity`]'s grant), and a second grant-managed
/// socket in the same directory would let whichever channel binds last
/// silently overwrite the other's grant. Two directories make the privilege
/// a property of a FILE, legible in one `ls -l` — same reasoning as
/// [`MONITOR_WIRE_SOCK`] living apart from [`MONITOR_CONTROL_SOCK`].
const MACHINE_IDENTITY_HANDOVER_SOCK: &str = "/run/mirage/machine-handover/handover.sock";

/// node → cli2's edge-client supervisor. The subscriber hand-off: an
/// authenticated subscriber stream the node's `core::chain_splice::
/// dispatch_entrance` loopback-connects into cli2's SOCKS5 listener, in
/// place of the loopback TCP port (`SubscriberEntranceConfig.socks_addr`,
/// cli2's router `127.0.0.1:19489`) this channel replaces (owner ruling
/// 2026-09-23: boxes have no internal TCP ports; every in-box channel is a
/// unix socket). The stream framing carried over this socket is unchanged —
/// still SOCKS5, since it only names the destination; this channel changes
/// the TRANSPORT the frames ride, not the protocol.
///
/// Its own directory for the same reason [`NODE_CHAIN_SOCK`] is not
/// [`MONITOR_CONTROL_SOCK`]: the grant this channel needs (the node's own
/// uid, once de-rooted) is a property of a FILE, not a branch in a handler.
/// cli2 (the edge-client supervisor) is the LISTENER here — the reverse
/// direction from [`NODE_CHAIN_SOCK`], where the node listens and the
/// perimeter dials in.
const EDGE_CLIENT_ENTRANCE_SOCK: &str = "/run/mirage/edge-client/entrance.sock";

/// `mirage-edge` ← perimeter. The chain splice for an Edge box — the
/// `LocalChannel::NodeChainSplice` sibling for a box that runs no
/// `mirage-node` at all (`docs/mirage/plans/2026-09-24-edge-as-entry.md`,
/// "Perimeter face target and capsule change"): a connection that arrived
/// on a face the box declared `FacePurpose::EdgeEntrance` for, spliced
/// inward to `mirage-edge` instead of a node.
///
/// Its own directory and its own socket for the same reason
/// [`NODE_CHAIN_SOCK`] is not [`MONITOR_CONTROL_SOCK`]: the grant this
/// channel needs (the perimeter's own uid) is a property of a FILE, not a
/// branch in a handler. `mirage-edge` is the LISTENER here, the perimeter
/// dials in — the same direction as [`NodeChainSplice`][LocalChannel::NodeChainSplice].
const EDGE_CHAIN_SOCK: &str = "/run/mirage/edge/chain.sock";

// ── Modes ────────────────────────────────────────────────────────────────

/// Directory mode when a group is granted: traverse without list. The
/// grantee can reach a socket it knows the name of and cannot enumerate what
/// else is there.
const DIR_MODE_GRANTED: u32 = 0o710;
/// Directory mode with no grant — owner only.
const DIR_MODE_CLOSED: u32 = 0o700;
/// Socket mode when a group is granted.
const SOCK_MODE_GRANTED: u32 = 0o660;
/// Socket mode with no grant.
const SOCK_MODE_CLOSED: u32 = 0o600;

/// Root's uid, admitted on every channel. See the module doc.
const ROOT_UID: u32 = 0;
/// Root's group. Granting it would widen nothing — see [`grant_from_resolutions`].
const ROOT_GID: u32 = 0;

// ── Channels ─────────────────────────────────────────────────────────────

/// One named in-box channel. Callers name the CHANNEL; the address is this
/// module's business and nobody else's.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LocalChannel {
    /// monitor ← db-worker, secd, sentry, node, mshd. Control-plane
    /// request/response.
    MonitorControl,
    /// monitor ← perimeter. The wire splice, attacker bytes inside.
    MonitorWireSplice,
    /// db-worker ← monitor, secd, sentry, mshd. SQL gate.
    DbWorker,
    /// perimeter ← mshd, monitor. Typed reads: faces, health, counters.
    /// Never a write — see [`crate::perimeter_query`].
    PerimeterQuery,
    /// mshd ← perimeter. The SSH splice.
    MshdSshSplice,
    /// warden ← every supervised service. `Take { role }` and nothing else —
    /// see [`crate::machine_identity_query`].
    MachineIdentity,
    /// warden ← mshd. `FetchAnnounce` / `DeliverSealed` and nothing else —
    /// see [`crate::machine_identity_handover`]. Deliberately a SEPARATE
    /// channel from [`LocalChannel::MachineIdentity`]: the transport must
    /// not be able to ask for a slice, and a service must not be able to
    /// deliver an envelope.
    MachineIdentityHandover,
    /// node ← perimeter. The chain splice — see [`NODE_CHAIN_SOCK`].
    NodeChainSplice,
    /// cli2's edge-client supervisor ← node. The subscriber hand-off — see
    /// [`EDGE_CLIENT_ENTRANCE_SOCK`].
    EdgeClientEntrance,
    /// `mirage-edge` ← perimeter. The chain splice on an Edge box — see
    /// [`EDGE_CHAIN_SOCK`].
    EdgeChainSplice,
}

impl LocalChannel {
    /// Every channel this module knows. Used by the invariant tests and by
    /// the operator-side instrument that has to prove the ports are gone.
    pub const ALL: [LocalChannel; 10] = [
        LocalChannel::MonitorControl,
        LocalChannel::MonitorWireSplice,
        LocalChannel::DbWorker,
        LocalChannel::PerimeterQuery,
        LocalChannel::MshdSshSplice,
        LocalChannel::MachineIdentity,
        LocalChannel::MachineIdentityHandover,
        LocalChannel::NodeChainSplice,
        LocalChannel::EdgeClientEntrance,
        LocalChannel::EdgeChainSplice,
    ];

    /// Stable short name for logs and for the operator's readout.
    pub const fn label(self) -> &'static str {
        match self {
            LocalChannel::MonitorControl => "monitor-control",
            LocalChannel::MonitorWireSplice => "monitor-wire",
            LocalChannel::DbWorker => "db-worker",
            LocalChannel::PerimeterQuery => "perimeter-query",
            LocalChannel::MshdSshSplice => "mshd-ssh",
            LocalChannel::MachineIdentity => "machine-identity",
            LocalChannel::MachineIdentityHandover => "machine-identity-handover",
            LocalChannel::NodeChainSplice => "node-chain",
            LocalChannel::EdgeClientEntrance => "edge-client-entrance",
            LocalChannel::EdgeChainSplice => "edge-chain",
        }
    }

    /// Filesystem path on the unix arm. Present on every target so an
    /// instrument compiled for Windows can still NAME what it is looking
    /// for on a Linux box.
    pub const fn unix_path(self) -> &'static str {
        match self {
            LocalChannel::MonitorControl => MONITOR_CONTROL_SOCK,
            LocalChannel::MonitorWireSplice => MONITOR_WIRE_SOCK,
            LocalChannel::DbWorker => DBWORKER_SOCK,
            LocalChannel::PerimeterQuery => PERIMETER_QUERY_SOCK,
            LocalChannel::MshdSshSplice => MSHD_SSH_SOCK,
            LocalChannel::MachineIdentity => MACHINE_IDENTITY_SOCK,
            LocalChannel::MachineIdentityHandover => MACHINE_IDENTITY_HANDOVER_SOCK,
            LocalChannel::NodeChainSplice => NODE_CHAIN_SOCK,
            LocalChannel::EdgeClientEntrance => EDGE_CLIENT_ENTRANCE_SOCK,
            LocalChannel::EdgeChainSplice => EDGE_CHAIN_SOCK,
        }
    }

    /// The loopback address this channel uses on Windows — and the one it
    /// used on Linux before the move.
    ///
    /// [`LocalChannel::MonitorControl`] and [`LocalChannel::MonitorWireSplice`]
    /// share `19444` on purpose: on the port model they ARE one listener, and
    /// the Windows arm is an honest rendering of today rather than a
    /// separation invented for a platform no box runs. The separation is a
    /// unix property because it is made of file permissions, and file
    /// permissions are what Windows does not have here.
    pub fn loopback_addr(self) -> SocketAddr {
        let port = match self {
            LocalChannel::MonitorControl | LocalChannel::MonitorWireSplice => 19444,
            LocalChannel::DbWorker => 19446,
            LocalChannel::PerimeterQuery => 19470,
            LocalChannel::MshdSshSplice => 19471,
            LocalChannel::MachineIdentity => 19472,
            LocalChannel::MachineIdentityHandover => 19473,
            LocalChannel::NodeChainSplice => 19474,
            // 19475-19478 belong to `LocalDgramChannel` (see that enum's own
            // `loopback_addr` doc) — this stream channel's port must not
            // collide with any of them.
            LocalChannel::EdgeClientEntrance => 19479,
            LocalChannel::EdgeChainSplice => 19480,
        };
        SocketAddr::from(([127, 0, 0, 1], port))
    }

    /// The directory whose mode and group this channel's listener manages,
    /// or `None` when the socket sits directly in [`RUN_ROOT`].
    ///
    /// The shared root is never touched: it holds `warden.sock` and
    /// `secd/`, and a channel tightening it would break neighbours that
    /// never asked. Only [`LocalChannel::MonitorControl`] returns `None`,
    /// because it keeps a path that predates this module — and it wants no
    /// grant anyway, being root-to-root.
    pub fn managed_dir(self) -> Option<&'static Path> {
        if runtime_root().is_some() {
            return managed_parent(self.label(), &resolve_unix_path(self.unix_path()));
        }
        let parent = Path::new(self.unix_path()).parent()?;
        if parent == Path::new(RUN_ROOT) {
            None
        } else {
            Some(parent)
        }
    }

    /// The accounts admitted beyond root, by name, in the order their groups
    /// are considered for ownership of the socket (see [`grant_from_resolutions`]).
    /// Empty for root-only.
    pub const fn peer_accounts(self) -> &'static [&'static str] {
        match self {
            // The de-rooted perimeter is the client on both splices.
            LocalChannel::MshdSshSplice
            | LocalChannel::MonitorWireSplice
            | LocalChannel::NodeChainSplice
            | LocalChannel::EdgeChainSplice => &[PERIMETER_ACCOUNT],
            // The slice channel has two de-rooted callers: the perimeter, and
            // `mirage-edge` (which runs under its own account from its first
            // deploy). Each may take ONLY its own role's slice — that is
            // `mirage-warden`'s per-role check behind `SO_PEERCRED`, not this
            // table. Every OTHER supervised service is still root today, and
            // root is admitted on every channel regardless (see the module
            // doc). Perimeter first: on a box that has both, its group keeps
            // owning the socket exactly as it did before the edge existed, and
            // the edge's group is the added ACL entry.
            LocalChannel::MachineIdentity => &[PERIMETER_ACCOUNT, EDGE_ACCOUNT],
            // Only mshd carries bytes across the handover seam.
            LocalChannel::MachineIdentityHandover => &[MSHD_ACCOUNT],
            // cli2's edge-client supervisor listens; the node is the one
            // caller admitted on this channel — see [`EDGE_CLIENT_ENTRANCE_SOCK`].
            LocalChannel::EdgeClientEntrance => &[NODE_ACCOUNT],
            // Root-to-root. The perimeter LISTENS on its query socket; its
            // clients are root, and root needs no grant.
            LocalChannel::MonitorControl
            | LocalChannel::DbWorker
            | LocalChannel::PerimeterQuery => &[],
        }
    }

    /// The address this channel resolves to on THIS build.
    pub fn endpoint(self) -> LocalEndpoint {
        #[cfg(unix)]
        {
            LocalEndpoint::Unix(resolve_unix_path(self.unix_path()))
        }
        #[cfg(not(unix))]
        {
            LocalEndpoint::Tcp(self.loopback_addr())
        }
    }

    /// Resolve this channel's accounts against the box's own database and
    /// build the bind plan from them. One resolution decides BOTH who is
    /// admitted and who can reach the socket — deciding them separately is
    /// what left a socket root-only under a `drwx------` directory while the
    /// daemon logged that the perimeter's uid was allowed.
    pub fn plan(self) -> BindPlan {
        let resolutions: Vec<AccountResolution> = self
            .peer_accounts()
            .iter()
            .map(|account| resolve_account(Some(account)))
            .collect();
        plan_from_resolutions(&resolutions)
    }

    /// Bind this channel and serve. See [`LocalEndpoint::bind_with`].
    ///
    /// The outcome is recorded, so a caller who did NOT perform the bind can
    /// still ask what happened — see [`LocalChannel::bind_status`].
    pub async fn bind(self) -> io::Result<LocalListener> {
        let plan = self.plan();
        tracing::info!(
            channel = self.label(),
            endpoint = %self.endpoint(),
            resolutions = ?plan.resolutions,
            admitted_uids = ?plan.admitted_uids,
            dir_mode = format!("{:o}", plan.grant.dir_mode),
            socket_mode = format!("{:o}", plan.grant.socket_mode),
            granted_gid = ?plan.grant.gid,
            also_granted_gids = ?plan.grant.also_gids,
            "[local] binding a box-local channel"
        );
        let result = self.endpoint().bind_with(self.managed_dir(), &plan).await;
        record_bind(self, &result);
        result
    }

    /// What the last bind of this channel did, if this process attempted one.
    ///
    /// `None` when the channel was never bound through
    /// [`LocalChannel::bind`] — on a platform where the channel rides a TCP
    /// listener, or before the bind happens.
    ///
    /// WHY this exists: the monitor's inbound wire is bound by
    /// `mirage-mesh-client`, a crate away from the monitor's own health
    /// surface. A bind that fails there used to be a log line and nothing
    /// else — the box kept answering `/health` with `status: "ok"` while
    /// nothing could reach it. Recording the outcome where the bind happens
    /// is what lets the monitor say "wire splice bound: false" instead of
    /// guessing from the presence of a file.
    pub fn bind_status(self) -> Option<ChannelBindStatus> {
        let records = bind_records().lock().unwrap_or_else(|e| e.into_inner());
        records.get(self.label()).map(|r| r.status.clone())
    }

    /// Release the socket file this process bound for this channel.
    ///
    /// WHY: dropping a listener closes its DESCRIPTOR but leaves the FILE on
    /// disk — `/run` outlives the process, so the next generation of a
    /// service inherits a socket path that nobody listens on. The next bind
    /// then has to unlink that file before it can bind, and a bind that
    /// loses that race leaves the channel deaf for the life of the box.
    /// Measured on ru-hostkey-203.0.113.16, 2026-10-23: `wire.sock` dated
    /// 3 October with nothing listening on it, and every inbound connection
    /// refused.
    ///
    /// Only the very file this process created is removed: the path is
    /// stat-ed and its `(device, inode)` compared with the pair recorded at
    /// bind time, so a path another process has since taken over is left
    /// alone. On a platform with no filesystem socket this is a no-op.
    pub fn release(self) -> io::Result<()> {
        #[cfg(unix)]
        {
            let identity = {
                let records = bind_records().lock().unwrap_or_else(|e| e.into_inner());
                records.get(self.label()).and_then(|r| r.socket_identity)
            };
            let Some((dev, ino)) = identity else {
                return Ok(());
            };
            let path = Path::new(self.unix_path());
            let Ok(md) = std::fs::symlink_metadata(path) else {
                return Ok(());
            };
            use std::os::unix::fs::{FileTypeExt, MetadataExt};
            if !md.file_type().is_socket() || md.dev() != dev || md.ino() != ino {
                return Ok(());
            }
            std::fs::remove_file(path)
        }
        #[cfg(not(unix))]
        {
            let _ = self;
            Ok(())
        }
    }

    /// Dial this channel.
    pub async fn connect(self) -> io::Result<LocalStream> {
        self.endpoint().connect().await
    }
}

// ── The bind record ──────────────────────────────────────────────────────

/// What the last bind of a box-local channel did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelBindStatus {
    /// `true` when the listener was established.
    pub bound: bool,
    /// The endpoint the bind targeted.
    pub endpoint: String,
    /// Why the bind failed, when it failed.
    pub error: Option<String>,
}

/// One channel's bind record: the outcome, and — on unix — the identity of
/// the socket file this process created.
#[derive(Debug, Clone)]
struct BindRecord {
    status: ChannelBindStatus,
    /// `(device, inode)` of the socket file this process bound. `None` when
    /// the bind failed (there is no file of ours) and on platforms with no
    /// filesystem socket.
    #[cfg(unix)]
    socket_identity: Option<(u64, u64)>,
}

/// The bind records, by channel label.
///
/// Process-global on purpose: the party that performs the bind
/// (`mirage-mesh-client`) is not the party that needs the answer (the
/// monitor's health surface), and a value only the binder can see cannot
/// answer the second question.
fn bind_records() -> &'static Mutex<std::collections::BTreeMap<&'static str, BindRecord>> {
    static RECORDS: OnceLock<Mutex<std::collections::BTreeMap<&'static str, BindRecord>>> =
        OnceLock::new();
    RECORDS.get_or_init(|| Mutex::new(std::collections::BTreeMap::new()))
}

/// Record what a channel's bind did.
fn record_bind(channel: LocalChannel, result: &io::Result<LocalListener>) {
    let status = ChannelBindStatus {
        bound: result.is_ok(),
        endpoint: channel.endpoint().to_string(),
        error: result.as_ref().err().map(|e| e.to_string()),
    };
    // The identity is read only for a bind that SUCCEEDED: a failed bind may
    // have left somebody else's file at the path, and that file is not ours
    // to release.
    #[cfg(unix)]
    let socket_identity = if result.is_ok() {
        socket_identity_of(channel)
    } else {
        None
    };
    let mut records = bind_records().lock().unwrap_or_else(|e| e.into_inner());
    records.insert(
        channel.label(),
        BindRecord {
            status,
            #[cfg(unix)]
            socket_identity,
        },
    );
}

/// The `(device, inode)` of the socket file this process created, if any.
///
/// Read AFTER the bind, so it names the file this process owns — the
/// identity a later [`LocalChannel::release`] compares against before
/// removing anything.
#[cfg(unix)]
fn socket_identity_of(channel: LocalChannel) -> Option<(u64, u64)> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    let md = std::fs::symlink_metadata(channel.unix_path()).ok()?;
    if !md.file_type().is_socket() {
        return None;
    }
    Some((md.dev(), md.ino()))
}

/// No filesystem socket on this platform: there is no file to remember.
#[cfg(not(unix))]
fn socket_identity_of(_channel: LocalChannel) -> Option<(u64, u64)> {
    None
}

// ── Endpoint ─────────────────────────────────────────────────────────────

/// A box-local address, already resolved for this compilation target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LocalEndpoint {
    /// `AF_UNIX` at a filesystem path.
    Unix(PathBuf),
    /// Loopback TCP. Windows only in fleet code; also what a unix test uses
    /// when it wants to exercise the other arm.
    Tcp(SocketAddr),
}

impl std::fmt::Display for LocalEndpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LocalEndpoint::Unix(p) => write!(f, "unix:{}", p.display()),
            LocalEndpoint::Tcp(a) => write!(f, "tcp:{a}"),
        }
    }
}

impl LocalEndpoint {
    /// Bind, applying `plan` — stale-socket removal, directory mode and
    /// group, socket mode — and returning a listener that enforces the
    /// allowlist at accept time.
    ///
    /// `managed_dir` is created if absent and then has the grant applied.
    /// Pass `None` to leave the parent directory entirely alone; see
    /// [`LocalChannel::managed_dir`].
    pub async fn bind_with(
        &self,
        managed_dir: Option<&Path>,
        plan: &BindPlan,
    ) -> io::Result<LocalListener> {
        match self {
            LocalEndpoint::Unix(path) => bind_unix(path, managed_dir, plan).await,
            LocalEndpoint::Tcp(addr) => {
                let listener = tokio::net::TcpListener::bind(addr).await?;
                Ok(LocalListener {
                    inner: ListenerInner::Tcp(listener),
                    admitted_uids: plan.admitted_uids.clone(),
                    refused: AtomicU64::new(0),
                })
            }
        }
    }

    /// Dial. Carries no credential of its own — the kernel attaches the
    /// caller's real uid to the connecting socket, and the listener reads it
    /// there.
    pub async fn connect(&self) -> io::Result<LocalStream> {
        match self {
            #[cfg(unix)]
            LocalEndpoint::Unix(path) => Ok(LocalStream(StreamInner::Unix(
                tokio::net::UnixStream::connect(path).await?,
            ))),
            #[cfg(not(unix))]
            LocalEndpoint::Unix(path) => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!(
                    "unix socket {} cannot be dialled on this target",
                    path.display()
                ),
            )),
            LocalEndpoint::Tcp(addr) => Ok(LocalStream(StreamInner::Tcp(
                tokio::net::TcpStream::connect(addr).await?,
            ))),
        }
    }
}

#[cfg(unix)]
async fn bind_unix(
    path: &Path,
    managed_dir: Option<&Path>,
    plan: &BindPlan,
) -> io::Result<LocalListener> {
    use std::os::unix::fs::PermissionsExt;

    if let Some(dir) = managed_dir {
        std::fs::create_dir_all(dir)?;
        // The directory outlives the process that bound it (`/run` survives a
        // restart), so it can still carry a named-group entry from a previous
        // bind whose account no longer resolves. Drop every such entry BEFORE
        // anything is granted, so what remains afterwards is exactly what this
        // plan implies and nothing a former plan left behind.
        clear_extra_group_acl(dir);
        // chown BEFORE chmod: the reverse order briefly presents a
        // group-accessible directory still owned by the wrong group.
        // Re-applied on every boot on purpose — an operator's hand-`chown`
        // is lost on the next restart and re-breaks the channel silently.
        chown_to_group(dir, plan.grant.gid)?;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(plan.grant.dir_mode))?;
        // Last, because setting an ACL rewrites the group bits of the mode to
        // the ACL's mask — which `grant_extra_groups` sets to the very same
        // bits the chmod above just applied.
        grant_extra_groups(dir, plan.grant.dir_mode, &plan.grant.also_gids);
    }

    remove_stale_socket_if_dead(path).await?;
    let listener = tokio::net::UnixListener::bind(path)?;
    chown_to_group(path, plan.grant.gid)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(plan.grant.socket_mode))?;
    // A socket is created fresh by the bind above, so it carries no stale
    // entry to clear — only the current plan's grant to add.
    grant_extra_groups(path, plan.grant.socket_mode, &plan.grant.also_gids);

    Ok(LocalListener {
        inner: ListenerInner::Unix {
            listener,
            path: path.to_path_buf(),
        },
        admitted_uids: plan.admitted_uids.clone(),
        refused: AtomicU64::new(0),
    })
}

#[cfg(not(unix))]
async fn bind_unix(
    path: &Path,
    _managed_dir: Option<&Path>,
    _plan: &BindPlan,
) -> io::Result<LocalListener> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        format!(
            "unix socket {} cannot be bound on this target",
            path.display()
        ),
    ))
}

/// How long the pre-bind probe may wait for an answer.
///
/// A live listener whose accept backlog is full leaves the connect pending;
/// an unbounded wait would hang the bind instead of reporting it.
#[cfg(any(unix, test))]
const SOCKET_PROBE_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(500);

/// What a probe of a socket path found.
#[cfg(any(unix, test))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PathProbe {
    /// Nothing is at the path.
    Absent,
    /// A live listener answered the probe.
    Live,
    /// The path exists, but nothing is listening on it.
    Stale,
    /// The probe could not tell — permissions, a full backlog, a timeout.
    Inconclusive,
}

/// What to do about the path before binding.
#[cfg(any(unix, test))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StaleDecision {
    /// Bind straight away.
    Bind,
    /// The file is stale — unlink it, then bind.
    UnlinkThenBind,
    /// Somebody may own the path — refuse, and do not steal it.
    Refuse,
}

/// The decision, as a pure function of the probe.
///
/// WHY a function and not a `match` inside the probe: this is the rule that
/// keeps one process from taking a channel from another, and it has to be
/// readable — and testable — on every target, including the ones with no
/// unix socket at all.
#[cfg(any(unix, test))]
fn decide_stale_removal(probe: PathProbe) -> StaleDecision {
    match probe {
        PathProbe::Absent => StaleDecision::Bind,
        PathProbe::Stale => StaleDecision::UnlinkThenBind,
        // A live listener is somebody else's channel. An inconclusive probe
        // MIGHT be one too: unlinking on a doubt is how a second process
        // silently steals a channel from a first that is still serving it.
        PathProbe::Live | PathProbe::Inconclusive => StaleDecision::Refuse,
    }
}

/// Remove a socket file left by an unclean exit — but only after proving
/// nothing is listening on it.
///
/// A successful connect means a live process owns the path: leave it alone
/// and fail the bind, loudly. A connect that was REFUSED means the file is
/// stale and safe to unlink. Any other answer — a permission error, a full
/// backlog, a probe that timed out — is no proof of anything, so the file is
/// left alone and the bind fails loudly rather than taking a channel that
/// may still be served.
#[cfg(unix)]
async fn remove_stale_socket_if_dead(path: &Path) -> io::Result<()> {
    match decide_stale_removal(probe_socket_path(path).await) {
        StaleDecision::Bind => Ok(()),
        StaleDecision::UnlinkThenBind => std::fs::remove_file(path),
        StaleDecision::Refuse => Err(io::Error::new(
            io::ErrorKind::AddrInUse,
            format!("a live listener already owns {}", path.display()),
        )),
    }
}

/// Probe the path: is anybody listening on it?
#[cfg(unix)]
async fn probe_socket_path(path: &Path) -> PathProbe {
    use std::os::unix::fs::FileTypeExt;
    // A path that is not a socket at all cannot be served by anybody: it is a
    // leftover of some other kind, and unlinking it cannot steal a channel.
    match std::fs::symlink_metadata(path) {
        Ok(md) if !md.file_type().is_socket() => return PathProbe::Stale,
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => return PathProbe::Absent,
        Err(_) => return PathProbe::Inconclusive,
    }
    match tokio::time::timeout(SOCKET_PROBE_TIMEOUT, tokio::net::UnixStream::connect(path)).await {
        Ok(Ok(_stream)) => PathProbe::Live,
        Ok(Err(e)) if e.kind() == io::ErrorKind::ConnectionRefused => PathProbe::Stale,
        Ok(Err(_)) => PathProbe::Inconclusive,
        Err(_elapsed) => PathProbe::Inconclusive,
    }
}

/// Give `path` to `gid`, leaving the owning user alone. No-op with no grant.
///
/// `pub(crate)` rather than private: [`crate::local_dgram_endpoint`] applies
/// the identical grant machinery to its own `SOCK_DGRAM` sockets and must not
/// duplicate this call — see that module's doc for why it reuses this
/// resolution rather than inventing a parallel one.
#[cfg(unix)]
pub(crate) fn chown_to_group(path: &Path, gid: Option<u32>) -> io::Result<()> {
    let Some(gid) = gid else { return Ok(()) };
    let c_path = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path is not a C string"))?;
    // SAFETY: `c_path` is a valid NUL-terminated string owned for the call.
    // `-1` (as u32::MAX) for the uid is chown(2)'s documented "leave the
    // owner alone".
    let rc = unsafe { libc::chown(c_path.as_ptr(), u32::MAX, gid) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

// ── The extra-group grant: a POSIX ACL ───────────────────────────────────

/// The extended attribute a file's access ACL lives in.
#[cfg(target_os = "linux")]
const ACL_ACCESS_XATTR: &[u8] = b"system.posix_acl_access\0";

/// `POSIX_ACL_XATTR_VERSION` — the only version the kernel accepts.
#[cfg(any(target_os = "linux", test))]
const ACL_XATTR_VERSION: u32 = 2;
/// ACL entry tags, from `<linux/posix_acl_xattr.h>` (`ACL_USER_OBJ` and
/// friends). The kernel requires entries in ascending tag order.
#[cfg(any(target_os = "linux", test))]
const ACL_USER_OBJ: u16 = 0x01;
#[cfg(any(target_os = "linux", test))]
const ACL_GROUP_OBJ: u16 = 0x04;
#[cfg(any(target_os = "linux", test))]
const ACL_GROUP: u16 = 0x08;
#[cfg(any(target_os = "linux", test))]
const ACL_MASK: u16 = 0x10;
#[cfg(any(target_os = "linux", test))]
const ACL_OTHER: u16 = 0x20;
/// The id the kernel expects on an entry that names no user or group.
#[cfg(any(target_os = "linux", test))]
const ACL_UNDEFINED_ID: u32 = u32::MAX;

/// The `system.posix_acl_access` value for a file of permission `mode` that
/// grants each of `also_gids` the SAME access as the file's owning group.
///
/// Pure, so the byte layout is testable on every target. The entries are the
/// three the mode already implies (owner, owning group, other) plus one named
/// group entry per `also_gids` and the mask that the presence of a named
/// entry makes mandatory. The mask equals the owning group's bits, so it
/// filters nothing — and it is what `ls -l` and `stat` will show as the
/// group bits, which is why they still read `0710` / `0660`.
///
/// `also_gids` is sorted and de-duplicated here: the kernel refuses an ACL
/// whose named entries are not in strictly ascending id order.
#[cfg(any(target_os = "linux", test))]
fn access_acl_bytes(mode: u32, also_gids: &[u32]) -> Vec<u8> {
    // The r/w/x bits and the ACL permission bits are the same 4/2/1.
    let owner = ((mode >> 6) & 0o7) as u16;
    let group = ((mode >> 3) & 0o7) as u16;
    let other = (mode & 0o7) as u16;

    let mut gids = also_gids.to_vec();
    gids.sort_unstable();
    gids.dedup();

    let mut out = Vec::with_capacity(4 + 8 * (4 + gids.len()));
    out.extend_from_slice(&ACL_XATTR_VERSION.to_le_bytes());
    let mut entry = |tag: u16, perm: u16, id: u32| {
        out.extend_from_slice(&tag.to_le_bytes());
        out.extend_from_slice(&perm.to_le_bytes());
        out.extend_from_slice(&id.to_le_bytes());
    };
    entry(ACL_USER_OBJ, owner, ACL_UNDEFINED_ID);
    entry(ACL_GROUP_OBJ, group, ACL_UNDEFINED_ID);
    for gid in gids {
        entry(ACL_GROUP, group, gid);
    }
    entry(ACL_MASK, group, ACL_UNDEFINED_ID);
    entry(ACL_OTHER, other, ACL_UNDEFINED_ID);
    out
}

#[cfg(target_os = "linux")]
fn path_to_cstring(path: &Path) -> io::Result<std::ffi::CString> {
    std::ffi::CString::new(path.as_os_str().as_encoded_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path is not a C string"))
}

/// Remove `path`'s access ACL. Absent already, or a filesystem with no ACL
/// support at all, is success: there is nothing to remove.
#[cfg(target_os = "linux")]
fn remove_access_acl(path: &Path) -> io::Result<()> {
    let c_path = path_to_cstring(path)?;
    // SAFETY: `c_path` and `ACL_ACCESS_XATTR` are valid NUL-terminated strings
    // that outlive the call.
    let rc = unsafe { libc::removexattr(c_path.as_ptr(), ACL_ACCESS_XATTR.as_ptr().cast()) };
    if rc == 0 {
        return Ok(());
    }
    let err = io::Error::last_os_error();
    match err.raw_os_error() {
        Some(libc::ENODATA) | Some(libc::EOPNOTSUPP) => Ok(()),
        _ => Err(err),
    }
}

/// Replace `path`'s access ACL with the one [`access_acl_bytes`] builds.
#[cfg(target_os = "linux")]
fn set_access_acl(path: &Path, mode: u32, also_gids: &[u32]) -> io::Result<()> {
    let c_path = path_to_cstring(path)?;
    let value = access_acl_bytes(mode, also_gids);
    // SAFETY: `c_path` and `ACL_ACCESS_XATTR` are valid NUL-terminated
    // strings, and `value` is a valid buffer whose length is passed alongside
    // its pointer, per setxattr(2); all three outlive the call.
    let rc = unsafe {
        libc::setxattr(
            c_path.as_ptr(),
            ACL_ACCESS_XATTR.as_ptr().cast(),
            value.as_ptr().cast(),
            value.len(),
            0,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// No ACL machinery outside Linux: nothing to remove, and nothing this
/// module could grant if asked to.
#[cfg(all(unix, not(target_os = "linux")))]
fn remove_access_acl(_path: &Path) -> io::Result<()> {
    Ok(())
}

#[cfg(all(unix, not(target_os = "linux")))]
fn set_access_acl(_path: &Path, _mode: u32, _also_gids: &[u32]) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "POSIX ACL grants are only implemented on Linux",
    ))
}

/// Remove any extra-group entries a previous bind left on `path`.
///
/// Logged, not returned: a directory that keeps an entry for a group that no
/// longer maps to an account is a lingering grant to nobody, and refusing to
/// bind over it would take the channel — and every service that depends on
/// it — down to avoid that.
#[cfg(unix)]
fn clear_extra_group_acl(path: &Path) {
    if let Err(e) = remove_access_acl(path) {
        tracing::error!(
            path = %path.display(),
            error = %e,
            "[local] could not remove the previous extra-group ACL from a managed directory — a \
             group that no longer resolves may still hold access to it"
        );
    }
}

/// Grant each of `also_gids` the same access to `path` as its owning group.
/// A no-op with none, which is every channel but a two-account one on a box
/// where both accounts resolve.
///
/// A failure is logged and does NOT fail the bind: the primary grant is
/// already in place and is the only one this module had before this existed,
/// so the failing extra grant costs exactly the service it was for — and
/// says so — instead of the whole channel. The usual cause is a filesystem
/// mounted without ACL support.
#[cfg(unix)]
fn grant_extra_groups(path: &Path, mode: u32, also_gids: &[u32]) {
    if also_gids.is_empty() {
        return;
    }
    if let Err(e) = set_access_acl(path, mode, also_gids) {
        tracing::error!(
            path = %path.display(),
            ?also_gids,
            error = %e,
            "[local] could not grant an additional resolved account's group access to a box-local \
             channel — that account cannot reach it (the filesystem may not support POSIX ACLs)"
        );
    }
}

// ── Peer identity ────────────────────────────────────────────────────────

/// Who is on the other end, as the platform is able to say.
///
/// An enum rather than an `Option<u32>` for two reasons. A caller that wants
/// a uid cannot compile without deciding what it does on the platform that
/// has none — the compiler asks the question instead of a reviewer. And the
/// loopback arm still carries the peer address, which is the only thing
/// there is to log there.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerIdentity {
    /// Kernel-supplied credentials, filled at `connect()` time from the real
    /// credentials of the connecting process. Nothing in the byte stream can
    /// produce or alter them.
    Credentials {
        uid: u32,
        gid: u32,
        /// `None` when the platform reports no pid (macOS `LOCAL_PEERPID`
        /// is not universal). A pid is for logging only — it is racy by
        /// nature and must never gate a decision.
        pid: Option<i32>,
    },
    /// Loopback TCP: the platform supplies no peer credential at all. Every
    /// local process is indistinguishable here, which is exactly why no box
    /// runs this arm.
    Loopback { peer: SocketAddr },
}

impl PeerIdentity {
    /// The peer's uid, when the platform supplies one.
    pub fn uid(&self) -> Option<u32> {
        match self {
            PeerIdentity::Credentials { uid, .. } => Some(*uid),
            PeerIdentity::Loopback { .. } => None,
        }
    }
}

/// Whether `peer` is admitted by `admitted_uids`.
///
/// Pure — the accept-time check reduces to exactly this call once the
/// credentials are read, so the decision is testable without a socket.
///
/// The loopback arm is admitted: it has already been bound to `127.0.0.1`,
/// so the peer is on this machine, and there is no further question this
/// platform can answer. Refusing it instead would not add a boundary — it
/// would only make the Windows arm unusable while pretending to be strict.
pub fn peer_admitted(peer: &PeerIdentity, admitted_uids: &[u32]) -> bool {
    match peer {
        PeerIdentity::Credentials { uid, .. } => admitted_uids.contains(uid),
        PeerIdentity::Loopback { .. } => true,
    }
}

// ── Account resolution and the bind plan ─────────────────────────────────

/// The outcome of looking an account name up against the box's database.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccountResolution {
    /// The channel asked for no account beyond root.
    NotRequested,
    /// The account exists; this is its uid and primary gid right now.
    ///
    /// The gid is carried because the uid alone answers only the ACCEPT-time
    /// question. The socket also has to be REACHABLE, and that is a
    /// filesystem grant on a group. Both come from one lookup: two lookups
    /// could disagree, and a socket chowned to one account while the
    /// allowlist admits another fails in the most confusing direction there
    /// is — permission denied on a peer the log says is allowed.
    Resolved { uid: u32, gid: u32 },
    /// The account does not exist on this box. Expected before it is
    /// de-rooted, permanent on a box that never is.
    NotFound,
    /// The lookup itself did not complete (NSS failure, resource
    /// exhaustion, or a platform with no account database). Distinct from
    /// [`AccountResolution::NotFound`] only in which sentence gets logged.
    LookupFailed,
}

/// Directory and socket permissions implied by the resolutions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SocketGrant {
    pub dir_mode: u32,
    pub socket_mode: u32,
    /// Group to own both, or `None` to leave ownership alone.
    pub gid: Option<u32>,
    /// Further groups given the same access as [`Self::gid`] through a
    /// named-group ACL entry, for a channel with more than one de-rooted
    /// account (see the module doc). Empty whenever fewer than two distinct
    /// non-root groups resolved — which is every box and every channel that
    /// had one account before this field existed.
    pub also_gids: Vec<u32>,
}

/// Everything a bind needs, derived from the channel's resolutions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindPlan {
    /// One entry per account the channel names, in [`LocalChannel::peer_accounts`]
    /// order. For the log: it says which accounts resolved and which did not,
    /// which is the first thing to know when a socket does not admit a caller.
    pub resolutions: Vec<AccountResolution>,
    pub grant: SocketGrant,
    pub admitted_uids: Vec<u32>,
}

/// The grant the resolutions imply.
///
/// The first resolved account with a non-root group owns the directory and
/// the socket; every further DISTINCT non-root group is carried in
/// [`SocketGrant::also_gids`]. Two accounts that share a group therefore
/// produce no extra entry.
///
/// Fail-closed by construction: only the `Resolved` arm widens anything, so
/// a variant added later falls through to owner-only without anyone
/// remembering to handle it. A root-owned account widens nothing either —
/// granting a group that already owns the socket is a no-op dressed as a
/// permission change, while `0660`/`0710` would be a real loosening the day
/// it were not root.
pub fn grant_from_resolutions(resolutions: &[AccountResolution]) -> SocketGrant {
    let mut gids: Vec<u32> = Vec::new();
    for resolution in resolutions {
        if let AccountResolution::Resolved { gid, .. } = *resolution {
            if gid != ROOT_GID && !gids.contains(&gid) {
                gids.push(gid);
            }
        }
    }
    let mut gids = gids.into_iter();
    match gids.next() {
        Some(owner) => SocketGrant {
            dir_mode: DIR_MODE_GRANTED,
            socket_mode: SOCK_MODE_GRANTED,
            gid: Some(owner),
            also_gids: gids.collect(),
        },
        None => SocketGrant {
            dir_mode: DIR_MODE_CLOSED,
            socket_mode: SOCK_MODE_CLOSED,
            gid: None,
            also_gids: Vec::new(),
        },
    }
}

/// The accept-time allowlist the resolutions imply. Root unconditionally,
/// plus every resolved account — see the module doc for why root is never
/// excluded.
pub fn allowlist_from_resolutions(resolutions: &[AccountResolution]) -> Vec<u32> {
    let mut allowed = vec![ROOT_UID];
    for resolution in resolutions {
        if let AccountResolution::Resolved { uid, .. } = *resolution {
            if !allowed.contains(&uid) {
                allowed.push(uid);
            }
        }
    }
    allowed
}

/// Both halves of the decision, from ALL of a channel's resolutions at once.
/// Pure.
pub fn plan_from_resolutions(resolutions: &[AccountResolution]) -> BindPlan {
    BindPlan {
        resolutions: resolutions.to_vec(),
        grant: grant_from_resolutions(resolutions),
        admitted_uids: allowlist_from_resolutions(resolutions),
    }
}

/// [`plan_from_resolutions`] for the common case of a channel that names one
/// account (or none). Pure.
pub fn plan_from_resolution(resolution: AccountResolution) -> BindPlan {
    plan_from_resolutions(&[resolution])
}

/// Largest buffer [`resolve_account`] grows to before failing closed. 1 MiB
/// is generous many times over for one password-database entry; the bound
/// exists so a pathological NSS backend cannot loop forever instead of
/// failing.
#[cfg(unix)]
const MAX_PWBUF_LEN: usize = 1 << 20;

/// Resolve an account name against the box's own database.
///
/// `getpwnam_r` — the reentrant form, which is what makes this safe to call
/// from a multi-threaded async runtime. Plain `getpwnam` returns a pointer
/// into a static buffer a concurrent call could overwrite mid-read.
#[cfg(unix)]
pub fn resolve_account(account: Option<&str>) -> AccountResolution {
    let Some(account) = account else {
        return AccountResolution::NotRequested;
    };
    let Ok(name) = std::ffi::CString::new(account) else {
        return AccountResolution::LookupFailed;
    };

    // SAFETY: an all-zero bit pattern is a valid `libc::passwd` — every
    // field is an integer or a pointer, and `getpwnam_r` either fully
    // populates it (writing pointers into `buf`, which outlives the call) or
    // leaves it untouched and reports failure through its return code and
    // `result`, both checked before any field is read.
    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    let mut buf = vec![0_u8; 4096];

    loop {
        // SAFETY: `name` is a valid NUL-terminated string owned for the
        // call; `pwd` and `result` are correctly-typed out-params; `buf` is
        // a valid buffer whose length is passed alongside its pointer, per
        // getpwnam_r(3).
        let rc = unsafe {
            libc::getpwnam_r(
                name.as_ptr(),
                &mut pwd,
                buf.as_mut_ptr().cast(),
                buf.len(),
                &mut result,
            )
        };
        match rc {
            0 if result.is_null() => return AccountResolution::NotFound,
            0 => {
                return AccountResolution::Resolved {
                    uid: pwd.pw_uid,
                    gid: pwd.pw_gid,
                }
            }
            libc::ERANGE => {
                if buf.len() >= MAX_PWBUF_LEN {
                    return AccountResolution::LookupFailed;
                }
                buf.resize((buf.len() * 2).min(MAX_PWBUF_LEN), 0);
            }
            _ => return AccountResolution::LookupFailed,
        }
    }
}

/// Windows has no account database this module can consult, and no channel
/// on that arm needs one — the loopback listener has no credential to check
/// against. Fails closed to root-only, like every other unresolved case.
#[cfg(not(unix))]
pub fn resolve_account(account: Option<&str>) -> AccountResolution {
    match account {
        None => AccountResolution::NotRequested,
        Some(_) => AccountResolution::LookupFailed,
    }
}

// ── Listener ─────────────────────────────────────────────────────────────

enum ListenerInner {
    #[cfg(unix)]
    Unix {
        listener: tokio::net::UnixListener,
        path: PathBuf,
    },
    Tcp(tokio::net::TcpListener),
}

/// An accept loop that enforces the channel's allowlist.
pub struct LocalListener {
    inner: ListenerInner,
    admitted_uids: Vec<u32>,
    refused: AtomicU64,
}

impl LocalListener {
    /// Accept the next ADMITTED connection.
    ///
    /// Refused peers are counted and logged, and this keeps waiting: one
    /// unlisted local process must not be able to end the channel by
    /// knocking on it. The returned identity is the kernel's, for the
    /// caller's own logging and attribution — the decision has already been
    /// made here.
    pub async fn accept(&self) -> io::Result<(LocalStream, PeerIdentity)> {
        loop {
            let (stream, peer) = self.accept_raw().await?;
            if peer_admitted(&peer, &self.admitted_uids) {
                match peer_image_admitted(&peer) {
                    ImageVerdict::Ours { .. }
                    | ImageVerdict::OursSelf
                    | ImageVerdict::OursByProtection
                    | ImageVerdict::NotChecked => {
                        return Ok((stream, peer));
                    }
                    // Admitted: the RUNNING image is one of ours, which is
                    // the whole question this check asks. Logged at WARN
                    // rather than silently, because it states a real and
                    // temporary condition of the box — a service is running
                    // a binary that no longer exists at its own path, so
                    // what is on disk is NOT what is executing until that
                    // unit restarts.
                    ImageVerdict::OursImageReplaced { unit } => {
                        tracing::warn!(
                            ?peer,
                            unit,
                            "[local] admitted a peer whose binary was replaced on disk while it was \
                             running — the process is still ours, but the file at its path is a \
                             different one, so this unit is NOT running what a deploy just put \
                             there"
                        );
                        return Ok((stream, peer));
                    }
                    ImageVerdict::Foreign(reason) => {
                        self.refused.fetch_add(1, Ordering::Relaxed);
                        // The uid was fine and the program was not. Louder
                        // than the uid refusal below, because this is the
                        // shape of a swapped binary: something that IS root
                        // on this box speaking on a channel meant for the
                        // eight programs we ship.
                        tracing::error!(
                            ?peer,
                            reason = %reason,
                            "[local] refused a peer on a box-local channel — the program on the other end is not one of ours"
                        );
                        drop(stream);
                        continue;
                    }
                }
            }
            self.refused.fetch_add(1, Ordering::Relaxed);
            // Loud on purpose. These sockets carry the operator's path onto
            // the box and the arbiter's view of it; an unlisted local peer
            // reaching `accept()` at all means something tried to speak on
            // that channel, and that is worth a human's attention every
            // time, not just a count.
            tracing::error!(
                ?peer,
                admitted_uids = ?self.admitted_uids,
                "[local] refused a peer on a box-local channel — uid not admitted"
            );
            drop(stream);
        }
    }

    async fn accept_raw(&self) -> io::Result<(LocalStream, PeerIdentity)> {
        match &self.inner {
            #[cfg(unix)]
            ListenerInner::Unix { listener, .. } => {
                let (stream, _addr) = listener.accept().await?;
                // SO_PEERCRED before a single byte is read. The question
                // this channel has to answer is "who is this", not "what
                // did they say" — and a credential read after the first
                // read is a credential read after the decision.
                let cred = stream.peer_cred()?;
                let peer = PeerIdentity::Credentials {
                    uid: cred.uid(),
                    gid: cred.gid(),
                    pid: cred.pid(),
                };
                Ok((LocalStream(StreamInner::Unix(stream)), peer))
            }
            ListenerInner::Tcp(listener) => {
                let (stream, peer) = listener.accept().await?;
                Ok((
                    LocalStream(StreamInner::Tcp(stream)),
                    PeerIdentity::Loopback { peer },
                ))
            }
        }
    }

    /// How many peers this listener has refused since it bound. Exposed so
    /// a refusal is visible to an operator as a NUMBER, not only as a line
    /// in a journal that may have rotated.
    pub fn refused(&self) -> u64 {
        self.refused.load(Ordering::Relaxed)
    }

    /// The uids this listener admits.
    pub fn admitted_uids(&self) -> &[u32] {
        &self.admitted_uids
    }

    /// Where this listener is bound, for logging.
    pub fn endpoint(&self) -> LocalEndpoint {
        match &self.inner {
            #[cfg(unix)]
            ListenerInner::Unix { path, .. } => LocalEndpoint::Unix(path.clone()),
            ListenerInner::Tcp(l) => LocalEndpoint::Tcp(
                l.local_addr()
                    .unwrap_or_else(|_| SocketAddr::from(([127, 0, 0, 1], 0))),
            ),
        }
    }
}

/// What the check of the peer's running program concluded.
#[derive(Debug)]
pub enum ImageVerdict {
    /// The peer runs one of the binaries this fleet ships, named here.
    Ours { unit: &'static str },
    /// The peer runs THE VERY PROGRAM THIS PROCESS RUNS FROM.
    ///
    /// A box that hosts both ends of a channel in one program — the
    /// standalone box, where the perimeter and the node are one binary — has
    /// a peer whose image is our image. The fleet's table names its daemons
    /// by path, and a standalone box ships a program under its own name, so
    /// the table cannot name it: without this arm the box refuses its own
    /// channels and every customer connection dies silently behind the
    /// perimeter.
    ///
    /// The check's own question is "is the program on the other end one of
    /// ours", and for the same image the answer is yes by definition. It
    /// stays narrow — the paths must be equal, so a different program that
    /// happens to be a copy of ours elsewhere on the disk is still refused.
    OursSelf,
    /// The kernel REFUSED to name the peer's image. On a Tier2 box that is
    /// the signature of one of our own daemons — see [`peer_image_admitted`].
    OursByProtection,
    /// The peer runs one of our binaries, and the FILE it was started from
    /// has since been replaced or removed on disk. Admitted — the running
    /// image is still ours, which is the only thing this check asks — but
    /// reported separately, because "this process no longer matches the
    /// file at its own path" is a fact an operator wants to see.
    OursImageReplaced { unit: &'static str },
    /// It runs something else, or it is already gone.
    Foreign(String),
    /// This target has no `/proc` to ask (Windows: the dev box and
    /// `cargo test`). The uid check stands alone there, as it always did.
    NotChecked,
}


/// What the kernel appends to `/proc/<pid>/exe` when the file the process
/// was started from is no longer linked into the filesystem.
const DELETED_SUFFIX: &str = " (deleted)";

/// If the kernel appended [`DELETED_SUFFIX`] to a rendered `/proc/<pid>/exe`
/// path, give back the real path underneath it. `None` when the suffix is
/// absent, or when it cannot be shown to be the kernel's.
///
/// # The defect this exists for
///
/// [`peer_image_admitted`]'s own doc states the property this check relies
/// on: `/proc/<pid>/exe` names the RUNNING IMAGE, and replacing the file on
/// disk afterwards does not move it — the process keeps running from the old
/// inode. That is true of the LINK. It is not true of how the kernel RENDERS
/// the link: once the original dentry is gone, `d_path` appends
/// [`DELETED_SUFFIX`], and `unit_name_for_exe` compares by exact equality
/// (deliberately — never a prefix or glob match), so the rendered string
/// stops matching the allowlist the instant the file is replaced.
///
/// Measured on `us-example-203.0.113.25`, 2026-08-21, twice. Uploading a new
/// `mirage-perimeter` over the running one made the LIVE process foreign on
/// every box-local channel within the same second:
///
/// ```text
/// ERROR [local] refused a peer on a box-local channel — the program on the
///       other end is not one of ours
///       peer=Credentials { uid: 999, gid: 988, pid: Some(725) }
///       reason=running /usr/local/bin/mirage-perimeter (deleted)
/// ```
///
/// The perimeter kept its identity, kept its faces and kept serving every
/// port; what it lost was the right to splice SSH through to mshd, so the
/// box's front door accepted connections and closed them with zero bytes.
/// Both times, recovery was a power cycle. This is not specific to the
/// perimeter: hot-replacing ANY of the binaries in
/// [`crate::mirage_units::MIRAGE_UNITS`] severs that running service from
/// the box's local channels until it restarts.
///
/// # Why this is not just `trim_end_matches`
///
/// A path may legitimately END in that text: nothing stops a local attacker
/// from creating a file literally named `/usr/local/bin/mirage-perimeter
/// (deleted)` and running it, at which point a naive strip would hand it the
/// allowlist entry for the real binary. So the suffix is only removed when
/// no file bears the rendered name — if something is actually there, the
/// text came from the filesystem rather than from `d_path`, and this refuses
/// to speak for it. `exists` is injected so that decision is testable
/// without a `/proc` or a planted file.
///
/// Fails closed in both directions: no suffix, or a suffix that cannot be
/// shown to be the kernel's, yields `None` and the caller refuses exactly as
/// it did before.
fn strip_kernel_deleted_suffix<'a>(shown: &'a str, exists: impl Fn(&str) -> bool) -> Option<&'a str> {
    let stripped = shown.strip_suffix(DELETED_SUFFIX)?;
    if stripped.is_empty() || exists(shown) {
        return None;
    }
    Some(stripped)
}

/// The systemd unit named by one `/proc/<pid>/cgroup` line, if it names one.
///
/// cgroup v2 prints a single line, `0::<path>`, e.g.
/// `0::/system.slice/mirage-perimeter.service`. v1 prints several
/// `hier:controllers:path` lines. Both end in the unit's directory when the
/// process belongs to a systemd service, so the last `/`-separated component
/// that ends in `.service` is the answer, and anything else is `None`.
///
/// Pure and separate from the file read so it can be tested without a
/// `/proc` — the shapes below are the ones measured on the fleet.
#[must_use]
pub fn unit_from_cgroup_text(text: &str) -> Option<&str> {
    text.lines()
        .filter_map(|line| line.rsplit(':').next())
        .filter_map(|path| path.rsplit('/').next())
        .find(|last| last.ends_with(".service"))
}

/// The mirage unit that owns `pid`'s cgroup, if any.
///
/// # Why this is asked BEFORE `/proc/<pid>/exe`
///
/// `exe`, `fd/`, `maps` and `mem` are all gated by `ptrace_may_access`, and
/// this fleet's own Tier-2 hook denies exactly that for every protected
/// mirage daemon. [`peer_image_admitted`] therefore used to read the DENY as
/// its answer — `PermissionDenied` meant "one of ours" — and generated one
/// kernel security event per accept while doing it. Measured on the canary
/// 2026-08-29: `mirage2monitor-v2` reading `mirage-perimeter` was six rows
/// and sixty-three aggregated denies in a 26.5-second window, tracking
/// inbound wire traffic rather than any timer, and the fleet's whole
/// kernel-event history was 26 seconds because rows like these crowd out
/// everything else.
///
/// `/proc/<pid>/cgroup` is **not** ptrace-gated. It is world-readable, it
/// names the systemd unit outright, and reading it provokes nothing.
///
/// # And it is a stronger check, not merely a cheaper one
///
/// The deny arm admits ANY peer whose `exe` cannot be read — it infers
/// "must be ours" from a refusal, which is true only while Tier-2 is armed
/// and protects exactly our set. This names the unit. Placing a process into
/// another unit's cgroup requires root and write access to the cgroup
/// hierarchy, which is strictly more than what the deny arm already lets
/// through.
///
/// A cgroup that names no mirage unit falls through to the original
/// `readlink` path unchanged, so nothing that used to be refused is now
/// admitted: this arm can only turn a deny-inferred `OursByProtection` into
/// a named `Ours`.
///
/// `pid` is taken as the platform's own `pid_t` (`i32`), the type
/// `SO_PEERCRED` yields, rather than a widened one — a value that is not a
/// real pid must not be silently converted into a `/proc` path that could
/// name a different process.
#[cfg(unix)]
fn mirage_unit_from_cgroup_file(pid: i32) -> Option<&'static str> {
    if pid <= 0 {
        return None;
    }
    let text = std::fs::read_to_string(format!("/proc/{pid}/cgroup")).ok()?;
    let unit = unit_from_cgroup_text(&text)?;
    crate::mirage_units::MIRAGE_UNITS
        .iter()
        .find(|u| u.unit_name == unit)
        .map(|u| u.unit_name)
}

/// Which program is on the other end of this connection.
///
/// # Why the uid is not enough
///
/// `SO_PEERCRED` answers "which ACCOUNT is calling", and on this fleet the
/// answer is almost always root — admitted on every box-local channel
/// deliberately, because root can `setuid`, `chown` the socket or read the
/// keys directly, so excluding it buys nothing. What that leaves unanswered
/// is "which PROGRAM": anything running as root could open these sockets and
/// be indistinguishable from the daemon that belongs there.
///
/// # The kernel answers, and on this fleet it answers in two ways
///
/// `SO_PEERCRED` also carries the peer's pid, and `/proc/<pid>/exe` links to
/// the RUNNING IMAGE — not to a path that could have been replaced since.
/// Replacing the file on disk after the process started does not move that
/// link: the process keeps running from the old inode.
///
/// Measured on nl-example-203.0.113.31, 2026-08-15, as root on a Tier2 box:
///
/// ```text
/// readlink /proc/1/exe    -> /usr/lib/systemd/systemd   rc=0
/// readlink /proc/self/exe -> /usr/bin/readlink          rc=0
/// readlink /proc/401/exe  ->                            rc=1   (the monitor)
/// ```
///
/// So the deny is not an obstacle to this check — it IS the check's second
/// half. Tier2 protects exactly the binaries this fleet ships, so a peer
/// whose image the kernel refuses to name is one of ours, and a peer whose
/// image reads freely has to be in [`crate::mirage_units::MIRAGE_UNITS`] to
/// be admitted. Both arms are covered on a box where Tier2 is NOT armed
/// (Tier0/Tier1): there everything reads, and the path allowlist decides
/// alone.
///
/// A vanished process is refused rather than admitted: `NotFound` is not
/// `PermissionDenied`, and a peer that is already gone has nothing to serve.
///
/// # Why a path and not a hash
///
/// A path costs one `readlink`; a hash costs reading the whole binary on
/// every accept — and, per the measurement above, the read is denied for
/// exactly the binaries worth hashing. The content question belongs to a
/// measurement taken once, by the warden, and verified by the operator
/// against what it built.
///
/// # The pid is a handle, never an identity
///
/// It is read inside this one `accept` and never stored: pids are recycled
/// and differ across every boot. The verdict is recomputed per connection.
pub fn peer_image_admitted(peer: &PeerIdentity) -> ImageVerdict {
    #[cfg(unix)]
    {
        let PeerIdentity::Credentials { pid, .. } = peer else {
            // A loopback TCP peer on a unix target: a test rig, never a
            // fleet path. It has no pid to ask about.
            return ImageVerdict::NotChecked;
        };
        let Some(pid) = pid else {
            return ImageVerdict::Foreign(
                "the kernel gave no pid for this peer, so its program cannot be named".to_string(),
            );
        };
        // Ask the cheap, ungated question first. See
        // `mirage_unit_from_cgroup_file` for why this is not merely an
        // optimisation.
        if let Some(unit) = mirage_unit_from_cgroup_file(*pid) {
            return ImageVerdict::Ours { unit };
        }

        let link = format!("/proc/{pid}/exe");
        match std::fs::read_link(&link) {
            Ok(image) => {
                let shown = image.to_string_lossy().to_string();
                if let Some(unit) = crate::mirage_units::unit_name_for_exe(&shown) {
                    return ImageVerdict::Ours { unit };
                }
                // The very program this process runs from. The fleet's table
                // names its daemons by path; a box that hosts both ends of a
                // channel in ONE binary cannot be named by that table, and
                // without this arm it refuses its own channels.
                if is_our_own_image(&shown) {
                    return ImageVerdict::OursSelf;
                }
                // The path did not match verbatim. Before calling it
                // foreign, ask whether the kernel appended DELETED_SUFFIX —
                // see `strip_kernel_deleted_suffix` for why that is a
                // different fact from "the path ends in that text".
                match strip_kernel_deleted_suffix(&shown, |p| std::path::Path::new(p).exists())
                    .and_then(crate::mirage_units::unit_name_for_exe)
                {
                    Some(unit) => ImageVerdict::OursImageReplaced { unit },
                    None => ImageVerdict::Foreign(format!("running {shown}")),
                }
            }
            Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
                ImageVerdict::OursByProtection
            }
            Err(e) => ImageVerdict::Foreign(format!("cannot read {link}: {e}")),
        }
    }
    #[cfg(not(unix))]
    {
        let _ = peer;
        ImageVerdict::NotChecked
    }
}

/// Is the path the kernel named the very image THIS process runs from?
///
/// The kernel answers `/proc/<pid>/exe` with the peer's running image; our
/// own answer to the same question is `/proc/self/exe`, which
/// `std::env::current_exe` reads. Equal paths mean the peer runs the SAME
/// program as this process — the standalone box's case, where the perimeter
/// and the node are one binary, so the peer on the channel between them is
/// us.
///
/// An image whose file was removed keeps the same path with the kernel's
/// suffix appended; that goes through the same helper that decides whether
/// the suffix is really the kernel's, so a file that merely carries that
/// text cannot buy admission.
fn is_our_own_image(shown: &str) -> bool {
    let Ok(own) = std::env::current_exe() else {
        return false;
    };
    let own = own.to_string_lossy();
    if own == shown {
        return true;
    }
    strip_kernel_deleted_suffix(shown, |p| std::path::Path::new(p).exists())
        .is_some_and(|stripped| stripped == own)
}

// ── Stream ───────────────────────────────────────────────────────────────

#[derive(Debug)]
enum StreamInner {
    #[cfg(unix)]
    Unix(tokio::net::UnixStream),
    Tcp(tokio::net::TcpStream),
}

/// A byte stream on either arm.
///
/// `AsyncRead + AsyncWrite` is the whole contract, which is all
/// `russh::server::run_stream` and `tokio::io::copy_bidirectional` need —
/// neither cares what is underneath.
///
/// `Debug` so a caller can log a stream, and so `io::Result<LocalStream>`
/// can be `unwrap_err`'d in a test without the type getting in the way.
#[derive(Debug)]
pub struct LocalStream(StreamInner);

impl LocalStream {
    /// `TCP_NODELAY` on the TCP arm; a no-op on the unix arm, which has no
    /// Nagle to disable. Kept so a splice can ask for it unconditionally
    /// rather than branching on the transport at the call site.
    pub fn set_nodelay(&self, nodelay: bool) -> io::Result<()> {
        match &self.0 {
            #[cfg(unix)]
            StreamInner::Unix(_) => Ok(()),
            StreamInner::Tcp(s) => s.set_nodelay(nodelay),
        }
    }
}

impl AsyncRead for LocalStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match &mut self.get_mut().0 {
            #[cfg(unix)]
            StreamInner::Unix(s) => Pin::new(s).poll_read(cx, buf),
            StreamInner::Tcp(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for LocalStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match &mut self.get_mut().0 {
            #[cfg(unix)]
            StreamInner::Unix(s) => Pin::new(s).poll_write(cx, buf),
            StreamInner::Tcp(s) => Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut self.get_mut().0 {
            #[cfg(unix)]
            StreamInner::Unix(s) => Pin::new(s).poll_flush(cx),
            StreamInner::Tcp(s) => Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut self.get_mut().0 {
            #[cfg(unix)]
            StreamInner::Unix(s) => Pin::new(s).poll_shutdown(cx),
            StreamInner::Tcp(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}

#[cfg(test)]
mod cgroup_identification_tests {
    use super::unit_from_cgroup_text;

    /// cgroup v2, the shape every fleet box prints. Measured on the canary
    /// 2026-08-29.
    #[test]
    fn a_v2_line_names_its_unit() {
        assert_eq!(
            unit_from_cgroup_text("0::/system.slice/mirage-perimeter.service\n"),
            Some("mirage-perimeter.service")
        );
        assert_eq!(
            unit_from_cgroup_text("0::/system.slice/systemd-journald.service\n"),
            Some("systemd-journald.service")
        );
    }

    /// cgroup v1 prints one line per hierarchy; the unit is still the last
    /// path component.
    #[test]
    fn a_v1_multi_line_body_still_names_its_unit() {
        let v1 = "12:pids:/system.slice/mirage-secd.service\n\
                  4:memory:/system.slice/mirage-secd.service\n\
                  0::/system.slice/mirage-secd.service\n";
        assert_eq!(unit_from_cgroup_text(v1), Some("mirage-secd.service"));
    }

    /// A process outside any service — a login shell, a scope, the root
    /// cgroup — names no unit, and must not be guessed at.
    #[test]
    fn a_process_in_no_service_names_nothing() {
        assert_eq!(unit_from_cgroup_text("0::/\n"), None);
        assert_eq!(unit_from_cgroup_text("0::/user.slice/user-1000.slice/session-3.scope\n"), None);
        assert_eq!(unit_from_cgroup_text(""), None);
        // A `.slice` is not a `.service` — the suffix test is exact.
        assert_eq!(unit_from_cgroup_text("0::/system.slice\n"), None);
    }

    /// The name is taken whole. A cgroup path that merely CONTAINS a unit
    /// name deeper up must not be mistaken for it — the last component is
    /// the one that owns the process.
    #[test]
    fn only_the_last_component_counts() {
        assert_eq!(
            unit_from_cgroup_text("0::/system.slice/mirage-secd.service/sub.service\n"),
            Some("sub.service")
        );
    }
}

#[cfg(test)]
mod tests {

    // ── the kernel's "(deleted)" rendering ───────────────────────────────
    //
    // Uploading a new binary over a running service used to make that
    // service foreign on every box-local channel, instantly, because the
    // rendered `/proc/<pid>/exe` stopped matching the allowlist. Twice on
    // `us-example-203.0.113.25` that took the box's front door with it — see
    // `strip_kernel_deleted_suffix`'s own doc.

    /// The path underneath the kernel's suffix is the one the allowlist
    /// knows. Nothing is on disk under the rendered name, so the suffix is
    /// the kernel's.
    #[test]
    fn a_replaced_binary_resolves_to_the_path_it_was_started_from() {
        let shown = "/usr/local/bin/mirage-perimeter (deleted)";
        assert_eq!(
            strip_kernel_deleted_suffix(shown, |_| false),
            Some("/usr/local/bin/mirage-perimeter")
        );
    }

    /// The attack this is not allowed to open: a local file literally named
    /// `<our binary> (deleted)`. Nothing was deleted, the text came from the
    /// filesystem, and handing it our allowlist entry would let anything
    /// that can create a file speak on these channels.
    #[test]
    fn a_file_actually_named_deleted_is_never_given_our_allowlist_entry() {
        let shown = "/usr/local/bin/mirage-perimeter (deleted)";
        assert_eq!(strip_kernel_deleted_suffix(shown, |p| p == shown), None);
    }

    /// An ordinary path is untouched — the common case must not go anywhere
    /// near this.
    #[test]
    fn a_path_without_the_suffix_is_not_stripped() {
        assert_eq!(
            strip_kernel_deleted_suffix("/usr/local/bin/mirage-perimeter", |_| false),
            None
        );
    }

    /// Stripping is not admission. A foreign binary that happens to have
    /// been deleted resolves to a foreign path, and the allowlist still
    /// refuses it.
    #[test]
    fn a_deleted_foreign_binary_is_still_foreign() {
        let stripped = strip_kernel_deleted_suffix("/tmp/evil (deleted)", |_| false);
        assert_eq!(stripped, Some("/tmp/evil"));
        assert!(crate::mirage_units::unit_name_for_exe(stripped.unwrap()).is_none());
    }

    /// The suffix alone names no program.
    #[test]
    fn the_suffix_on_its_own_resolves_to_nothing() {
        assert_eq!(strip_kernel_deleted_suffix(" (deleted)", |_| false), None);
    }

    /// End to end through the allowlist: what the box actually reported on
    /// 2026-08-21 now names its unit instead of being refused.
    #[test]
    fn the_line_the_box_logged_now_resolves_to_the_perimeter_unit() {
        let shown = "/usr/local/bin/mirage-perimeter (deleted)";
        let unit = strip_kernel_deleted_suffix(shown, |_| false)
            .and_then(crate::mirage_units::unit_name_for_exe);
        assert_eq!(unit, Some("mirage-perimeter.service"));
    }
    // ── the peer's program ───────────────────────────────────────────────

    // Unix only, and that is the point: on Windows there is no `/proc` to
    // ask, so every peer is `NotChecked` and this arm does not exist.
    #[cfg(unix)]
    #[test]
    fn a_peer_the_kernel_gave_no_pid_for_is_refused() {
        // "Cannot be named" is not "probably fine" — the same discipline the
        // uid check uses. On Linux the kernel always fills this, so reaching
        // this arm at all is a condition worth refusing on.
        let verdict = peer_image_admitted(&PeerIdentity::Credentials {
            uid: 0,
            gid: 0,
            pid: None,
        });
        assert!(matches!(verdict, ImageVerdict::Foreign(_)), "{verdict:?}");
    }

    #[test]
    fn a_loopback_peer_has_no_program_to_check() {
        // The Windows arm and the test rigs. There is no `/proc` to ask, and
        // the uid check stands alone there exactly as it did before.
        let verdict = peer_image_admitted(&PeerIdentity::Loopback {
            peer: SocketAddr::from(([127, 0, 0, 1], 1234)),
        });
        assert!(matches!(verdict, ImageVerdict::NotChecked), "{verdict:?}");
    }

    /// The box that hosts BOTH ends of a channel in one binary: the peer on
    /// the wire is this very process. The fleet's table cannot name that
    /// binary — it names daemons by path, and a standalone box ships one
    /// program under its own name — so without this arm the box refuses its
    /// own channels and every customer dies silently behind the perimeter.
    #[cfg(unix)]
    #[test]
    fn our_own_image_is_admitted() {
        let verdict = peer_image_admitted(&PeerIdentity::Credentials {
            uid: 0,
            gid: 0,
            pid: Some(std::process::id()),
        });
        assert!(matches!(verdict, ImageVerdict::OursSelf), "{verdict:?}");
    }

    /// The arm stays narrow: a different program that merely resembles ours
    /// is not us.
    #[test]
    fn a_foreign_path_is_not_our_own_image() {
        assert!(!is_our_own_image("/usr/local/bin/something-else"));
        assert!(!is_our_own_image(""));
        assert!(!is_our_own_image("/tmp/evil (deleted)"));
    }

    #[test]
    fn every_shipped_binary_resolves_to_a_unit() {
        // The allowlist this check reads is the same table the rest of the
        // fleet names its binaries by. An entry that stopped resolving would
        // silently turn one of our own daemons into a refused peer.
        for unit in crate::mirage_units::MIRAGE_UNITS {
            assert_eq!(
                crate::mirage_units::unit_name_for_exe(unit.exe_path),
                Some(unit.unit_name),
                "{} must resolve",
                unit.exe_path
            );
        }
    }

    use super::*;

    // ── The table's invariants. Pure, and they run on every target. ──

    #[test]
    fn no_two_channels_share_a_path() {
        for (i, a) in LocalChannel::ALL.iter().enumerate() {
            for b in &LocalChannel::ALL[i + 1..] {
                assert_ne!(
                    a.unix_path(),
                    b.unix_path(),
                    "{} and {} would bind the same socket",
                    a.label(),
                    b.label()
                );
            }
        }
    }

    #[test]
    fn the_wire_splice_and_the_control_plane_are_different_sockets() {
        // The load-bearing separation: the perimeter's uid must not be able
        // to open the control plane. One socket with a uid check in the
        // handler puts that in a branch a later endpoint can be added beside.
        assert_ne!(
            LocalChannel::MonitorWireSplice.unix_path(),
            LocalChannel::MonitorControl.unix_path()
        );
        assert!(
            LocalChannel::MonitorControl.peer_accounts().is_empty(),
            "the control plane admits root only"
        );
        assert_eq!(
            LocalChannel::MonitorWireSplice.peer_accounts(),
            &[PERIMETER_ACCOUNT]
        );
    }

    #[test]
    fn the_slice_channel_and_the_handover_channel_are_different_sockets_with_different_grants() {
        // "The transport must not be able to ask for a slice, and a service
        // must not be able to deliver an envelope" only holds if the two
        // sockets sit in DIFFERENT managed directories: two grant-managed
        // directories cannot share one path, or whichever channel binds
        // last silently overwrites the other's grant (see
        // MACHINE_IDENTITY_HANDOVER_SOCK's own doc).
        assert_ne!(
            LocalChannel::MachineIdentity.unix_path(),
            LocalChannel::MachineIdentityHandover.unix_path()
        );
        assert_ne!(
            LocalChannel::MachineIdentity.managed_dir(),
            LocalChannel::MachineIdentityHandover.managed_dir(),
            "the two machine-identity sockets must not share a managed directory"
        );
        assert_eq!(
            LocalChannel::MachineIdentity.peer_accounts(),
            &[PERIMETER_ACCOUNT, EDGE_ACCOUNT],
            "the de-rooted services are the perimeter and mirage-edge, in that order; every \
             other caller is still root"
        );
        assert_eq!(
            LocalChannel::MachineIdentityHandover.peer_accounts(),
            &[MSHD_ACCOUNT],
            "mshd, and only mshd, carries bytes across this seam"
        );
    }

    #[test]
    fn only_the_slice_channel_names_the_edge_account() {
        // The edge account gets no other channel: every other in-box
        // channel is a separate socket whose grant it has no part in, so a
        // change to the slice channel's table can never widen one of them.
        for ch in LocalChannel::ALL {
            let names_edge = ch.peer_accounts().contains(&EDGE_ACCOUNT);
            assert_eq!(
                names_edge,
                ch == LocalChannel::MachineIdentity,
                "{} has the wrong answer for naming {EDGE_ACCOUNT}",
                ch.label(),
            );
        }
    }

    #[test]
    fn the_edge_client_entrance_channel_admits_the_node_and_only_the_node() {
        // Mirrors NodeChainSplice's own shape (a different daemon LISTENS
        // and admits the one caller it expects), reversed: here cli2's
        // edge-client supervisor listens and the node is the caller.
        assert_ne!(
            LocalChannel::EdgeClientEntrance.unix_path(),
            LocalChannel::NodeChainSplice.unix_path()
        );
        assert_eq!(
            LocalChannel::EdgeClientEntrance.peer_accounts(),
            &[NODE_ACCOUNT]
        );
        assert_eq!(
            LocalChannel::EdgeClientEntrance.unix_path(),
            "/run/mirage/edge-client/entrance.sock"
        );
    }

    #[test]
    fn the_edge_chain_splice_channel_admits_the_perimeter_and_only_the_perimeter() {
        // Mirrors NodeChainSplice's own shape exactly: `mirage-edge` LISTENS,
        // the de-rooted perimeter is the one caller admitted — the edge box's
        // own sibling of the node's chain splice, since an edge box runs no
        // node at all.
        assert_ne!(
            LocalChannel::EdgeChainSplice.unix_path(),
            LocalChannel::NodeChainSplice.unix_path()
        );
        assert_eq!(
            LocalChannel::EdgeChainSplice.peer_accounts(),
            &[PERIMETER_ACCOUNT]
        );
        assert_eq!(
            LocalChannel::EdgeChainSplice.unix_path(),
            "/run/mirage/edge/chain.sock"
        );
    }

    #[test]
    fn every_socket_lives_under_the_run_root() {
        for ch in LocalChannel::ALL {
            assert!(
                ch.unix_path().starts_with(RUN_ROOT),
                "{} escapes {RUN_ROOT}",
                ch.label()
            );
        }
    }

    #[test]
    fn no_channel_manages_the_shared_root() {
        // /run/mirage holds warden.sock and secd/. A channel tightening it
        // would break neighbours that never asked.
        for ch in LocalChannel::ALL {
            if let Some(dir) = ch.managed_dir() {
                assert_ne!(
                    dir,
                    Path::new(RUN_ROOT),
                    "{} would re-mode the shared root",
                    ch.label()
                );
            }
        }
        // And the one channel that keeps its legacy path in the root manages
        // no directory at all.
        assert_eq!(LocalChannel::MonitorControl.managed_dir(), None);
    }

    #[test]
    fn the_monitor_control_channel_keeps_the_path_that_is_already_live() {
        // mirage_mesh_client::local_transport::MIRAGE_LOCAL_SOCKET_PATH.
        // Renaming it would move a channel that already works.
        assert_eq!(
            LocalChannel::MonitorControl.unix_path(),
            "/run/mirage/monitor.sock"
        );
    }

    // ── The plan, from a resolution. Pure. ──

    #[test]
    fn a_resolved_account_is_both_admitted_and_reachable() {
        // The defect this keeps closed: a socket admitting uid 995 while the
        // filesystem refused it, with the daemon logging that 995 was
        // allowed. Being on the allowlist and being able to reach the socket
        // are ONE decision, so they come from one resolution.
        let plan = plan_from_resolution(AccountResolution::Resolved { uid: 995, gid: 986 });
        assert!(peer_admitted(
            &PeerIdentity::Credentials { uid: 995, gid: 986, pid: None },
            &plan.admitted_uids
        ));
        assert_eq!(plan.grant.gid, Some(986));
        assert_eq!(plan.grant.dir_mode, 0o710, "traverse without list");
        assert_eq!(plan.grant.socket_mode, 0o660);
        assert_eq!(plan.grant.dir_mode & 0o007, 0, "others keep nothing");
        assert_eq!(plan.grant.socket_mode & 0o007, 0);
    }

    #[test]
    fn root_stays_admitted_on_every_resolution() {
        // Deliberate, and the module doc says why: excluding root buys
        // nothing (it can setuid, chown, or read the keys) and costs the
        // operator path on a box whose perimeter is not de-rooted yet.
        for r in [
            AccountResolution::NotRequested,
            AccountResolution::Resolved { uid: 995, gid: 986 },
            AccountResolution::NotFound,
            AccountResolution::LookupFailed,
        ] {
            let plan = plan_from_resolution(r);
            assert!(
                peer_admitted(
                    &PeerIdentity::Credentials { uid: 0, gid: 0, pid: None },
                    &plan.admitted_uids
                ),
                "root must stay admitted on {r:?}"
            );
        }
    }

    #[test]
    fn an_unresolved_account_leaves_the_socket_owner_only() {
        for r in [
            AccountResolution::NotRequested,
            AccountResolution::NotFound,
            AccountResolution::LookupFailed,
        ] {
            let plan = plan_from_resolution(r);
            assert_eq!(plan.grant.gid, None, "no grant on {r:?}");
            assert_eq!(plan.grant.dir_mode, 0o700);
            assert_eq!(plan.grant.socket_mode, 0o600);
            assert_eq!(plan.admitted_uids, vec![0], "root only on {r:?}");
            assert!(
                !peer_admitted(
                    &PeerIdentity::Credentials { uid: 1000, gid: 1000, pid: None },
                    &plan.admitted_uids
                ),
                "an arbitrary local uid must be refused on {r:?}"
            );
        }
    }

    #[test]
    fn a_root_gid_is_not_treated_as_a_grant() {
        // Granting a group that already owns the socket is a no-op dressed
        // as a permission change, and 0o660/0o710 would be a real loosening
        // the day the account were not root.
        let plan = plan_from_resolution(AccountResolution::Resolved { uid: 0, gid: 0 });
        assert_eq!(plan.grant.gid, None);
        assert_eq!(plan.grant.socket_mode, 0o600);
        assert_eq!(plan.admitted_uids, vec![0], "no duplicate root entry");
    }

    #[test]
    fn a_uid_one_off_the_resolved_one_is_still_refused() {
        let plan = plan_from_resolution(AccountResolution::Resolved { uid: 995, gid: 986 });
        for uid in [994_u32, 996, 1000, u32::MAX] {
            assert!(
                !peer_admitted(
                    &PeerIdentity::Credentials { uid, gid: 0, pid: None },
                    &plan.admitted_uids
                ),
                "uid {uid} must be refused"
            );
        }
    }

    // ── A channel with two de-rooted accounts. Pure. ──

    const PERIMETER: AccountResolution = AccountResolution::Resolved { uid: 995, gid: 986 };
    const EDGE: AccountResolution = AccountResolution::Resolved { uid: 994, gid: 985 };

    #[test]
    fn two_resolved_accounts_are_both_admitted_and_the_first_group_owns_the_socket() {
        let plan = plan_from_resolutions(&[PERIMETER, EDGE]);
        assert_eq!(plan.admitted_uids, vec![0, 995, 994], "root, then each account in order");
        assert_eq!(plan.grant.gid, Some(986), "the perimeter keeps owning the socket");
        assert_eq!(plan.grant.also_gids, vec![985], "the edge's group is the added entry");
        assert_eq!(plan.grant.dir_mode, 0o710, "traverse without list");
        assert_eq!(plan.grant.socket_mode, 0o660);
        assert_eq!(plan.grant.dir_mode & 0o007, 0, "others keep nothing");
        assert_eq!(plan.grant.socket_mode & 0o007, 0);
    }

    #[test]
    fn both_accounts_are_reachable_and_admitted_by_the_same_resolution() {
        // The defect this module keeps closed, now for the second account:
        // being on the allowlist and being able to reach the socket are ONE
        // decision. Every admitted non-root uid has its group in the grant.
        let plan = plan_from_resolutions(&[PERIMETER, EDGE]);
        for (resolution, uid, gid) in [(PERIMETER, 995, 986), (EDGE, 994, 985)] {
            assert!(
                peer_admitted(&PeerIdentity::Credentials { uid, gid, pid: None }, &plan.admitted_uids),
                "{resolution:?} must be admitted"
            );
            assert!(
                plan.grant.gid == Some(gid) || plan.grant.also_gids.contains(&gid),
                "{resolution:?} must be able to reach the socket"
            );
        }
    }

    #[test]
    fn an_account_that_does_not_resolve_leaves_the_plan_as_the_other_alone_made_it() {
        // A box with no `mirage-edge` account: nothing about the slice
        // channel may differ from what it was before that account was named.
        let alone = plan_from_resolution(PERIMETER);
        for missing in [
            AccountResolution::NotFound,
            AccountResolution::LookupFailed,
            AccountResolution::NotRequested,
        ] {
            let plan = plan_from_resolutions(&[PERIMETER, missing]);
            assert_eq!(plan.grant, alone.grant, "grant must be unchanged with {missing:?}");
            assert!(plan.grant.also_gids.is_empty(), "no extra entry with {missing:?}");
            assert_eq!(plan.admitted_uids, alone.admitted_uids, "allowlist must be unchanged");
        }
    }

    #[test]
    fn the_edge_alone_owns_the_socket_when_the_perimeter_does_not_resolve() {
        // No extra entry is needed (or wanted) when only one group resolved:
        // the ordinary owner/group bits express it exactly.
        let plan = plan_from_resolutions(&[AccountResolution::NotFound, EDGE]);
        assert_eq!(plan.grant.gid, Some(985));
        assert!(plan.grant.also_gids.is_empty());
        assert_eq!(plan.admitted_uids, vec![0, 994]);
    }

    #[test]
    fn two_accounts_sharing_a_group_produce_no_extra_entry() {
        let sibling = AccountResolution::Resolved { uid: 996, gid: 986 };
        let plan = plan_from_resolutions(&[PERIMETER, sibling]);
        assert_eq!(plan.grant.gid, Some(986));
        assert!(plan.grant.also_gids.is_empty(), "the same group is granted once");
        assert_eq!(plan.admitted_uids, vec![0, 995, 996], "but both uids are still admitted");
    }

    #[test]
    fn a_root_group_is_never_an_extra_entry() {
        let root_grouped = AccountResolution::Resolved { uid: 997, gid: 0 };
        let plan = plan_from_resolutions(&[PERIMETER, root_grouped]);
        assert!(plan.grant.also_gids.is_empty());
        assert_eq!(plan.grant.gid, Some(986));
    }

    #[test]
    fn no_resolved_account_at_all_is_root_only() {
        let plan = plan_from_resolutions(&[AccountResolution::NotFound, AccountResolution::NotFound]);
        assert_eq!(plan.grant.gid, None);
        assert!(plan.grant.also_gids.is_empty());
        assert_eq!(plan.grant.dir_mode, 0o700);
        assert_eq!(plan.grant.socket_mode, 0o600);
        assert_eq!(plan.admitted_uids, vec![0]);
    }

    #[test]
    fn a_uid_that_is_neither_account_is_still_refused_on_the_two_account_plan() {
        let plan = plan_from_resolutions(&[PERIMETER, EDGE]);
        for uid in [993_u32, 996, 1000, u32::MAX] {
            assert!(
                !peer_admitted(
                    &PeerIdentity::Credentials { uid, gid: 0, pid: None },
                    &plan.admitted_uids
                ),
                "uid {uid} must be refused"
            );
        }
    }

    // ── The ACL value. Pure — the bytes are the contract with the kernel. ──

    #[test]
    fn the_directory_acl_grants_the_extra_group_traverse_and_nothing_else() {
        // posix_acl_xattr: le32 version, then {le16 tag, le16 perm, le32 id}.
        let expected: Vec<u8> = [
            &2u32.to_le_bytes()[..],
            // USER_OBJ rwx
            &[0x01, 0x00, 0x07, 0x00, 0xff, 0xff, 0xff, 0xff],
            // GROUP_OBJ --x
            &[0x04, 0x00, 0x01, 0x00, 0xff, 0xff, 0xff, 0xff],
            // GROUP 985 --x
            &[0x08, 0x00, 0x01, 0x00, 0xd9, 0x03, 0x00, 0x00],
            // MASK --x
            &[0x10, 0x00, 0x01, 0x00, 0xff, 0xff, 0xff, 0xff],
            // OTHER ---
            &[0x20, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff],
        ]
        .concat();
        assert_eq!(access_acl_bytes(DIR_MODE_GRANTED, &[985]), expected);
    }

    #[test]
    fn the_socket_acl_grants_the_extra_group_connect_and_nothing_else() {
        let expected: Vec<u8> = [
            &2u32.to_le_bytes()[..],
            // USER_OBJ rw-
            &[0x01, 0x00, 0x06, 0x00, 0xff, 0xff, 0xff, 0xff],
            // GROUP_OBJ rw-
            &[0x04, 0x00, 0x06, 0x00, 0xff, 0xff, 0xff, 0xff],
            // GROUP 985 rw-
            &[0x08, 0x00, 0x06, 0x00, 0xd9, 0x03, 0x00, 0x00],
            // MASK rw-
            &[0x10, 0x00, 0x06, 0x00, 0xff, 0xff, 0xff, 0xff],
            // OTHER ---
            &[0x20, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff],
        ]
        .concat();
        assert_eq!(access_acl_bytes(SOCK_MODE_GRANTED, &[985]), expected);
    }

    #[test]
    fn the_acl_never_gives_others_anything_the_mode_did_not() {
        for mode in [DIR_MODE_GRANTED, SOCK_MODE_GRANTED] {
            let acl = access_acl_bytes(mode, &[985, 990]);
            // The last entry is OTHER; its perm is the second u16 of it.
            let other_perm = u16::from_le_bytes([acl[acl.len() - 6], acl[acl.len() - 5]]);
            assert_eq!(u32::from(other_perm), mode & 0o7, "mode {mode:o}");
            assert_eq!(other_perm, 0, "mode {mode:o}: others keep nothing");
        }
    }

    #[test]
    fn named_groups_are_written_in_the_ascending_unique_order_the_kernel_requires() {
        let acl = access_acl_bytes(SOCK_MODE_GRANTED, &[990, 985, 990]);
        let named: Vec<u32> = acl[4..]
            .chunks_exact(8)
            .filter(|e| u16::from_le_bytes([e[0], e[1]]) == ACL_GROUP)
            .map(|e| u32::from_le_bytes([e[4], e[5], e[6], e[7]]))
            .collect();
        assert_eq!(named, vec![985, 990]);
    }

    #[test]
    fn an_empty_allowlist_admits_nobody_not_even_root() {
        assert!(!peer_admitted(
            &PeerIdentity::Credentials { uid: 0, gid: 0, pid: None },
            &[]
        ));
    }

    #[test]
    fn a_loopback_peer_reports_no_uid() {
        // The property that makes the enum worth having: a caller that wants
        // a uid has to decide what it does here, and cannot silently read
        // "no credential" as "root".
        let peer = PeerIdentity::Loopback {
            peer: SocketAddr::from(([127, 0, 0, 1], 40001)),
        };
        assert_eq!(peer.uid(), None);
    }

    // ── Socket behaviour. Unix only — these do not exist on Windows. ──

    #[cfg(unix)]
    mod unix_sockets {
        use super::*;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        /// A private scratch directory, since /run/mirage is not writable in
        /// a test and the point here is the mechanism, not the path.
        fn scratch(name: &str) -> PathBuf {
            let dir = std::env::temp_dir().join(format!("mirage-local-{name}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).expect("scratch dir");
            dir
        }

        fn root_only_plan() -> BindPlan {
            plan_from_resolution(AccountResolution::NotRequested)
        }

        #[tokio::test]
        async fn a_socket_file_left_by_a_dead_process_is_removed_before_bind() {
            // /run is tmpfs so a REBOOT clears it — but an ordinary restart
            // does not, and the second bind fails EADDRINUSE. This is the
            // whole reason the primitive owns the bind.
            let dir = scratch("stale");
            let path = dir.join("ch.sock");
            let ep = LocalEndpoint::Unix(path.clone());
            let plan = root_only_plan();

            let first = ep.bind_with(Some(&dir), &plan).await.expect("first bind");
            drop(first); // process death: the file survives, the listener does not
            assert!(path.exists(), "the socket file outlives its listener");

            let second = ep.bind_with(Some(&dir), &plan).await;
            assert!(
                second.is_ok(),
                "a stale socket must be unlinked, got {:?}",
                second.err()
            );
        }

        #[tokio::test]
        async fn a_live_listener_is_never_stolen_from() {
            // The other half: unlinking unconditionally would let a second
            // process take a channel from a first that is still serving it.
            let dir = scratch("live");
            let path = dir.join("ch.sock");
            let ep = LocalEndpoint::Unix(path.clone());
            let plan = root_only_plan();

            let _held = ep.bind_with(Some(&dir), &plan).await.expect("first bind");
            let second = ep.bind_with(Some(&dir), &plan).await;
            let err = second.err().expect("a live listener must not be displaced");
            assert_eq!(err.kind(), io::ErrorKind::AddrInUse);
            // And the live socket is STILL the live socket: the refused bind
            // did not take the path away from the process that owns it.
            ep.connect()
                .await
                .expect("the live listener must still be reachable");
        }

        #[tokio::test]
        async fn the_modes_are_applied_to_both_the_directory_and_the_socket() {
            use std::os::unix::fs::PermissionsExt;

            let dir = scratch("modes");
            let path = dir.join("ch.sock");
            // Start the directory wide open, as a careless `create_dir_all`
            // under a permissive umask would leave it.
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o777)).unwrap();

            let plan = root_only_plan();
            let _l = LocalEndpoint::Unix(path.clone())
                .bind_with(Some(&dir), &plan)
                .await
                .expect("bind");

            let dir_mode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
            let sock_mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(dir_mode, 0o700, "the directory mode must be re-applied");
            assert_eq!(sock_mode, 0o600, "the socket mode must be applied");
        }

        #[tokio::test]
        async fn a_managed_dir_of_none_leaves_the_directory_alone() {
            // MonitorControl keeps its legacy path directly under the shared
            // root, and the shared root must come out of the bind unchanged.
            use std::os::unix::fs::PermissionsExt;

            let dir = scratch("unmanaged");
            let path = dir.join("ch.sock");
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();

            let _l = LocalEndpoint::Unix(path)
                .bind_with(None, &root_only_plan())
                .await
                .expect("bind");

            let dir_mode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
            assert_eq!(dir_mode, 0o755, "an unmanaged directory must not be re-moded");
        }

        #[tokio::test]
        async fn an_admitted_peer_gets_its_credentials_and_its_bytes_through() {
            let dir = scratch("admit");
            let path = dir.join("ch.sock");
            let ep = LocalEndpoint::Unix(path.clone());
            // Admit whoever is running the test, whatever uid that is.
            // SAFETY: getuid(2) reads a process property and cannot fail.
            let me = unsafe { libc::getuid() };
            let plan = BindPlan {
                resolutions: vec![AccountResolution::Resolved { uid: me, gid: 0 }],
                grant: grant_from_resolutions(&[AccountResolution::NotRequested]),
                admitted_uids: vec![me],
            };

            let listener = ep.bind_with(Some(&dir), &plan).await.expect("bind");
            let server = tokio::spawn(async move {
                let (mut s, peer) = listener.accept().await.expect("accept");
                let mut buf = [0_u8; 4];
                s.read_exact(&mut buf).await.expect("read");
                s.write_all(b"pong").await.expect("write");
                (peer, buf, listener.refused())
            });

            let mut client = ep.connect().await.expect("connect");
            client.write_all(b"ping").await.expect("write");
            let mut back = [0_u8; 4];
            client.read_exact(&mut back).await.expect("read");
            assert_eq!(&back, b"pong");

            let (peer, got, refused) = server.await.expect("server task");
            assert_eq!(&got, b"ping");
            assert_eq!(peer.uid(), Some(me), "the kernel names the peer");
            assert_eq!(refused, 0);
        }

        #[tokio::test]
        async fn a_peer_outside_the_allowlist_is_refused_and_the_listener_keeps_serving() {
            // The SO_PEERCRED refusal. The test process cannot become
            // another uid, so the allowlist is set to one it is NOT — which
            // exercises the same branch from the same direction: the kernel
            // says who the peer is and the listener does not admit it.
            let dir = scratch("refuse");
            let path = dir.join("ch.sock");
            let ep = LocalEndpoint::Unix(path.clone());
            // SAFETY: getuid(2) reads a process property and cannot fail.
            let me = unsafe { libc::getuid() };
            let stranger = me.wrapping_add(1);
            let plan = BindPlan {
                resolutions: vec![AccountResolution::Resolved { uid: stranger, gid: 0 }],
                grant: grant_from_resolutions(&[AccountResolution::NotRequested]),
                admitted_uids: vec![stranger],
            };

            let listener = ep.bind_with(Some(&dir), &plan).await.expect("bind");
            assert!(
                !plan.admitted_uids.contains(&me),
                "the test must actually be outside the allowlist"
            );

            let mut refused_client = ep.connect().await.expect("connect is not the gate");
            // Nothing is accepted, so the write either lands in the socket
            // buffer or fails once the listener drops the stream — both are
            // fine. What matters is that `accept` never yields it.
            let _ = refused_client.write_all(b"ping").await;

            let accepted = tokio::time::timeout(
                std::time::Duration::from_millis(300),
                listener.accept(),
            )
            .await;
            assert!(
                accepted.is_err(),
                "a peer outside the allowlist must never reach the caller"
            );
            assert_eq!(listener.refused(), 1, "and the refusal must be counted");

            // And the listener is still alive: one unlisted local process
            // must not be able to end the channel by knocking on it.
            let mut second_client = ep.connect().await.expect("second connect");
            let _ = second_client.write_all(b"ping").await;
            let still_refusing = tokio::time::timeout(
                std::time::Duration::from_millis(300),
                listener.accept(),
            )
            .await;
            assert!(still_refusing.is_err(), "still refusing, not dead");
            assert_eq!(listener.refused(), 2, "and still counting");
        }
    }

    /// The extra-group grant against a real filesystem. Linux only: it is the
    /// one target that has the attribute.
    #[cfg(target_os = "linux")]
    mod linux_acl {
        use super::*;
        use std::os::unix::fs::PermissionsExt;

        fn scratch(name: &str) -> PathBuf {
            let dir = std::env::temp_dir().join(format!("mirage-acl-{name}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).expect("scratch dir");
            dir
        }

        /// The raw `system.posix_acl_access` value of `path`.
        fn read_access_acl(path: &Path) -> io::Result<Vec<u8>> {
            let c_path = path_to_cstring(path)?;
            let mut buf = vec![0_u8; 256];
            // SAFETY: `c_path` and `ACL_ACCESS_XATTR` are valid NUL-terminated
            // strings, and `buf` is a valid writable buffer whose length is
            // passed alongside its pointer, per getxattr(2).
            let n = unsafe {
                libc::getxattr(
                    c_path.as_ptr(),
                    ACL_ACCESS_XATTR.as_ptr().cast(),
                    buf.as_mut_ptr().cast(),
                    buf.len(),
                )
            };
            if n < 0 {
                return Err(io::Error::last_os_error());
            }
            buf.truncate(usize::try_from(n).expect("getxattr length is non-negative here"));
            Ok(buf)
        }

        /// `true` when this filesystem cannot carry an ACL at all, in which
        /// case a test that needs one says so and stops rather than failing
        /// on a property of the machine it happens to run on.
        fn no_acl_support(err: &io::Error) -> bool {
            err.raw_os_error() == Some(libc::EOPNOTSUPP)
        }

        fn granted_plan(gid: Option<u32>, also_gids: Vec<u32>) -> BindPlan {
            // SAFETY: getuid(2) reads a process property and cannot fail.
            let me = unsafe { libc::getuid() };
            BindPlan {
                resolutions: vec![AccountResolution::NotRequested],
                grant: SocketGrant {
                    dir_mode: DIR_MODE_GRANTED,
                    socket_mode: SOCK_MODE_GRANTED,
                    gid,
                    also_gids,
                },
                admitted_uids: vec![me],
            }
        }

        #[tokio::test]
        async fn an_extra_group_is_written_to_the_directory_and_the_socket() {
            let dir = scratch("written");
            let path = dir.join("ch.sock");
            let plan = granted_plan(None, vec![65001]);

            let _l = LocalEndpoint::Unix(path.clone())
                .bind_with(Some(&dir), &plan)
                .await
                .expect("bind");

            match read_access_acl(&dir) {
                Err(e) if no_acl_support(&e) => {
                    eprintln!("skipped: {} takes no POSIX ACLs", dir.display());
                    return;
                }
                other => assert_eq!(
                    other.expect("the directory must carry the ACL"),
                    access_acl_bytes(DIR_MODE_GRANTED, &[65001])
                ),
            }
            assert_eq!(
                read_access_acl(&path).expect("the socket must carry the ACL"),
                access_acl_bytes(SOCK_MODE_GRANTED, &[65001])
            );
            // The ACL's mask IS the group bits, so the mode reads as granted.
            let dir_mode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
            let sock_mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(dir_mode, 0o710);
            assert_eq!(sock_mode, 0o660);
        }

        #[tokio::test]
        async fn a_plan_with_no_extra_group_writes_no_acl() {
            let dir = scratch("none");
            let path = dir.join("ch.sock");

            let _l = LocalEndpoint::Unix(path.clone())
                .bind_with(Some(&dir), &granted_plan(None, Vec::new()))
                .await
                .expect("bind");

            for p in [&dir, &path] {
                let err = read_access_acl(p).expect_err("no ACL may be written without an extra group");
                assert!(
                    err.raw_os_error() == Some(libc::ENODATA) || no_acl_support(&err),
                    "{}: {err}",
                    p.display()
                );
            }
        }

        #[tokio::test]
        async fn a_group_from_a_previous_bind_is_gone_after_the_next() {
            // A directory outlives the process that bound it. An account
            // that resolved last boot and does not now must not keep the
            // access it was given.
            let dir = scratch("stale");
            let path = dir.join("ch.sock");
            let ep = LocalEndpoint::Unix(path.clone());

            let first = ep
                .bind_with(Some(&dir), &granted_plan(None, vec![65001]))
                .await
                .expect("first bind");
            if let Err(e) = read_access_acl(&dir) {
                assert!(no_acl_support(&e), "{e}");
                eprintln!("skipped: {} takes no POSIX ACLs", dir.display());
                return;
            }
            drop(first);

            let _second = ep
                .bind_with(Some(&dir), &granted_plan(None, Vec::new()))
                .await
                .expect("second bind");
            let err = read_access_acl(&dir).expect_err("the stale entry must have been removed");
            assert_eq!(err.raw_os_error(), Some(libc::ENODATA), "{err}");
        }

        /// Try to connect to `path` holding only uid/gid `id` and no
        /// supplementary groups.
        ///
        /// The credentials are dropped with the RAW syscalls on a thread of
        /// its own: glibc's `setuid` wrappers broadcast to every thread of the
        /// process, the bare syscall changes the calling thread only. That is
        /// what makes this safe next to the other tests running in this
        /// process, and the thread ends with the attempt.
        fn connect_as(path: &Path, id: u32) -> io::Result<()> {
            let path = path.to_path_buf();
            let id = id as libc::c_long; // test ids are small; never truncates
            std::thread::spawn(move || {
                // SAFETY: bare credential syscalls with valid arguments
                // (widened to the `long` the variadic `syscall` reads);
                // `setgroups(0, NULL)` is the documented way to clear the
                // supplementary groups. Each affects only this thread.
                unsafe {
                    if libc::syscall(libc::SYS_setgroups, 0 as libc::c_long, std::ptr::null::<libc::gid_t>()) != 0
                        || libc::syscall(libc::SYS_setresgid, id, id, id) != 0
                        || libc::syscall(libc::SYS_setresuid, id, id, id) != 0
                    {
                        return Err(io::Error::last_os_error());
                    }
                }
                std::os::unix::net::UnixStream::connect(&path).map(|_| ())
            })
            .join()
            .expect("the credential thread must not panic")
        }

        #[tokio::test]
        #[ignore = "needs root (to become other uids) and a filesystem with POSIX ACL support"]
        async fn each_granted_group_can_connect_and_a_stranger_cannot() {
            // SAFETY: getuid(2) reads a process property and cannot fail.
            assert_eq!(unsafe { libc::getuid() }, 0, "this test must run as root");
            let dir = scratch("connect");
            let path = dir.join("ch.sock");
            // 65002 owns the socket (the perimeter's place), 65001 is the
            // added entry (the edge's).
            let plan = granted_plan(Some(65002), vec![65001]);
            let _l = LocalEndpoint::Unix(path.clone())
                .bind_with(Some(&dir), &plan)
                .await
                .expect("bind");

            connect_as(&path, 65002).expect("the owning group must reach the socket");
            connect_as(&path, 65001).expect("the added group must reach the socket");
            let stranger = connect_as(&path, 65099).expect_err("a group with no entry must be refused");
            assert_eq!(stranger.kind(), io::ErrorKind::PermissionDenied, "{stranger}");
        }

        #[tokio::test]
        #[ignore = "needs root (to become other uids) and a filesystem with POSIX ACL support"]
        async fn a_group_removed_from_the_plan_can_no_longer_connect() {
            // SAFETY: getuid(2) reads a process property and cannot fail.
            assert_eq!(unsafe { libc::getuid() }, 0, "this test must run as root");
            let dir = scratch("revoked");
            let path = dir.join("ch.sock");
            let ep = LocalEndpoint::Unix(path.clone());

            let first = ep
                .bind_with(Some(&dir), &granted_plan(Some(65002), vec![65001]))
                .await
                .expect("first bind");
            connect_as(&path, 65001).expect("the added group reaches the socket while granted");
            drop(first);

            let _second = ep
                .bind_with(Some(&dir), &granted_plan(Some(65002), Vec::new()))
                .await
                .expect("second bind");
            let revoked = connect_as(&path, 65001).expect_err("the dropped group must be refused");
            assert_eq!(revoked.kind(), io::ErrorKind::PermissionDenied, "{revoked}");
            connect_as(&path, 65002).expect("the owning group is unaffected");
        }
    }

    // ── The pre-bind probe. Pure, and it runs on every target. ──

    #[test]
    fn an_empty_path_is_bound_without_a_probe() {
        assert_eq!(decide_stale_removal(PathProbe::Absent), StaleDecision::Bind);
    }

    #[test]
    fn a_refused_probe_means_the_file_is_stale_and_may_be_unlinked() {
        assert_eq!(
            decide_stale_removal(PathProbe::Stale),
            StaleDecision::UnlinkThenBind
        );
    }

    #[test]
    fn a_live_listener_is_never_unlinked() {
        assert_eq!(
            decide_stale_removal(PathProbe::Live),
            StaleDecision::Refuse
        );
    }

    #[test]
    fn an_inconclusive_probe_never_unlinks() {
        // The probe could not tell whether somebody is serving the path.
        // Unlinking on that doubt is how a second process takes a channel
        // from a first that is still serving it.
        assert_eq!(
            decide_stale_removal(PathProbe::Inconclusive),
            StaleDecision::Refuse
        );
    }

    // ── The bind record: what a caller that did not bind can read. ──

    #[test]
    fn a_failed_bind_is_readable_by_anybody_in_the_process() {
        // The monitor's health surface has to learn that the wire splice's
        // bind failed — and the bind happens in another crate.
        let failed: io::Result<LocalListener> = Err(io::Error::new(
            io::ErrorKind::AddrInUse,
            "a live listener already owns it",
        ));
        record_bind(LocalChannel::MonitorWireSplice, &failed);

        let status = LocalChannel::MonitorWireSplice
            .bind_status()
            .expect("the record must be there");
        assert!(!status.bound, "a failed bind is not a bound channel");
        assert_eq!(
            status.error.as_deref(),
            Some("a live listener already owns it")
        );
        assert!(!status.endpoint.is_empty(), "the endpoint must be named");
    }

    #[test]
    fn a_channel_that_was_never_bound_has_no_record() {
        // Nothing was attempted on this channel in this process, so there is
        // no answer to give — and a caller must be able to tell that from
        // "the bind failed".
        assert!(LocalChannel::PerimeterQuery.bind_status().is_none());
    }
}
