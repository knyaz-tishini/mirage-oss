//! Ask the kernel which cgroup owns each socket, without touching `/proc`.
//!
//! # The blindness this removes
//!
//! Attributing a listening socket to a process has meant one thing here:
//! walk every `/proc/<pid>/fd/`, `readlink` each entry, and match
//! `socket:[N]` against the inode in `/proc/net/tcp`. That path is gated by
//! `ptrace_may_access`, and **this fleet's own Tier-2 hook denies it** for
//! every protected mirage daemon. Two consequences, both measured:
//!
//! - `ss -tlnp` and `box_inventory` alike print `0.0.0.0:22` with **no
//!   owner** on every converged box, because the perimeter holds it and the
//!   perimeter is protected. `unexpected_listener_count` is therefore 0 on a
//!   box carrying an unmanaged public SSH daemon: nothing can tell the
//!   perimeter's `:22` face from a foreign `sshd` on the same port.
//! - the walk generates one kernel deny per open descriptor per protected
//!   daemon per pass — on the canary, 7 rows and 237 aggregated denies in a
//!   26.5-second window, against a fleet-wide 200-row event ring. The
//!   sentry was the largest single producer of the noise that evicted real
//!   events.
//!
//! # `INET_DIAG_CGROUP_ID`
//!
//! `sock_diag` netlink returns, per socket, the **cgroup id that owns it**.
//! No `/proc`, no ptrace gate, nothing provoked. Joined against the
//! cgroup→unit map (see [`crate::cgroup_units`]), it names the owning
//! systemd unit for OUR sockets and foreign ones alike — which is strictly
//! more than the fd walk could ever produce, since the fd walk is denied for
//! exactly the processes worth naming.
//!
//! Verified on the canary (`us-example-203.0.113.25`, kernel
//! 6.8.0-138-generic) on 2026-08-29 with a raw netlink probe: 18 sockets
//! returned, every one carrying attribute 21, resolving `:22`, `:80`,
//! `:443`, `:3000` and `:8080` to cgroup 3112 — `mirage-perimeter.service`.
//! The attribute arrives **unconditionally**; it does not have to be
//! requested through `idiag_ext`, which is an 8-bit field that could not
//! address attribute 21 anyway.
//!
//! # Why raw netlink rather than shelling out to `ss`
//!
//! `ss --cgroup` prints the same fact, and parsing its output would make
//! this instrument depend on an iproute2 version and a human-readable
//! layout. The wire format below is a kernel ABI: additive, versioned by
//! attribute number, and stable in a way `ss`'s columns are not.
//!
//! No new dependency — this crate already links `libc` for the capability
//! probes in `box_profile.rs`.

use std::collections::HashMap;

// ── netlink / sock_diag ABI constants ─────────────────────────────────────

/// `NETLINK_INET_DIAG` protocol number.
const NETLINK_INET_DIAG: i32 = 4;
/// `SOCK_DIAG_BY_FAMILY` message type.
const SOCK_DIAG_BY_FAMILY: u16 = 20;
const NLM_F_REQUEST: u16 = 0x001;
const NLM_F_DUMP: u16 = 0x300;
const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;

/// `struct nlmsghdr` — 16 bytes.
const NLMSG_HDR_LEN: usize = 16;
/// `struct inet_diag_req_v2` — 4 scalar bytes + `idiag_states` + a 48-byte
/// `inet_diag_sockid`.
const REQ_V2_LEN: usize = 56;
/// `struct inet_diag_msg` — family/state/timer/retrans, a 48-byte sockid,
/// then expires/rqueue/wqueue/uid/inode.
const DIAG_MSG_LEN: usize = 72;
/// Byte offset of `idiag_inode` inside `struct inet_diag_msg`.
const DIAG_MSG_INODE_OFF: usize = 68;

/// `INET_DIAG_CGROUP_ID` attribute type — carries a `u64` cgroup id.
const INET_DIAG_CGROUP_ID: u16 = 21;

/// Every TCP state, so a dump returns listeners and established
/// connections alike. The outbound half of the inventory needs the second.
const ALL_STATES: u32 = 0xFFFF_FFFF;

// Address families and IP protocols, as the LINUX ABI numbers them.
//
// Spelled out rather than taken from `libc` because these travel INSIDE a
// netlink message as `u8` fields of a Linux kernel structure — their values
// are fixed by that ABI, not by the host this happens to compile on, and
// `libc` does not export them uniformly across targets. Writing them here
// also lets the wire-format tests below run on the dev box.
const AF_INET: u8 = 2;
const AF_INET6: u8 = 10;
const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;

/// The four dumps that together cover this box's IP sockets.
const DUMPS: &[(u8, u8)] = &[
    (AF_INET, IPPROTO_TCP),
    (AF_INET6, IPPROTO_TCP),
    (AF_INET, IPPROTO_UDP),
    (AF_INET6, IPPROTO_UDP),
];

/// Build one `SOCK_DIAG_BY_FAMILY` dump request.
///
/// `idiag_ext` is left zero deliberately: it is a `u8`, so it cannot even
/// address attribute 21, and the measurement above confirms the kernel
/// emits the cgroup id without being asked.
#[must_use]
pub fn build_request(family: u8, protocol: u8, seq: u32) -> Vec<u8> {
    let total = NLMSG_HDR_LEN + REQ_V2_LEN;
    let mut buf = Vec::with_capacity(total);
    // struct nlmsghdr
    buf.extend_from_slice(&(total as u32).to_ne_bytes());
    buf.extend_from_slice(&SOCK_DIAG_BY_FAMILY.to_ne_bytes());
    buf.extend_from_slice(&(NLM_F_REQUEST | NLM_F_DUMP).to_ne_bytes());
    buf.extend_from_slice(&seq.to_ne_bytes());
    buf.extend_from_slice(&0u32.to_ne_bytes()); // portid: the kernel fills it
    // struct inet_diag_req_v2
    buf.push(family);
    buf.push(protocol);
    buf.push(0); // idiag_ext — see the doc above
    buf.push(0); // pad
    buf.extend_from_slice(&ALL_STATES.to_ne_bytes());
    buf.extend_from_slice(&[0u8; 48]); // inet_diag_sockid: match everything
    debug_assert_eq!(buf.len(), total);
    buf
}

/// What one dump message said about one socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SocketOwner {
    /// `idiag_inode` — the same inode `/proc/net/{tcp,udp}` prints, which is
    /// what joins this to a listener row.
    pub inode: u32,
    /// The owning cgroup id, when the kernel supplied one. `None` on a
    /// kernel too old to emit attribute 21 — reported as absent rather than
    /// as zero, because cgroup 0 is a real value (the root cgroup).
    pub cgroup_id: Option<u64>,
}

/// How a dump ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DumpEnd {
    /// `NLMSG_DONE` — the kernel finished.
    Done,
    /// `NLMSG_ERROR` — carries the errno the kernel reported.
    Error(i32),
    /// The buffer ran out mid-stream; more recv calls are needed.
    More,
}

/// Parse one recv buffer of netlink messages.
///
/// Pure: takes bytes, returns what they said. Every kernel interaction in
/// this module is one syscall away from this function, so the wire format
/// can be tested exhaustively without a kernel.
#[must_use]
pub fn parse_dump(buf: &[u8]) -> (Vec<SocketOwner>, DumpEnd) {
    let mut out = Vec::new();
    let mut off = 0usize;

    while off + NLMSG_HDR_LEN <= buf.len() {
        let mlen = u32::from_ne_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]]) as usize;
        let mtype = u16::from_ne_bytes([buf[off + 4], buf[off + 5]]);

        // A header claiming to be shorter than a header, or longer than what
        // we hold, ends the walk. Trusting either would index out of the
        // buffer or loop forever.
        if mlen < NLMSG_HDR_LEN {
            return (out, DumpEnd::More);
        }
        if off + mlen > buf.len() {
            return (out, DumpEnd::More);
        }

        match mtype {
            NLMSG_DONE => return (out, DumpEnd::Done),
            NLMSG_ERROR => {
                // struct nlmsgerr { int error; struct nlmsghdr msg; }
                let p = off + NLMSG_HDR_LEN;
                let errno = if p + 4 <= buf.len() {
                    i32::from_ne_bytes([buf[p], buf[p + 1], buf[p + 2], buf[p + 3]])
                } else {
                    0
                };
                return (out, DumpEnd::Error(errno));
            }
            _ => {
                let payload = &buf[off + NLMSG_HDR_LEN..off + mlen];
                if let Some(owner) = parse_diag_msg(payload) {
                    out.push(owner);
                }
            }
        }

        // Netlink messages are 4-byte aligned.
        off += (mlen + 3) & !3;
    }

    (out, DumpEnd::More)
}

/// Parse one `struct inet_diag_msg` plus its trailing attributes.
fn parse_diag_msg(payload: &[u8]) -> Option<SocketOwner> {
    if payload.len() < DIAG_MSG_LEN {
        return None;
    }
    let inode = u32::from_ne_bytes([
        payload[DIAG_MSG_INODE_OFF],
        payload[DIAG_MSG_INODE_OFF + 1],
        payload[DIAG_MSG_INODE_OFF + 2],
        payload[DIAG_MSG_INODE_OFF + 3],
    ]);

    let mut cgroup_id = None;
    let mut a = DIAG_MSG_LEN;
    while a + 4 <= payload.len() {
        let alen = u16::from_ne_bytes([payload[a], payload[a + 1]]) as usize;
        let atype = u16::from_ne_bytes([payload[a + 2], payload[a + 3]]);
        if alen < 4 || a + alen > payload.len() {
            break;
        }
        if atype == INET_DIAG_CGROUP_ID && alen >= 12 {
            cgroup_id = Some(u64::from_ne_bytes([
                payload[a + 4],
                payload[a + 5],
                payload[a + 6],
                payload[a + 7],
                payload[a + 8],
                payload[a + 9],
                payload[a + 10],
                payload[a + 11],
            ]));
        }
        a += (alen + 3) & !3;
    }

    Some(SocketOwner { inode, cgroup_id })
}

// ── the syscall half ──────────────────────────────────────────────────────

/// Ask the kernel for every IP socket's owning cgroup.
///
/// Returns `inode -> cgroup_id` for the sockets the kernel named one for.
/// An error here is a real error and is reported as such: this must never
/// degrade into an empty map that a caller reads as "no socket has an
/// owner", which is precisely the shape of the blindness it replaces.
#[cfg(target_os = "linux")]
pub fn socket_cgroups() -> Result<HashMap<u32, u64>, String> {
    let mut out = HashMap::new();
    for (i, (family, protocol)) in DUMPS.iter().enumerate() {
        match dump_one(*family, *protocol, i as u32 + 1) {
            Ok(rows) => {
                for r in rows {
                    if let Some(cg) = r.cgroup_id {
                        out.insert(r.inode, cg);
                    }
                }
            }
            // One family failing (a box with IPv6 disabled answers EAFNOSUPPORT)
            // must not lose the other three. The map is a union; a missing
            // family means missing rows, and every consumer treats an absent
            // inode as "unattributed" rather than as "nobody owns it".
            Err(e) => {
                tracing::debug!(
                    family = *family,
                    protocol = *protocol,
                    err = %e,
                    "[sock-diag] one dump failed — the other families still count"
                );
            }
        }
    }
    if out.is_empty() {
        return Err("sock_diag returned no socket with a cgroup id".to_string());
    }
    Ok(out)
}

#[cfg(target_os = "linux")]
fn dump_one(family: u8, protocol: u8, seq: u32) -> Result<Vec<SocketOwner>, String> {
    // SAFETY: a plain `socket(2)`. The fd is closed on every path below.
    let fd = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            NETLINK_INET_DIAG,
        )
    };
    if fd < 0 {
        return Err(format!("socket(AF_NETLINK): {}", std::io::Error::last_os_error()));
    }
    let guard = FdGuard(fd);

    // A dump can outlive a wedged kernel path; bound the wait rather than
    // hanging a scan pass forever.
    let tv = libc::timeval { tv_sec: 5, tv_usec: 0 };
    // SAFETY: `tv` outlives the call and the length matches its type.
    unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            std::ptr::addr_of!(tv).cast(),
            std::mem::size_of::<libc::timeval>() as libc::socklen_t,
        );
    }

    let req = build_request(family, protocol, seq);
    // SAFETY: `req` is a live slice and its length is passed alongside.
    let sent = unsafe { libc::send(fd, req.as_ptr().cast(), req.len(), 0) };
    if sent < 0 {
        return Err(format!("send: {}", std::io::Error::last_os_error()));
    }

    let mut rows = Vec::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        // SAFETY: `buf` is a live, owned allocation of the length passed.
        let n = unsafe { libc::recv(fd, buf.as_mut_ptr().cast(), buf.len(), 0) };
        if n < 0 {
            return Err(format!("recv: {}", std::io::Error::last_os_error()));
        }
        if n == 0 {
            break;
        }
        let (mut got, end) = parse_dump(&buf[..n as usize]);
        rows.append(&mut got);
        match end {
            DumpEnd::Done => break,
            DumpEnd::Error(errno) => {
                return Err(format!("kernel refused the dump: errno {}", -errno))
            }
            DumpEnd::More => continue,
        }
    }
    drop(guard);
    Ok(rows)
}

/// Closes its fd on drop, including on an early `return Err`.
#[cfg(target_os = "linux")]
struct FdGuard(i32);

#[cfg(target_os = "linux")]
impl Drop for FdGuard {
    fn drop(&mut self) {
        // SAFETY: the fd was obtained from `socket(2)` above and is closed
        // exactly once, here.
        unsafe {
            libc::close(self.0);
        }
    }
}

#[cfg(not(target_os = "linux"))]
pub fn socket_cgroups() -> Result<HashMap<u32, u64>, String> {
    Err("sock_diag is Linux-only — this host was not asked".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nlmsg(mtype: u16, payload: &[u8]) -> Vec<u8> {
        let total = NLMSG_HDR_LEN + payload.len();
        let mut v = Vec::new();
        v.extend_from_slice(&(total as u32).to_ne_bytes());
        v.extend_from_slice(&mtype.to_ne_bytes());
        v.extend_from_slice(&0u16.to_ne_bytes());
        v.extend_from_slice(&0u32.to_ne_bytes());
        v.extend_from_slice(&0u32.to_ne_bytes());
        v.extend_from_slice(payload);
        while v.len() % 4 != 0 {
            v.push(0);
        }
        v
    }

    /// One `inet_diag_msg` with `inode`, optionally followed by a cgroup
    /// attribute.
    fn diag_msg(inode: u32, cgroup: Option<u64>) -> Vec<u8> {
        let mut p = vec![0u8; DIAG_MSG_LEN];
        p[DIAG_MSG_INODE_OFF..DIAG_MSG_INODE_OFF + 4].copy_from_slice(&inode.to_ne_bytes());
        if let Some(cg) = cgroup {
            p.extend_from_slice(&12u16.to_ne_bytes());
            p.extend_from_slice(&INET_DIAG_CGROUP_ID.to_ne_bytes());
            p.extend_from_slice(&cg.to_ne_bytes());
        }
        p
    }

    #[test]
    fn a_request_is_the_size_the_kernel_expects() {
        let r = build_request(AF_INET, IPPROTO_TCP, 1);
        assert_eq!(r.len(), NLMSG_HDR_LEN + REQ_V2_LEN);
        // The declared length must equal the real length, or the kernel
        // reads past the buffer or refuses the message.
        let declared = u32::from_ne_bytes([r[0], r[1], r[2], r[3]]) as usize;
        assert_eq!(declared, r.len());
        assert_eq!(u16::from_ne_bytes([r[4], r[5]]), SOCK_DIAG_BY_FAMILY);
        assert_eq!(r[NLMSG_HDR_LEN], AF_INET);
        assert_eq!(r[NLMSG_HDR_LEN + 1], IPPROTO_TCP);
    }

    /// The measurement this module exists for: inode joined to the cgroup
    /// that owns the socket.
    #[test]
    fn a_socket_carries_the_cgroup_that_owns_it() {
        // The canary's real numbers: the perimeter's faces on cgroup 3112.
        let buf = [
            nlmsg(SOCK_DIAG_BY_FAMILY, &diag_msg(13519, Some(3112))),
            nlmsg(SOCK_DIAG_BY_FAMILY, &diag_msg(152188, Some(3280))),
            nlmsg(NLMSG_DONE, &[]),
        ]
        .concat();
        let (rows, end) = parse_dump(&buf);
        assert_eq!(end, DumpEnd::Done);
        assert_eq!(
            rows,
            vec![
                SocketOwner { inode: 13519, cgroup_id: Some(3112) },
                SocketOwner { inode: 152188, cgroup_id: Some(3280) },
            ]
        );
    }

    /// A kernel that does not emit attribute 21 must produce `None`, never
    /// cgroup 0 — the root cgroup is a real answer and must stay
    /// distinguishable from "the kernel did not say".
    #[test]
    fn a_socket_without_the_attribute_reports_absence_not_zero() {
        let buf = [
            nlmsg(SOCK_DIAG_BY_FAMILY, &diag_msg(7, None)),
            nlmsg(NLMSG_DONE, &[]),
        ]
        .concat();
        let (rows, _) = parse_dump(&buf);
        assert_eq!(rows, vec![SocketOwner { inode: 7, cgroup_id: None }]);
        assert_ne!(rows[0].cgroup_id, Some(0));
    }

    /// A dump the kernel refused must be an error, never an empty success —
    /// "no sockets have owners" and "the kernel said no" are the two states
    /// this whole module exists to keep apart.
    #[test]
    fn a_refused_dump_is_an_error_not_an_empty_answer() {
        // EPERM, negated, the way netlink reports an errno.
        let mut err_payload = (-1i32).to_ne_bytes().to_vec();
        err_payload.extend_from_slice(&[0u8; NLMSG_HDR_LEN]);
        let buf = [
            nlmsg(SOCK_DIAG_BY_FAMILY, &diag_msg(1, Some(9))),
            nlmsg(NLMSG_ERROR, &err_payload),
        ]
        .concat();
        let (rows, end) = parse_dump(&buf);
        assert_eq!(end, DumpEnd::Error(-1));
        assert_eq!(rows.len(), 1, "rows before the error are still real");
    }

    /// A truncated tail asks for more bytes rather than inventing a row or
    /// walking off the end.
    #[test]
    fn a_truncated_buffer_asks_for_more_instead_of_guessing() {
        let full = [
            nlmsg(SOCK_DIAG_BY_FAMILY, &diag_msg(11, Some(3112))),
            nlmsg(SOCK_DIAG_BY_FAMILY, &diag_msg(12, Some(3112))),
        ]
        .concat();
        let cut = &full[..full.len() - 10];
        let (rows, end) = parse_dump(cut);
        assert_eq!(end, DumpEnd::More);
        assert_eq!(rows.len(), 1, "only the message that arrived whole counts");
    }

    /// A header claiming an impossible length must terminate the walk
    /// rather than loop or index out of bounds.
    #[test]
    fn a_malformed_length_terminates_the_walk() {
        let mut buf = nlmsg(SOCK_DIAG_BY_FAMILY, &diag_msg(1, Some(2)));
        buf.extend_from_slice(&3u32.to_ne_bytes()); // len < header
        buf.extend_from_slice(&[0u8; 12]);
        let (rows, end) = parse_dump(&buf);
        assert_eq!(rows.len(), 1);
        assert_eq!(end, DumpEnd::More);
    }

    /// An attribute whose length runs past the message must not be read.
    #[test]
    fn an_overlong_attribute_is_ignored_rather_than_read_past_the_end() {
        let mut p = vec![0u8; DIAG_MSG_LEN];
        p[DIAG_MSG_INODE_OFF..DIAG_MSG_INODE_OFF + 4].copy_from_slice(&42u32.to_ne_bytes());
        p.extend_from_slice(&9999u16.to_ne_bytes());
        p.extend_from_slice(&INET_DIAG_CGROUP_ID.to_ne_bytes());
        p.extend_from_slice(&[0u8; 8]);
        let buf = [nlmsg(SOCK_DIAG_BY_FAMILY, &p), nlmsg(NLMSG_DONE, &[])].concat();
        let (rows, end) = parse_dump(&buf);
        assert_eq!(end, DumpEnd::Done);
        assert_eq!(rows, vec![SocketOwner { inode: 42, cgroup_id: None }]);
    }
}
