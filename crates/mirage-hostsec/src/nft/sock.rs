//! Netlink socket transport — Linux only.
//!
//! All `unsafe` in the `nft` module is confined here.  `wire.rs` and
//! `ops.rs` are fully safe Rust.

use super::{wire::build_batch, NftError};

/// Send `msgs` as a single atomic batch transaction and wait for all ACKs.
///
/// Wraps the messages in `BATCH_BEGIN` / `BATCH_END`, sends the combined
/// buffer in one `sendmsg`, then reads `NLMSG_ERROR` replies.  An error
/// code of 0 in `nlmsgerr` means ACK (success).
pub(crate) fn send_batch(msgs: &[Vec<u8>]) -> Result<(), NftError> {
    let fd = open_netlink()?;
    let result = send_and_recv(fd, msgs);
    // SAFETY: closing a valid file descriptor.
    unsafe { libc::close(fd) };
    result
}

fn open_netlink() -> Result<i32, NftError> {
    // AF_NETLINK=16, SOCK_RAW=3, NETLINK_NETFILTER=12.
    // SAFETY: standard socket(2) call with known-valid constants.
    let fd = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW, 12 /* NETLINK_NETFILTER */) };
    if fd < 0 {
        return Err(NftError::Syscall(errno()));
    }

    // bind(AF_NETLINK) — nl_pid=0 lets the kernel assign a unique pid.
    // Use zeroed() + set the family to avoid `nl_pad` type differences
    // between glibc (u16) and musl (Padding<u16>).
    // SAFETY: sockaddr_nl is a POD; all-zeros is a valid representation
    // (AF_UNSPEC family, zero pid/groups), and we immediately overwrite family.
    let mut sa: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    sa.nl_family = libc::AF_NETLINK as u16;
    sa.nl_pid = 0;
    sa.nl_groups = 0;
    // SAFETY: `sa` is correctly initialised and its size is passed.
    let rc = unsafe {
        libc::bind(
            fd,
            &sa as *const libc::sockaddr_nl as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        // SAFETY: closing the fd we just opened.
        unsafe { libc::close(fd) };
        return Err(NftError::Syscall(errno()));
    }

    Ok(fd)
}

fn send_and_recv(fd: i32, msgs: &[Vec<u8>]) -> Result<(), NftError> {
    let batch = build_batch(msgs);

    // sendmsg via send(2) — one atomic write.
    // SAFETY: `batch` is a valid buffer; fd is open.
    let sent = unsafe {
        libc::send(
            fd,
            batch.as_ptr() as *const libc::c_void,
            batch.len(),
            0,
        )
    };
    if sent < 0 {
        return Err(NftError::Syscall(errno()));
    }

    recv_acks(fd, msgs.len())
}

/// Read `NLMSG_ERROR` replies — ONE PER INNER MESSAGE, and all of them.
///
/// A `nlmsgerr.error == 0` = success ACK; non-zero = kernel errno (negated).
///
/// # The bug this shape exists to prevent
///
/// This used to `return Ok(())` as soon as it had drained a single `recv`.
/// Netlink is a DATAGRAM socket: one `recv` returns one message, so for a
/// multi-message batch the first read carried the ACK for message 1 and the
/// function reported success — for the whole transaction. nftables commits a
/// batch atomically, so a failure in message 2..N aborts everything, and the
/// caller was told it had worked.
///
/// Measured cost of that, 2026-08-05: `ensure_base_policy` had been logging
/// `base policy applied` on every secd boot for the life of the code, and
/// `inet fw` did not exist on a single box in the fleet. The only reason
/// anything ever surfaced an error is that `ban` / `trust` send ONE message,
/// so their first datagram was also their only one.
///
/// So: count the results, and do not claim success for a message whose
/// answer was never read. `expected` is `msgs.len()` — the batch envelope
/// itself is sent without `NLM_F_ACK` and is not counted.
fn recv_acks(fd: i32, expected: usize) -> Result<(), NftError> {
    // Without a timeout, a kernel that answers fewer messages than we sent
    // would hang this thread forever. Waiting is not the failure mode we
    // want; reporting the shortfall is.
    set_recv_timeout(fd, RECV_TIMEOUT_SECS)?;

    // Buffer: 32 pages ~ 128 KB.
    let buf_size = 4096 * 32;
    let mut buf: Vec<u8> = vec![0u8; buf_size];
    let mut seen = 0usize;

    loop {
        // SAFETY: `buf` is valid with correct length; fd is open.
        let n = unsafe {
            libc::recv(
                fd,
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
                0,
            )
        };
        if n < 0 {
            let e = errno();
            // The socket went quiet. Success ONLY if every message we sent
            // has been answered; otherwise say what is missing rather than
            // reporting a transaction we never saw the end of.
            if e == libc::EAGAIN || e == libc::EWOULDBLOCK || e == libc::EINTR {
                if seen >= expected {
                    return Ok(());
                }
                return Err(NftError::BadReply(format!(
                    "kernel answered {seen} of {expected} batch messages before going quiet"
                )));
            }
            return Err(NftError::Syscall(e));
        }
        let n = n as usize;
        let mut off = 0usize;

        while off + 16 <= n {
            // Parse nlmsghdr.
            let nlmsg_len = u32::from_le_bytes(buf[off..off + 4].try_into().unwrap()) as usize;
            let nlmsg_type = u16::from_le_bytes(buf[off + 4..off + 6].try_into().unwrap());

            if nlmsg_len < 16 || off + nlmsg_len > n {
                return Err(NftError::BadReply("truncated nlmsghdr".into()));
            }

            // NLMSG_DONE = 0x03, NLMSG_ERROR = 0x02.
            if nlmsg_type == 0x0003 {
                // NLMSG_DONE — the kernel has nothing further to say. Same
                // rule as a timeout: it is only success if everything was
                // answered.
                if seen >= expected {
                    return Ok(());
                }
                return Err(NftError::BadReply(format!(
                    "kernel closed the batch after {seen} of {expected} messages"
                )));
            }
            if nlmsg_type == 0x0002 {
                // NLMSG_ERROR — body is `struct nlmsgerr { int error; nlmsghdr msg; }`.
                // error field at offset 16 (after nlmsghdr), 4 bytes signed LE.
                if off + 16 + 4 > n {
                    return Err(NftError::BadReply("truncated nlmsgerr".into()));
                }
                let err = i32::from_le_bytes(buf[off + 16..off + 20].try_into().unwrap());
                if err != 0 {
                    // Kernel returns negative errno; we store the absolute
                    // value. One failure aborts the whole transaction, so
                    // there is nothing to keep reading for — but WHICH
                    // message failed is the difference between a diagnosis
                    // and a guess, and the ack count is that index.
                    let errno = err.unsigned_abs() as i32;
                    if expected > 1 {
                        return Err(NftError::BatchRejected {
                            index: seen + 1,
                            total: expected,
                            errno,
                        });
                    }
                    return Err(NftError::Netlink(errno));
                }
                // err == 0 → ACK for one inner message.
                seen += 1;
                if seen >= expected {
                    return Ok(());
                }
            }
            // Advance to next message (4-byte aligned).
            let step = (nlmsg_len + 3) & !3;
            off += step;
        }
    }
}

/// How long to wait for the kernel to finish answering a batch.
const RECV_TIMEOUT_SECS: i64 = 3;

fn set_recv_timeout(fd: i32, secs: i64) -> Result<(), NftError> {
    let tv = libc::timeval {
        tv_sec: secs,
        tv_usec: 0,
    };
    // SAFETY: `tv` is a valid timeval; fd is an open socket.
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            &tv as *const libc::timeval as *const libc::c_void,
            std::mem::size_of::<libc::timeval>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(NftError::Syscall(errno()));
    }
    Ok(())
}

#[inline]
fn errno() -> i32 {
    // SAFETY: `__errno_location` returns a valid per-thread pointer on Linux.
    unsafe { *libc::__errno_location() }
}
