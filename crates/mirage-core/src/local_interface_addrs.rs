//! This machine's own network-interface addresses, read from the kernel —
//! the shared primitive behind "does an address belong to this box".
//!
//! # Why this exists here
//!
//! `mirage-secd::banengine` grew this exact enumeration
//! (`local_global_unicast_addrs` + `is_local_exempt_candidate`,
//! `docs/mirage/plans/four-items-2026-08-19.md` item 3) so a box can never
//! ban its own address. Item 2 of that same plan needs the identical fact
//! for a different question — whether a monitor dial's target is this box,
//! so the dial can be routed onto the local channel instead of a socket
//! aimed at itself (`mirage-mesh-client::monitor_dial`) — and item 2's crate
//! cannot depend on `mirage-secd` (wrong direction: `mirage-secd` already
//! depends on `mirage-core`, and gaining a Linux-only security daemon as a
//! transitive dependency of a client-facing mesh crate would be worse than
//! the duplication it avoids). `mirage-core` is the one crate both already
//! depend on, so the enumeration lives here and each caller supplies its own
//! POLICY on top of the same FACTS — see [`local_machine_addrs`]'s doc for
//! the fleet-graph-safety reasoning that policy exists to protect either
//! way.
//!
//! `mirage-secd`'s own copy is **not** deleted by this module's addition —
//! that would mean editing `mirage-secd`, out of scope for the change that
//! introduced this file (see that change's own report). The two
//! implementations are functionally equivalent by construction (same
//! `getifaddrs(3)` read, same address-family handling, same exclusion
//! rules); collapsing `mirage-secd` onto this one is a follow-up for
//! whoever owns that crate, not a silent fork of a third variant.
//!
//! # This is NOT a whitelist
//!
//! Nothing here is read from disk, wired in as a constant, or told to this
//! box by anyone else — every address [`local_machine_addrs`] returns is
//! what THIS box's own kernel reports as bound to one of ITS OWN interfaces,
//! at the moment of the call. A box can therefore only ever learn its OWN
//! addresses this way: there is no path from this function to any other
//! machine's address, and no file a compromise of this box could read to
//! learn the fleet's shape.
//!
//! # [`cached_local_machine_addrs`] — the source a fixed-signature caller uses
//!
//! `mirage-mesh-client::monitor_faces::FaceDialer::dial_v9` is a public
//! signature two other crates already call
//! (`mirage2sentry::wire_client`, and this crate's own `capsule_ask.rs`);
//! neither can be asked to change to thread an address list through it, and
//! this crate cannot touch either caller's own `Cargo.toml`/call sites to
//! adopt one if it could. [`cached_local_machine_addrs`] is the answer: a
//! zero-argument, self-refreshing accessor a fixed-signature function can
//! call with no plumbing anywhere above it — see its own doc for the cache
//! shape and for [`set_cached_local_machine_addrs_for_test`], the seam that
//! makes it possible to test that call site deterministically anyway.

use std::cell::RefCell;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// This box's own global-unicast-shaped addresses (IPv4 and IPv6), read
/// directly from the kernel's interface list via `getifaddrs(3)`.
///
/// Loopback is deliberately excluded — see [`is_local_interface_candidate`]'s
/// doc for why callers that also want to treat loopback as "this machine"
/// check `IpAddr::is_loopback` themselves rather than finding it in this
/// list.
///
/// Linux-only: `getifaddrs`/`freeifaddrs` are POSIX, not Windows, APIs. The
/// non-Linux stub below returns an empty list so `cargo check` (and every
/// caller's own tests) stay green on the dev box; every consumer of this
/// function today runs only on the Linux fleet.
#[cfg(target_os = "linux")]
pub fn local_machine_addrs() -> Vec<IpAddr> {
    let mut out = Vec::new();
    let mut head: *mut libc::ifaddrs = std::ptr::null_mut();

    // SAFETY: `&mut head` is a valid `*mut *mut ifaddrs` out-param.
    // `getifaddrs` either heap-allocates a linked list and writes its head
    // here (freed exactly once below via `freeifaddrs`), or returns nonzero
    // and leaves `head` untouched — checked before `head` is read.
    let rc = unsafe { libc::getifaddrs(&mut head) };
    if rc != 0 {
        tracing::warn!(
            error = %std::io::Error::last_os_error(),
            "[mirage-core/local_interface_addrs] getifaddrs failed — this box's own \
             addresses will not be recognised until the next call succeeds"
        );
        return out;
    }

    let mut node = head;
    while !node.is_null() {
        // SAFETY: `node` is non-null, and is either `head` itself (just
        // confirmed non-null by `getifaddrs` succeeding above) or a previous
        // iteration's `ifa_next`, which `getifaddrs(3)` guarantees is either
        // null or a further valid node in the same allocation. The whole
        // list stays valid until `freeifaddrs(head)` below, which runs only
        // after this loop has finished reading every node.
        let ifa = unsafe { &*node };
        if let Some(ip) = sockaddr_to_ip(ifa.ifa_addr) {
            if is_local_interface_candidate(ip) {
                out.push(ip);
            }
        }
        node = ifa.ifa_next;
    }

    // SAFETY: `head` is exactly the pointer `getifaddrs` populated on the
    // success path above (the only path that reaches here), freed exactly
    // once, after every node has been read and nothing retains a reference
    // into the list.
    unsafe { libc::freeifaddrs(head) };

    out
}

/// Non-Linux stub — see [`local_machine_addrs`]'s own doc for why an empty
/// list here is correct rather than a missing feature.
#[cfg(not(target_os = "linux"))]
pub fn local_machine_addrs() -> Vec<IpAddr> {
    Vec::new()
}

// ── Cached accessor for fixed-signature callers ─────────────────────────

/// How long a cached read stays valid before the next call refreshes it —
/// the same 60s cadence `mirage-secd`'s own analogous refresh loop uses for
/// this exact fact (item 3 of `docs/mirage/plans/four-items-2026-08-19.md`).
const CACHE_TTL: Duration = Duration::from_secs(60);

struct Cache {
    addrs: Vec<IpAddr>,
    refreshed_at: Option<Instant>,
}

/// Process-wide, refreshed on [`CACHE_TTL`]. A plain (not `tokio::sync`)
/// mutex is correct here: every critical section below is synchronous —
/// a vec clone, a comparison, at most one [`local_machine_addrs`] call — and
/// never holds the lock across an `.await`.
static CACHE: Mutex<Cache> = Mutex::new(Cache { addrs: Vec::new(), refreshed_at: None });

thread_local! {
    /// Test-only override — see [`set_cached_local_machine_addrs_for_test`].
    /// Thread-local, not a second process-global, specifically so two tests
    /// running concurrently (the default `cargo test` harness: one freshly
    /// spawned OS thread per test, `#[tokio::test]`'s default
    /// current-thread runtime never hands the test's own task to a
    /// different thread) can each pin their own answer, or none at all,
    /// without racing each other or a third test that never calls the
    /// setter at all.
    static TEST_OVERRIDE: RefCell<Option<Vec<IpAddr>>> = const { RefCell::new(None) };
}

/// The cached, self-refreshing answer to "what does this process consider
/// itself" — [`local_machine_addrs`]'s live interface reading, plus the
/// sentinel self-addresses (`127.0.0.1`, `::1`, `0.0.0.0`, `::`) folded in
/// unconditionally so a caller needs exactly ONE membership check
/// (`.contains(&ip)`) rather than a separate hardcoded literal check beside
/// it. That folding is what makes this function different from
/// [`local_machine_addrs`] itself, which deliberately excludes loopback —
/// see that function's own doc for why the two questions ("what does
/// `getifaddrs` report" vs. "what should this process refuse to dial")
/// are kept apart there. Here they are the same question, because this
/// accessor exists FOR that second one.
///
/// Refreshed at most once per [`CACHE_TTL`] — cheap for a caller like
/// `FaceDialer::dial_v9` to call on every dial, since the common case is a
/// vec clone with no syscall.
///
/// # Testing a fixed-signature caller
///
/// `mirage_mesh_client::monitor_faces::FaceDialer::dial_v9` (a different
/// crate) cannot take a `local_addrs` parameter — its signature is public
/// and already called by crates this workspace's rules forbid editing.
/// [`set_cached_local_machine_addrs_for_test`] is the seam
/// instead: call it at the top of a test, on the thread that test runs on,
/// and every call to this function from that SAME thread for the rest of
/// the test returns exactly what was set — no interface read, no loopback
/// folded in unless the caller put it there. `mirage-mesh-client`'s
/// `capsule_ask.rs` test suite uses this to keep its loopback-bound mock
/// monitors reading as "a different, remote monitor" once `dial_v9` gained
/// this cache as its own self-check.
pub fn cached_local_machine_addrs() -> Vec<IpAddr> {
    if let Some(overridden) = TEST_OVERRIDE.with(|cell| cell.borrow().clone()) {
        return overridden;
    }

    let mut cache = CACHE.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    let stale = cache.refreshed_at.is_none_or(|t| t.elapsed() >= CACHE_TTL);
    if stale {
        let mut fresh = local_machine_addrs();
        for sentinel in [
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        ] {
            if !fresh.contains(&sentinel) {
                fresh.push(sentinel);
            }
        }
        cache.addrs = fresh;
        cache.refreshed_at = Some(Instant::now());
    }
    cache.addrs.clone()
}

/// Pin [`cached_local_machine_addrs`]'s answer, on the CALLING THREAD only,
/// to exactly `addrs` — no loopback or unspecified folded in, no interface
/// read, ever, once this has been called on that thread. See
/// [`cached_local_machine_addrs`]'s own doc for why this exists and why it
/// is thread-local rather than a second process-global.
///
/// Deliberately not `#[cfg(test)]`-gated: that attribute is evaluated when
/// THIS crate is compiled, and `mirage-mesh-client`'s own `cargo test` run
/// compiles `mirage-core` as an ordinary (non-test) library dependency — an
/// item gated on `cfg(test)` here would not exist at all in that build, the
/// exact build this function needs to work in. The `_for_test` name carries
/// the contract that `#[cfg(test)]` cannot express across the crate
/// boundary.
///
/// `doc(hidden)` because the contract carried by a name is weaker than one
/// carried by the API surface: this ships in every release binary, and what
/// it switches off is a security check. Thread-local, so a caller can only
/// ever blind its own thread — but it must not read as ordinary API to
/// anyone browsing this crate.
#[doc(hidden)]
pub fn set_cached_local_machine_addrs_for_test(addrs: Vec<IpAddr>) {
    TEST_OVERRIDE.with(|cell| *cell.borrow_mut() = Some(addrs));
}

/// Read the address out of a `getifaddrs(3)` entry's `ifa_addr`, for the two
/// families this module cares about. `ifa_addr` is null for some
/// pseudo-interfaces (documented `getifaddrs(3)` behaviour) and is an
/// `AF_PACKET` link-layer address for every interface's own entry — neither
/// is an IP, and both are skipped by returning `None`.
#[cfg(target_os = "linux")]
fn sockaddr_to_ip(addr: *mut libc::sockaddr) -> Option<IpAddr> {
    if addr.is_null() {
        return None;
    }
    // SAFETY: non-null, and owned by the `ifaddrs` list this function's only
    // caller ([`local_machine_addrs`]) is currently iterating — valid for
    // the duration of this read. Only `sa_family` is read here, which every
    // `sockaddr`-shaped struct carries at the same offset regardless of
    // which larger type the kernel actually populated.
    let family = i32::from(unsafe { (*addr).sa_family });
    match family {
        libc::AF_INET => {
            // SAFETY: `sa_family == AF_INET` is `getifaddrs(3)`'s own
            // guarantee that the kernel wrote a `sockaddr_in` here — the
            // same cast every C caller of this API performs.
            let sin = unsafe { &*addr.cast::<libc::sockaddr_in>() };
            // `s_addr` is already in network byte order. Reading it back out
            // via `to_ne_bytes` recovers exactly those bytes — a native read
            // followed by a native write is a no-op on the same host,
            // whatever that host's endianness is — so this never
            // reinterprets the value numerically and needs no `ntohl`.
            Some(IpAddr::V4(std::net::Ipv4Addr::from(sin.sin_addr.s_addr.to_ne_bytes())))
        }
        libc::AF_INET6 => {
            // SAFETY: same reasoning as the `AF_INET` arm, for `sockaddr_in6`.
            let sin6 = unsafe { &*addr.cast::<libc::sockaddr_in6>() };
            Some(IpAddr::V6(std::net::Ipv6Addr::from(sin6.sin6_addr.s6_addr)))
        }
        _ => None,
    }
}

/// Whether an address read off a local interface belongs in "this box's own
/// addresses" for the callers this module has today.
///
/// Every global-unicast-shaped address, both families. Loopback is excluded
/// here on purpose — not because it is ever safe to dial, but because every
/// consumer of [`local_machine_addrs`] already recognises loopback through
/// its own unconditional literal check (`127.0.0.1` / `::1` and friends),
/// same as `mirage-secd::banengine::is_exempt` does independently of its own
/// copy of this filter. Folding it in here too would make loopback
/// recognition depend on a successful `getifaddrs(3)` call for no reason —
/// it is always true, on every box, whether or not the interface read ever
/// runs. Link-local is excluded because it is never a face a fleet peer or
/// this box's own perimeter could be reached on from outside this box's own
/// link, so it can never be the shape of the self-dial this module exists to
/// catch. Multicast and unspecified are not addresses a socket dials to.
/// Everything else this box's kernel reports as bound to one of its own
/// interfaces — public or private, IPv4 or IPv6 — is a shape the box really
/// could dial itself on, so it is included: a private/mesh-internal address
/// is exactly as capable of producing a self-dial as the public one that
/// actually did (measured on `nl-example-203.0.113.30`, 2026-08-18).
///
/// Pure and OS-independent on purpose, so the classification RULE is
/// testable without a kernel call, separately from [`local_machine_addrs`]'s
/// own Linux-only enumeration — see this module's tests.
#[cfg(any(target_os = "linux", test))]
pub fn is_local_interface_candidate(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            !v4.is_loopback() && !v4.is_link_local() && !v4.is_unspecified() && !v4.is_multicast()
        }
        IpAddr::V6(v6) => {
            // fe80::/10 — computed by hand rather than via
            // `Ipv6Addr::is_unicast_link_local` (unstable at the time of
            // writing): a fixed 10-bit prefix match on the first segment,
            // which every stable Rust has always been able to do.
            const LINK_LOCAL_PREFIX: u16 = 0xfe80;
            const LINK_LOCAL_MASK: u16 = 0xffc0;
            !v6.is_loopback()
                && !v6.is_unspecified()
                && !v6.is_multicast()
                && (v6.segments()[0] & LINK_LOCAL_MASK) != LINK_LOCAL_PREFIX
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordinary_addresses_are_candidates() {
        for ip in [
            "203.0.113.11",
            "10.0.4.9",
            "192.168.1.20",
            "2001:db8::1",
            "fd00::1",
        ] {
            let parsed: IpAddr = ip.parse().expect("valid literal");
            assert!(is_local_interface_candidate(parsed), "{ip} should be a candidate");
        }
    }

    #[test]
    fn loopback_is_excluded() {
        for ip in ["127.0.0.1", "::1"] {
            let parsed: IpAddr = ip.parse().expect("valid literal");
            assert!(!is_local_interface_candidate(parsed), "{ip} must be excluded");
        }
    }

    #[test]
    fn link_local_is_excluded() {
        for ip in ["169.254.1.1", "fe80::1"] {
            let parsed: IpAddr = ip.parse().expect("valid literal");
            assert!(!is_local_interface_candidate(parsed), "{ip} must be excluded");
        }
    }

    #[test]
    fn unspecified_and_multicast_are_excluded() {
        for ip in ["0.0.0.0", "224.0.0.1", "::", "ff02::1"] {
            let parsed: IpAddr = ip.parse().expect("valid literal");
            assert!(!is_local_interface_candidate(parsed), "{ip} must be excluded");
        }
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn the_non_linux_stub_returns_an_empty_list() {
        assert!(local_machine_addrs().is_empty());
    }

    // ── cached_local_machine_addrs / set_cached_local_machine_addrs_for_test ──
    //
    // Each `#[test]` runs on its own freshly spawned OS thread (the default
    // `libtest` harness), and `TEST_OVERRIDE` is thread-local, so a test
    // here never sees another test's override and never needs
    // `--test-threads=1` to stay deterministic.

    #[test]
    fn the_default_answer_includes_the_loopback_and_unspecified_sentinels() {
        // No override set on this thread -- this is the production shape
        // `dial_v9` gets when nothing has told it otherwise.
        let addrs = cached_local_machine_addrs();
        for sentinel in ["127.0.0.1", "::1", "0.0.0.0", "::"] {
            let parsed: IpAddr = sentinel.parse().expect("valid literal");
            assert!(addrs.contains(&parsed), "{sentinel} must be in the default answer");
        }
    }

    #[test]
    fn an_empty_override_replaces_the_default_entirely() {
        set_cached_local_machine_addrs_for_test(Vec::new());
        assert_eq!(
            cached_local_machine_addrs(),
            Vec::<IpAddr>::new(),
            "an empty override must not have loopback/unspecified folded back in"
        );
    }

    #[test]
    fn a_non_empty_override_is_returned_exactly_as_set() {
        let mine: Vec<IpAddr> = vec!["203.0.113.50".parse().expect("valid literal")];
        set_cached_local_machine_addrs_for_test(mine.clone());
        assert_eq!(cached_local_machine_addrs(), mine);
    }
}
