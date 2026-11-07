//! Per-boot machine-identity acquisition — the perimeter's ONLY identity
//! path.
//!
//! # The machine-identity cutover (2026-08-17)
//!
//! Identity moved from a per-role sealed capsule this daemon chased for
//! itself — announce, poll a tmpfs drop, ask the mesh, renew on its own
//! clock — to a single per-MACHINE capsule the box's keeper
//! (`mirage-warden`) holds and serves over a local socket. See
//! `docs/mirage/plans/machine-identity-consolidated-2026-08-17.md` §2 and
//! §4. [`acquire_identity`] is now one call: ask the keeper for this box's
//! perimeter slice ([`take_machine_slice`], which loops internally — see
//! its own doc for why the wait has no deadline and no network fallback)
//! and bind on whatever it hands back. There is no announce, no per-service
//! renewal loop, and no `mirage_mesh_client::CapsuleAsker` here any more:
//! the keeper owns admission and renewal for the whole machine, once.
//!
//! # The property this preserves, and why the mechanism could be deleted
//!
//! Before this cutover, this crate was the ONE consumer that already read a
//! machine-lifetime rest capsule (`load_rest_capsule`,
//! `/run/mirage/<role>/rest_capsule`) and bound its faces on a hit instead
//! of waiting on the network for a fresh one — because this daemon is the
//! box's only public listener, and a version that waited on a mesh dial
//! before binding anything left the box's front door down for exactly as
//! long as that dial took. The property that mattered was never the file;
//! it was "the box's only public listener must not wait on a network round
//! trip it might not win before it can serve".
//!
//! The keeper now gives every consumer that property structurally, for
//! free: [`take_machine_slice`] talks to a LOCAL socket a supervisor
//! process starts before every other unit on the box, and when that socket
//! already holds an admitted machine capsule — the ordinary case, a
//! restart on a machine that was not reset — it answers from RAM in one
//! hop. There is nothing left for this crate to cache, no boot-nonce to
//! chase a fresher answer for in the background, and no separate baseline
//! surface to bind while waiting: a second mechanism next to a wait that is
//! already this cheap would only be something else to keep honest.
//!
//! The one case where [`acquire_identity`] genuinely blocks — the machine
//! itself was just reset, and the keeper is mid-admission — is the SAME
//! case every other service on the box blocks through, together (the
//! plan's §4, "Cold boot after a machine reset": every unit blocks on the
//! keeper socket and wakes up identified in one pass). The operator's way
//! in during that window is mshd's recovery door, which is
//! capsule-independent for exactly this reason — not a surface this crate
//! would otherwise have to bind and keep honest on its own.
//!
//! # Telling the two facts apart
//!
//! An operator reading the journal still needs to be able to tell "this
//! boot inherited an identity it did not mint" (the ordinary, fast case)
//! from "this boot's own wait is what produced the admission" (a machine
//! reset, correlated with this boot) — the same distinction the old
//! "BOOTING ON A REST IDENTITY" warning drew, kept in spirit even though
//! the mechanism it described (a second, boot-nonce-bound capsule chased in
//! the background) no longer exists: the keeper's answer to `Take` IS the
//! current identity, never a placeholder for something better arriving
//! later. [`Provenance`] draws the distinction from one comparison — was
//! the slice the keeper handed over minted before or after this process
//! started asking — logged once in [`acquire_identity`] and mirrored into
//! [`GRACE`] for the query channel (`crate::stats`) exactly as the old
//! grace flag was.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use ed25519_dalek::SigningKey;
use mirage_core::crypto::KeyPair;
use mirage_core::identity::ServiceRole;
use mirage_core::identity_boot::take_machine_slice;
use mirage_core::machine_identity_query::MachineSlice;
use tracing::{debug, info, warn};

use crate::identity::{self, Identity};

pub(crate) fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Process-wide "this boot's identity was inherited from the keeper rather
/// than freshly admitted while this boot was waiting" signal.
///
/// A `'static` singleton rather than something threaded through
/// [`acquire_identity`]'s return value: `crate::stats`'s query reader reads
/// it independently and after `acquire_identity` has already returned, so a
/// shared static is simpler than plumbing an `Arc` through `lib.rs::run`'s
/// existing signature. Nothing stored here is secret — a UUID and three
/// timestamps, never key material — so exposing it costs nothing.
///
/// Unlike the mechanism this replaces, nothing here ever transitions LATER:
/// there is no second capsule chased in the background to resolve into, so
/// [`Self::enter`] is called at most once, from [`acquire_identity`], and
/// the state it sets is what this boot reports for its whole lifetime. See
/// [`GraceSnapshot`] and the module doc, "Telling the two facts apart".
pub struct GraceState {
    active: AtomicBool,
    entered_at_ms: AtomicU64,
    capsule_issued_at_ms: AtomicU64,
    capsule_not_after_ms: AtomicU64,
}

impl GraceState {
    const fn new() -> Self {
        Self {
            active: AtomicBool::new(false),
            entered_at_ms: AtomicU64::new(0),
            capsule_issued_at_ms: AtomicU64::new(0),
            capsule_not_after_ms: AtomicU64::new(0),
        }
    }

    /// Record that this boot is running on an identity it did not mint —
    /// called at most once, from [`acquire_identity`], the instant a slice
    /// classifies as [`Provenance::Inherited`]. There is no matching
    /// "leave" call: nothing later ever changes this boot's answer, so the
    /// state this sets is the state this process reports until it exits.
    fn enter(&self, entered_at_ms: u64, capsule_issued_at_ms: u64, capsule_not_after_ms: u64) {
        self.entered_at_ms.store(entered_at_ms, Ordering::Relaxed);
        self.capsule_issued_at_ms.store(capsule_issued_at_ms, Ordering::Relaxed);
        self.capsule_not_after_ms.store(capsule_not_after_ms, Ordering::Relaxed);
        self.active.store(true, Ordering::Relaxed);
    }

    /// A point-in-time read for `crate::stats` and the query channel.
    /// Always returns a value — before [`Self::enter`] is ever called (this
    /// boot's identity was freshly minted, or acquisition has not completed
    /// yet), that value is simply "not running on an inherited identity"
    /// (`active: false`, every timestamp zero).
    ///
    /// `renewal` is NOT this state's own field — it is read live from
    /// [`renewal_snapshot`], which tracks the KEEPER's own view of the
    /// machine capsule (refreshed on every acquire/reacquire), unlike every
    /// field above, which describe only this boot's own one-time
    /// inherited-vs-fresh classification and never move again. Folded in
    /// here anyway because `/perimeter/stats` and `/health` already read
    /// grace through this one call — see `crate::stats::Stats::health`/
    /// `snapshot`'s own call sites.
    #[must_use]
    pub fn snapshot(&self, now_ms: u64) -> GraceSnapshot {
        let active = self.active.load(Ordering::Relaxed);
        let entered_at_ms = self.entered_at_ms.load(Ordering::Relaxed);
        GraceSnapshot {
            active,
            entered_at_ms,
            age_ms: if active { now_ms.saturating_sub(entered_at_ms) } else { 0 },
            capsule_issued_at_ms: self.capsule_issued_at_ms.load(Ordering::Relaxed),
            capsule_not_after_ms: self.capsule_not_after_ms.load(Ordering::Relaxed),
            // No later event ever resolves this state (see this type's own
            // doc), so there is nothing honest to report here beyond "never
            // resolved" — kept at the wire shape's default (0) rather than
            // repurposed for something this state machine no longer has.
            resolved_at_ms: 0,
            renewal: renewal_snapshot(),
        }
    }
}

/// The keeper's renewal-stall snapshot, cached from the last successful
/// [`refresh_renewal_status`] call — see [`GraceSnapshot::renewal`]'s own
/// doc. `active: false` for the entire life of a box whose renewals keep
/// landing inside one ask cycle.
///
/// Removed 2026-09-23: this crate's own `CURRENT_CAPSULE_NOT_AFTER_MS` /
/// `capsule_expired_for_ms`, which computed "how far past due" from the ONE
/// slice this process took at its own start and never re-took. A role never
/// re-takes its slice by design, so that number only ever got staler — every
/// perimeter older than 24h read "expired 12 days" while the keeper it asks
/// (`mirage-warden`) was renewing that same machine's capsule fine, every
/// ~18h, `expires_in` a healthy 10-14h on every box. `keeper_capsule_not_after_ms`
/// below, mirrored straight from the keeper's own live RAM cache, is the
/// replacement — the only capsule-expiry number this crate shows.
struct RenewalStatusCache {
    active: AtomicBool,
    due_since_ms: AtomicU64,
    /// `0` encodes `None` — a due-since timestamp of exactly unix epoch zero
    /// is not a value any real clock produces.
    window_opened_ms: AtomicU64,
    /// The keeper's own live capsule `not_after_ms`, mirrored from
    /// [`mirage_core::machine_identity_query::RenewalStallState::
    /// capsule_not_after_ms`] — see this cache's own doc. `0` encodes `None`
    /// the same way `window_opened_ms` does.
    keeper_capsule_not_after_ms: AtomicU64,
}

impl RenewalStatusCache {
    const fn new() -> Self {
        Self {
            active: AtomicBool::new(false),
            due_since_ms: AtomicU64::new(0),
            window_opened_ms: AtomicU64::new(0),
            keeper_capsule_not_after_ms: AtomicU64::new(0),
        }
    }

    fn set(&self, state: Option<mirage_core::machine_identity_query::RenewalStallState>) {
        match state {
            Some(s) => {
                self.due_since_ms.store(s.due_since_ms, Ordering::Relaxed);
                self.window_opened_ms.store(s.window_opened_ms.unwrap_or(0), Ordering::Relaxed);
                self.keeper_capsule_not_after_ms
                    .store(s.capsule_not_after_ms.unwrap_or(0), Ordering::Relaxed);
                self.active.store(true, Ordering::Relaxed);
            }
            None => self.active.store(false, Ordering::Relaxed),
        }
    }

    fn snapshot(&self) -> Option<mirage_core::perimeter_query::RenewalSnapshot> {
        if !self.active.load(Ordering::Relaxed) {
            return None;
        }
        let window_opened_ms = match self.window_opened_ms.load(Ordering::Relaxed) {
            0 => None,
            ms => Some(ms),
        };
        let keeper_capsule_not_after_ms = match self.keeper_capsule_not_after_ms.load(Ordering::Relaxed)
        {
            0 => None,
            ms => Some(ms),
        };
        Some(mirage_core::perimeter_query::RenewalSnapshot {
            due_since_ms: self.due_since_ms.load(Ordering::Relaxed),
            window_opened_ms,
            keeper_capsule_not_after_ms,
        })
    }
}

static RENEWAL_STATUS: RenewalStatusCache = RenewalStatusCache::new();

/// `/perimeter/stats`'s read of the keeper's own renewal-stall state — see
/// [`GraceSnapshot::renewal`]'s own doc.
#[must_use]
pub fn renewal_snapshot() -> Option<mirage_core::perimeter_query::RenewalSnapshot> {
    RENEWAL_STATUS.snapshot()
}

/// Ask the keeper for its renewal-stall state and cache the answer for the
/// query channel — best-effort, never fails the caller: a keeper that
/// cannot be reached THIS instant leaves the last known snapshot in place,
/// the same disposition a briefly-unreachable keeper already gets from
/// `Surface::watch_for_a_new_capsule` for the capsule itself.
async fn refresh_renewal_status() {
    match mirage_core::identity_boot::ask_renewal_status().await {
        Ok(state) => RENEWAL_STATUS.set(state),
        Err(e) => {
            debug!(
                error = %e,
                "[perimeter/capsule] renewal-status read did not resolve — keeping the last known \
                 state"
            );
        }
    }
}

/// Serialisable read of [`GraceState`], defined in `mirage-core` alongside
/// the rest of what this daemon answers on
/// [`mirage_core::local_endpoint::LocalChannel::PerimeterQuery`].
///
/// The ATOMICS above stay here — they are this process's own business — and
/// only the shape that leaves the process is shared, so a consumer parses
/// the same struct the producer built.
pub use mirage_core::perimeter_query::GraceSnapshot;

/// This boot's identity-provenance state. See [`GraceState`]'s own doc for
/// why a static, and the module doc, "Telling the two facts apart".
pub static GRACE: GraceState = GraceState::new();

/// Which of the two facts this boot's identity represents.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Provenance {
    /// The keeper already held this identity before this process ever
    /// asked for it — an ordinary restart on a machine that was not reset.
    Inherited,
    /// Admission happened while this process was waiting on the keeper —
    /// only possible once per machine reset.
    FreshlyMinted,
}

/// Classify a slice's provenance relative to when this boot started asking
/// for it. A pure comparison, factored out of [`acquire_identity`] so it is
/// testable without a keeper socket — see the tests below.
fn classify_provenance(slice_issued_at_ms: u64, boot_started_at_ms: u64) -> Provenance {
    if slice_issued_at_ms < boot_started_at_ms {
        Provenance::Inherited
    } else {
        Provenance::FreshlyMinted
    }
}

/// Acquire this box's perimeter slice from the keeper and wait for it — the
/// crate's ONLY identity path, and its ONLY boot-time wait. See the module
/// doc for the property this preserves from the crate's old per-role
/// rest-capsule fast path, and [`take_machine_slice`]'s own doc for why the
/// wait itself has no deadline and no network fallback.
///
/// Returns `Err` only for conditions retrying cannot fix: the compiled-in
/// operator pubkey is itself still the checked-in placeholder, or the
/// keeper handed over a slice that fails its own coherence check for a
/// reason other than expiry (`take_machine_slice` already refuses to retry
/// through those — see its own doc).
pub async fn acquire_identity() -> Result<Identity> {
    let operator_pub = identity::operator_pubkey()
        .context("cannot acquire a slice without a real compiled-in operator pubkey")?;

    let boot_started_at_ms = now_ms();
    let slice = take_machine_slice(ServiceRole::Perimeter, &operator_pub)
        .await
        .context("keeper handed over a slice that does not check out")?;
    let acquired_at_ms = now_ms();

    refresh_renewal_status().await;

    match classify_provenance(slice.issued_at_ms, boot_started_at_ms) {
        Provenance::Inherited => {
            GRACE.enter(acquired_at_ms, slice.issued_at_ms, slice.not_after_ms);
            info!(
                self_id = %slice.self_id,
                machine_id = %slice.machine_id.as_str(),
                mesh_id = %slice.mesh_id.as_str(),
                capsule_issued_at_ms = slice.issued_at_ms,
                capsule_not_after_ms = slice.not_after_ms,
                "[perimeter/capsule] bound on an identity this boot did not mint — the keeper \
                 already held it, no admission happened this boot"
            );
        }
        Provenance::FreshlyMinted => {
            warn!(
                self_id = %slice.self_id,
                machine_id = %slice.machine_id.as_str(),
                mesh_id = %slice.mesh_id.as_str(),
                capsule_issued_at_ms = slice.issued_at_ms,
                capsule_not_after_ms = slice.not_after_ms,
                "[perimeter/capsule] bound on a FRESH identity — admission happened while this \
                 boot was waiting on the keeper, which only happens once per machine reset"
            );
        }
    }

    Ok(build_identity(slice))
}

/// Ask the keeper which capsule this box holds **now** — the re-read, not a
/// second boot.
///
/// [`acquire_identity`] answers "who is this box, as this process starts";
/// this answers "who is this box, as of this moment", and the surface calls
/// it on a cadence for as long as the process lives
/// (`crate::Surface::watch_for_a_new_capsule`). Both go through the same
/// [`take_machine_slice`] and the same [`build_identity`]; what this one
/// deliberately does NOT do is repeat the boot's side effects.
///
/// # Why this is not `acquire_identity` called twice
///
/// [`Provenance`] is a statement about a BOOT: it compares when the
/// keeper's slice was minted against `boot_started_at_ms`, to tell "this
/// process inherited an identity that already existed" from "this
/// process's own wait is what produced the admission". Asked once, at
/// start, that is a true and useful thing to log. Asked again on every
/// poll, it would call every capsule delivered later in the box's life
/// `FreshlyMinted` — they are all minted after this process started, by
/// definition — and each one would re-arm [`GRACE`], announcing a
/// post-reset grace window on a box that has been running for days. The
/// re-read wants the slice and the identity built from it; it has no
/// opinion to offer about how this boot went, and must not manufacture
/// one.
///
/// Calling [`take_machine_slice`] repeatedly is safe by construction: it
/// holds no state between calls, registers nothing with the keeper, and is
/// one `Take` request per turn of its own loop. It still blocks without a
/// deadline while the keeper has nothing to hand over, and still returns
/// `Err` — rather than waiting — on a slice that fails coherence for any
/// reason other than expiry, exactly as it does at boot.
pub async fn reacquire_identity() -> Result<Identity> {
    let operator_pub = identity::operator_pubkey()
        .context("cannot re-read a slice without a real compiled-in operator pubkey")?;
    let slice = take_machine_slice(ServiceRole::Perimeter, &operator_pub)
        .await
        .context("keeper handed over a slice that does not check out")?;
    refresh_renewal_status().await;
    Ok(build_identity(slice))
}

/// Map a verified [`MachineSlice`] onto this crate's own [`Identity`]
/// shape. A signing-less slice is perfectly usable here — see
/// `identity.rs`'s module doc for why `signing_keypair` is `None` on
/// today's fleet and what that degrades to.
fn build_identity(slice: MachineSlice) -> Identity {
    let signing_keypair = slice.slice.signing_secret().map(|s| SigningKey::from_bytes(&s));
    Identity {
        perimeter_id: slice.self_id.to_string(),
        mesh_id: slice.mesh_id.as_str().to_string(),
        shortname: slice.service_config.shortname.clone().unwrap_or_default(),
        wire_keypair: KeyPair::from_secret(*slice.slice.wire_secret()),
        declared_identity: Some(slice.declared_identity.clone()),
        service_config: slice.service_config.clone(),
        charter: slice.charter.clone(),
        signing_keypair,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_slice_older_than_this_boot_is_inherited() {
        assert_eq!(classify_provenance(900, 1_000), Provenance::Inherited);
    }

    #[test]
    fn a_slice_minted_at_or_after_this_boot_started_is_freshly_minted() {
        // `>=`, not `>`: a slice minted in the SAME millisecond this boot
        // started asking is still the admission this boot's own wait
        // produced, not one that predates it.
        assert_eq!(classify_provenance(1_000, 1_000), Provenance::FreshlyMinted);
        assert_eq!(classify_provenance(1_100, 1_000), Provenance::FreshlyMinted);
    }

    #[test]
    fn grace_state_starts_inactive_and_enter_makes_it_active() {
        let g = GraceState::new();
        let before = g.snapshot(1_000);
        assert!(!before.active);
        assert_eq!(before.age_ms, 0);

        g.enter(1_000, 900, 5_000);
        let after = g.snapshot(1_500);
        assert!(after.active);
        assert_eq!(after.age_ms, 500);
        assert_eq!(after.capsule_issued_at_ms, 900);
        assert_eq!(after.capsule_not_after_ms, 5_000);
        assert_eq!(after.resolved_at_ms, 0, "nothing ever resolves this state");
    }

    /// `renewal_snapshot` mirrors whatever the keeper last reported —
    /// `None` while nothing is stalled, `Some` with the keeper's own three
    /// mirrored fields once one is.
    #[test]
    fn renewal_status_cache_reports_none_then_the_keepers_own_fields() {
        let cache = RenewalStatusCache::new();
        assert!(cache.snapshot().is_none());

        cache.set(Some(mirage_core::machine_identity_query::RenewalStallState {
            due_since_ms: 1_000,
            window_opened_ms: Some(1_200),
            // Not read back by `RenewalStatusCache` — see
            // `mirage_core::perimeter_query::RenewalSnapshot`'s own doc for
            // why `expired_for_ms` is not duplicated onto this cache.
            expired_for_ms: Some(9_999),
            capsule_not_after_ms: Some(1_700_150_000_000),
        }));
        let snap = cache.snapshot().expect("a stall was just set");
        assert_eq!(snap.due_since_ms, 1_000);
        assert_eq!(snap.window_opened_ms, Some(1_200));
        assert_eq!(snap.keeper_capsule_not_after_ms, Some(1_700_150_000_000));

        cache.set(None);
        assert!(cache.snapshot().is_none());
    }

    /// The exact property this whole fix exists for: the keeper's LIVE
    /// capsule `not_after_ms` — never this process's own one-time boot
    /// slice — is what ends up in the perimeter's renewal block, under its
    /// explicit name. A keeper that answers with no `capsule_not_after_ms`
    /// at all (predates the field) must flow through as `None`, not a false
    /// zero.
    #[test]
    fn the_keepers_live_not_after_flows_into_the_perimeters_renewal_block() {
        let cache = RenewalStatusCache::new();
        cache.set(Some(mirage_core::machine_identity_query::RenewalStallState {
            due_since_ms: 2_000,
            window_opened_ms: None,
            expired_for_ms: None,
            capsule_not_after_ms: Some(1_700_200_000_000),
        }));
        let snap = cache.snapshot().expect("a stall was just set");
        assert_eq!(snap.keeper_capsule_not_after_ms, Some(1_700_200_000_000));

        cache.set(Some(mirage_core::machine_identity_query::RenewalStallState {
            due_since_ms: 3_000,
            window_opened_ms: None,
            expired_for_ms: None,
            capsule_not_after_ms: None,
        }));
        let snap = cache.snapshot().expect("a stall was just set");
        assert_eq!(
            snap.keeper_capsule_not_after_ms, None,
            "an older keeper's missing field must read as \"we don't know\", never a false zero"
        );
    }
}
