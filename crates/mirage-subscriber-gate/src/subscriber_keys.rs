//! Box-local subscriber allowlist gate: the edge's currently-installed,
//! issuer-signed [`SubscriberSet`] (`mirage_core::crypto::credential::
//! subscriber_set`) — the set of subscriber static X25519 public keys
//! authorized to enter through this box's entrance path
//! (`crate::entrance_auth::make_entrance_auth`, consulted by
//! `crate::entrance_auth::PresentedCredential::classify`), each with its own
//! expiry (`not_after_ms == subscription.period_end_ms`) and scope
//! (`public` | pinned to one edge's `machine_id`).
//!
//! See `docs/mirage/plans/2026-09-25-subscription-bound-credentials.md`,
//! "Coordinator decision (2026-09-25)" — the file this module loads is no
//! longer a bare list of hex keys (nor the keys-plus-`personal_mesh_id`
//! shape that preceded it, now dropped for edges: `SubscriberSetEntry`
//! carries no such field); it is one issuer-signed [`SubscriberSet`], pushed
//! by opbox through the SAME mechanism as before (`POST
//! /mshd/put/subscriber-key`, box-local hot-reload, JSON on disk) — only the
//! shape of that JSON, and the trust model around it, changed.
//!
//! # Why a local file, not a gossip frame
//!
//! Unchanged from before this module's rewrite: the box is OURS, provisioned
//! by us, and opbox can write to it directly. Subscriber key material is a
//! LOCAL file on the box, loaded at startup ([`load_subscriber_set_file`])
//! and hot-reloaded on change ([`spawn_hot_reload`]) into the same
//! [`SubscriberKeyStore`] the gate reads — no gossip, no fleet-wide
//! frame-compatibility roll order, no round trip off the box.
//!
//! # Trust model
//!
//! [`SubscriberKeyStore::install`] verifies the issuer signature (and every
//! bound `SubscriberSet::decode`/`verify` enforces) BEFORE ever replacing the
//! installed set. A bad signature or a malformed file is refused outright —
//! the PREVIOUS good set (if any) stays installed, and the caller logs the
//! refusal by name once (see [`spawn_hot_reload`]'s own doc). A box that has
//! never installed a single good set admits nobody
//! ([`SubscriberKeyStore::admit`]'s own [`StoreAdmitError::NoGoodSetEver`]) —
//! there is no "empty allowlist as a permissive default" reading of an
//! absent or ever-broken file.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use arc_swap::ArcSwapOption;
use ed25519_dalek::VerifyingKey;
use mirage_core::crypto::credential::subscriber_set::{
    AdmitRefusal, EdgeScopeView, SubscriberSet, SubscriberSetEntry, SubscriberSetError,
};
use thiserror::Error;
use tracing::{debug, info, warn};

/// One subscriber's static X25519 public key, exactly the bytes carried in
/// `mirage_protocol::ClientAuthContext::static_pub`. Unrelated to
/// [`SubscriberSet`]'s own `device_pubkey_hex` string encoding — this is the
/// raw-bytes identity every OTHER part of this crate (bandwidth caps, byte
/// counters, UDP-flow limits) keys by; the store hex-encodes it at its own
/// boundary, once, rather than pushing that encoding out to every caller.
pub type SubscriberKey = [u8; 32];

/// Box-local, issuer-verified subscriber allowlist. Hot-swappable, full-set
/// atomic replace on every successful [`install`](Self::install) — no
/// per-key locking on the hot path ([`contains`](Self::contains) and
/// [`admit`](Self::admit) each load one snapshot per call).
pub struct SubscriberKeyStore {
    /// This box's own pinned subscriber-issuer verifying key
    /// (`mirage_edge::bootstrap::subscriber_issuer_pubkey`) — fixed for the
    /// life of the process, never itself hot-reloaded.
    issuer_pub: VerifyingKey,
    /// The last successfully verified [`SubscriberSet`] — `None` until the
    /// first good install ever happens on this box.
    good: ArcSwapOption<SubscriberSet>,
}

/// Everything [`SubscriberKeyStore::admit`] can refuse an admission
/// decision for — independently reachable, independently tested.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum StoreAdmitError {
    /// This box has never installed a single good signed set — admit
    /// nobody, by design (this module's own doc).
    #[error("subscriber-keys: no good signed set has ever been installed on this box -- refusing every dial")]
    NoGoodSetEver,
    /// The currently-installed set (already verified once, at
    /// [`SubscriberKeyStore::install`] time) failed re-verification against
    /// this box's own pinned issuer key. Should not be reachable in
    /// practice — the set is immutable once installed — but named and
    /// tested rather than assumed away.
    #[error("subscriber-keys: the installed set failed re-verification -- {0}")]
    Reverify(SubscriberSetError),
    #[error(transparent)]
    Refused(#[from] AdmitRefusal),
}

impl SubscriberKeyStore {
    /// A store with no good set installed yet — the boot-time state for
    /// every box, and the permanent state of a box whose
    /// `subscriber_keys_path` file has never once verified. Admits nobody
    /// until [`install`](Self::install) succeeds at least once.
    pub fn empty(issuer_pub: VerifyingKey) -> Arc<Self> {
        Arc::new(Self { issuer_pub, good: ArcSwapOption::from(None) })
    }

    /// Verify `set` against this box's own pinned issuer key and, only on
    /// success, atomically replace the installed set. On failure the
    /// PREVIOUS good set (if any) is left untouched and the error is
    /// returned for the caller to log by name — this function never empties
    /// the gate on a bad input.
    pub fn install(&self, set: SubscriberSet) -> Result<(), SubscriberSetError> {
        set.verify(&self.issuer_pub)?;
        self.good.store(Some(Arc::new(set)));
        Ok(())
    }

    /// Pre-handshake classification signal ONLY — presence of
    /// `key`, hex-encoded, in the current good set, regardless of that
    /// entry's own expiry or scope. Never a security decision on its own:
    /// see `crate::entrance_auth::PresentedCredential`'s own doc. The real
    /// admission decision is [`admit`](Self::admit), always run against the
    /// V9-authenticated static key, after the handshake's own cryptography
    /// already holds.
    pub fn contains(&self, key: &SubscriberKey) -> bool {
        let hex_key = hex::encode(key);
        match self.good.load_full() {
            Some(set) => set.entries.iter().any(|e| e.device_pubkey_hex.eq_ignore_ascii_case(&hex_key)),
            None => false,
        }
    }

    /// The real admission decision: `key`, hex-encoded, must name an entry
    /// in the current good set that has not expired at `now_ms` and whose
    /// scope matches `own_scope`. Returns the matched entry (owned — cheap,
    /// a handful of short strings and two `u64`s) so the caller can arm a
    /// session deadline against its OWN `not_after_ms`, never
    /// `next_expiry_after`'s "latest across every entry" answer.
    pub fn admit(
        &self,
        key: &SubscriberKey,
        now_ms: u64,
        own_scope: &EdgeScopeView,
    ) -> Result<SubscriberSetEntry, StoreAdmitError> {
        let hex_key = hex::encode(key);
        self.admit_hex(&hex_key, now_ms, own_scope)
    }

    /// [`admit`](Self::admit)'s own logic, taking an already-hex-encoded key
    /// — the shape `crate::entrance_auth`'s live-session reload recheck
    /// needs (it only ever holds the hex string, not the raw 32 bytes, once
    /// a connection is registered).
    pub fn admit_hex(
        &self,
        device_pubkey_hex: &str,
        now_ms: u64,
        own_scope: &EdgeScopeView,
    ) -> Result<SubscriberSetEntry, StoreAdmitError> {
        let set = self.good.load_full().ok_or(StoreAdmitError::NoGoodSetEver)?;
        let verified = set.verify(&self.issuer_pub).map_err(StoreAdmitError::Reverify)?;
        verified
            .admit(device_pubkey_hex, now_ms, own_scope)
            .cloned()
            .map_err(StoreAdmitError::from)
    }
}

/// Errors loading the subscriber-set file from disk.
#[derive(Debug, thiserror::Error)]
pub enum SubscriberKeysError {
    #[error("read {path}: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("subscriber-set file: {0}")]
    Invalid(#[from] SubscriberSetError),
}

/// Default poll interval for [`spawn_hot_reload`]'s boot call site
/// (`mirage_edge::run`). Chosen to keep revocation "local and instant"
/// without `stat()`-ing the file more often than a human operator's
/// mint/revoke cadence could ever need.
pub const DEFAULT_POLL_INTERVAL: Duration = Duration::from_secs(5);

/// Load and decode (but not verify — see [`SubscriberKeyStore::install`],
/// which every caller of this function is expected to run the result
/// through) the subscriber-set file from disk once, for use at boot.
pub fn load_subscriber_set_file(path: &Path) -> Result<SubscriberSet, SubscriberKeysError> {
    let raw = std::fs::read(path).map_err(|source| SubscriberKeysError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    Ok(SubscriberSet::decode(&raw)?)
}

/// Spawn a background task that polls `path`'s mtime every `poll_interval`
/// and reloads [`SubscriberKeyStore`] when it changes.
///
/// Polling, not a filesystem-event watcher — same rationale as before this
/// module's rewrite: a subscriber-set file changes on an operator's
/// mint/revoke/renew action, not on a schedule needing sub-second
/// precision, and "local and instant" means no ROUND TRIP off the box, which
/// a local poll already satisfies.
///
/// A read/decode/verify failure on a later poll is logged ONCE — by name,
/// via [`SubscriberKeysError`]'s own `Display` — and the PREVIOUS good set
/// (if any) stays installed; `last_modified` is updated on EITHER outcome,
/// so a persistently bad file (mid-write, or genuinely malformed/mis-signed)
/// is retried only when it changes AGAIN, never re-logged every poll tick.
///
/// `on_reload` fires after every SUCCESSFUL install (never after a failed
/// one — a failed reload changes nothing for the caller to react to) so
/// `mirage-edge`'s own live-session registry can re-check every currently
/// open connection against the freshly installed set (close a
/// no-longer-admitted device, extend a renewed one) — see
/// `mirage_edge::live_sessions`. Kept as a plain, synchronous callback
/// (rather than an `async fn` in this signature) so this crate does not have
/// to name `mirage-edge`'s own registry type; a caller that needs to await
/// something inside it spawns its own task.
pub fn spawn_hot_reload(
    store: Arc<SubscriberKeyStore>,
    path: PathBuf,
    poll_interval: Duration,
    on_reload: Arc<dyn Fn() + Send + Sync>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut last_modified: Option<SystemTime> =
            std::fs::metadata(&path).and_then(|m| m.modified()).ok();
        let mut ticker = tokio::time::interval(poll_interval);
        ticker.tick().await; // first tick fires immediately; skip it.
        loop {
            ticker.tick().await;
            let modified = match std::fs::metadata(&path).and_then(|m| m.modified()) {
                Ok(m) => m,
                Err(e) => {
                    debug!(
                        path = %path.display(),
                        error = %e,
                        "subscriber-keys: stat failed on poll -- keeping current set"
                    );
                    continue;
                }
            };
            if Some(modified) == last_modified {
                continue;
            }
            last_modified = Some(modified);

            let set = match load_subscriber_set_file(&path) {
                Ok(set) => set,
                Err(e) => {
                    warn!(
                        path = %path.display(),
                        error = %e,
                        "subscriber-keys: reload failed -- keeping current set"
                    );
                    continue;
                }
            };
            match store.install(set) {
                Ok(()) => {
                    info!(path = %path.display(), "subscriber-keys: reloaded a new good signed set");
                    on_reload();
                }
                Err(e) => {
                    warn!(
                        path = %path.display(),
                        error = %e,
                        "subscriber-keys: reload failed -- keeping current set"
                    );
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use mirage_core::crypto::credential::subscriber_set::{sign, SubscriberScope};
    use rand::rngs::OsRng;
    use std::sync::atomic::{AtomicUsize, Ordering};

    const NOW: u64 = 1_800_000_000_000;

    fn key(byte: u8) -> SubscriberKey {
        [byte; 32]
    }

    fn hex_key(byte: u8) -> String {
        hex::encode(key(byte))
    }

    fn issuer() -> SigningKey {
        SigningKey::generate(&mut OsRng)
    }

    fn public_entry(byte: u8, not_after_ms: u64) -> SubscriberSetEntry {
        SubscriberSetEntry {
            device_pubkey_hex: hex_key(byte),
            scope: SubscriberScope::Public,
            not_after_ms,
            subscription_ref: format!("sub-{byte:02x}"),
        }
    }

    fn edge_entry(byte: u8, machine_id: &str, not_after_ms: u64) -> SubscriberSetEntry {
        SubscriberSetEntry {
            device_pubkey_hex: hex_key(byte),
            scope: SubscriberScope::Edge { machine_id: machine_id.to_string() },
            not_after_ms,
            subscription_ref: format!("sub-{byte:02x}"),
        }
    }

    // ── SubscriberKeyStore::install / admit / contains ───────────────────

    #[test]
    fn empty_store_admits_nobody() {
        let signing = issuer();
        let store = SubscriberKeyStore::empty(signing.verifying_key());
        let result = store.admit(&key(0x11), NOW, &EdgeScopeView::Public);
        assert_eq!(result.unwrap_err(), StoreAdmitError::NoGoodSetEver);
        assert!(!store.contains(&key(0x11)));
    }

    #[test]
    fn install_refuses_a_set_signed_by_a_different_issuer() {
        let real_issuer = issuer();
        let impostor = issuer();
        let store = SubscriberKeyStore::empty(real_issuer.verifying_key());
        let forged = sign(vec![public_entry(0x11, NOW + 3_600_000)], NOW, &impostor);

        let err = store.install(forged).unwrap_err();
        assert_eq!(err, SubscriberSetError::BadIssuerSig);
        assert!(!store.contains(&key(0x11)), "a badly-signed set must never be installed");
    }

    #[test]
    fn a_valid_install_is_admitted() {
        let signing = issuer();
        let store = SubscriberKeyStore::empty(signing.verifying_key());
        let set = sign(vec![public_entry(0x11, NOW + 3_600_000)], NOW, &signing);
        store.install(set).expect("valid set must install");

        assert!(store.contains(&key(0x11)));
        let entry = store.admit(&key(0x11), NOW, &EdgeScopeView::Public).expect("must admit");
        assert_eq!(entry.subscription_ref, "sub-11");
    }

    #[test]
    fn admit_refuses_an_expired_entry() {
        let signing = issuer();
        let store = SubscriberKeyStore::empty(signing.verifying_key());
        let set = sign(vec![public_entry(0x11, NOW + 1_000)], NOW, &signing);
        store.install(set).expect("valid set must install");

        let result = store.admit(&key(0x11), NOW + 1_001, &EdgeScopeView::Public);
        assert_eq!(result.unwrap_err(), StoreAdmitError::Refused(AdmitRefusal::Expired { not_after_ms: NOW + 1_000 }));
    }

    #[test]
    fn admit_refuses_a_scope_mismatch() {
        let signing = issuer();
        let store = SubscriberKeyStore::empty(signing.verifying_key());
        let set = sign(vec![edge_entry(0x22, "box-1", NOW + 3_600_000)], NOW, &signing);
        store.install(set).expect("valid set must install");

        let own = EdgeScopeView::Edge { machine_id: "box-2".to_string() };
        let result = store.admit(&key(0x22), NOW, &own);
        assert_eq!(result.unwrap_err(), StoreAdmitError::Refused(AdmitRefusal::ScopeMismatch));
    }

    #[test]
    fn admit_refuses_a_device_not_in_the_set() {
        let signing = issuer();
        let store = SubscriberKeyStore::empty(signing.verifying_key());
        let set = sign(vec![public_entry(0x11, NOW + 3_600_000)], NOW, &signing);
        store.install(set).expect("valid set must install");

        let result = store.admit(&key(0x99), NOW, &EdgeScopeView::Public);
        assert_eq!(result.unwrap_err(), StoreAdmitError::Refused(AdmitRefusal::NotInSet));
    }

    #[test]
    fn install_fully_replaces_the_previous_good_set() {
        let signing = issuer();
        let store = SubscriberKeyStore::empty(signing.verifying_key());
        store
            .install(sign(vec![public_entry(0x11, NOW + 3_600_000)], NOW, &signing))
            .expect("first install");
        store
            .install(sign(vec![public_entry(0x22, NOW + 3_600_000)], NOW + 1, &signing))
            .expect("second install");

        assert!(!store.contains(&key(0x11)), "the old key must be gone after a full replace");
        assert!(store.contains(&key(0x22)));
    }

    #[test]
    fn a_failed_install_keeps_the_previous_good_set() {
        let real_issuer = issuer();
        let impostor = issuer();
        let store = SubscriberKeyStore::empty(real_issuer.verifying_key());
        store
            .install(sign(vec![public_entry(0x11, NOW + 3_600_000)], NOW, &real_issuer))
            .expect("first install must succeed");

        let forged = sign(vec![public_entry(0x22, NOW + 3_600_000)], NOW + 1, &impostor);
        assert!(store.install(forged).is_err());

        assert!(store.contains(&key(0x11)), "the previous good set must still be installed");
        assert!(!store.contains(&key(0x22)), "the failed install must never take effect");
    }

    // ── file loading ─────────────────────────────────────────────────────

    #[test]
    fn load_missing_file_errors() {
        let path = std::env::temp_dir().join("mirage-subscriber-set-does-not-exist.json");
        let err = load_subscriber_set_file(&path).unwrap_err();
        assert!(matches!(err, SubscriberKeysError::Read { .. }));
    }

    #[test]
    fn load_malformed_json_errors_named() {
        let path = std::env::temp_dir().join(format!("mirage-subscriber-set-bad-{}.json", std::process::id()));
        std::fs::write(&path, "not json at all").expect("write");
        let err = load_subscriber_set_file(&path).unwrap_err();
        assert!(matches!(err, SubscriberKeysError::Invalid(SubscriberSetError::Malformed(_))));
        let _ = std::fs::remove_file(&path);
    }

    // ── hot reload ───────────────────────────────────────────────────────

    #[tokio::test]
    async fn hot_reload_picks_up_a_newly_signed_good_set() {
        let signing = issuer();
        let path = std::env::temp_dir().join(format!("mirage-subscriber-set-reload-{}.json", std::process::id()));
        let set = sign(vec![public_entry(0x11, NOW + 3_600_000)], NOW, &signing);
        std::fs::write(&path, set.encode().expect("encode")).expect("initial write");

        let store = SubscriberKeyStore::empty(signing.verifying_key());
        store
            .install(load_subscriber_set_file(&path).expect("initial load"))
            .expect("initial install");
        assert!(store.contains(&key(0x11)));

        let reload_count = Arc::new(AtomicUsize::new(0));
        let on_reload = {
            let reload_count = Arc::clone(&reload_count);
            Arc::new(move || {
                reload_count.fetch_add(1, Ordering::SeqCst);
            })
        };
        let handle = spawn_hot_reload(Arc::clone(&store), path.clone(), Duration::from_millis(20), on_reload);

        // Give the filesystem's mtime a chance to tick to a new value before
        // rewriting — some filesystems have coarse mtime resolution.
        tokio::time::sleep(Duration::from_millis(50)).await;
        let renewed = sign(vec![public_entry(0x22, NOW + 7_200_000)], NOW + 1, &signing);
        std::fs::write(&path, renewed.encode().expect("encode")).expect("rewrite");

        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        loop {
            if store.contains(&key(0x22)) {
                break;
            }
            assert!(std::time::Instant::now() < deadline, "reload did not pick up the change in time");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(!store.contains(&key(0x11)), "the revoked key must be gone after reload");
        assert_eq!(reload_count.load(Ordering::SeqCst), 1, "on_reload must fire exactly once, for the one good reload");

        handle.abort();
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn hot_reload_keeps_the_last_good_set_on_a_bad_signature_and_never_fires_on_reload() {
        let real_issuer = issuer();
        let impostor = issuer();
        let path = std::env::temp_dir().join(format!("mirage-subscriber-set-badreload-{}.json", std::process::id()));
        let good = sign(vec![public_entry(0x11, NOW + 3_600_000)], NOW, &real_issuer);
        std::fs::write(&path, good.encode().expect("encode")).expect("initial write");

        let store = SubscriberKeyStore::empty(real_issuer.verifying_key());
        store
            .install(load_subscriber_set_file(&path).expect("initial load"))
            .expect("initial install");

        let reload_count = Arc::new(AtomicUsize::new(0));
        let on_reload = {
            let reload_count = Arc::clone(&reload_count);
            Arc::new(move || {
                reload_count.fetch_add(1, Ordering::SeqCst);
            })
        };
        let handle = spawn_hot_reload(Arc::clone(&store), path.clone(), Duration::from_millis(20), on_reload);

        tokio::time::sleep(Duration::from_millis(50)).await;
        let forged = sign(vec![public_entry(0x22, NOW + 7_200_000)], NOW + 1, &impostor);
        std::fs::write(&path, forged.encode().expect("encode")).expect("rewrite with a badly-signed set");

        // Give the poller several ticks to notice the (bad) change.
        tokio::time::sleep(Duration::from_millis(200)).await;

        assert!(store.contains(&key(0x11)), "the last GOOD set must still be installed");
        assert!(!store.contains(&key(0x22)), "a badly-signed reload must never take effect");
        assert_eq!(reload_count.load(Ordering::SeqCst), 0, "on_reload must never fire for a failed reload");

        handle.abort();
        let _ = std::fs::remove_file(&path);
    }
}
