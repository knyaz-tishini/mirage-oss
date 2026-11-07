//! Entrance-handshake classification and auth predicate: telling a mesh
//! credential apart from a known subscriber key on the SAME wire slot, and
//! composing an edge's mesh gate with the subscriber store into one
//! `client_auth` predicate for the V9 handshake.
//!
//! Extracted out of `mirage-node`'s own `core::listener` module
//! (`docs/mirage/plans/2026-09-24-edge-as-entry.md`: "the subscriber gate
//! moves out of `mirage-node`") — `mirage-node` keeps no subscriber-entrance
//! code path at all any more; every accepted dial on an ordinary node is a
//! mesh-credential chain-hop dial. This module is `mirage-edge`'s own
//! entrance gate instead.
//!
//! # Admission moved into the handshake predicate itself
//!
//! Per `docs/mirage/plans/2026-09-25-subscription-bound-credentials.md`,
//! "Coordinator decision (2026-09-25)": the box's own `SubscriberKeyStore`
//! now carries a signed, per-entry expiry and scope
//! (`mirage_core::crypto::credential::subscriber_set`), and
//! [`SubscriberKeyStore::admit`] is the ONE real authorization decision —
//! run HERE, inside [`make_entrance_auth`]'s own closure, because the V9
//! driver's `client_auth` predicate return value is what the handshake's own
//! cryptographic proof is conditioned on: there is no "authenticate first,
//! decide later" seam to defer this check into (an already-completed
//! handshake for an expired or revoked device would hand out a live tunnel
//! before anything downstream ever got a chance to refuse it). Presence in
//! the set ([`PresentedCredential::classify`]'s own `contains` check) still
//! decides only ROUTING — mesh gate vs. subscriber gate — never
//! authorization; `admit`'s expiry/scope check is the actual grant.
//!
//! This also drops the per-key `personal_mesh_id` legacy shape entirely —
//! `mirage_core::crypto::credential::subscriber_set::SubscriberSetEntry`
//! carries no such field, so every subscriber's V9 handshake now verifies
//! against this box's own real `mesh_id`, exactly like a mesh-credential
//! dial. `resolve_entrance_mesh_id` (and the pre-handshake ClientHello peek
//! it required) is retired along with it — `crate::entrance` no longer
//! reads a byte off the wire before handing the raw stream to the V9
//! driver.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use arc_swap::ArcSwapOption;
use mirage_core::crypto::credential::subscriber_set::{EdgeScopeView, SubscriberSetEntry};
use tracing::{debug, warn};

use crate::subscriber_keys::{SubscriberKey, SubscriberKeyStore};

fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

/// First 4 bytes of a device key, hex-encoded — enough to correlate a
/// refusal log line with an operator's own records without printing the
/// whole static public key into logs.
fn key_prefix(key: &SubscriberKey) -> String {
    hex::encode(&key[..4])
}

/// What a caller presented on the entrance path — decided once, from the
/// ClientHello's own wire bytes, never by trying one verifier and then the
/// other. Used to decide which verifier's answer a connection is accepted
/// or refused on ([`make_entrance_auth`]).
///
/// The two signals are independent wire facts, not a fallback chain: a
/// non-zero `cred_scheme` byte says "a mesh credential is attached"
/// (`mirage_protocol::ClientAuthContext::scheme_byte`), and `static_pub`
/// matching an entry in [`SubscriberKeyStore`] says "this is a known
/// subscriber" — a caller controls both independently, so all four
/// combinations are real and each gets its own named outcome
/// (`docs/mirage/plans/ruling-2026-09-17-edge-boxes-trust-and-tiers.md`: the
/// type is what says who the caller is, never a branch that tries one gate
/// then the other).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PresentedCredential {
    /// `cred_scheme != 0x00`, `static_pub` not a known subscriber key: an
    /// ordinary mesh-credential dial. Verified only by the mesh gate.
    Mesh,
    /// `cred_scheme == 0x00`, `static_pub` IS a known subscriber key.
    /// Verified only against the subscriber store.
    Subscriber,
    /// Neither signal present — nothing to verify against on either path.
    Neither,
    /// Both signals present: a mesh credential is attached AND `static_pub`
    /// also matches a known subscriber key. Refused outright rather than
    /// picking one — a caller producing this shape has broken the "the type
    /// says who you are" invariant on its own dial, and guessing which he
    /// meant is exactly the branch the ruling forbids.
    Both,
}

impl PresentedCredential {
    /// Classify what `(scheme_byte, static_pub)` presents, against the
    /// current subscriber set.
    ///
    /// Consulting `subscriber_keys.contains` here — even for what turns out
    /// to be [`Mesh`](Self::Mesh) or [`Both`](Self::Both) — is
    /// classification, not verification: its answer can only ever turn what
    /// would have been an accept into `Both`'s outright refusal, never grant
    /// one, and it checks PRESENCE only (regardless of expiry/scope) — see
    /// [`SubscriberKeyStore::contains`]'s own doc. The mesh gate's own
    /// cryptographic verdict is still the ONLY thing that decides a
    /// `Mesh`-classified dial, and [`SubscriberKeyStore::admit`] is still
    /// the ONLY thing that decides a `Subscriber`-classified one — see
    /// [`make_entrance_auth`].
    pub fn classify(
        scheme_byte: u8,
        static_pub: &SubscriberKey,
        subscriber_keys: &SubscriberKeyStore,
    ) -> Self {
        let has_mesh_credential = scheme_byte != 0x00;
        let is_known_subscriber = subscriber_keys.contains(static_pub);
        match (has_mesh_credential, is_known_subscriber) {
            (true, false) => PresentedCredential::Mesh,
            (false, true) => PresentedCredential::Subscriber,
            (false, false) => PresentedCredential::Neither,
            (true, true) => PresentedCredential::Both,
        }
    }
}

/// Dispatch a V9 entrance dial by what it PRESENTED — never by trying one
/// verifier then falling back to the other.
/// [`PresentedCredential::classify`] decides the type from the ClientHello's
/// own wire bytes; each type is verified by exactly one gate and NEVER the
/// other:
///
/// - [`PresentedCredential::Mesh`] → `mesh_auth` alone decides.
/// - [`PresentedCredential::Subscriber`] → [`SubscriberKeyStore::admit`]
///   alone decides — the real authorization check (presence, expiry, and
///   scope against `own_scope`), run fresh on every dial. A refusal is
///   logged by name with the device key's own prefix
///   ([`key_prefix`]) and the predicate returns `false`; nothing about WHY
///   is trusted to any caller downstream of this closure.
/// - [`PresentedCredential::Neither`] / [`PresentedCredential::Both`] —
///   refused by name, before either gate's cryptographic verdict would
///   matter. `Neither` is the ordinary shape of noise reaching this face and
///   logs at `debug!`; `Both` should structurally never happen and logs at
///   `warn!`.
///
/// `subscriber_hit` is a FRESH per-connection flag the caller reads AFTER a
/// successful handshake to decide which fork the connection takes:
/// `ClientAuthContext` only lives for the duration of this closure call, and
/// neither `Tunnel` nor `TransportInfo` carry a field for which branch
/// matched (`mirage_protocol::traits`) — the flag is how the decision
/// survives past the crypto layer into the caller's own post-auth dispatch
/// (`crate::entrance_dispatch::resolve_subscriber_cap`, then
/// `crate::entrance_dispatch::copy_tunnel_to_tunnel_capped`).
///
/// **Bandwidth-cap seam, closed**: the per-subscriber cap
/// (`crate::bandwidth_cap`) needs to know WHICH subscriber matched, not just
/// THAT one did. `subscriber_key_out` is that second carrier —
/// `ArcSwapOption` rather than a second `AtomicBool` pair, because the
/// payload is 32 bytes, not a bit: set once here, read once by the caller
/// after the handshake accepts, same lifecycle as `subscriber_hit`.
///
/// **Session-deadline seam**: `subscriber_entry_out` carries the ADMITTED
/// [`SubscriberSetEntry`] itself, so the caller can arm a live-session
/// deadline against that entry's OWN `not_after_ms` — never
/// `next_expiry_after`'s "latest across every entry" answer, which would be
/// wrong the moment a device holds more than one entry across a scope
/// transition. Same lifecycle as `subscriber_key_out`.
pub fn make_entrance_auth(
    mesh_auth: impl for<'a> Fn(&mirage_protocol::ClientAuthContext<'a>) -> bool + Send + 'static,
    subscriber_keys: Arc<SubscriberKeyStore>,
    own_scope: EdgeScopeView,
    subscriber_hit: Arc<AtomicBool>,
    subscriber_key_out: Arc<ArcSwapOption<SubscriberKey>>,
    subscriber_entry_out: Arc<ArcSwapOption<SubscriberSetEntry>>,
) -> impl for<'a> Fn(&mirage_protocol::ClientAuthContext<'a>) -> bool + Send + 'static {
    move |ctx| match PresentedCredential::classify(ctx.scheme_byte, ctx.static_pub, &subscriber_keys) {
        PresentedCredential::Mesh => mesh_auth(ctx),
        PresentedCredential::Subscriber => {
            match subscriber_keys.admit(ctx.static_pub, now_ms(), &own_scope) {
                Ok(entry) => {
                    subscriber_hit.store(true, Ordering::Relaxed);
                    subscriber_key_out.store(Some(Arc::new(*ctx.static_pub)));
                    subscriber_entry_out.store(Some(Arc::new(entry)));
                    true
                }
                Err(refusal) => {
                    warn!(
                        device_pubkey_prefix = %key_prefix(ctx.static_pub),
                        error = %refusal,
                        "entrance: refusing -- subscriber admission check failed"
                    );
                    false
                }
            }
        }
        PresentedCredential::Neither => {
            debug!(
                "entrance: refusing — dial presents neither a mesh credential nor a known \
                 subscriber key"
            );
            false
        }
        PresentedCredential::Both => {
            warn!(
                "entrance: refusing — dial presents BOTH a mesh credential and a known \
                 subscriber key on the same connection; refusing rather than guessing which the \
                 caller is"
            );
            false
        }
    }
}

#[cfg(test)]
mod entrance_auth_tests {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    use ed25519_dalek::SigningKey;
    use mirage_core::crypto::credential::subscriber_set::{
        sign, EdgeScopeView, SubscriberScope, SubscriberSetEntry,
    };
    use mirage_protocol::ClientAuthContext;
    use rand::rngs::OsRng;

    use super::{make_entrance_auth, PresentedCredential};
    use crate::subscriber_keys::{SubscriberKey, SubscriberKeyStore};

    const NOW: u64 = 1_800_000_000_000;

    fn ctx<'a>(static_pub: &'a [u8; 32], e_pub_c: &'a [u8; 32], scheme_byte: u8) -> ClientAuthContext<'a> {
        ClientAuthContext {
            static_pub,
            ts_ms: 0,
            e_pub_c,
            scheme_byte,
            credential: &[],
        }
    }

    fn key_out() -> Arc<arc_swap::ArcSwapOption<SubscriberKey>> {
        Arc::new(arc_swap::ArcSwapOption::from(None))
    }

    fn entry_out() -> Arc<arc_swap::ArcSwapOption<SubscriberSetEntry>> {
        Arc::new(arc_swap::ArcSwapOption::from(None))
    }

    /// A store carrying exactly one admitted, non-expired public entry for
    /// `byte`, signed by a fresh test issuer.
    fn store_with_one_public_entry(byte: u8) -> Arc<SubscriberKeyStore> {
        let issuer = SigningKey::generate(&mut OsRng);
        let store = SubscriberKeyStore::empty(issuer.verifying_key());
        let entry = SubscriberSetEntry {
            device_pubkey_hex: hex::encode([byte; 32]),
            scope: SubscriberScope::Public,
            not_after_ms: NOW + 3_600_000,
            subscription_ref: "sub-test".to_string(),
        };
        store.install(sign(vec![entry], NOW, &issuer)).expect("valid set must install");
        store
    }

    // ── PresentedCredential::classify — all four combinations ───────────────

    #[test]
    fn classify_covers_all_four_combinations() {
        let subscriber_keys = store_with_one_public_entry(0x11);
        let known = [0x11u8; 32];
        let unknown = [0x22u8; 32];

        assert_eq!(
            PresentedCredential::classify(0x01, &unknown, &subscriber_keys),
            PresentedCredential::Mesh
        );
        assert_eq!(
            PresentedCredential::classify(0x00, &known, &subscriber_keys),
            PresentedCredential::Subscriber
        );
        assert_eq!(
            PresentedCredential::classify(0x00, &unknown, &subscriber_keys),
            PresentedCredential::Neither
        );
        assert_eq!(
            PresentedCredential::classify(0x01, &known, &subscriber_keys),
            PresentedCredential::Both
        );
    }

    // ── dispatch by presented type, never a fallback chain ──────────────────

    /// A mesh credential the mesh gate accepts is accepted — the mesh path
    /// can still succeed, and succeeding through it never touches the
    /// subscriber carriers.
    #[test]
    fn a_mesh_credential_is_verified_only_by_the_mesh_gate() {
        let subscriber_keys = SubscriberKeyStore::empty(SigningKey::generate(&mut OsRng).verifying_key());
        let subscriber_hit = Arc::new(AtomicBool::new(false));
        let key_out = key_out();
        let entry_out = entry_out();
        let auth = make_entrance_auth(
            |_ctx| true,
            Arc::clone(&subscriber_keys),
            EdgeScopeView::Public,
            Arc::clone(&subscriber_hit),
            Arc::clone(&key_out),
            Arc::clone(&entry_out),
        );

        let dummy = [0u8; 32];
        let e_pub = [0u8; 32];
        assert!(
            auth(&ctx(&dummy, &e_pub, 0x01)),
            "a mesh credential the mesh gate accepts must be accepted"
        );
        assert!(!subscriber_hit.load(Ordering::Relaxed), "a mesh credential must never set subscriber_hit");
        assert!(key_out.load_full().is_none(), "a mesh credential must never set subscriber_key_out");
        assert!(entry_out.load_full().is_none());
    }

    /// A mesh credential presented on the customer entrance is refused when
    /// the mesh gate itself rejects it, and — the property that matters — it
    /// never reaches the subscriber store: `static_pub` here is ALSO a known
    /// subscriber key, and the refusal must not fall back to accepting it
    /// that way.
    #[test]
    fn a_mesh_credential_rejected_by_the_mesh_gate_never_reaches_the_subscriber_store() {
        let subscriber_keys = store_with_one_public_entry(0x33);

        let subscriber_hit = Arc::new(AtomicBool::new(false));
        let key_out = key_out();
        let entry_out = entry_out();
        let auth = make_entrance_auth(
            |_ctx| false,
            Arc::clone(&subscriber_keys),
            EdgeScopeView::Public,
            Arc::clone(&subscriber_hit),
            Arc::clone(&key_out),
            Arc::clone(&entry_out),
        );

        let key = [0x33u8; 32];
        let e_pub = [0u8; 32];
        // scheme_byte != 0 with a static_pub that is ALSO a subscriber key
        // classifies as `Both`, refused before the mesh gate even runs —
        // still the correct outcome for this test's claim either way: a
        // mesh-shaped dial must never fall back to the subscriber store.
        assert!(
            !auth(&ctx(&key, &e_pub, 0x01)),
            "a mesh credential the mesh gate would reject must be refused"
        );
        assert!(!subscriber_hit.load(Ordering::Relaxed), "must never reach the subscriber store");
        assert!(key_out.load_full().is_none());
        assert!(entry_out.load_full().is_none());
    }

    /// A subscriber key with a valid, non-expired, scope-matched entry is
    /// accepted with NO mesh credential attached, and the mesh gate is
    /// structurally never consulted for it — proven with a panicking
    /// mesh_auth rather than merely asserting its return value is ignored.
    #[test]
    fn an_admitted_subscriber_key_never_reaches_the_mesh_verifier() {
        let subscriber_keys = store_with_one_public_entry(0x42);

        let subscriber_hit = Arc::new(AtomicBool::new(false));
        let key_out = key_out();
        let entry_out = entry_out();
        let auth = make_entrance_auth(
            |_ctx| panic!("the mesh verifier must never be consulted for a subscriber-classified dial"),
            Arc::clone(&subscriber_keys),
            EdgeScopeView::Public,
            Arc::clone(&subscriber_hit),
            Arc::clone(&key_out),
            Arc::clone(&entry_out),
        );

        let key = [0x42u8; 32];
        let e_pub = [0u8; 32];
        assert!(
            auth(&ctx(&key, &e_pub, 0x00)),
            "an admitted subscriber key with no mesh credential attached must be accepted"
        );
        assert!(
            subscriber_hit.load(Ordering::Relaxed),
            "accepting via the subscriber gate must set subscriber_hit"
        );
        assert_eq!(
            key_out.load_full().as_deref(),
            Some(&key),
            "the matched subscriber key must be recorded for the bandwidth cap"
        );
        assert_eq!(
            entry_out.load_full().as_deref().map(|e| e.not_after_ms),
            Some(NOW + 3_600_000),
            "the admitted entry must be recorded for the session-deadline seam"
        );
    }

    /// A subscriber key that IS in the set but whose entry has expired is
    /// refused — never falls back to the mesh gate, and never sets either
    /// carrier.
    ///
    /// `not_after_ms` is `1` (an actual real-clock past timestamp), not a
    /// value relative to this test module's own fictional `NOW` constant:
    /// `make_entrance_auth`'s own admission check always reads the REAL
    /// system clock (`now_ms()` inside this module, not an injected value),
    /// so "expired" here must be expired against real wall-clock time.
    #[test]
    fn an_expired_subscriber_entry_is_refused() {
        let issuer = SigningKey::generate(&mut OsRng);
        let store = SubscriberKeyStore::empty(issuer.verifying_key());
        let entry = SubscriberSetEntry {
            device_pubkey_hex: hex::encode([0x55u8; 32]),
            scope: SubscriberScope::Public,
            not_after_ms: 1,
            subscription_ref: "sub-expired".to_string(),
        };
        store.install(sign(vec![entry], 0, &issuer)).expect("valid set must install");

        let subscriber_hit = Arc::new(AtomicBool::new(false));
        let key_out = key_out();
        let entry_out = entry_out();
        let auth = make_entrance_auth(
            |_ctx| panic!("the mesh verifier must never be consulted for an expired subscriber entry"),
            Arc::clone(&store),
            EdgeScopeView::Public,
            Arc::clone(&subscriber_hit),
            Arc::clone(&key_out),
            Arc::clone(&entry_out),
        );

        let key = [0x55u8; 32];
        let e_pub = [0u8; 32];
        assert!(!auth(&ctx(&key, &e_pub, 0x00)), "an expired subscriber entry must be refused");
        assert!(!subscriber_hit.load(Ordering::Relaxed));
        assert!(key_out.load_full().is_none());
        assert!(entry_out.load_full().is_none());
    }

    /// A subscriber key with a `Public` entry is refused at an edge whose
    /// own scope is `Edge { .. }` — a scope mismatch is a refusal, not a
    /// fall-through.
    #[test]
    fn a_scope_mismatched_subscriber_entry_is_refused() {
        let subscriber_keys = store_with_one_public_entry(0x66);

        let subscriber_hit = Arc::new(AtomicBool::new(false));
        let key_out = key_out();
        let entry_out = entry_out();
        let own_scope = EdgeScopeView::Edge {
            machine_id: "box-1".to_string(),
        };
        let auth = make_entrance_auth(
            |_ctx| panic!("the mesh verifier must never be consulted on a scope mismatch either"),
            Arc::clone(&subscriber_keys),
            own_scope,
            Arc::clone(&subscriber_hit),
            Arc::clone(&key_out),
            Arc::clone(&entry_out),
        );

        let key = [0x66u8; 32];
        let e_pub = [0u8; 32];
        assert!(!auth(&ctx(&key, &e_pub, 0x00)), "a public entry at a private edge must be refused");
        assert!(!subscriber_hit.load(Ordering::Relaxed));
        assert!(key_out.load_full().is_none());
        assert!(entry_out.load_full().is_none());
    }

    /// Neither signal present: no mesh credential, and `static_pub` is not a
    /// known subscriber key. Refused, and the mesh gate is never consulted
    /// either (proven with a panicking closure) — there is nothing to
    /// dispatch to.
    #[test]
    fn neither_signal_present_is_refused() {
        let subscriber_keys = SubscriberKeyStore::empty(SigningKey::generate(&mut OsRng).verifying_key());
        let subscriber_hit = Arc::new(AtomicBool::new(false));
        let key_out = key_out();
        let entry_out = entry_out();
        let auth = make_entrance_auth(
            |_ctx| panic!("the mesh verifier must never be consulted when no mesh credential is presented"),
            Arc::clone(&subscriber_keys),
            EdgeScopeView::Public,
            Arc::clone(&subscriber_hit),
            Arc::clone(&key_out),
            Arc::clone(&entry_out),
        );

        let dummy = [0u8; 32];
        let e_pub = [0u8; 32];
        assert!(!auth(&ctx(&dummy, &e_pub, 0x00)), "no credential and no subscriber key must reject");
        assert!(!subscriber_hit.load(Ordering::Relaxed));
        assert!(key_out.load_full().is_none());
        assert!(entry_out.load_full().is_none());
    }

    /// Both signals present: a mesh credential is attached AND `static_pub`
    /// is ALSO a known subscriber key. Refused by name, before either
    /// verifier's cryptographic answer would matter — proven with a
    /// panicking mesh_auth: the ambiguity is resolved by refusal, never by
    /// picking a side.
    #[test]
    fn both_signals_present_is_refused_by_name() {
        let subscriber_keys = store_with_one_public_entry(0x77);

        let subscriber_hit = Arc::new(AtomicBool::new(false));
        let key_out = key_out();
        let entry_out = entry_out();
        let auth = make_entrance_auth(
            |_ctx| panic!("the mesh verifier must never be consulted on a both-presented dial either"),
            Arc::clone(&subscriber_keys),
            EdgeScopeView::Public,
            Arc::clone(&subscriber_hit),
            Arc::clone(&key_out),
            Arc::clone(&entry_out),
        );

        let key = [0x77u8; 32];
        let e_pub = [0u8; 32];
        assert!(
            !auth(&ctx(&key, &e_pub, 0x01)),
            "presenting a mesh credential AND a known subscriber key on the same dial must be refused"
        );
        assert!(!subscriber_hit.load(Ordering::Relaxed));
        assert!(key_out.load_full().is_none());
        assert!(entry_out.load_full().is_none());
    }
}
