//! The subscriber allowlist this box signs and enforces.
//!
//! # One owner, several guests
//!
//! A standalone box serves **one owner** — the customer who installed it —
//! and may serve several **guests** the owner invites. Both are subscribers in
//! the same sense: each holds an X25519 device key, and the box admits a dial
//! only when that key is named in the signed allowlist the box writes.
//!
//! * The **owner's** key is the box's own `identity.subscriber` — it lives in
//!   `identity.json`, it is minted together with the box, and it is never
//!   rewritten. Its entry keeps the reference it has always had
//!   (`standalone:<mesh_id>`).
//! * A **guest's** key is minted on the spot when the owner invites it. The
//!   key, the name it was issued under, and the whole history of what was
//!   issued and what was revoked live in `<dir>/subscribers.json`.
//!
//! The signed allowlist (`<dir>/subscriber.set`) carries the owner and every
//! **live** guest. It is signed by the box's own subscriber-issuer key, the
//! same signature shape every edge in the fleet verifies, so the file this
//! module writes is directly loadable by
//! [`mirage_subscriber_gate::subscriber_keys::load_subscriber_set_file`] and
//! installable through
//! [`mirage_subscriber_gate::subscriber_keys::SubscriberKeyStore::install`].
//!
//! The signing itself is **not** re-implemented here: the canonical preimage
//! and the Ed25519 signature come from
//! [`mirage_core::crypto::credential::subscriber_set`], the one place that
//! defines them.
//!
//! # Revocation
//!
//! Revoking a guest marks its record and rebuilds the allowlist without it.
//! The running gate re-reads the file on its own timer
//! ([`mirage_subscriber_gate::subscriber_keys::spawn_hot_reload`]), so the
//! guest stops being admitted without the box being restarted. The revoked
//! record stays in `subscribers.json`: the history of who was given a key is
//! the point of the file.
//!
//! # Secrets
//!
//! A guest's device secret is written to `subscribers.json` and handed to the
//! guest in the invitation — nowhere else. It never reaches a log line, never
//! appears in an error message, and never shows up in a `Debug` rendering.

use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use mirage_core::crypto::credential::subscriber_set::{
    sign, SubscriberScope, SubscriberSet, SubscriberSetEntry,
};
use mirage_core::crypto::KeyPair;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::artefact::{ArtefactError, ArtefactMode, EntranceArtefact};
use crate::env::Face;
use crate::fsio;
use crate::identity::ServerIdentity;

/// File name of the subscriber allowlist, inside the box's data directory.
pub const SUBSCRIBER_SET_FILE_NAME: &str = "subscriber.set";

/// File name of the subscriber registry, inside the box's data directory.
pub const SUBSCRIBERS_FILE_NAME: &str = "subscribers.json";

/// Schema version of `subscribers.json`.
pub const SUBSCRIBERS_FILE_VERSION: u32 = 1;

/// How long one subscription is valid, in milliseconds — 365 days.
///
/// The owner's subscription is re-stamped on every rebuild of the allowlist.
/// A guest's subscription ends this long after the key was **issued** — a
/// rebuild of the allowlist does not extend it.
pub const SUBSCRIPTION_TTL_MS: u64 = 365 * 24 * 60 * 60 * 1000;

/// Longest name a subscriber may carry, in characters.
///
/// The name is part of the subscription reference, and the reference is
/// bounded by the signed-set format — so the name is bounded too.
pub const MAX_SUBSCRIBER_NAME_LEN: usize = 64;

/// The name the box's own subscriber is listed under.
pub const OWNER_SUBSCRIBER_NAME: &str = "owner";

/// Everything that can go wrong while building, issuing, revoking or
/// persisting the subscriber list.
#[derive(Debug, Error)]
pub enum SubscriberError {
    /// The subscriber registry could not be read.
    #[error("subscriber registry: cannot read {path}")]
    Read {
        /// The file that could not be read.
        path: PathBuf,
        /// The underlying I/O failure.
        #[source]
        source: io::Error,
    },

    /// A file could not be written.
    #[error("subscriber registry: cannot write {path}")]
    Write {
        /// The file that could not be written.
        path: PathBuf,
        /// The underlying I/O failure.
        #[source]
        source: io::Error,
    },

    /// The registry file exists but is not usable.
    #[error("subscriber registry: {path} is not usable ({reason})")]
    Malformed {
        /// The offending file.
        path: PathBuf,
        /// Why it was rejected — a fixed phrase, never a value.
        reason: &'static str,
    },

    /// The allowlist could not be encoded.
    #[error("subscriber set: cannot encode the set ({reason})")]
    Encode {
        /// Why encoding failed.
        reason: String,
    },

    /// The registry could not be encoded.
    #[error("subscriber registry: cannot encode the registry ({reason})")]
    RegistryEncode {
        /// Why encoding failed.
        reason: String,
    },

    /// The invitation's artefact could not be built.
    #[error("invitation: the artefact could not be built ({source})")]
    Artefact {
        /// Why the artefact was refused.
        #[source]
        source: ArtefactError,
    },

    /// The name a subscriber was to be issued under is not usable.
    #[error("invitation: the subscriber name is not usable ({reason})")]
    InvalidName {
        /// Why the name was refused — a fixed phrase, never a value.
        reason: &'static str,
    },

    /// That name already has a key on this box.
    #[error("invitation: '{name}' already has a key on this box — revoke it first, or pick another name")]
    DuplicateName {
        /// The name that was taken.
        name: String,
    },

    /// No subscriber goes by that name or by that subscription reference.
    #[error("revocation: no subscriber goes by '{target}' on this box")]
    UnknownSubscriber {
        /// What the operator asked for.
        target: String,
    },

    /// That subscriber's key was already revoked.
    #[error("revocation: '{name}' was already revoked")]
    AlreadyRevoked {
        /// The name of the already-revoked subscriber.
        name: String,
    },
}

/// One subscriber key this box has issued.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubscriberRecord {
    /// The name this key was issued under — how the operator asks for it back
    /// when revoking.
    pub name: String,
    /// The subscriber's X25519 device secret, hex.
    ///
    /// The secret half of the invitation. It is never printed, never logged,
    /// and never rendered by this type's `Debug`.
    pub secret_hex: String,
    /// The subscriber's X25519 device public key, hex — what the signed
    /// allowlist admits.
    pub pubkey_hex: String,
    /// When the key was issued, in milliseconds since the epoch.
    pub issued_at_ms: u64,
    /// The opaque reference this box records for the subscription.
    pub subscription_ref: String,
    /// Whether the key has been revoked.
    pub revoked: bool,
    /// When the key was revoked, in milliseconds since the epoch — `None`
    /// while the key is live.
    pub revoked_at_ms: Option<u64>,
}

impl fmt::Debug for SubscriberRecord {
    /// Prints the non-secret shape only — the device secret never appears.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SubscriberRecord")
            .field("name", &self.name)
            .field("pubkey_hex", &self.pubkey_hex)
            .field("issued_at_ms", &self.issued_at_ms)
            .field("subscription_ref", &self.subscription_ref)
            .field("revoked", &self.revoked)
            .field("revoked_at_ms", &self.revoked_at_ms)
            .finish_non_exhaustive()
    }
}

/// Every subscriber key this box has issued — the live ones and the revoked
/// ones.
///
/// The history is never dropped: it is the record of who was given a key.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubscriberRegistry {
    /// Schema version of this file.
    pub v: u32,
    /// The records, in the order they were issued.
    pub entries: Vec<SubscriberRecord>,
}

impl fmt::Debug for SubscriberRegistry {
    /// Prints the non-secret shape only — every record's own `Debug` hides
    /// the device secret.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SubscriberRegistry")
            .field("v", &self.v)
            .field("entries", &self.entries)
            .finish_non_exhaustive()
    }
}

/// What an invitation hands out: the guest's artefact, and the reference the
/// box recorded for it.
#[derive(Clone, PartialEq, Eq)]
pub struct Invitation {
    /// The artefact the guest's client is configured with.
    pub artefact: EntranceArtefact,
    /// The name the key was issued under.
    pub name: String,
    /// The opaque reference the box recorded for this subscription.
    pub subscription_ref: String,
    /// The guest's public device key, hex — what the signed allowlist admits.
    pub pubkey_hex: String,
}

impl fmt::Debug for Invitation {
    /// Prints the non-secret shape only — the guest's device secret is
    /// hidden by the artefact's own `Debug`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Invitation")
            .field("name", &self.name)
            .field("subscription_ref", &self.subscription_ref)
            .field("pubkey_hex", &self.pubkey_hex)
            .field("artefact", &self.artefact)
            .finish_non_exhaustive()
    }
}

/// What a revocation did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Revocation {
    /// The name of the revoked subscriber.
    pub name: String,
    /// The opaque reference of the revoked subscription.
    pub subscription_ref: String,
    /// The public device key that is no longer admitted.
    pub pubkey_hex: String,
    /// When the key was revoked, in milliseconds since the epoch.
    pub revoked_at_ms: u64,
}

/// One subscriber this box currently admits — the shape a listing shows.
///
/// Carries no secret: a public key, a name and a reference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmittedSubscriber {
    /// The name the subscriber is listed under.
    pub name: String,
    /// The subscriber's public device key, hex.
    pub pubkey_hex: String,
    /// The opaque reference the box recorded for the subscription.
    pub subscription_ref: String,
    /// When the key was issued, in milliseconds since the epoch — `None` for
    /// the box's own subscriber, whose key was minted with the box and whose
    /// issue time the box does not record.
    pub issued_at_ms: Option<u64>,
    /// Whether this is the box's own subscriber rather than a guest.
    pub owner: bool,
}

impl SubscriberRegistry {
    /// An empty registry — a box that has never issued a guest key.
    pub fn empty() -> Self {
        Self {
            v: SUBSCRIBERS_FILE_VERSION,
            entries: Vec::new(),
        }
    }

    /// The records that are still live, in issuance order.
    pub fn live(&self) -> impl Iterator<Item = &SubscriberRecord> + '_ {
        self.entries.iter().filter(|record| !record.revoked)
    }

    /// The record with that name, if this box issued one.
    pub fn find(&self, name: &str) -> Option<&SubscriberRecord> {
        self.entries.iter().find(|record| record.name == name)
    }

    /// The record with that subscription reference, if this box issued one.
    pub fn find_by_ref(&self, subscription_ref: &str) -> Option<&SubscriberRecord> {
        self.entries
            .iter()
            .find(|record| record.subscription_ref == subscription_ref)
    }

    /// Whether a name is already taken — by a live key or by a revoked one.
    pub fn has_name(&self, name: &str) -> bool {
        self.find(name).is_some()
    }
}

/// The path of the subscriber allowlist inside `dir`.
pub fn subscriber_set_path(dir: &Path) -> PathBuf {
    fsio::path_in(dir, SUBSCRIBER_SET_FILE_NAME)
}

/// The path of the subscriber registry inside `dir`.
pub fn subscribers_path(dir: &Path) -> PathBuf {
    fsio::path_in(dir, SUBSCRIBERS_FILE_NAME)
}

/// Load the subscriber registry from `dir`.
///
/// A box that has never issued a guest key has no registry file: that is an
/// empty registry, not an error.
pub fn load_registry(dir: &Path) -> Result<SubscriberRegistry, SubscriberError> {
    let path = subscribers_path(dir);
    let raw = match fs::read(&path) {
        Ok(raw) => raw,
        Err(source) if source.kind() == io::ErrorKind::NotFound => {
            return Ok(SubscriberRegistry::empty())
        }
        Err(source) => return Err(SubscriberError::Read { path, source }),
    };
    let registry: SubscriberRegistry =
        serde_json::from_slice(&raw).map_err(|_| SubscriberError::Malformed {
            path: path.clone(),
            reason: "not valid JSON",
        })?;
    if registry.v != SUBSCRIBERS_FILE_VERSION {
        return Err(SubscriberError::Malformed {
            path,
            reason: "unsupported file version",
        });
    }
    Ok(registry)
}

/// Write the subscriber registry into `dir`, atomically and privately.
///
/// The file holds every record — issued and revoked — and is written with
/// mode 0600 on Unix, like every other file this crate owns.
pub fn write_registry(
    dir: &Path,
    registry: &SubscriberRegistry,
) -> Result<PathBuf, SubscriberError> {
    let path = subscribers_path(dir);
    let json =
        serde_json::to_vec_pretty(registry).map_err(|e| SubscriberError::RegistryEncode {
            reason: e.to_string(),
        })?;
    fsio::write_atomic(&path, &json)
        .map_err(|source| SubscriberError::Write { path: path.clone(), source })?;
    Ok(path)
}

/// Build the signed subscriber allowlist for this box.
///
/// The set carries the box's own subscriber key plus every **live** guest —
/// each with the [`SubscriberScope::Public`] scope, its own expiry and its
/// own subscription reference:
///
/// * the owner expires [`SUBSCRIPTION_TTL_MS`] after `now_ms` — the
///   subscription is re-stamped on every rebuild;
/// * a guest expires [`SUBSCRIPTION_TTL_MS`] after the moment it was
///   **issued** — rebuilding the allowlist does not extend it.
///
/// `now_ms` is passed in rather than read from the clock so the caller — and
/// the tests — control time explicitly.
pub fn build_subscriber_set(
    identity: &ServerIdentity,
    registry: &SubscriberRegistry,
    now_ms: u64,
) -> SubscriberSet {
    let mut entries = Vec::with_capacity(registry.entries.len() + 1);
    entries.push(SubscriberSetEntry {
        device_pubkey_hex: identity.subscriber_pubkey_hex(),
        scope: SubscriberScope::Public,
        not_after_ms: now_ms.saturating_add(SUBSCRIPTION_TTL_MS),
        subscription_ref: owner_subscription_ref(identity),
    });
    for record in registry.live() {
        entries.push(SubscriberSetEntry {
            device_pubkey_hex: record.pubkey_hex.clone(),
            scope: SubscriberScope::Public,
            not_after_ms: record.issued_at_ms.saturating_add(SUBSCRIPTION_TTL_MS),
            subscription_ref: record.subscription_ref.clone(),
        });
    }
    sign(entries, now_ms, &identity.subscriber_issuer_signing_key())
}

/// Build and persist the signed subscriber allowlist into `dir`.
///
/// The registry on disk is read first, so the set carries the box's own
/// subscriber and every live guest. The file is written atomically and, like
/// every other file this crate owns, with mode 0600 on Unix. The returned
/// set is the one that was written — the caller does not have to rebuild it
/// to check it.
pub fn write_subscriber_set(
    dir: &Path,
    identity: &ServerIdentity,
    now_ms: u64,
) -> Result<SubscriberSet, SubscriberError> {
    let registry = load_registry(dir)?;
    write_subscriber_set_with(dir, identity, &registry, now_ms)
}

/// Build and persist the signed subscriber allowlist from an explicit
/// registry.
///
/// This is what the invite and revoke paths use: they already hold the
/// registry they just changed, and they must not read a second copy of it
/// back from the disk.
pub fn write_subscriber_set_with(
    dir: &Path,
    identity: &ServerIdentity,
    registry: &SubscriberRegistry,
    now_ms: u64,
) -> Result<SubscriberSet, SubscriberError> {
    let set = build_subscriber_set(identity, registry, now_ms);
    let bytes = set
        .encode()
        .map_err(|e| SubscriberError::Encode { reason: e.to_string() })?;
    let path = subscriber_set_path(dir);
    fsio::write_atomic(&path, &bytes)
        .map_err(|source| SubscriberError::Write { path: path.clone(), source })?;
    Ok(set)
}

/// Mint a guest subscriber key and hand out its invitation.
///
/// The guest gets its **own** X25519 device key: it is minted here, recorded
/// in `<dir>/subscribers.json`, admitted by the signed allowlist, and carried
/// in the returned artefact. The box's own subscriber key is untouched — the
/// owner keeps the access it had.
///
/// The artefact is the box's own — the same doors, the same `mesh_id` — with
/// the guest's key in `private_key_hex`, the guest's name in `label`, and
/// `now_ms` in `issued_at_ms`.
///
/// The registry is written **before** the allowlist: a guest whose key is on
/// disk but not yet in the signed set is refused by the gate, which is the
/// safe direction in which to fail.
pub fn issue_invitation(
    dir: &Path,
    identity: &ServerIdentity,
    pub_addr: &str,
    faces: &[Face],
    mode: ArtefactMode,
    name: &str,
    now_ms: u64,
) -> Result<Invitation, SubscriberError> {
    validate_name(name)?;
    let mut registry = load_registry(dir)?;
    if registry.has_name(name) {
        return Err(SubscriberError::DuplicateName {
            name: name.to_owned(),
        });
    }

    // The guest's own device key — a fresh X25519 pair, minted here.
    let key_pair = KeyPair::generate();
    let secret_bytes = Zeroizing::new(key_pair.secret.to_bytes());
    let public_bytes = key_pair.public.as_bytes();
    let secret_hex = hex::encode(secret_bytes.as_slice());
    let pubkey_hex = hex::encode(public_bytes);
    drop(key_pair);

    let subscription_ref = guest_subscription_ref(identity, name, now_ms);
    let record = SubscriberRecord {
        name: name.to_owned(),
        secret_hex: secret_hex.clone(),
        pubkey_hex: pubkey_hex.clone(),
        issued_at_ms: now_ms,
        subscription_ref: subscription_ref.clone(),
        revoked: false,
        revoked_at_ms: None,
    };
    registry.entries.push(record);

    write_registry(dir, &registry)?;
    write_subscriber_set_with(dir, identity, &registry, now_ms)?;

    let artefact = EntranceArtefact::build_for_subscriber(
        identity,
        pub_addr,
        faces,
        mode,
        name,
        now_ms,
        &secret_hex,
    )
    .map_err(|source| SubscriberError::Artefact { source })?;

    Ok(Invitation {
        artefact,
        name: name.to_owned(),
        subscription_ref,
        pubkey_hex,
    })
}

/// Revoke a subscriber key, by name or by subscription reference.
///
/// The record is marked revoked — the history stays in
/// `<dir>/subscribers.json` — and the signed allowlist is rebuilt **without**
/// that key, so the running gate stops admitting it at its next poll.
///
/// The registry is written first, then the allowlist: a revocation that is
/// on disk but not yet in the signed set is dropped at the next rebuild, and
/// is never re-added by one.
pub fn revoke_subscriber(
    dir: &Path,
    identity: &ServerIdentity,
    target: &str,
    now_ms: u64,
) -> Result<Revocation, SubscriberError> {
    let mut registry = load_registry(dir)?;
    let index = registry
        .entries
        .iter()
        .position(|record| record.name == target || record.subscription_ref == target)
        .ok_or_else(|| SubscriberError::UnknownSubscriber {
            target: target.to_owned(),
        })?;
    if registry.entries[index].revoked {
        return Err(SubscriberError::AlreadyRevoked {
            name: registry.entries[index].name.clone(),
        });
    }
    let record = &mut registry.entries[index];
    record.revoked = true;
    record.revoked_at_ms = Some(now_ms);
    let revoked = Revocation {
        name: record.name.clone(),
        subscription_ref: record.subscription_ref.clone(),
        pubkey_hex: record.pubkey_hex.clone(),
        revoked_at_ms: now_ms,
    };

    write_registry(dir, &registry)?;
    write_subscriber_set_with(dir, identity, &registry, now_ms)?;
    Ok(revoked)
}

/// Every subscriber this box currently admits — the owner first, then the
/// live guests in issuance order.
///
/// Carries no secrets: a name, a public key and a reference.
pub fn admitted_subscribers(
    identity: &ServerIdentity,
    registry: &SubscriberRegistry,
) -> Vec<AdmittedSubscriber> {
    let mut admitted = Vec::with_capacity(registry.entries.len() + 1);
    admitted.push(AdmittedSubscriber {
        name: OWNER_SUBSCRIBER_NAME.to_owned(),
        pubkey_hex: identity.subscriber_pubkey_hex(),
        subscription_ref: owner_subscription_ref(identity),
        issued_at_ms: None,
        owner: true,
    });
    for record in registry.live() {
        admitted.push(AdmittedSubscriber {
            name: record.name.clone(),
            pubkey_hex: record.pubkey_hex.clone(),
            subscription_ref: record.subscription_ref.clone(),
            issued_at_ms: Some(record.issued_at_ms),
            owner: false,
        });
    }
    admitted
}

/// The opaque reference this box records for its own subscription.
///
/// Opaque to every edge — it correlates issuance and revocation on the
/// issuing side only.
fn owner_subscription_ref(identity: &ServerIdentity) -> String {
    format!("standalone:{}", identity.mesh_id())
}

/// The opaque reference this box records for a guest's subscription.
///
/// Unique per guest: the box's own mesh id, the name the key was issued
/// under, and the moment it was issued.
fn guest_subscription_ref(identity: &ServerIdentity, name: &str, issued_at_ms: u64) -> String {
    format!("standalone:{}:{}:{}", identity.mesh_id(), name, issued_at_ms)
}

/// Refuse a name that cannot be used as one.
fn validate_name(name: &str) -> Result<(), SubscriberError> {
    if name.trim().is_empty() {
        return Err(SubscriberError::InvalidName {
            reason: "the name is empty",
        });
    }
    if name.len() > MAX_SUBSCRIBER_NAME_LEN {
        return Err(SubscriberError::InvalidName {
            reason: "the name is too long",
        });
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    {
        return Err(SubscriberError::InvalidName {
            reason: "the name carries a character that is not a letter, a digit, '-', '_' or '.'",
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use mirage_core::crypto::credential::subscriber_set::SubscriberSet;
    use mirage_core::mirage::wire::Protocol;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::Arc;

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(tag: &str) -> Self {
            use std::sync::atomic::{AtomicU64, Ordering};
            static COUNTER: AtomicU64 = AtomicU64::new(0);
            let path = std::env::temp_dir().join(format!(
                "mirage-standalone-sub-{}-{}-{}",
                tag,
                std::process::id(),
                COUNTER.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir_all(&path).expect("temp dir");
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn faces() -> Vec<Face> {
        vec![
            Face {
                port: 443,
                id: "cloak".to_owned(),
                protocol: Protocol::Tls {
                    sni: "web421.example.net".to_owned(),
                    alpn: vec!["h2".to_owned()],
                },
            },
            Face {
                port: 80,
                id: "xray".to_owned(),
                protocol: Protocol::WebSocket {
                    path: "/".to_owned(),
                    host: "web421.example.net".to_owned(),
                },
            },
        ]
    }

    /// The 32 raw bytes behind a hex device key.
    fn device_key(hex_key: &str) -> [u8; 32] {
        hex::decode(hex_key)
            .expect("hex")
            .try_into()
            .expect("32 bytes")
    }

    /// The gate this box enforces, with the set from disk installed in it.
    fn gate_with_the_set_on_disk(
        id: &ServerIdentity,
        dir: &Path,
    ) -> Arc<mirage_subscriber_gate::subscriber_keys::SubscriberKeyStore> {
        let loaded =
            mirage_subscriber_gate::subscriber_keys::load_subscriber_set_file(&subscriber_set_path(dir))
                .expect("the edge gate must be able to load the file");
        let store = mirage_subscriber_gate::subscriber_keys::SubscriberKeyStore::empty(
            id.subscriber_issuer_verifying_key(),
        );
        store.install(loaded).expect("the edge gate must accept the set");
        store
    }

    #[test]
    fn the_set_carries_the_owner_and_every_live_guest() {
        let id = ServerIdentity::mint();
        let dir = TempDir::new("multi");
        issue_invitation(
            dir.path(),
            &id,
            "203.0.113.7",
            &faces(),
            ArtefactMode::FullAuto,
            "alice",
            1_000,
        )
        .expect("invite alice");
        issue_invitation(
            dir.path(),
            &id,
            "203.0.113.7",
            &faces(),
            ArtefactMode::FullAuto,
            "bob",
            2_000,
        )
        .expect("invite bob");
        revoke_subscriber(dir.path(), &id, "bob", 3_000).expect("revoke bob");

        let registry = load_registry(dir.path()).expect("registry");
        let set = build_subscriber_set(&id, &registry, 4_000);
        assert_eq!(set.entries.len(), 2, "the owner and the one live guest");
        assert_eq!(set.entries[0].device_pubkey_hex, id.subscriber_pubkey_hex());
        assert_eq!(set.entries[0].scope, SubscriberScope::Public);
        assert_eq!(set.entries[0].not_after_ms, 4_000 + SUBSCRIPTION_TTL_MS);
        assert_eq!(set.entries[0].subscription_ref, format!("standalone:{}", id.mesh_id()));
        assert_eq!(set.entries[1].subscription_ref, format!("standalone:{}:alice:1000", id.mesh_id()));
        assert_eq!(set.entries[1].not_after_ms, 1_000 + SUBSCRIPTION_TTL_MS);
    }

    #[test]
    fn the_signature_verifies_with_the_native_verifier() {
        let id = ServerIdentity::mint();
        let registry = SubscriberRegistry::empty();
        let set = build_subscriber_set(&id, &registry, 1_000);
        set.verify(&id.subscriber_issuer_verifying_key())
            .expect("the native verifier must accept our signature");
    }

    #[test]
    fn a_tampered_set_fails_the_native_verifier() {
        let id = ServerIdentity::mint();
        let registry = SubscriberRegistry::empty();
        let mut set = build_subscriber_set(&id, &registry, 1_000);
        set.entries[0].not_after_ms += 1;
        assert!(set.verify(&id.subscriber_issuer_verifying_key()).is_err());
    }

    #[test]
    fn the_written_file_loads_and_installs_through_the_edge_gate() {
        let id = ServerIdentity::mint();
        let dir = TempDir::new("gate");
        write_subscriber_set(dir.path(), &id, 1_000).expect("write");

        let loaded = mirage_subscriber_gate::subscriber_keys::load_subscriber_set_file(
            &subscriber_set_path(dir.path()),
        )
        .expect("the edge gate must be able to load the file");
        assert_eq!(loaded.entries.len(), 1);

        let store = mirage_subscriber_gate::subscriber_keys::SubscriberKeyStore::empty(
            id.subscriber_issuer_verifying_key(),
        );
        store.install(loaded).expect("the edge gate must accept the set");
        let device_key: [u8; 32] = hex::decode(id.subscriber_pubkey_hex())
            .expect("hex")
            .try_into()
            .expect("32 bytes");
        assert!(store.contains(&device_key));
    }

    #[test]
    fn the_written_file_is_valid_json_bytes() {
        let id = ServerIdentity::mint();
        let dir = TempDir::new("json");
        write_subscriber_set(dir.path(), &id, 1_000).expect("write");
        let raw = fs::read(subscriber_set_path(dir.path())).expect("read");
        let set = SubscriberSet::decode(&raw).expect("decode");
        assert_eq!(set.entries.len(), 1);
    }

    #[test]
    fn the_gate_finds_every_subscriber_of_a_multi_subscriber_box() {
        let id = ServerIdentity::mint();
        let dir = TempDir::new("gate-multi");
        let alice = issue_invitation(
            dir.path(),
            &id,
            "203.0.113.7",
            &faces(),
            ArtefactMode::FullAuto,
            "alice",
            1_000,
        )
        .expect("invite alice");
        let bob = issue_invitation(
            dir.path(),
            &id,
            "203.0.113.7",
            &faces(),
            ArtefactMode::FullAuto,
            "bob",
            2_000,
        )
        .expect("invite bob");

        let store = gate_with_the_set_on_disk(&id, dir.path());
        assert!(store.contains(&device_key(&id.subscriber_pubkey_hex())));
        assert!(store.contains(&device_key(&alice.pubkey_hex)));
        assert!(store.contains(&device_key(&bob.pubkey_hex)));
    }

    #[test]
    fn a_revoked_key_stops_being_found_by_the_gate() {
        let id = ServerIdentity::mint();
        let dir = TempDir::new("revoke-gate");
        let alice = issue_invitation(
            dir.path(),
            &id,
            "203.0.113.7",
            &faces(),
            ArtefactMode::FullAuto,
            "alice",
            1_000,
        )
        .expect("invite alice");

        let store = gate_with_the_set_on_disk(&id, dir.path());
        assert!(store.contains(&device_key(&alice.pubkey_hex)));

        revoke_subscriber(dir.path(), &id, "alice", 5_000).expect("revoke alice");

        // The gate re-reads the file on its own timer and installs the new
        // set — the same path a running box takes.
        let reloaded = mirage_subscriber_gate::subscriber_keys::load_subscriber_set_file(
            &subscriber_set_path(dir.path()),
        )
        .expect("reload");
        store.install(reloaded).expect("install");

        assert!(!store.contains(&device_key(&alice.pubkey_hex)));
        assert!(store.contains(&device_key(&id.subscriber_pubkey_hex())));
    }

    #[test]
    fn a_revoked_key_is_not_in_the_new_set() {
        let id = ServerIdentity::mint();
        let dir = TempDir::new("revoke-set");
        let alice = issue_invitation(
            dir.path(),
            &id,
            "203.0.113.7",
            &faces(),
            ArtefactMode::FullAuto,
            "alice",
            1_000,
        )
        .expect("invite alice");

        revoke_subscriber(dir.path(), &id, "alice", 2_000).expect("revoke alice");

        let set = mirage_subscriber_gate::subscriber_keys::load_subscriber_set_file(
            &subscriber_set_path(dir.path()),
        )
        .expect("load");
        assert!(!set
            .entries
            .iter()
            .any(|entry| entry.device_pubkey_hex == alice.pubkey_hex));
        assert_eq!(set.entries.len(), 1);
    }

    #[test]
    fn the_revocation_is_kept_in_the_history() {
        let id = ServerIdentity::mint();
        let dir = TempDir::new("history");
        issue_invitation(
            dir.path(),
            &id,
            "203.0.113.7",
            &faces(),
            ArtefactMode::FullAuto,
            "alice",
            1_000,
        )
        .expect("invite alice");
        revoke_subscriber(dir.path(), &id, "alice", 2_000).expect("revoke alice");

        let registry = load_registry(dir.path()).expect("registry");
        assert_eq!(registry.entries.len(), 1, "the revoked record is not dropped");
        let record = registry.find("alice").expect("the record is still there");
        assert!(record.revoked);
        assert_eq!(record.revoked_at_ms, Some(2_000));
        assert_eq!(registry.live().count(), 0);
    }

    #[test]
    fn an_invitation_is_a_valid_artefact_for_the_guest() {
        let id = ServerIdentity::mint();
        let dir = TempDir::new("invite");
        let owner = EntranceArtefact::build(
            &id,
            "203.0.113.7",
            &faces(),
            ArtefactMode::FullAuto,
            "standalone",
            1,
        )
        .expect("build the owner's artefact");
        let invitation = issue_invitation(
            dir.path(),
            &id,
            "203.0.113.7",
            &faces(),
            ArtefactMode::FullAuto,
            "alice",
            2_000,
        )
        .expect("invite alice");

        invitation
            .artefact
            .validate()
            .expect("the invitation must be an artefact the client accepts");
        assert_ne!(invitation.artefact.private_key_hex, id.subscriber_secret_hex());
        assert_ne!(invitation.artefact.private_key_hex, owner.private_key_hex);
        assert_eq!(invitation.artefact.entrances, owner.entrances);
        assert_eq!(invitation.artefact.mesh_id, id.mesh_id());
        assert_eq!(invitation.artefact.label, "alice");
        assert_eq!(invitation.artefact.issued_at_ms, 2_000);
    }

    #[test]
    fn the_guests_key_is_the_one_the_allowlist_admits() {
        let id = ServerIdentity::mint();
        let dir = TempDir::new("guest-key");
        let invitation = issue_invitation(
            dir.path(),
            &id,
            "203.0.113.7",
            &faces(),
            ArtefactMode::FullAuto,
            "alice",
            1_000,
        )
        .expect("invite alice");

        let registry = load_registry(dir.path()).expect("registry");
        let record = registry.find("alice").expect("the record");
        assert_eq!(record.pubkey_hex, invitation.pubkey_hex);
        assert_eq!(record.secret_hex, invitation.artefact.private_key_hex);
        assert_eq!(record.subscription_ref, invitation.subscription_ref);
    }

    #[test]
    fn a_second_invitation_under_the_same_name_is_refused() {
        let id = ServerIdentity::mint();
        let dir = TempDir::new("dup");
        issue_invitation(
            dir.path(),
            &id,
            "203.0.113.7",
            &faces(),
            ArtefactMode::FullAuto,
            "alice",
            1_000,
        )
        .expect("invite alice");
        let err = issue_invitation(
            dir.path(),
            &id,
            "203.0.113.7",
            &faces(),
            ArtefactMode::FullAuto,
            "alice",
            2_000,
        )
        .expect_err("must refuse");
        assert!(matches!(err, SubscriberError::DuplicateName { .. }));
    }

    #[test]
    fn revoking_an_unknown_subscriber_is_refused() {
        let id = ServerIdentity::mint();
        let dir = TempDir::new("unknown");
        let err = revoke_subscriber(dir.path(), &id, "nobody", 1_000).expect_err("must refuse");
        assert!(matches!(err, SubscriberError::UnknownSubscriber { .. }));
    }

    #[test]
    fn a_subscriber_can_be_revoked_by_its_reference() {
        let id = ServerIdentity::mint();
        let dir = TempDir::new("by-ref");
        let invitation = issue_invitation(
            dir.path(),
            &id,
            "203.0.113.7",
            &faces(),
            ArtefactMode::FullAuto,
            "alice",
            1_000,
        )
        .expect("invite alice");

        let revoked =
            revoke_subscriber(dir.path(), &id, &invitation.subscription_ref, 2_000).expect("revoke");
        assert_eq!(revoked.name, "alice");
        assert_eq!(revoked.pubkey_hex, invitation.pubkey_hex);
    }

    #[test]
    fn an_unusable_name_is_refused() {
        let id = ServerIdentity::mint();
        let dir = TempDir::new("bad-name");
        for name in ["", "  ", "with a space", "with/slash"] {
            let err = issue_invitation(
                dir.path(),
                &id,
                "203.0.113.7",
                &faces(),
                ArtefactMode::FullAuto,
                name,
                1_000,
            )
            .expect_err("must refuse");
            assert!(matches!(err, SubscriberError::InvalidName { .. }));
        }
    }

    #[test]
    fn debug_never_shows_a_guests_secret() {
        let id = ServerIdentity::mint();
        let dir = TempDir::new("debug");
        let invitation = issue_invitation(
            dir.path(),
            &id,
            "203.0.113.7",
            &faces(),
            ArtefactMode::FullAuto,
            "alice",
            1_000,
        )
        .expect("invite alice");
        let registry = load_registry(dir.path()).expect("registry");
        let record = registry.find("alice").expect("the record");

        for text in [
            format!("{:?}", invitation),
            format!("{:?}", registry),
            format!("{:?}", record),
        ] {
            assert!(!text.contains(&record.secret_hex));
            assert!(!text.contains(&invitation.artefact.private_key_hex));
        }
        assert!(format!("{:?}", invitation).contains("alice"));
    }

    #[test]
    fn the_registry_survives_a_reload() {
        let id = ServerIdentity::mint();
        let dir = TempDir::new("reload");
        let invitation = issue_invitation(
            dir.path(),
            &id,
            "203.0.113.7",
            &faces(),
            ArtefactMode::FullAuto,
            "alice",
            1_000,
        )
        .expect("invite alice");
        let registry = load_registry(dir.path()).expect("registry");
        let record = registry.find("alice").expect("the record");
        assert_eq!(record.secret_hex, invitation.artefact.private_key_hex);
    }

    #[test]
    fn the_listing_carries_the_owner_and_the_live_guests() {
        let id = ServerIdentity::mint();
        let dir = TempDir::new("listing");
        issue_invitation(
            dir.path(),
            &id,
            "203.0.113.7",
            &faces(),
            ArtefactMode::FullAuto,
            "alice",
            1_000,
        )
        .expect("invite alice");
        issue_invitation(
            dir.path(),
            &id,
            "203.0.113.7",
            &faces(),
            ArtefactMode::FullAuto,
            "bob",
            2_000,
        )
        .expect("invite bob");
        revoke_subscriber(dir.path(), &id, "bob", 3_000).expect("revoke bob");

        let registry = load_registry(dir.path()).expect("registry");
        let admitted = admitted_subscribers(&id, &registry);
        assert_eq!(admitted.len(), 2);
        assert!(admitted[0].owner);
        assert_eq!(admitted[0].name, OWNER_SUBSCRIBER_NAME);
        assert_eq!(admitted[0].pubkey_hex, id.subscriber_pubkey_hex());
        assert!(!admitted[1].owner);
        assert_eq!(admitted[1].name, "alice");
    }

    #[cfg(unix)]
    #[test]
    fn the_registry_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let id = ServerIdentity::mint();
        let dir = TempDir::new("mode");
        issue_invitation(
            dir.path(),
            &id,
            "203.0.113.7",
            &faces(),
            ArtefactMode::FullAuto,
            "alice",
            1_000,
        )
        .expect("invite alice");
        let mode = fs::metadata(subscribers_path(dir.path()))
            .expect("stat")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }
}
