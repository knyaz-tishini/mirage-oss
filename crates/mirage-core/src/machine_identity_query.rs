//! What the keeper (`mirage-warden`) answers when a supervised service asks
//! for its own role's slice.
//!
//! # One socket, one question
//!
//! [`crate::local_endpoint::LocalChannel::MachineIdentity`] is dialled by
//! every service the box supervises — monitor, secd, sentry, node, mshd,
//! db-worker, perimeter, and the warden's own restart path. Each asks for
//! exactly its own role's material out of the current
//! [`crate::capsule::MachineCapsule`]; none of them can ask for anyone
//! else's, and the answer never carries another role's private key. See
//! `docs/mirage/plans/machine-identity-consolidated-2026-08-17.md` §2 —
//! "Why the keeper hands out slices instead of the whole capsule".
//!
//! # Why these types live here and not in `mirage-warden`
//!
//! The same reason [`crate::perimeter_query`] moved out of
//! `mirage-perimeter`: the shape has to be defined once, compiled into both
//! the keeper (producer) and every consumer, so a field rename is a build
//! error instead of a silent `null` on one side of the socket.
//!
//! # No field that can name a path, a unit, or a command
//!
//! [`MachineIdentityRequest::Take`] carries a typed [`ServiceRole`] — never a
//! free-form string, a filename, or a unit name. The caller says WHICH role
//! it means; it does not get to say WHERE to read from or WHAT to run.

use serde::{Deserialize, Serialize};

use crate::capsule::{CapsulePeer, CapsuleServiceConfig, CapsuleSigner, GroupCharter, RoleSlice};
use crate::identity::{DeclaredIdentity, ServiceRole};
use crate::ids::{MachineId, MeshId};

/// A request on [`crate::local_endpoint::LocalChannel::MachineIdentity`].
/// One frame, because the socket does exactly one thing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MachineIdentityRequest {
    /// Give me the slice for this role, plus the shared machine-scoped
    /// context every role needs regardless of which one it is.
    Take { role: ServiceRole },
    /// Is a renewal currently stalled, and since when — see
    /// [`RenewalStallState`]'s own doc. Carries no role: the answer is
    /// machine-scoped and carries no secret, so unlike [`Self::Take`] it is
    /// not gated per-caller beyond this socket's own connect-time
    /// allowlist.
    RenewalStatus,
}

/// The keeper's answer. Not a bare `Option<MachineSlice>` — a caller asking
/// before the keeper has ever admitted a machine capsule (cold boot, still
/// waiting on mshd) is a different fact from asking for a role nobody sealed
/// a slice for, and the two must be told apart rather than folded into one
/// `None`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MachineIdentityResponse {
    /// This role's slice, plus the shared, non-secret parts of the machine
    /// capsule.
    Slice(Box<MachineSlice>),
    /// The keeper holds no machine capsule yet — still waiting on admission.
    /// The caller should keep waiting; see
    /// [`crate::identity_boot::take_machine_slice`] for why there is
    /// deliberately no deadline on that wait.
    NotYetAdmitted,
    /// The keeper holds a machine capsule, but it carries no slice for the
    /// requested role — a capsule sealed without this role in it, or a role
    /// this box does not actually run.
    NoSuchRole,
    /// Answer to [`MachineIdentityRequest::RenewalStatus`]. `None` for the
    /// entire life of a box whose renewals keep landing inside one ask
    /// cycle — most boxes, most of the time.
    Renewal(Option<RenewalStallState>),
}

/// A snapshot of the keeper's own renewal-stall bookkeeping — see
/// `mirage-warden`'s `machine_store::renew_before_expiry` for the two
/// grounds that make this exist at all: the served capsule has run past its
/// own `not_after_ms`, or a delivery window has been open longer than one
/// full ask cycle with nothing landing. Exists ONLY while one of those is
/// true; the keeper reports `None` the rest of the time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RenewalStallState {
    /// Wall-clock ms this renewal attempt first became due.
    pub due_since_ms: u64,
    /// Wall-clock ms the delivery window currently open for this attempt
    /// was opened. `None` on the narrow pass where the attempt just became
    /// due and no window has been opened for it yet.
    pub window_opened_ms: Option<u64>,
    /// How long the served capsule has been past its own `not_after_ms`,
    /// against the box clock, at the instant this was read. `None` while
    /// the served capsule has not yet expired — a renewal can stall on the
    /// window-cycle ground alone, well before its capsule actually expires.
    pub expired_for_ms: Option<u64>,
    /// The LIVE `not_after_ms` of the machine capsule this keeper is
    /// currently serving, read fresh off its own RAM cache at the same
    /// instant as every other field here — never a per-role process's own
    /// once-per-boot copy of a slice it took and never re-took.
    ///
    /// Every OTHER consumer on this box (the perimeter among them) computed
    /// its own "am I expired" number from the slice it happened to be
    /// holding at boot, which does not move even once the keeper has long
    /// since renewed — measured on `tr-hostkey-203.0.113.14` and the rest of
    /// the fleet, 2026-09-23: every perimeter older than 24h read "expired
    /// 12 days" while this keeper's own `expires_in` was a healthy 10-14h,
    /// renewed roughly every 18h. This field is the one number any consumer
    /// of [`MachineIdentityResponse::Renewal`] should ever show for
    /// "capsule expiry" — see `mirage_core::perimeter_query::RenewalSnapshot
    /// ::keeper_capsule_not_after_ms`, which mirrors it onto the perimeter's
    /// own wire shape under that explicit name. `#[serde(default)]` so a
    /// keeper built before this field existed still answers a parseable
    /// `RenewalStallState`; a consumer reading `None` learns nothing false,
    /// only that this particular keeper predates the field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capsule_not_after_ms: Option<u64>,
}

/// Everything ONE caller receives from the keeper: its own role's slice,
/// plus the shared, non-secret parts of the machine capsule every role
/// needs regardless of which one it is.
///
/// Another role's private key is never in this type, by construction — the
/// keeper builds one of these per caller from its own
/// [`crate::capsule::MachineCapsule`]; it does not hand the capsule itself
/// across the socket. `db_key` is `None` here for every role but the one the
/// keeper actually populates it for (db-worker), mirroring the scoping the
/// old per-role capsule already did by issuer discipline — see
/// [`crate::capsule::MachineCapsule::db_key`]'s own doc.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MachineSlice {
    pub self_id: uuid::Uuid,
    pub machine_id: MachineId,
    pub mesh_id: MeshId,
    /// This caller's own slice — role, wire key, signing key.
    pub slice: RoleSlice,
    /// The machine's own operator-signed public envelope, naming every role
    /// it runs.
    pub declared_identity: DeclaredIdentity,
    /// Who to talk to, as signed identities rather than a parallel table.
    pub peers: Vec<CapsulePeer>,
    pub service_config: CapsuleServiceConfig,
    pub charter: Option<GroupCharter>,
    /// SQLCipher master key. Populated only when the keeper is answering
    /// db-worker's own request — see this struct's own doc.
    pub db_key: Option<[u8; 32]>,
    pub issued_at_ms: u64,
    pub not_after_ms: u64,
    /// Which key admitted the machine capsule this slice was cut from — the
    /// authority this service is actually running under, instead of every
    /// caller assuming operator. The keeper reads this once out of the
    /// `SealedCapsule` it accepted and carries it forward here; see
    /// `mirage-warden`'s `MachineStore` for where it is recorded.
    ///
    /// `#[serde(default)]` because this socket crosses process boundaries
    /// between independently-restarted services on the same box: a keeper
    /// built before this field existed answers with no `signer` key at all,
    /// and a consumer built after it must still deserialise that answer
    /// rather than fail the whole slice request over one informational
    /// field. The default is `CapsuleSigner::Operator`, which is always
    /// correct for that specific case — a keeper predating this field
    /// predates `CapsuleSigner::Machine` too, so anything it could have
    /// admitted was already `Operator` or `Group`-signed, never self-issued.
    #[serde(default = "default_capsule_signer")]
    pub signer: CapsuleSigner,
    /// This machine's own attestation public key (hex, 64 chars), present
    /// exactly when [`Self::signer`] is [`CapsuleSigner::Machine`]
    /// (equivalently, when [`Self::declared_identity`]'s own
    /// [`crate::identity::IdentitySigner`] is `Machine`) — carried so a
    /// consumer of this socket can verify the declared identity's
    /// self-signature locally, the same way
    /// [`crate::identity_boot::BootSession::accept`] already can on the
    /// keeper's own box (it holds the attestation key itself). Not a
    /// secret: the attestation public key is already gossiped fleet-wide
    /// once a machine is enrolled
    /// ([`crate::attestation::AttestationPubkey`]), so carrying it here
    /// reveals nothing a peer could not already read. `#[serde(default)]`
    /// for the same cross-version reason [`Self::signer`] is: a keeper
    /// built before this field existed answers with none, and that keeper
    /// could never have produced a `Machine`-signed identity anyway (see
    /// [`Self::signer`]'s own doc).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attestation_pubkey_hex: Option<String>,
}

/// [`MachineSlice::signer`]'s serde default — see that field's own doc for
/// why `Operator` is the only value that can be correct for a payload
/// missing this field entirely.
fn default_capsule_signer() -> CapsuleSigner {
    CapsuleSigner::Operator
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_take_request_round_trips_and_is_legible_in_a_log() {
        let req = MachineIdentityRequest::Take { role: ServiceRole::Sentry };
        let raw = serde_json::to_string(&req).expect("encodes");
        assert!(raw.contains("\"take\""), "{raw}");
        let back: MachineIdentityRequest = serde_json::from_str(&raw).expect("decodes");
        assert_eq!(back, req);
    }

    #[test]
    fn every_response_variant_round_trips() {
        let cases = vec![
            MachineIdentityResponse::NotYetAdmitted,
            MachineIdentityResponse::NoSuchRole,
            MachineIdentityResponse::Renewal(None),
            MachineIdentityResponse::Renewal(Some(RenewalStallState {
                due_since_ms: 1_700_000_000_000,
                window_opened_ms: Some(1_700_000_000_500),
                expired_for_ms: Some(42),
                capsule_not_after_ms: Some(1_700_003_600_000),
            })),
            MachineIdentityResponse::Slice(Box::new(MachineSlice {
                self_id: uuid::Uuid::from_u128(1),
                machine_id: MachineId::new("ru-hostkey-203.0.113.10").expect("machine id"),
                mesh_id: MeshId::new("v3-staging").expect("mesh id"),
                slice: RoleSlice {
                    role: ServiceRole::Sentry,
                    wire_privkey: [0x11; 32],
                    signing_privkey: None,
                    wire_pubkey_hex: "aa".repeat(32),
                    signing_pubkey_hex: None,
                },
                declared_identity: DeclaredIdentity::sign_new(
                    uuid::Uuid::from_u128(1),
                    MachineId::new("ru-hostkey-203.0.113.10").expect("machine id"),
                    MeshId::new("v3-staging").expect("mesh id"),
                    vec![ServiceRole::Sentry],
                    vec![crate::identity::RolePublicKeys {
                        role: ServiceRole::Sentry,
                        wire_pubkey_hex: "aa".repeat(32),
                        signing_pubkey_hex: None,
                    }],
                    1_700_000_000_000,
                    &ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]),
                ),
                peers: vec![],
                service_config: CapsuleServiceConfig::default(),
                charter: None,
                db_key: None,
                issued_at_ms: 1_700_000_000_000,
                not_after_ms: 1_700_003_600_000,
                signer: CapsuleSigner::Operator,
                attestation_pubkey_hex: None,
            })),
        ];
        for c in cases {
            let raw = serde_json::to_vec(&c).expect("encodes");
            let back: MachineIdentityResponse =
                serde_json::from_slice(&raw).expect("decodes");
            // `RoleSlice`/`MachineSlice` hold secrets and deliberately do not
            // derive `PartialEq` (see their own docs) — compare by re-encoding
            // rather than by value.
            assert_eq!(serde_json::to_vec(&back).expect("re-encodes"), raw);
        }
    }

    /// A `MachineSlice` payload from a keeper built before [`MachineSlice::
    /// signer`] existed must still deserialise — this is the roll-order
    /// property `#[serde(default)]` exists for, proven against the actual
    /// wire bytes rather than only against the struct definition.
    #[test]
    fn a_slice_missing_signer_deserialises_as_operator() {
        let with_signer = MachineSlice {
            self_id: uuid::Uuid::from_u128(1),
            machine_id: MachineId::new("ru-hostkey-203.0.113.10").expect("machine id"),
            mesh_id: MeshId::new("v3-staging").expect("mesh id"),
            slice: RoleSlice {
                role: ServiceRole::Sentry,
                wire_privkey: [0x11; 32],
                signing_privkey: None,
                wire_pubkey_hex: "aa".repeat(32),
                signing_pubkey_hex: None,
            },
            declared_identity: DeclaredIdentity::sign_new(
                uuid::Uuid::from_u128(1),
                MachineId::new("ru-hostkey-203.0.113.10").expect("machine id"),
                MeshId::new("v3-staging").expect("mesh id"),
                vec![ServiceRole::Sentry],
                vec![crate::identity::RolePublicKeys {
                    role: ServiceRole::Sentry,
                    wire_pubkey_hex: "aa".repeat(32),
                    signing_pubkey_hex: None,
                }],
                1_700_000_000_000,
                &ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]),
            ),
            peers: vec![],
            service_config: CapsuleServiceConfig::default(),
            charter: None,
            db_key: None,
            issued_at_ms: 1_700_000_000_000,
            not_after_ms: 1_700_003_600_000,
            signer: CapsuleSigner::Operator,
            attestation_pubkey_hex: None,
        };
        let mut value = serde_json::to_value(&with_signer).expect("encodes");
        value
            .as_object_mut()
            .expect("MachineSlice serialises as a JSON object")
            .remove("signer");
        let restored: MachineSlice =
            serde_json::from_value(value).expect("must deserialise without a signer field");
        assert_eq!(restored.signer, CapsuleSigner::Operator);
    }

    /// A `MachineSlice` whose `service_config.subscriber_entrance` carries no
    /// `socks_addr` key at all (the shape a current opbox seals -
    /// `crate::config::SubscriberEntranceConfig::legacy_socks_addr` is
    /// `#[serde(default, skip_serializing)]`) must still round-trip. Measured
    /// live on `ae-example-203.0.113.86`, 2026-09-24: an `mshd` binary built
    /// before that field went optional could not decode exactly this shape
    /// and waited on the keeper forever - see
    /// `crate::identity_boot::take_machine_slice`'s own `AskKeeperError::
    /// Decode` doc for the incident this closes.
    #[test]
    fn a_slice_with_a_subscriber_entrance_missing_socks_addr_round_trips() {
        let mut service_config = CapsuleServiceConfig::default();
        service_config.subscriber_entrance = Some(crate::config::SubscriberEntranceConfig {
            legacy_socks_addr: None,
            aggregate_rate_bytes_per_sec: None,
            aggregate_burst_bytes: None,
            per_connection_rate_bytes_per_sec: None,
            monthly_volume_bytes: None,
            degraded_floor_bytes_per_sec: None,
        });
        let slice = MachineSlice {
            self_id: uuid::Uuid::from_u128(1),
            machine_id: MachineId::new("ae-example-203.0.113.86").expect("machine id"),
            mesh_id: MeshId::new("v3-staging").expect("mesh id"),
            slice: RoleSlice {
                role: ServiceRole::Mshd,
                wire_privkey: [0x11; 32],
                signing_privkey: None,
                wire_pubkey_hex: "aa".repeat(32),
                signing_pubkey_hex: None,
            },
            declared_identity: DeclaredIdentity::sign_new(
                uuid::Uuid::from_u128(1),
                MachineId::new("ae-example-203.0.113.86").expect("machine id"),
                MeshId::new("v3-staging").expect("mesh id"),
                vec![ServiceRole::Mshd],
                vec![crate::identity::RolePublicKeys {
                    role: ServiceRole::Mshd,
                    wire_pubkey_hex: "aa".repeat(32),
                    signing_pubkey_hex: None,
                }],
                1_700_000_000_000,
                &ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]),
            ),
            peers: vec![],
            service_config,
            charter: None,
            db_key: None,
            issued_at_ms: 1_700_000_000_000,
            not_after_ms: 1_700_003_600_000,
            signer: CapsuleSigner::Operator,
            attestation_pubkey_hex: None,
        };

        let value = serde_json::to_value(&slice).expect("encodes");
        let entrance = value
            .get("service_config")
            .and_then(|c| c.get("subscriber_entrance"))
            .expect("subscriber_entrance must be present");
        assert!(
            entrance.get("socks_addr").is_none(),
            "a current seal must never carry socks_addr: {entrance}"
        );

        let restored: MachineSlice =
            serde_json::from_value(value).expect("must deserialise with no socks_addr present");
        assert!(restored.service_config.subscriber_entrance.is_some());
    }

    /// A `RenewalStallState` from a keeper built before `capsule_not_after_ms`
    /// existed still parses, reading as `None` rather than failing the whole
    /// renewal answer over one added field.
    #[test]
    fn a_renewal_stall_state_missing_capsule_not_after_ms_deserialises_as_none() {
        let legacy = r#"{"due_since_ms":1000,"window_opened_ms":null,"expired_for_ms":null}"#;
        let state: RenewalStallState =
            serde_json::from_str(legacy).expect("legacy renewal-stall state parses");
        assert_eq!(state.capsule_not_after_ms, None);
    }

    /// `NotYetAdmitted` and `NoSuchRole` are told apart — a cold-boot caller
    /// waiting on admission and a caller asking for a role nobody sealed are
    /// different facts, and folding them into one `None` would hide which
    /// one a service is actually looking at.
    #[test]
    fn not_yet_admitted_and_no_such_role_are_distinct_on_the_wire() {
        let a = serde_json::to_string(&MachineIdentityResponse::NotYetAdmitted).unwrap();
        let b = serde_json::to_string(&MachineIdentityResponse::NoSuchRole).unwrap();
        assert_ne!(a, b);
    }

    /// A `MachineSlice` payload from a keeper built before
    /// [`MachineSlice::attestation_pubkey_hex`] existed must still
    /// deserialise, the same roll-order property [`Self::signer`]'s own
    /// test proves — a keeper that predates this field predates
    /// `CapsuleSigner::Machine` too, so `None` is the only value that could
    /// ever be correct for a payload missing it entirely.
    #[test]
    fn a_slice_missing_attestation_pubkey_hex_deserialises_as_none() {
        let with_it = MachineSlice {
            self_id: uuid::Uuid::from_u128(1),
            machine_id: MachineId::new("ru-hostkey-203.0.113.10").expect("machine id"),
            mesh_id: MeshId::new("v3-staging").expect("mesh id"),
            slice: RoleSlice {
                role: ServiceRole::Sentry,
                wire_privkey: [0x11; 32],
                signing_privkey: None,
                wire_pubkey_hex: "aa".repeat(32),
                signing_pubkey_hex: None,
            },
            declared_identity: DeclaredIdentity::sign_new(
                uuid::Uuid::from_u128(1),
                MachineId::new("ru-hostkey-203.0.113.10").expect("machine id"),
                MeshId::new("v3-staging").expect("mesh id"),
                vec![ServiceRole::Sentry],
                vec![crate::identity::RolePublicKeys {
                    role: ServiceRole::Sentry,
                    wire_pubkey_hex: "aa".repeat(32),
                    signing_pubkey_hex: None,
                }],
                1_700_000_000_000,
                &ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]),
            ),
            peers: vec![],
            service_config: CapsuleServiceConfig::default(),
            charter: None,
            db_key: None,
            issued_at_ms: 1_700_000_000_000,
            not_after_ms: 1_700_003_600_000,
            signer: CapsuleSigner::Machine { machine_id: "ru-hostkey-203.0.113.10".to_string() },
            attestation_pubkey_hex: Some("aa".repeat(32)),
        };
        let mut value = serde_json::to_value(&with_it).expect("encodes");
        value
            .as_object_mut()
            .expect("MachineSlice serialises as a JSON object")
            .remove("attestation_pubkey_hex");
        let restored: MachineSlice = serde_json::from_value(value)
            .expect("must deserialise without an attestation_pubkey_hex field");
        assert_eq!(restored.attestation_pubkey_hex, None);
    }
}
