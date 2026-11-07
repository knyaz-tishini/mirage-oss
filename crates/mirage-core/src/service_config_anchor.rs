//! Operator-signed, gossiped `service_config` — lets any monitor source a
//! subject's [`CapsuleServiceConfig`] when minting a capsule, not only the
//! subject's own box.
//!
//! ## The gap this closes
//!
//! `capsule_mint::assemble_rotated_capsule` (in `mirage2monitor`) needs a
//! `service_config` for whichever `(machine_id, role)` it is rotating, and
//! today nothing on ANY monitor can produce one except opbox itself — see
//! `docs/mirage/plans/service-config-monitor-side-source-2026-08-08.md`. A
//! quorum rotation happens precisely when opbox is unreachable (S5.6's own
//! gate: "reboot a box with opbox stopped"), so the one existing source is
//! exactly the one guaranteed absent at the moment this type exists to
//! serve.
//!
//! ## Why operator-signed only — argued, not asserted
//!
//! Unlike [`crate::machine_park::MachineParkFact`], this fact has no
//! `Quorum` authority variant, and that omission is deliberate.
//! `secd_policy` draws the identical line for a different table: policy is
//! the operator's, and a mesh that could sign its own policy could lift its
//! own restrictions. `service_config` is policy in the same sense — it is
//! where a box's perimeter routes SSH-shaped traffic and how it answers on
//! the wire. A quorum able to mint fresh `service_config` facts could, with
//! a compromised `t`-of-`n` majority, repoint a box's control-plane
//! endpoints or its SSH-shaped routing destination — a config any member can
//! forge is a config that can redirect a rebooted box.
//!
//! Compare this to what the quorum genuinely must originate: a ban (fleet
//! self-defense while the operator is asleep) and a fresh identity keypair
//! (the one thing only the quorum can produce without custody of the OLD
//! key). Neither argument applies here — a rebooting box's operational
//! settings do not need to CHANGE at reboot; the correct behaviour is to
//! replay the operator's last-set value, exactly like `charter` and `peers`
//! already do for a booting service (see `crate::capsule`'s own module
//! doc). `service_config` belongs in the "read, don't mint" bucket with
//! those two, not in the "quorum must be able to originate this" bucket
//! with an identity rotation.
//!
//! ## Confidentiality
//!
//! Only the typed, already-projected [`CapsuleServiceConfig`] is ever
//! carried here — **never** opbox's raw `service_configs` JSON blob, which
//! is a strict superset that also carries `outbound_bearer` (a peer-link
//! bearer secret, in cleartext) and a bearer-hash `api_keys` table. Every
//! field `CapsuleServiceConfig` actually has is either already gossiped
//! elsewhere (`public_addr`) or meaningless off-box (the `127.0.0.1`-only
//! loopback handover addresses); see the plan doc §3 for the field-by-field
//! audit. Nothing here changes that boundary — this module only ever signs
//! and verifies the safe, typed struct, and there is no code path from the
//! raw opbox blob into it.
//!
//! ## Determinism
//!
//! See [`ServiceConfigAnchor::signing_bytes`]'s doc for the field-by-field
//! audit of [`CapsuleServiceConfig`]: no `HashMap`/`HashSet`, no float, at
//! any depth of its transitive closure. That absence is what makes
//! embedding its `serde_json` serialisation into the preimage safe — the
//! same argument, and the same technique,
//! [`crate::identity::DeclaredIdentity::signing_bytes`]'s `faces` tail
//! already uses for the very same nested `Vec<CapsuleControlEndpoint>`
//! type. This preimage extends that established, already-shipped technique
//! to the whole struct rather than inventing a second one.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::capsule::CapsuleServiceConfig;
use crate::identity::ServiceRole;

/// Signing-preimage domain label. Distinct from every other label in the
/// tree so a service-config signature can never be replayed as a park
/// fact, enrolment, capsule, charter, or quorum event.
const SERVICE_CONFIG_ANCHOR_SIG_LABEL: &[u8] = b"MIRAGE-SERVICE-CONFIG-ANCHOR-V1";

/// The operator's current, signed statement of one `(machine_id, role)`'s
/// [`CapsuleServiceConfig`] — see the module doc for why this exists and
/// why it carries no `Quorum` authority.
///
/// 1-row/subject LWW on `updated_at_ms`, the same shape as
/// [`crate::attestation::AttestationPubkey`] and
/// [`crate::machine_park::MachineParkFact`]: a monitor keeps only the most
/// recent record per `(machine_id, role)`, and a strictly-newer
/// `updated_at_ms` is required to overwrite it — see
/// [`service_config_apply_verdict`] for the applier's rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceConfigAnchor {
    /// Plain string, matching [`crate::machine_park::MachineParkFact`]'s
    /// convention for this table class — not the typed `MachineId` used on
    /// identity-adjacent types like `DeclaredIdentity`.
    pub machine_id: String,
    pub role: ServiceRole,
    /// **Never** opbox's raw `service_configs` JSON blob — see the module
    /// doc's "Confidentiality" section. Only this typed projection.
    pub config: CapsuleServiceConfig,
    /// When the operator last set this. LWW key when gossiped, and bound
    /// into the signature so it cannot be stripped or replayed against a
    /// later edit.
    pub updated_at_ms: u64,
    /// Signature over [`ServiceConfigAnchor::signing_bytes`], hex.
    /// Operator-only — there is no second key this ever verifies against,
    /// unlike `MachineParkFact`'s dual `ParkAuthority`. Without this the
    /// record is worthless: a monitor accepting an unsigned config would
    /// let anyone who can gossip redirect any rebooting box.
    pub operator_sig_hex: String,
}

impl ServiceConfigAnchor {
    /// Fixed, length-prefixed signing preimage — never a hash of JSON.
    ///
    /// The tail IS a `serde_json` serialisation of `config`, length-prefixed
    /// so it cannot be confused with a neighbouring field — but that tail
    /// is the only JSON in this preimage, and it is safe only because of
    /// the audit below.
    ///
    /// ## Determinism audit of [`CapsuleServiceConfig`], field by field
    ///
    /// | Field | Shape | Unordered container? | Float? |
    /// |---|---|---|---|
    /// | `public_addr` | `Option<String>` | no | no |
    /// | `control_plane_endpoints` | `Vec<CapsuleControlEndpoint>` | no (`Vec`, order preserved) | no |
    /// | `perimeter_inner_addr` | `Option<String>` | no | no |
    /// | `perimeter_stats_bind` | `Option<String>` | no | no |
    /// | `perimeter_ssh_addr` | `Option<String>` | no | no |
    /// | `perimeter_jail_default` | `Option<String>` | no | no |
    /// | `perimeter_jail_faces` | `Vec<CapsuleJailFace>` | no | no |
    /// | `perimeter_jail_hold_ms` | `Option<u64>` | no | no |
    /// | `perimeter_jail_max_held_per_face` | `Option<usize>` | no | no |
    /// | `control_bind_addr` | `Option<String>` | no | no |
    /// | `shortname` | `Option<String>` | no | no |
    /// | `lifecycle` | `Option<String>` | no | no |
    /// | `node_seeds` | `Vec<String>` | no | no |
    /// | `country_cidrs` | `BTreeMap<String, Vec<String>>` | no (`BTreeMap`, sorted key order) | no |
    ///
    /// One level deeper: `CapsuleControlEndpoint { port: u16, camouflage:
    /// TransportCamouflage, wire_version: Option<u8>, purpose:
    /// Option<FacePurpose> }` and `CapsuleJailFace { port: u16, disposition:
    /// String }` are both plain structs — no unordered container, no float.
    /// `TransportCamouflage`
    /// (`crate::mirage::wire::camouflage`) is a 15-variant
    /// internally-tagged enum (`#[serde(tag = "type")]`) whose variant
    /// fields are `String`, `Vec<String>`, `u8`/`u16`/`u32`, `bool`,
    /// `Option<String>`, `SocketAddr`, `IpAddr` — again no `HashMap`,
    /// `HashSet`, or float anywhere in the closure.
    ///
    /// With no unordered container and no float anywhere in
    /// `CapsuleServiceConfig`'s transitive closure, `serde_json`'s output
    /// is determined entirely by the VALUE: struct fields serialise in
    /// declaration order (fixed by the type, not by construction-site
    /// field order — a Rust struct literal's field order is source-code
    /// cosmetics, never part of the value) and enum variants serialise by
    /// their fixed tag. Two independently-built values that are equal
    /// therefore produce byte-identical JSON. See
    /// `service_config_signing_bytes_are_stable_across_construction_order`
    /// in this module's tests for the proof.
    ///
    /// If `CapsuleServiceConfig`'s shape ever grows an unordered container,
    /// this function must change to encode it in sorted-key order — the
    /// argument above is a property of today's shape, not a standing
    /// guarantee independent of it.
    fn signing_bytes(&self) -> Vec<u8> {
        let json = serde_json::to_vec(&self.config).unwrap_or_default();
        let mut p = Vec::with_capacity(
            SERVICE_CONFIG_ANCHOR_SIG_LABEL.len() + self.machine_id.len() + json.len() + 32,
        );
        p.extend_from_slice(SERVICE_CONFIG_ANCHOR_SIG_LABEL);
        push_lp(&mut p, self.machine_id.as_bytes());
        push_lp(&mut p, self.role.to_string().as_bytes());
        p.extend_from_slice(&self.updated_at_ms.to_le_bytes());
        push_lp(&mut p, &json);
        p
    }

    /// Sign the operator's current `service_config` for one `(machine_id,
    /// role)`.
    #[must_use]
    pub fn sign_new(
        machine_id: impl Into<String>,
        role: ServiceRole,
        config: CapsuleServiceConfig,
        updated_at_ms: u64,
        key: &SigningKey,
    ) -> Self {
        let mut me = Self {
            machine_id: machine_id.into(),
            role,
            config,
            updated_at_ms,
            operator_sig_hex: String::new(),
        };
        let sig = key.sign(&me.signing_bytes());
        me.operator_sig_hex = hex::encode(sig.to_bytes());
        me
    }

    /// Verify against the pinned operator key.
    ///
    /// Returns `false` on any decoding failure (malformed hex, wrong
    /// signature length) or a genuine signature mismatch — callers only
    /// need a boolean accept/reject, never a reason.
    #[must_use]
    pub fn verify(&self, operator_pubkey: &VerifyingKey) -> bool {
        let Ok(raw_sig) = hex::decode(&self.operator_sig_hex) else {
            return false;
        };
        let Ok(sig_arr) = <[u8; 64]>::try_from(raw_sig) else {
            return false;
        };
        let sig = Signature::from_bytes(&sig_arr);
        operator_pubkey.verify(&self.signing_bytes(), &sig).is_ok()
    }
}

fn push_lp(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(bytes);
}

/// The applier's verdict for one incoming [`ServiceConfigAnchor`] against
/// whatever a monitor currently holds for the same `(machine_id, role)`.
///
/// Pure: no I/O, no clock, no signature check — same shape as
/// [`crate::machine_park::park_apply_verdict`]. `incoming` must already
/// have passed [`ServiceConfigAnchor::verify`] before this is called; this
/// function makes no attempt to authenticate it.
///
/// Only two outcomes, unlike `park_apply_verdict`'s three: this fact has a
/// single authority (the operator), so there is no `RejectAuthority` case
/// — nothing else is ever allowed to touch a standing row, and the
/// operator may always replace its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceConfigApply {
    /// Store `incoming`, replacing whatever is held (or nothing, if this is
    /// the first record for the subject).
    Accept,
    /// `incoming.updated_at_ms` is not strictly greater than what is held.
    /// Discard it — the ordinary LWW rule.
    RejectStale,
}

/// Decide whether `incoming` may replace `current` for one `(machine_id,
/// role)`. Strictly-greater, not greater-or-equal — a replay at the same
/// millisecond must never masquerade as the record of record.
#[must_use]
pub fn service_config_apply_verdict(
    current: Option<&ServiceConfigAnchor>,
    incoming: &ServiceConfigAnchor,
) -> ServiceConfigApply {
    match current {
        Some(cur) if incoming.updated_at_ms <= cur.updated_at_ms => {
            ServiceConfigApply::RejectStale
        }
        _ => ServiceConfigApply::Accept,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capsule::{CapsuleControlEndpoint, CapsuleJailFace};
    use crate::mirage::wire::camouflage::TransportCamouflage;
    use rand::rngs::OsRng;

    const NOW: u64 = 1_800_000_000_000;

    fn sample_config() -> CapsuleServiceConfig {
        CapsuleServiceConfig {
            public_addr: Some("203.0.113.10:19444".to_string()),
            control_plane_endpoints: vec![
                CapsuleControlEndpoint {
                    port: 443,
                    camouflage: TransportCamouflage::TlsReal {
                        sni: "cdn.example.com".to_string(),
                        alpn: vec!["h2".to_string(), "http/1.1".to_string()],
                    },
                    wire_version: Some(9),
                    purpose: None,
                },
                CapsuleControlEndpoint {
                    port: 80,
                    camouflage: TransportCamouflage::None,
                    wire_version: None,
                    purpose: None,
                },
            ],
            perimeter_inner_addr: Some("127.0.0.1:19444".to_string()),
            perimeter_jail_faces: vec![CapsuleJailFace {
                port: 443,
                disposition: "jail".to_string(),
            }],
            node_seeds: vec!["v2-seed-a".to_string(), "v2-seed-b".to_string()],
            ..Default::default()
        }
    }

    // ── sign / verify ───────────────────────────────────────────────

    /// The signed preimage is the length-prefixed JSON tail of
    /// `CapsuleServiceConfig`, so a country map that serialised as a
    /// present-but-empty object would change the bytes EVERY already-issued
    /// anchor in the fleet signed and break verification everywhere at
    /// once.
    ///
    /// The byte-for-byte proof of the JSON itself lives in
    /// `crate::capsule`'s own tests (`a_service_config_without_a_country_
    /// map_serialises_byte_for_byte_as_before`). What is proved HERE is the
    /// consequence for the SIGNED bytes: a config carrying no country map
    /// leaves no trace of it in the preimage, and a config that DOES carry
    /// one changes the preimage — so the map is committed to, not silently
    /// dropped on the way into the signature.
    #[test]
    fn a_country_map_changes_the_signed_bytes_only_when_it_is_present() {
        let operator = SigningKey::generate(&mut OsRng);

        let without = ServiceConfigAnchor::sign_new(
            "ru-hostkey-203.0.113.10",
            ServiceRole::Monitor,
            sample_config(),
            NOW,
            &operator,
        );
        assert!(
            !without
                .signing_bytes()
                .windows(b"country_cidrs".len())
                .any(|w| w == b"country_cidrs"),
            "a config carrying no country map must leave no trace of it in the \
             signed preimage — that is what keeps every already-issued anchor \
             verifying"
        );

        let mut with_map = sample_config();
        with_map.country_cidrs.insert(
            "RU".to_string(),
            vec!["5.8.0.0/16".to_string()],
        );
        let with = ServiceConfigAnchor::sign_new(
            "ru-hostkey-203.0.113.10",
            ServiceRole::Monitor,
            with_map,
            NOW,
            &operator,
        );
        assert_ne!(
            with.signing_bytes(),
            without.signing_bytes(),
            "a config that DOES carry a country map must change the signed bytes — \
             otherwise the map would not be committed to by the operator's signature"
        );
        assert!(with.verify(&operator.verifying_key()));
    }

    #[test]
    fn a_service_config_anchor_verifies_under_the_operator_key() {
        let operator = SigningKey::generate(&mut OsRng);
        let a = ServiceConfigAnchor::sign_new(
            "ru-hostkey-203.0.113.10",
            ServiceRole::Monitor,
            sample_config(),
            NOW,
            &operator,
        );
        assert!(a.verify(&operator.verifying_key()));
    }

    #[test]
    fn a_foreign_signature_is_refused() {
        let operator = SigningKey::generate(&mut OsRng);
        let attacker = SigningKey::generate(&mut OsRng);
        let a = ServiceConfigAnchor::sign_new(
            "ru-hostkey-203.0.113.10",
            ServiceRole::Monitor,
            sample_config(),
            NOW,
            &attacker,
        );
        assert!(!a.verify(&operator.verifying_key()));
    }

    #[test]
    fn machine_id_is_bound_into_the_signature() {
        let operator = SigningKey::generate(&mut OsRng);
        let mut a = ServiceConfigAnchor::sign_new(
            "ru-hostkey-203.0.113.10",
            ServiceRole::Monitor,
            sample_config(),
            NOW,
            &operator,
        );
        a.machine_id = "ch-example-203.0.113.40".to_string();
        assert!(!a.verify(&operator.verifying_key()));
    }

    #[test]
    fn role_is_bound_into_the_signature() {
        let operator = SigningKey::generate(&mut OsRng);
        let mut a = ServiceConfigAnchor::sign_new(
            "ru-hostkey-203.0.113.10",
            ServiceRole::Monitor,
            sample_config(),
            NOW,
            &operator,
        );
        a.role = ServiceRole::Sentry;
        assert!(!a.verify(&operator.verifying_key()));
    }

    #[test]
    fn updated_at_ms_is_bound_into_the_signature() {
        let operator = SigningKey::generate(&mut OsRng);
        let mut a = ServiceConfigAnchor::sign_new(
            "ru-hostkey-203.0.113.10",
            ServiceRole::Monitor,
            sample_config(),
            NOW,
            &operator,
        );
        a.updated_at_ms += 1;
        assert!(!a.verify(&operator.verifying_key()));
    }

    /// An `Option<String>` field, tampered directly.
    #[test]
    fn tampering_a_scalar_config_field_breaks_the_signature() {
        let operator = SigningKey::generate(&mut OsRng);
        let mut a = ServiceConfigAnchor::sign_new(
            "ru-hostkey-203.0.113.10",
            ServiceRole::Monitor,
            sample_config(),
            NOW,
            &operator,
        );
        a.config.public_addr = Some("198.51.100.7:19444".to_string());
        assert!(!a.verify(&operator.verifying_key()));
    }

    /// A `Vec<CapsuleControlEndpoint>` field — the nested-enum shape.
    #[test]
    fn tampering_the_control_plane_endpoints_breaks_the_signature() {
        let operator = SigningKey::generate(&mut OsRng);
        let mut a = ServiceConfigAnchor::sign_new(
            "ru-hostkey-203.0.113.10",
            ServiceRole::Monitor,
            sample_config(),
            NOW,
            &operator,
        );
        a.config.control_plane_endpoints.pop();
        assert!(!a.verify(&operator.verifying_key()));
    }

    /// A `Vec<String>` field.
    #[test]
    fn tampering_the_node_seeds_breaks_the_signature() {
        let operator = SigningKey::generate(&mut OsRng);
        let mut a = ServiceConfigAnchor::sign_new(
            "ru-hostkey-203.0.113.10",
            ServiceRole::Monitor,
            sample_config(),
            NOW,
            &operator,
        );
        a.config.node_seeds.push("v2-seed-injected".to_string());
        assert!(!a.verify(&operator.verifying_key()));
    }

    // ── determinism ──────────────────────────────────────────────────

    /// The property the whole preimage design depends on: two
    /// independently-constructed but logically-identical configs produce
    /// byte-identical `signing_bytes()`. Also cross-checked through
    /// `operator_sig_hex`: Ed25519 signing is deterministic (RFC 8032 — no
    /// random nonce), so identical signatures under the same key are
    /// independent proof the two preimages matched.
    #[test]
    fn service_config_signing_bytes_are_stable_across_construction_order() {
        let operator = SigningKey::generate(&mut OsRng);

        // Path A: struct literal, fields written in declaration order.
        let config_a = sample_config();

        // Path B: `Default` + field assignment in a DIFFERENT order, and
        // the endpoint list built by pushing pre-built elements (each
        // itself written with its fields in a different order) instead of
        // an inline `vec![]` literal. The logical VALUE — including every
        // `Vec`'s element order — is identical to path A throughout.
        let mut config_b = CapsuleServiceConfig::default();
        config_b.node_seeds = vec!["v2-seed-a".to_string(), "v2-seed-b".to_string()];
        let mut endpoints = Vec::new();
        endpoints.push(CapsuleControlEndpoint {
            wire_version: Some(9),
            purpose: None,
            port: 443,
            camouflage: TransportCamouflage::TlsReal {
                alpn: vec!["h2".to_string(), "http/1.1".to_string()],
                sni: "cdn.example.com".to_string(),
            },
        });
        endpoints.push(CapsuleControlEndpoint {
            camouflage: TransportCamouflage::None,
            port: 80,
            purpose: None,
            wire_version: None,
        });
        config_b.control_plane_endpoints = endpoints;
        config_b.perimeter_jail_faces = vec![CapsuleJailFace {
            disposition: "jail".to_string(),
            port: 443,
        }];
        config_b.perimeter_inner_addr = Some("127.0.0.1:19444".to_string());
        config_b.public_addr = Some("203.0.113.10:19444".to_string());

        let a = ServiceConfigAnchor::sign_new(
            "ru-hostkey-203.0.113.10",
            ServiceRole::Monitor,
            config_a,
            NOW,
            &operator,
        );
        let b = ServiceConfigAnchor::sign_new(
            "ru-hostkey-203.0.113.10",
            ServiceRole::Monitor,
            config_b,
            NOW,
            &operator,
        );

        assert_eq!(
            a.signing_bytes(),
            b.signing_bytes(),
            "two logically-identical configs built in different field/struct-literal \
             orders must produce byte-identical signing preimages"
        );
        assert_eq!(
            a.operator_sig_hex, b.operator_sig_hex,
            "identical preimages under the same key must sign identically"
        );
    }

    // ── service_config_apply_verdict ────────────────────────────────

    fn unsigned(role: ServiceRole, updated_at_ms: u64) -> ServiceConfigAnchor {
        ServiceConfigAnchor {
            machine_id: "ru-hostkey-203.0.113.10".to_string(),
            role,
            config: sample_config(),
            updated_at_ms,
            operator_sig_hex: String::new(),
        }
    }

    #[test]
    fn apply_accepts_the_first_record_for_a_subject() {
        let incoming = unsigned(ServiceRole::Monitor, NOW);
        assert_eq!(
            service_config_apply_verdict(None, &incoming),
            ServiceConfigApply::Accept
        );
    }

    #[test]
    fn apply_rejects_a_non_newer_update() {
        let current = unsigned(ServiceRole::Monitor, NOW);
        let same_ts = unsigned(ServiceRole::Monitor, NOW);
        let older = unsigned(ServiceRole::Monitor, NOW - 1);
        assert_eq!(
            service_config_apply_verdict(Some(&current), &same_ts),
            ServiceConfigApply::RejectStale
        );
        assert_eq!(
            service_config_apply_verdict(Some(&current), &older),
            ServiceConfigApply::RejectStale
        );
    }

    #[test]
    fn apply_accepts_a_strictly_newer_update() {
        let current = unsigned(ServiceRole::Monitor, NOW);
        let incoming = unsigned(ServiceRole::Monitor, NOW + 1);
        assert_eq!(
            service_config_apply_verdict(Some(&current), &incoming),
            ServiceConfigApply::Accept
        );
    }

    #[test]
    fn apply_accepts_the_operator_replacing_its_own_standing_row() {
        let current = unsigned(ServiceRole::Monitor, NOW);
        let mut incoming = unsigned(ServiceRole::Monitor, NOW + 1);
        incoming.config.public_addr = Some("198.51.100.7:19444".to_string());
        assert_eq!(
            service_config_apply_verdict(Some(&current), &incoming),
            ServiceConfigApply::Accept
        );
    }
}
