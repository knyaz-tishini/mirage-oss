//! What the keeper (`mirage-warden`) and mshd say to each other while
//! carrying one machine's identity to the mesh and back.
//!
//! # The handover is a socket, not a file drop
//!
//! A file rendezvous would give the transport write access to the identity
//! store's directory. mshd does not get that. The warden is the SERVER on
//! [`crate::local_endpoint::LocalChannel::MachineIdentityHandover`], and
//! mshd — the client — can say exactly the two things below. See
//! `docs/mirage/plans/machine-identity-consolidated-2026-08-17.md` §3.
//!
//! # No field that can name a path, a unit, or a command
//!
//! Neither frame carries a path, a unit name, or a role selector. mshd is a
//! transport for opaque bytes it must not be able to interpret, let alone
//! use to ask this socket for anything beyond "what is open" and "here is
//! what came back". [`MachineHandoverRequest::DeliverSealed::charter`] does
//! not change that: it names nothing to open or run, only a public,
//! operator-signed record — see the next section for what it is for and who
//! is trusted to judge it.
//!
//! # The charter rides WITH the capsule, or a reset box can never open a Group seal
//!
//! A freshly reset box holds no [`crate::capsule::GroupCharter`] of its own —
//! tmpfs was wiped along with everything else — so [`crate::capsule::
//! unseal_capsule`] refuses ANY Group-signed envelope with `NoCharter`
//! before a plaintext byte is ever read. Before this field existed, that made
//! [`MachineHandoverRequest::DeliverSealed`] able to carry only an
//! operator-sealed capsule in practice: the mesh could return a Group-signed
//! one and its charter together, but this frame had nowhere to put the
//! charter, so mshd dropped it and the delivery was doomed to `NoCharter`
//! regardless of what the quorum had actually signed. That meant a rebooted
//! box could only ever be re-admitted while an operator (opbox) was reachable
//! to mint an operator seal — autonomous recovery in name only.
//!
//! `charter` closes that: the keeper verifies it against the baked operator
//! key ([`crate::capsule::GroupCharter::verify`]) and, only once verified,
//! folds it into the [`crate::capsule::CapsuleTrustAnchor`] the accompanying
//! `bytes` unseals against — see [`crate::machine_identity_handover`]'s
//! consumer in `mirage-warden::machine_store` for the exact order. `None` is
//! ordinary and expected for an operator-sealed first admission, which needs
//! no charter at all.
//!
//! # Length-capped by the RPC framing itself
//!
//! [`MachineHandoverRequest::DeliverSealed`] — `bytes` and `charter`
//! together, the whole request frame — is bounded by
//! [`crate::local_rpc::MAX_RPC_LEN`] — the same bound every other box-local
//! channel already carries. There is no separate, tighter limit for either
//! field: slices make the envelope bigger than a single-role capsule was,
//! and how much bigger is unmeasured (see the plan's "Named risks"), so a
//! made-up number would be decorative rather than load-bearing. The generic
//! frame bound is the one that is actually enforced.
//!
//! # Security does not rest on mshd being trustworthy
//!
//! `SO_PEERCRED` admits exactly mshd's service account (plus root — see
//! [`crate::local_endpoint`]'s module doc for why root is never excluded).
//! `DeliverSealed` is accepted only while the keeper has an open announce for
//! THIS boot; outside that window the answer is
//! [`MachineHandoverResponse::Refused`]. The envelope itself is verified
//! against the baked operator key by the keeper, exactly as any other
//! delivery path is — this channel does not weaken that check, it is simply
//! the transport that carries the bytes to it. The worst mshd can do is not
//! deliver: a liveness failure, immediately visible, with no power over
//! content.

use std::io;

use serde::{Deserialize, Serialize};

use crate::capsule::GroupCharter;
use crate::identity_boot::BootAnnounce;
use crate::local_endpoint::LocalChannel;

/// A request on [`crate::local_endpoint::LocalChannel::MachineIdentityHandover`].
/// mshd is the only caller.
///
/// No `PartialEq` derive: [`GroupCharter`] is a signed record meant to be
/// verified, not compared by value, so a test that needs to compare a round
/// trip does it by re-encoding — the same reason
/// [`MachineHandoverResponse`] carries no `PartialEq` either.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MachineHandoverRequest {
    /// Is the keeper currently asking to be identified, and if so, with
    /// what announce?
    FetchAnnounce,
    /// Here is a sealed capsule for the announce you are currently holding
    /// open. Opaque bytes — mshd relays whatever it received off the wire,
    /// unparsed; the keeper is the one party that opens them.
    DeliverSealed {
        #[serde(with = "crate::b64_serde::b64_vec")]
        bytes: Vec<u8>,
        /// The charter the mesh returned alongside `bytes`, when it returned
        /// one. `None` for an operator-sealed first admission, which
        /// legitimately carries none — see this module's own "The charter
        /// rides WITH the capsule" doc.
        ///
        /// Unlike `bytes` this is not sealed to anyone's key — a
        /// [`crate::capsule::GroupCharter`] is a public, operator-signed
        /// statement of who the quorum is — but mshd still carries it
        /// unread: the keeper is the one party that VERIFIES it, against
        /// the baked operator key, before it is trusted for anything. See
        /// [`crate::capsule::GroupCharter::verify`]'s own doc: an
        /// unverified charter is an attacker-chosen verification key, not
        /// a value this frame's shape makes safe on its own.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        charter: Option<GroupCharter>,
    },
}

/// The keeper's answer.
///
/// No `PartialEq` derive: [`BootAnnounce`] does not carry one (it is
/// compared by its signed content, never by struct equality), so a test
/// that needs to compare a [`Self::Announce`] round trip does it by
/// re-encoding, the same way [`crate::machine_identity_query`] compares
/// [`crate::capsule::RoleSlice`] payloads.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MachineHandoverResponse {
    /// This boot's announce, for `FetchAnnounce`.
    Announce(Box<BootAnnounce>),
    /// The keeper is not currently asking — no open announce for mshd to
    /// carry. Ordinary outside a boot/reset window.
    NotAsking,
    /// A `DeliverSealed` landed and the keeper accepted it into the store.
    Accepted,
    /// A `DeliverSealed` landed outside the one window it is valid in — no
    /// open announce for this boot, a boot nonce that no longer matches, or
    /// a delivery already consumed this boot's one-shot window. See the
    /// module doc's "one successful delivery per boot nonce" rule.
    Refused,
}

// ── Client ───────────────────────────────────────────────────────────────
//
// The two functions below are the ONE client for this socket — any root
// process on the box may call them (mshd is the one caller in the live
// fleet today, but nothing here is mshd-specific; `SO_PEERCRED` is what
// actually restricts the socket, admitting root plus
// [`crate::local_endpoint::MSHD_ACCOUNT`] — see this module's own doc,
// "Security does not rest on mshd being trustworthy"). Both are thin
// wrappers over [`crate::local_rpc::call`], the same fail-closed,
// bounded-by-[`crate::local_rpc::DEFAULT_CALL_TIMEOUT`] primitive every
// other typed box-local channel in this crate already answers through —
// `call`'s own doc names exactly this socket's shape as the reason it
// exists: "a server that accepts and never answers must still resolve to
// a verdict... waited forever is not an answer it can act on."
//
// Hardcoded to [`crate::local_endpoint::LocalChannel::MachineIdentityHandover`]
// on purpose, the same way [`crate::identity_boot::take_machine_slice`] is
// hardcoded to [`LocalChannel::MachineIdentity`] — this is THE handover
// socket, not a channel a caller picks.

/// Ask the keeper what it is currently announcing.
///
/// `Err` is a TRANSPORT failure — the socket is not there, the keeper did
/// not answer within [`crate::local_rpc::DEFAULT_CALL_TIMEOUT`], or it
/// answered something this build cannot decode. `Ok` carries the keeper's
/// own typed verdict, including the ordinary "nothing to carry" case
/// ([`MachineHandoverResponse::NotAsking`]).
pub async fn fetch_announce() -> io::Result<MachineHandoverResponse> {
    crate::local_rpc::call(LocalChannel::MachineIdentityHandover, &MachineHandoverRequest::FetchAnnounce)
        .await
}

/// Deliver a sealed capsule — and, when the mesh returned one alongside it,
/// the charter needed to open a Group-signed envelope on a box that holds
/// none of its own — to the keeper.
///
/// See [`MachineHandoverRequest::DeliverSealed::charter`]'s own doc for what
/// `charter` is for; `None` is the ordinary, expected shape for an
/// operator-sealed admission. `bytes` travels opaque — this function does
/// not parse it, and neither may its caller; the keeper is the one party
/// that opens it.
///
/// Same bound and the same `Err`/`Ok` split as [`fetch_announce`]. A
/// [`MachineHandoverResponse::Refused`] inside `Ok` is not a transport
/// failure — the delivery reached the keeper and it declined to admit it
/// (no open window, a boot nonce that no longer matches, or a window
/// already consumed this boot) — see that variant's own doc.
pub async fn deliver_sealed(
    bytes: Vec<u8>,
    charter: Option<GroupCharter>,
) -> io::Result<MachineHandoverResponse> {
    crate::local_rpc::call(
        LocalChannel::MachineIdentityHandover,
        &MachineHandoverRequest::DeliverSealed { bytes, charter },
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requests_are_legible_in_a_log() {
        assert_eq!(
            serde_json::to_string(&MachineHandoverRequest::FetchAnnounce).unwrap(),
            "\"fetch_announce\""
        );
    }

    /// A `Vec<u8>` field serialises as base64, never a JSON number array —
    /// see `crate::b64_serde`'s own doc for the size cost of getting this
    /// wrong.
    #[test]
    fn delivered_bytes_are_base64_not_a_number_array() {
        let req = MachineHandoverRequest::DeliverSealed { bytes: vec![1, 2, 3, 255, 0], charter: None };
        let raw = serde_json::to_string(&req).unwrap();
        assert!(raw.contains("AQID/wA="), "{raw}");
        assert!(!raw.contains('['), "must not be a JSON array: {raw}");
        let back: MachineHandoverRequest = serde_json::from_str(&raw).unwrap();
        // See this type's own doc: no `PartialEq`, so compare by re-encoding.
        assert_eq!(serde_json::to_string(&back).unwrap(), raw);
    }

    /// `charter: None` is the ordinary shape — an operator-sealed first
    /// admission needs none — and must not put a `"charter":null` key on
    /// the wire: `skip_serializing_if` is what keeps this frame identical
    /// to the one every existing caller already sends.
    #[test]
    fn an_absent_charter_writes_no_json_field() {
        let req = MachineHandoverRequest::DeliverSealed { bytes: vec![9], charter: None };
        let raw = serde_json::to_string(&req).unwrap();
        assert!(!raw.contains("charter"), "{raw}");
    }

    /// A delivered charter round-trips through the same frame `bytes`
    /// already does — proving the field this type carries actually moves a
    /// [`GroupCharter`] end to end, not just a `None`.
    #[test]
    fn a_delivered_charter_round_trips() {
        let op = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let charter = GroupCharter::sign_new(
            crate::ids::MeshId::new("v3-staging").expect("mesh id"),
            1,
            "aa".repeat(32),
            3,
            vec![uuid::Uuid::from_u128(1), uuid::Uuid::from_u128(2)],
            1_700_000_000_000,
            &op,
        );
        let req = MachineHandoverRequest::DeliverSealed { bytes: vec![1, 2, 3], charter: Some(charter) };
        let raw = serde_json::to_vec(&req).unwrap();
        let back: MachineHandoverRequest = serde_json::from_slice(&raw).unwrap();
        assert_eq!(serde_json::to_vec(&back).unwrap(), raw);
        let MachineHandoverRequest::DeliverSealed { charter: Some(got), .. } = back else {
            panic!("charter must survive the round trip");
        };
        assert_eq!(got.epoch, 1);
    }

    #[test]
    fn fetch_announce_round_trips() {
        let req = MachineHandoverRequest::FetchAnnounce;
        let raw = serde_json::to_vec(&req).unwrap();
        let back: MachineHandoverRequest = serde_json::from_slice(&raw).unwrap();
        // See this type's own doc: no `PartialEq`, so compare by re-encoding.
        assert_eq!(serde_json::to_vec(&back).unwrap(), raw);
    }

    #[test]
    fn not_asking_and_refused_are_distinct_on_the_wire() {
        // A caller that folded these into one variant could not tell "there
        // is nothing to carry right now" from "your delivery was rejected" —
        // two different reasons for mshd's own retry logic to choose from.
        let a = serde_json::to_string(&MachineHandoverResponse::NotAsking).unwrap();
        let b = serde_json::to_string(&MachineHandoverResponse::Refused).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn every_response_variant_round_trips() {
        let cases = vec![
            MachineHandoverResponse::NotAsking,
            MachineHandoverResponse::Accepted,
            MachineHandoverResponse::Refused,
            MachineHandoverResponse::Announce(Box::new(sample_announce())),
        ];
        for c in cases {
            let raw = serde_json::to_vec(&c).expect("encodes");
            let back: MachineHandoverResponse =
                serde_json::from_slice(&raw).expect("decodes");
            // See this type's own doc: no `PartialEq`, so compare by
            // re-encoding rather than by value.
            assert_eq!(serde_json::to_vec(&back).expect("re-encodes"), raw);
        }
    }

    fn sample_announce() -> BootAnnounce {
        BootAnnounce {
            machine_id: "ru-hostkey-203.0.113.10".to_string(),
            build_id: "5a2aec1-universal".to_string(),
            eph_pubkey_hex: "aa".repeat(32),
            boot_nonce: "boot-nonce-abc".to_string(),
            started_at_ms: 1_700_000_000_000,
            platform: None,
            renewal: None,
            attestation_sig_hex: "bb".repeat(64),
        }
    }

    // ── The RPC frame [`fetch_announce`] and [`deliver_sealed`] actually put
    // on the wire — one level below the JSON-body tests above, which never
    // exercise `crate::local_rpc`'s length-prefixed framing at all. ──

    #[test]
    fn fetch_announce_request_survives_the_rpc_frame() {
        let framed = crate::local_rpc::encode(&MachineHandoverRequest::FetchAnnounce).expect("encodes");
        let header: [u8; crate::local_rpc::RPC_HEADER_LEN] =
            framed[..crate::local_rpc::RPC_HEADER_LEN].try_into().expect("header length");
        let len = crate::local_rpc::parse_header(&header).expect("header parses");
        let body = &framed[crate::local_rpc::RPC_HEADER_LEN..];
        assert_eq!(body.len(), len as usize, "the length must bound the body exactly");
        let back: MachineHandoverRequest = serde_json::from_slice(body).expect("decodes");
        assert_eq!(
            serde_json::to_vec(&back).expect("re-encodes"),
            serde_json::to_vec(&MachineHandoverRequest::FetchAnnounce).expect("encodes"),
        );
    }

    /// The larger of the two requests this channel ever carries — bytes plus
    /// a charter — through the same frame.
    #[test]
    fn deliver_sealed_request_survives_the_rpc_frame() {
        let op = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let charter = GroupCharter::sign_new(
            crate::ids::MeshId::new("v3-staging").expect("mesh id"),
            1,
            "aa".repeat(32),
            3,
            vec![uuid::Uuid::from_u128(1), uuid::Uuid::from_u128(2)],
            1_700_000_000_000,
            &op,
        );
        let req =
            MachineHandoverRequest::DeliverSealed { bytes: vec![1, 2, 3, 4, 5], charter: Some(charter) };

        let framed = crate::local_rpc::encode(&req).expect("encodes");
        let header: [u8; crate::local_rpc::RPC_HEADER_LEN] =
            framed[..crate::local_rpc::RPC_HEADER_LEN].try_into().expect("header length");
        let len = crate::local_rpc::parse_header(&header).expect("header parses");
        let body = &framed[crate::local_rpc::RPC_HEADER_LEN..];
        assert_eq!(body.len(), len as usize);

        let back: MachineHandoverRequest = serde_json::from_slice(body).expect("decodes");
        let MachineHandoverRequest::DeliverSealed { bytes, charter: Some(back_charter) } = back else {
            panic!("bytes and charter must both survive the frame");
        };
        assert_eq!(bytes, vec![1, 2, 3, 4, 5]);
        assert_eq!(back_charter.epoch, 1);
    }

    /// The client/server round trip over a REAL socket — the exact shape
    /// [`fetch_announce`] and [`deliver_sealed`] drive against
    /// [`crate::local_endpoint::LocalChannel::MachineIdentityHandover`] in
    /// production. That channel's own path is a fixed `/run/mirage/...`
    /// location no test may bind without root, so — the same substitution
    /// `crate::local_rpc`'s own socket tests make — this binds a scratch
    /// endpoint instead and drives it through `local_rpc`'s public
    /// `write_frame`/`read_frame`, exactly what `call` (and so both client
    /// functions above) do internally. What is NOT substituted is the wire
    /// shape: these are the real [`MachineHandoverRequest`] /
    /// [`MachineHandoverResponse`] types, not a toy stand-in.
    #[cfg(unix)]
    mod over_a_socket {
        use super::*;
        use crate::local_endpoint::{plan_from_resolution, AccountResolution, LocalEndpoint};
        use crate::local_rpc::{read_frame, serve_on, write_frame};
        use std::path::PathBuf;

        fn scratch(name: &str) -> PathBuf {
            let dir = std::env::temp_dir()
                .join(format!("mirage-handover-{name}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).expect("scratch dir");
            dir
        }

        /// A stand-in for the keeper's real handler
        /// (`mirage-warden::machine_handover::run`, a different crate this
        /// one cannot depend on) — just enough behaviour to prove the
        /// client-visible frames round-trip: `FetchAnnounce` answers a fixed
        /// announce, `DeliverSealed` answers `Accepted`.
        async fn stand_up(name: &str) -> LocalEndpoint {
            let dir = scratch(name);
            let ep = LocalEndpoint::Unix(dir.join("handover.sock"));
            // SAFETY: getuid(2) reads a process property and cannot fail.
            let me = unsafe { libc::getuid() };
            let mut plan = plan_from_resolution(AccountResolution::NotRequested);
            plan.admitted_uids = vec![me];
            let listener = ep.bind_with(Some(&dir), &plan).await.expect("bind");
            tokio::spawn(serve_on(
                listener,
                "test-handover",
                |req: MachineHandoverRequest| async move {
                    match req {
                        MachineHandoverRequest::FetchAnnounce => {
                            MachineHandoverResponse::Announce(Box::new(sample_announce()))
                        }
                        MachineHandoverRequest::DeliverSealed { .. } => MachineHandoverResponse::Accepted,
                    }
                },
            ));
            ep
        }

        #[tokio::test]
        async fn fetch_announce_round_trips_over_a_real_socket() {
            let ep = stand_up("fetch").await;
            let mut client = ep.connect().await.expect("connect");
            write_frame(&mut client, &MachineHandoverRequest::FetchAnnounce)
                .await
                .expect("write");
            let got: MachineHandoverResponse =
                read_frame(&mut client).await.expect("read").expect("a frame");
            match got {
                MachineHandoverResponse::Announce(a) => {
                    assert_eq!(a.machine_id, sample_announce().machine_id);
                }
                other => panic!("expected an announce, got {other:?}"),
            }
        }

        #[tokio::test]
        async fn deliver_sealed_with_a_charter_round_trips_over_a_real_socket() {
            let ep = stand_up("deliver").await;
            let mut client = ep.connect().await.expect("connect");
            let op = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
            let charter = GroupCharter::sign_new(
                crate::ids::MeshId::new("v3-staging").expect("mesh id"),
                1,
                "aa".repeat(32),
                3,
                vec![uuid::Uuid::from_u128(1)],
                1_700_000_000_000,
                &op,
            );
            let req = MachineHandoverRequest::DeliverSealed { bytes: vec![9, 9, 9], charter: Some(charter) };
            write_frame(&mut client, &req).await.expect("write");
            let got: MachineHandoverResponse =
                read_frame(&mut client).await.expect("read").expect("a frame");
            assert!(matches!(got, MachineHandoverResponse::Accepted), "{got:?}");
        }
    }
}
