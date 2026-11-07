//! Shared wire shape for one subscriber-key entry — pushed by a monitor
//! (constructed from an `EntranceGrant`-authorised back-office write, see
//! [`crate::entrance_grant`]) onto an edge's `MonitorToNode::
//! PushSubscriberKeys` control frame, and decoded by the edge's own node,
//! which persists it to its box-local `subscriber-keys.json`.
//!
//! See `docs/mirage/plans/2026-09-23-backoffice-automated-issuance.md` §2
//! ("A found bug this design must fix to work at all" / the
//! `MonitorToNode::PushSubscriberKeys` frame) for the design this type
//! serves. Living here, in `mirage-core`, rather than in either the monitor
//! or the node crate, is what lets the two never drift on field names the
//! way `opbox_client.rs`'s history shows a lone `pubkey_hex` vs.
//! `static_pubkey_hex` mismatch already cost one silent data loss.
//!
//! Every field beyond `public_key_hex` is `#[serde(default)]` — additive,
//! so a monitor or node build that predates a given field keeps
//! deserialising a set that omits it.

use serde::{Deserialize, Serialize};

use crate::config::SubscriberEntranceConfig;

/// One subscriber's entrance-gate entry, as it travels the wire between a
/// monitor and an edge node (and, one layer further out, between the
/// back-office and the monitor over `/relay/entrance/subscriber-key`).
///
/// Mirrors the box-local file shape `mirage-node::core::subscriber_keys`
/// already reads (`public_key_hex` + optional `personal_mesh_id`), plus the
/// two fields the shared-entrance/egress-split tiers add on top of it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubscriberKeyWireEntry {
    /// The subscriber's static X25519 public key, hex (64 lowercase chars)
    /// — exactly the bytes carried in
    /// `mirage_protocol::ClientAuthContext::static_pub`.
    pub public_key_hex: String,
    /// The personal mesh id this subscriber's V9 handshake folds into its
    /// confirm label instead of the fleet's real `mesh_id`, when the panel
    /// has minted one. `None` means "no personal mesh id yet" — the same
    /// meaning an omitted/bare-string file entry already carries.
    #[serde(default)]
    pub personal_mesh_id: Option<String>,
    /// Per-subscriber rate/burst caps — the shared-entrance tier's design
    /// (`edge-role-and-product-tiers-2026-09-17.md` §5). `None` falls back
    /// to the box-wide default, exactly as the file-based entry does today.
    #[serde(default)]
    pub caps: Option<SubscriberEntranceConfig>,
    /// The terminator/egress-split tier's per-subscriber country selection
    /// (`edge-role-and-product-tiers-2026-09-17.md` §6). Country CHANGE is
    /// not a new verb — it is the same full-set PUT with this field edited.
    #[serde(default)]
    pub egress_country: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_pubkey_hex() -> String {
        "a1".repeat(32)
    }

    /// The minimal shape — only `public_key_hex` present — deserialises
    /// with every additive field defaulted to `None`, matching a caller
    /// that predates `personal_mesh_id`/`caps`/`egress_country`.
    #[test]
    fn minimal_json_defaults_every_additive_field() {
        let json = format!(r#"{{"public_key_hex":"{}"}}"#, sample_pubkey_hex());
        let entry: SubscriberKeyWireEntry = serde_json::from_str(&json).expect("must parse");
        assert_eq!(entry.public_key_hex, sample_pubkey_hex());
        assert!(entry.personal_mesh_id.is_none());
        assert!(entry.caps.is_none());
        assert!(entry.egress_country.is_none());
    }

    /// A fully-populated entry round-trips through JSON with every field
    /// preserved.
    #[test]
    fn full_entry_round_trips() {
        let entry = SubscriberKeyWireEntry {
            public_key_hex: sample_pubkey_hex(),
            personal_mesh_id: Some("sub-7f3a".to_string()),
            caps: Some(SubscriberEntranceConfig {
                legacy_socks_addr: None,
                aggregate_rate_bytes_per_sec: Some(1_000_000),
                aggregate_burst_bytes: Some(2_000_000),
                per_connection_rate_bytes_per_sec: None,
                monthly_volume_bytes: Some(500_000_000_000),
                degraded_floor_bytes_per_sec: None,
            }),
            egress_country: Some("nl".to_string()),
        };
        let json = serde_json::to_string(&entry).expect("serialize");
        let back: SubscriberKeyWireEntry = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back.public_key_hex, entry.public_key_hex);
        assert_eq!(back.personal_mesh_id, entry.personal_mesh_id);
        assert_eq!(back.egress_country, entry.egress_country);
        let caps = back.caps.expect("caps must survive the round trip");
        assert_eq!(caps.legacy_socks_addr, None, "socks_addr is retired and never written back");
        assert_eq!(
            caps.aggregate_rate_bytes_per_sec,
            entry.caps.as_ref().unwrap().aggregate_rate_bytes_per_sec
        );
        assert_eq!(
            caps.monthly_volume_bytes,
            entry.caps.as_ref().unwrap().monthly_volume_bytes
        );
    }

    /// A whole array of entries — the actual wire shape
    /// `MonitorToNode::PushSubscriberKeys::entries` carries — round-trips
    /// too, including an empty array (the "revoke everyone" full-set
    /// replace).
    #[test]
    fn entry_vec_round_trips_including_empty() {
        let entries = vec![
            SubscriberKeyWireEntry {
                public_key_hex: "aa".repeat(32),
                personal_mesh_id: None,
                caps: None,
                egress_country: None,
            },
            SubscriberKeyWireEntry {
                public_key_hex: "bb".repeat(32),
                personal_mesh_id: Some("sub-1".to_string()),
                caps: None,
                egress_country: Some("us".to_string()),
            },
        ];
        let json = serde_json::to_string(&entries).expect("serialize vec");
        let back: Vec<SubscriberKeyWireEntry> =
            serde_json::from_str(&json).expect("deserialize vec");
        assert_eq!(back.len(), 2);
        assert_eq!(back[0].public_key_hex, "aa".repeat(32));
        assert_eq!(back[1].egress_country.as_deref(), Some("us"));

        let empty: Vec<SubscriberKeyWireEntry> = Vec::new();
        let empty_json = serde_json::to_string(&empty).expect("serialize empty vec");
        assert_eq!(empty_json, "[]");
        let back_empty: Vec<SubscriberKeyWireEntry> =
            serde_json::from_str(&empty_json).expect("deserialize empty vec");
        assert!(back_empty.is_empty());
    }
}
