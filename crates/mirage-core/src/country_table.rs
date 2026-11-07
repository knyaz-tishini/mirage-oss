//! Compact, portable representation of the operator's country table.
//!
//! # Why this module exists
//!
//! The country table — ISO-3166-1 alpha-2 country code -> the CIDR ranges
//! that belong to it — is a ~826 KB JSON object in the operator's stored
//! `geo_split.country_cidrs` block. It rides inside
//! [`crate::capsule::CapsuleServiceConfig::country_cidrs`], and at that
//! size it breaks three boundaries that every capsule-carrying message
//! has to cross:
//!
//! 1. **The quorum signature share.** `POST /relay/quorum/sign/share`
//!    carries the capsule to the share signers; its HTTP body measured
//!    ~3.3 MB against axum's 2 MiB default body limit, so the share was
//!    refused with a 413.
//! 2. **The box-local RPC frame.** [`crate::local_rpc::MAX_RPC_LEN`] is
//!    1 MiB; the handover-deliver frame that carries the capsule measured
//!    2 271 299 B and did not fit.
//! 3. **The gossiped anchor.** [`crate::service_config_anchor`]'s signed
//!    preimage embeds the whole config JSON
//!    (`ServiceConfigAnchor::signing_bytes`), so an uncompressed table is
//!    also re-signed and re-gossiped in full every time a single CIDR
//!    changes.
//!
//! gzip + base64 brings the same table down to ~207 KB, which fits all
//! three with room to spare.
//!
//! # What did NOT change
//!
//! The IN-MEMORY type is still `BTreeMap<String, Vec<String>>` — the map
//! a monitor classifies a client address against is exactly the map the
//! operator wrote, byte for byte. Only the SERIALISED representation
//! changed: the field is now a base64(gzip(canonical JSON)) string
//! instead of a nested JSON object. The in-memory type is deliberately
//! NOT abstracted behind a newtype: every consumer
//! (`mirage2monitor`'s `client_geo::detect_country`,
//! `mirage2monitor`'s `capsule_boot`, `operator-box`'s merge step)
//! already speaks `BTreeMap<String, Vec<String>>`, and none of them
//! needs to learn a new type for a wire-format change.
//!
//! # Byte stability is load-bearing
//!
//! The compressed bytes are INSIDE a signed preimage
//! (`ServiceConfigAnchor::signing_bytes` embeds the config JSON), so two
//! workspaces that build `mirage-core` must produce the SAME bytes for
//! the same table: operator-box signs, the monitors verify. A compressor
//! upgrade that changed a single output byte would silently invalidate
//! every anchor in the park. `flate2` is therefore pinned to an exact
//! version (and `miniz_oxide` with it) in `mirage-core`'s `Cargo.toml`,
//! and [`encode`]'s output is frozen by a golden-vector test in this
//! module (`the_compressed_form_is_byte_stable`).
//!
//! # Canonical JSON
//!
//! The payload that gets compressed is `serde_json::to_vec(table)`. A
//! `BTreeMap` iterates in sorted key order, so the JSON bytes are
//! determined by the VALUE, not by insertion order — which is what makes
//! the compressed output reproducible.

use std::collections::BTreeMap;
use std::fmt;
use std::io::{Read, Write};

use base64::Engine as _;
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use flate2::Compression;
use serde::de::value::MapAccessDeserializer;
use serde::de::{MapAccess, Visitor};
use serde::{Deserialize, Deserializer, Serializer};
use thiserror::Error;

/// Country (ISO-3166-1 alpha-2) -> list of CIDR ranges.
///
/// The in-memory shape of the operator's country table. Unchanged by the
/// compressed wire form — see the module doc.
pub type CountryTable = BTreeMap<String, Vec<String>>;

/// Everything that can go wrong while turning a country table into bytes
/// or back.
///
/// The three classes are kept apart on purpose: "the operator sent
/// garbage", "the compressed stream is damaged in transit" and "the
/// payload is not a country map at all" are three different faults for
/// three different operators, and a monitor that has to decide whether
/// to drop the table or to raise an alarm needs to tell them apart.
#[derive(Debug, Error)]
pub enum CountryTableError {
    /// The field was not valid base64 — it never was a compressed table.
    #[error("country table is not valid base64: {0}")]
    Base64(#[from] base64::DecodeError),
    /// The gzip stream could not be produced (compress side) or read back
    /// (decompress side).
    #[error("country table gzip stream is unreadable: {0}")]
    Gzip(#[from] std::io::Error),
    /// The decompressed payload is not a country -> CIDR map.
    #[error("country table payload is not a country -> CIDR map: {0}")]
    Json(#[from] serde_json::Error),
}

/// Encode a country table into its portable compressed form:
/// canonical JSON -> gzip (best compression) -> base64 (STANDARD, with
/// padding).
///
/// The output is byte-stable for a given table — see the module doc for
/// why that is a fleet-wide requirement rather than a nicety.
#[must_use]
pub fn encode(table: &CountryTable) -> String {
    // A `BTreeMap<String, Vec<String>>` always serialises; there is no
    // float, no map key that cannot be a string and no custom serialiser
    // in the way.
    let json = serde_json::to_vec(table)
        .expect("a BTreeMap<String, Vec<String>> always serialises to JSON");
    let mut encoder = GzEncoder::new(Vec::new(), Compression::best());
    encoder
        .write_all(&json)
        .expect("writing gzip output into a Vec cannot fail");
    let compressed = encoder
        .finish()
        .expect("finishing a gzip encoder over a Vec cannot fail");
    base64::engine::general_purpose::STANDARD.encode(compressed)
}

/// Decode a country table from its portable compressed form:
/// base64 -> gunzip -> canonical JSON -> table.
///
/// The gzip layer is read out separately from the JSON layer on purpose:
/// `serde_json::from_reader` over a gzip reader would fold a damaged
/// stream into the JSON error and leave the [`CountryTableError::Gzip`]
/// variant unreachable, and "the bytes were damaged" is a different fact
/// from "the bytes are not a country map".
pub fn decode(encoded: &str) -> Result<CountryTable, CountryTableError> {
    let compressed = base64::engine::general_purpose::STANDARD.decode(encoded)?;
    let mut plain = Vec::new();
    GzDecoder::new(compressed.as_slice()).read_to_end(&mut plain)?;
    Ok(serde_json::from_slice(&plain)?)
}

/// serde helper: serialise a country table as its compressed string.
///
/// Used by [`crate::capsule::CapsuleServiceConfig::country_cidrs`].
pub fn serialize_field<S: Serializer>(table: &CountryTable, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&encode(table))
}

/// serde helper: read a country table from EITHER the compressed string
/// form or the legacy plain JSON map.
///
/// The legacy map form is still accepted because capsules and anchors
/// carrying it are already issued and still in the park — a monitor that
/// refused them would drop the country table of every box sealed before
/// the compressed form existed. The two forms are told apart by their
/// JSON type: a string is the compressed form, a map is the legacy form.
///
/// A `null` (or an absent field) is an empty table — the ABSENCE of
/// country data, which is a meaningful state: the monitor then knows no
/// client's country and the exit rule simply does not apply. Any OTHER
/// shape is an error, never a silently empty table: a country table that
/// was dropped by accident must not look like one that was never set.
pub fn deserialize_field<'de, D: Deserializer<'de>>(d: D) -> Result<CountryTable, D::Error> {
    d.deserialize_any(CountryTableVisitor)
}

/// The visitor behind [`deserialize_field`] — see that function for the
/// three accepted shapes and the one refused default.
struct CountryTableVisitor;

impl<'de> Visitor<'de> for CountryTableVisitor {
    type Value = CountryTable;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(
            "a compressed country table string, a legacy country -> CIDR map, or null",
        )
    }

    fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<CountryTable, E> {
        decode(v).map_err(serde::de::Error::custom)
    }

    fn visit_string<E: serde::de::Error>(self, v: String) -> Result<CountryTable, E> {
        decode(&v).map_err(serde::de::Error::custom)
    }

    fn visit_map<A: MapAccess<'de>>(self, map: A) -> Result<CountryTable, A::Error> {
        // The legacy plain form: the map as it was written before the
        // compressed form existed. Read straight into the same in-memory
        // type, so both forms converge on ONE map downstream.
        BTreeMap::<String, Vec<String>>::deserialize(MapAccessDeserializer::new(map))
    }

    fn visit_unit<E: serde::de::Error>(self) -> Result<CountryTable, E> {
        // `null` = the operator supplied no country data. Same as an
        // absent field.
        Ok(BTreeMap::new())
    }

    fn visit_none<E: serde::de::Error>(self) -> Result<CountryTable, E> {
        Ok(BTreeMap::new())
    }

    fn visit_some<D: Deserializer<'de>>(self, d: D) -> Result<CountryTable, D::Error> {
        d.deserialize_any(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capsule::CapsuleServiceConfig;

    /// A small, fixed table — the input of the golden-vector test.
    fn golden_table() -> CountryTable {
        BTreeMap::from([
            (
                "NL".to_string(),
                vec!["1.1.0.0/16".to_string(), "1.2.0.0/16".to_string()],
            ),
            ("RU".to_string(), vec!["5.8.0.0/16".to_string()]),
        ])
    }

    /// A table of a few hundred CIDRs, generated the way a real
    /// IP-to-country table looks: a country owns a /8, four /16s inside
    /// it, and twenty CIDRs inside those. That shape is WHY the real
    /// table compresses (the operator's ~826 KB table becomes ~207 KB),
    /// so a generator that produced uniformly random addresses would
    /// measure the compressor on input that no real table looks like.
    fn big_table() -> CountryTable {
        let mut table = CountryTable::new();
        for country in 0..25u32 {
            let first = (country * 9 + 2) % 223 + 1;
            let mut cidrs = Vec::with_capacity(20);
            for i in 0..20u32 {
                // Four distinct /16s per country, twenty CIDRs inside
                // them — the shape of a real allocation block.
                let second = (country * 3 + i / 5) % 256;
                let third = (i * 11) % 64;
                cidrs.push(format!("{first}.{second}.{third}.0/24"));
            }
            table.insert(format!("C{country:02}"), cidrs);
        }
        table
    }

    /// The compressed form must survive the round trip unchanged — this is
    /// the property the whole capsule path depends on.
    #[test]
    fn a_country_table_round_trips_through_the_compressed_form() {
        let table = golden_table();
        let encoded = encode(&table);
        assert_eq!(
            decode(&encoded).expect("decode"),
            table,
            "the compressed form must decode back to exactly the table it was made from"
        );
        assert_eq!(
            encode(&decode(&encoded).expect("decode")),
            encoded,
            "encoding must be idempotent — the same table always yields the same bytes"
        );
    }

    /// A capsule or anchor carrying the LEGACY plain map must still be
    /// readable: those artefacts are already issued and still in the
    /// park, and a monitor that refused them would drop the country
    /// table of every box sealed before the compressed form existed.
    #[test]
    fn a_legacy_plain_country_table_is_still_accepted() {
        let json = r#"{"public_addr":"203.0.113.10:19444","country_cidrs":{"RU":["5.8.0.0/16","5.9.0.0/16"],"NL":["1.1.0.0/16"]}}"#;
        let cfg: CapsuleServiceConfig = serde_json::from_str(json).expect("legacy config");
        assert_eq!(
            cfg.country_cidrs.get("RU").map(Vec::as_slice),
            Some(["5.8.0.0/16".to_string(), "5.9.0.0/16".to_string()].as_slice()),
            "the legacy plain map must land on the same in-memory table as the compressed form"
        );
        assert_eq!(cfg.country_cidrs.get("NL").map(Vec::as_slice), Some(["1.1.0.0/16".to_string()].as_slice()));
        assert_eq!(cfg.country_cidrs.len(), 2);
    }

    /// The point of the exercise: the compressed form must be SMALLER
    /// than the plain form by a wide margin, or none of the three
    /// boundaries it was built for would actually be crossed.
    #[test]
    fn the_compressed_form_is_much_smaller_than_the_plain_form() {
        let table = big_table();
        let plain = serde_json::to_vec(&table).expect("serialise plain");
        let compressed = encode(&table);
        assert!(
            compressed.len() * 3 < plain.len(),
            "the compressed form ({}) must be under a third of the plain form ({})",
            compressed.len(),
            plain.len()
        );
        assert_eq!(
            decode(&compressed).expect("decode"),
            table,
            "the smaller form must still be the same table"
        );
    }

    /// GOLDEN VECTOR. The compressed bytes of a fixed table, written out
    /// literally.
    ///
    /// This is the test that stops a compressor change from passing
    /// silently: the compressed table is inside a SIGNED preimage
    /// (`ServiceConfigAnchor::signing_bytes` embeds the config JSON), so
    /// operator-box signs and the monitors verify with it. If `flate2` or
    /// `miniz_oxide` is bumped, or the compression level changed, the
    /// bytes below change and EVERY anchor in the park stops verifying
    /// — which is why `flate2` is pinned to an exact version in
    /// `mirage-core`'s `Cargo.toml`.
    ///
    /// The expected value is a constant, NOT a recomputed comparison: a
    /// comparison against "whatever the code produces today" would pass
    /// even after the bytes changed, which is the one thing this test
    /// exists to catch.
    #[test]
    fn the_compressed_form_is_byte_stable() {
        assert_eq!(
            encode(&golden_table()),
            "H4sIAAAAAAAC/z3KQQoAEBRF0b28sZ7/FckaZKCMZCWydwwYntudKBmpQ6kUitUAc+AehkFtd/CMv60N8aycITYAAAA=",
            "the compressed form of a fixed table must be byte-for-byte the same \
             in every workspace that builds mirage-core — it is inside a signed \
             preimage, so a compressor change invalidates every anchor in the park"
        );
    }

    /// A damaged table must be REFUSED, not silently turned into "no
    /// country data". The distinction matters: a dropped table leaves
    /// every client country unknown, and an unknown country never refuses
    /// anything — so a table that failed to load quietly disables the
    /// exit rule instead of failing loudly.
    #[test]
    fn a_corrupt_country_table_is_refused() {
        // Not base64 at all.
        let not_base64 = decode("not base64 !!").expect_err("must be refused");
        assert!(
            matches!(not_base64, CountryTableError::Base64(_)),
            "a non-base64 payload must fail as a base64 error, got {not_base64:?}"
        );

        // Valid base64, not a gzip stream.
        let not_gzip = decode("bm90IGd6aXA=").expect_err("must be refused");
        assert!(
            matches!(not_gzip, CountryTableError::Gzip(_)),
            "a payload that is not a gzip stream must fail as a gzip error, got {not_gzip:?}"
        );

        // A valid gzip stream that is not JSON.
        let mut encoder = GzEncoder::new(Vec::new(), Compression::best());
        encoder.write_all(b"not json").expect("compress");
        let not_json = encode_bytes(&encoder.finish().expect("finish"));
        let not_json = decode(&not_json).expect_err("must be refused");
        assert!(
            matches!(not_json, CountryTableError::Json(_)),
            "a payload that is not JSON must fail as a JSON error, got {not_json:?}"
        );

        // And the same corruption must not slip through the serde
        // helper either — a field that fails to decode is an error, not
        // an empty table.
        let broken = format!("{{\"country_cidrs\":\"{}\"}}", "%%%not-base64%%%");
        let result: Result<CapsuleServiceConfig, _> = serde_json::from_str(&broken);
        assert!(
            result.is_err(),
            "a corrupt compressed table must fail the deserialisation, not decode to an empty table"
        );
    }

    /// An empty table must serialise to NOTHING at all. The field is
    /// inside a signed preimage, so a present-but-empty table would
    /// change the signed bytes of every already-issued capsule and break
    /// verification fleet-wide.
    #[test]
    fn an_empty_country_table_is_absent_from_the_serialisation() {
        let cfg = CapsuleServiceConfig::default();
        let json = serde_json::to_string(&cfg).expect("serialise");
        assert_eq!(
            json, "{}",
            "a config with no country table must serialise to the empty object"
        );
        assert!(
            !json.contains("country_cidrs"),
            "the country table must not appear at all when it is empty"
        );
    }

    /// Base64 of raw bytes — a local helper so the test above can build
    /// a "valid gzip, invalid JSON" payload without reaching into the
    /// encoder's internals.
    fn encode_bytes(bytes: &[u8]) -> String {
        base64::engine::general_purpose::STANDARD.encode(bytes)
    }
}
