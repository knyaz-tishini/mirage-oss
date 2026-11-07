//! The `client.link` artefact — what the customer hands to their client.
//!
//! # The wire contract
//!
//! Two crates define this shape, independently, and they must agree:
//!
//! * the server side — `mirage2panel/crates/panel/src/entrance.rs`
//!   (`EntranceArtefact`, `ArtefactEntrance`, `ArtefactMode`);
//! * the client side — `mirage2app/crates/subscriber-client/src/artefact.rs`,
//!   which parses and validates the JSON.
//!
//! This module mirrors the **server-side** types field for field: same names,
//! same set, same version, except the entrance's link. `protocol` is a
//! [`serde_json::Value`] of [`mirage_core::mirage::wire::Protocol`]. The
//! port stays in `addr`. A WireGuard link that still holds the client's
//! private key is published as the client view: that private key, the
//! server's public key, and the server-only field removed. `Debug` prints
//! the link's name, not its body.
//!
//! # The file
//!
//! `client.link` holds **one line**: the artefact JSON and nothing else. The
//! installer reads the file's first line and hands it to the customer, and it
//! reads it **once** — so the file has to be complete before any listener
//! comes up. It is therefore written atomically (temporary file, then
//! rename), and this module never appends to it.
//!
//! The file carries the subscriber's private key. It is the one artefact in
//! the whole product that is secret, and it is handed to exactly one person:
//! the box's own customer.

use std::fmt;
use std::path::{Path, PathBuf};

use mirage_core::mirage::wire::Protocol;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

use crate::env::Face;
use crate::fsio;
use crate::identity::ServerIdentity;

/// File name of the artefact, inside the box's data directory.
pub const CLIENT_LINK_FILE_NAME: &str = "client.link";

/// This type's own version line — matches the panel's and the client's.
pub const CURRENT_VERSION: u32 = 1;

/// Decoded length of every 32-byte X25519 key the artefact carries, in bytes.
const HEX32_BYTES: usize = 32;

/// Everything that can go wrong while building, encoding or writing the
/// artefact.
#[derive(Debug, Error)]
pub enum ArtefactError {
    /// No face was given — an artefact with no entrances is nothing to dial.
    #[error("artefact: no faces to publish")]
    NoFaces,

    /// A face's address could not be assembled into `host:port`.
    #[error("artefact: face on port {port} has an unusable address ({reason})")]
    BadAddr {
        /// The port the face sits on.
        port: u16,
        /// Why the address was refused — a fixed phrase.
        reason: &'static str,
    },

    /// The artefact could not be encoded.
    #[error("artefact: cannot encode the artefact ({reason})")]
    Encode {
        /// Why encoding failed.
        reason: String,
    },

    /// The encoded artefact was not a single line — refused rather than
    /// written, because the installer reads one line and nothing else.
    #[error("artefact: the encoded artefact is not one line")]
    NotOneLine,

    /// The artefact could not be written.
    #[error("artefact: cannot write {path}")]
    Write {
        /// The file that could not be written.
        path: PathBuf,
        /// The underlying I/O failure.
        #[source]
        source: std::io::Error,
    },

    /// The artefact's version is not the one this crate speaks.
    #[error("artefact: unsupported version {found} (this box speaks {expected})")]
    UnsupportedVersion {
        /// The version the artefact carries.
        found: u32,
        /// The version this crate speaks.
        expected: u32,
    },

    /// The artefact carries no mesh id — nothing to fold into a handshake.
    #[error("artefact: the mesh id is empty")]
    EmptyMeshId,

    /// The artefact has no entrances — nothing to dial.
    #[error("artefact: the artefact has no entrances — nothing to dial")]
    NoEntrances,

    /// A hex-carrying field is not valid hex.
    #[error("artefact: field '{field}' is not valid hex ({reason})")]
    MalformedHex {
        /// The field that is not hex.
        field: String,
        /// Why the decode failed.
        reason: String,
    },

    /// A hex-carrying field does not decode to the expected length.
    #[error("artefact: field '{field}' must decode to {expected_bytes} bytes, got {got_bytes}")]
    WrongHexLength {
        /// The field with the wrong length.
        field: String,
        /// The length it must have.
        expected_bytes: usize,
        /// The length it has.
        got_bytes: usize,
    },

    /// An entrance's address is not `host:port`.
    #[error("artefact: entrance {index} has an unusable address ({addr})")]
    BadEntranceAddr {
        /// Which entrance is broken.
        index: usize,
        /// The address it carries.
        addr: String,
    },

    /// The egress country is not an ISO-3166 alpha-2 code.
    #[error("artefact: the egress country '{code}' is not a 2-letter uppercase ISO-3166 alpha-2 code")]
    BadCountryCode {
        /// The country code the artefact carries.
        code: String,
    },

    /// A WireGuard door's key is not 32 bytes of hex.
    ///
    /// The key itself is not in this message.
    #[error("artefact: the wireguard door on port {port} does not carry a usable key")]
    WireGuardKey {
        /// The door's port.
        port: u16,
    },
}

/// The whole deliverable — the customer's artefact.
///
/// Field for field the same as the panel's
/// `mirage2panel/crates/panel/src/entrance.rs::EntranceArtefact`, and the
/// same as the client's own type.
///
/// `Debug` is written by hand: the artefact carries the subscriber's private
/// key, and that key never reaches a log line.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntranceArtefact {
    /// Artefact format version.
    pub v: u32,
    /// The subscriber's own X25519 static secret, 64-char hex.
    ///
    /// The sole proof of subscription on the wire: it is presented identically
    /// on every dial, and the box checks it against its signed allowlist.
    pub private_key_hex: String,
    /// The personal identifier of this one subscriber.
    ///
    /// Folded into the V9 handshake's confirm label where the fleet's real
    /// mesh id would go; both sides must fold in the same bytes. Minted once
    /// per box and reused unchanged.
    pub mesh_id: String,
    /// Every face this box publishes.
    pub entrances: Vec<ArtefactEntrance>,
    /// Full-auto, or a named egress country.
    pub mode: ArtefactMode,
    /// A human tag for logs and settings screens — cosmetic, never an
    /// identity.
    pub label: String,
    /// When the artefact was minted, in milliseconds since the epoch.
    pub issued_at_ms: u64,
}

/// One face the client can dial.
///
/// `Debug` prints the protocol's name only. A WireGuard body carries keys.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtefactEntrance {
    /// `host:port`, ready to dial.
    pub addr: String,
    /// The box's own X25519 public key, hex — what the client verifies the
    /// server by. Public by construction: it is the subscriber's own box.
    pub server_pubkey_hex: String,
    /// The link this face speaks, as [`Protocol`] JSON. No port inside it.
    pub protocol: Value,
}

impl fmt::Debug for ArtefactEntrance {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind = self
            .protocol
            .get("type")
            .and_then(Value::as_str)
            .unwrap_or("protocol");
        f.debug_struct("ArtefactEntrance")
            .field("addr", &self.addr)
            .field("server_pubkey_hex", &self.server_pubkey_hex)
            .field("protocol", &kind)
            .finish()
    }
}

/// Full-auto, or a named egress country (ISO-3166 alpha-2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtefactMode {
    /// The box picks its own egress.
    FullAuto,
    /// The customer asked for a named egress country.
    Country(String),
}

impl fmt::Debug for EntranceArtefact {
    /// Prints the non-secret shape only — the subscriber's private key is
    /// never rendered, not even partly.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EntranceArtefact")
            .field("v", &self.v)
            .field("private_key_hex", &"<redacted>")
            .field("mesh_id", &self.mesh_id)
            .field("entrances", &self.entrances)
            .field("mode", &self.mode)
            .field("label", &self.label)
            .field("issued_at_ms", &self.issued_at_ms)
            .finish()
    }
}

impl EntranceArtefact {
    /// Build an artefact for this box.
    ///
    /// `pub_addr` is the host the customer dials — the box's public name or
    /// address, without a port. `faces` are the box's published faces; each
    /// one becomes an entrance whose address is `pub_addr:<port>`.
    ///
    /// Every entrance carries the **same** `server_pubkey_hex`: this box's own
    /// wire public key, which is what the client verifies the server by.
    ///
    /// The artefact carries the box's **own** subscriber key — the owner of
    /// the box. A guest the owner invites gets its own key through
    /// [`EntranceArtefact::build_for_subscriber`], which is the same builder
    /// with the key left out.
    pub fn build(
        identity: &ServerIdentity,
        pub_addr: &str,
        faces: &[Face],
        mode: ArtefactMode,
        label: &str,
        issued_at_ms: u64,
    ) -> Result<Self, ArtefactError> {
        Self::build_for_subscriber(
            identity,
            pub_addr,
            faces,
            mode,
            label,
            issued_at_ms,
            &identity.subscriber_secret_hex(),
        )
    }

    /// Build an artefact for a subscriber whose device key is **not** this
    /// box's own — a guest the box invited.
    ///
    /// Everything else is the box's: the same entrances, the same
    /// `server_pubkey_hex` on every one of them, the same `mesh_id`.
    /// `private_key_hex` is that subscriber's X25519 device secret, hex —
    /// the guest's half of the invitation.
    ///
    /// The key is checked before it goes in: an artefact that carries a
    /// malformed key is one no client could dial.
    pub fn build_for_subscriber(
        identity: &ServerIdentity,
        pub_addr: &str,
        faces: &[Face],
        mode: ArtefactMode,
        label: &str,
        issued_at_ms: u64,
        private_key_hex: &str,
    ) -> Result<Self, ArtefactError> {
        if faces.is_empty() {
            return Err(ArtefactError::NoFaces);
        }
        if pub_addr.trim().is_empty() {
            return Err(ArtefactError::BadAddr {
                port: faces[0].port,
                reason: "the public address is empty",
            });
        }
        check_hex_field("private_key_hex", private_key_hex, HEX32_BYTES)?;
        let server_pubkey_hex = identity.node_wire_pubkey_hex();
        let mut entrances = Vec::with_capacity(faces.len());
        for face in faces {
            let addr = format!("{}:{}", pub_addr.trim_end_matches(':'), face.port);
            if !looks_like_host_port(&addr) {
                return Err(ArtefactError::BadAddr {
                    port: face.port,
                    reason: "the address is not host:port",
                });
            }
            let protocol = entrance_protocol(&face.protocol, face.port)?;
            entrances.push(ArtefactEntrance {
                addr,
                server_pubkey_hex: server_pubkey_hex.clone(),
                protocol,
            });
        }
        Ok(Self {
            v: CURRENT_VERSION,
            private_key_hex: private_key_hex.to_owned(),
            mesh_id: identity.mesh_id().to_owned(),
            entrances,
            mode,
            label: label.to_owned(),
            issued_at_ms,
        })
    }

    /// Refuse a malformed artefact BY NAME — the same checks the client makes
    /// before it dials, so the box can check an artefact before handing it
    /// out.
    ///
    /// Only inspects `self`: never touches disk and never the network.
    pub fn validate(&self) -> Result<(), ArtefactError> {
        if self.v != CURRENT_VERSION {
            return Err(ArtefactError::UnsupportedVersion {
                found: self.v,
                expected: CURRENT_VERSION,
            });
        }
        if self.mesh_id.trim().is_empty() {
            return Err(ArtefactError::EmptyMeshId);
        }
        check_hex_field("private_key_hex", &self.private_key_hex, HEX32_BYTES)?;
        if self.entrances.is_empty() {
            return Err(ArtefactError::NoEntrances);
        }
        for (index, entrance) in self.entrances.iter().enumerate() {
            if !looks_like_host_port(&entrance.addr) {
                return Err(ArtefactError::BadEntranceAddr {
                    index,
                    addr: entrance.addr.clone(),
                });
            }
            check_hex_field(
                &format!("entrances[{index}].server_pubkey_hex"),
                &entrance.server_pubkey_hex,
                HEX32_BYTES,
            )?;
        }
        if let ArtefactMode::Country(code) = &self.mode {
            let valid = code.len() == 2 && code.chars().all(|c| c.is_ascii_uppercase());
            if !valid {
                return Err(ArtefactError::BadCountryCode { code: code.clone() });
            }
        }
        Ok(())
    }

    /// The artefact as **one line** of JSON — no line breaks anywhere.
    ///
    /// `serde_json` escapes control characters, so the compact encoding of a
    /// well-formed artefact never contains a raw newline. The check is kept
    /// anyway: the installer reads one line and nothing else, and a file with
    /// a stray newline in it would be read as a truncated artefact.
    pub fn to_json_line(&self) -> Result<String, ArtefactError> {
        let json = serde_json::to_string(self).map_err(|e| ArtefactError::Encode {
            reason: e.to_string(),
        })?;
        if json.contains('\n') || json.contains('\r') {
            return Err(ArtefactError::NotOneLine);
        }
        Ok(json)
    }

    /// The path of the artefact inside `dir`.
    pub fn path_in(dir: &Path) -> PathBuf {
        fsio::path_in(dir, CLIENT_LINK_FILE_NAME)
    }

    /// Write the artefact to `<dir>/client.link`, atomically.
    ///
    /// The file holds the artefact JSON and nothing else: one line, no
    /// trailing newline, so the installer's `head -n 1` gets exactly the
    /// artefact. The write is atomic, so a reader never sees half of it.
    pub fn write_client_link(dir: &Path, artefact: &Self) -> Result<PathBuf, ArtefactError> {
        let json = artefact.to_json_line()?;
        let path = Self::path_in(dir);
        fsio::write_atomic(&path, json.as_bytes())
            .map_err(|source| ArtefactError::Write { path: path.clone(), source })?;
        Ok(path)
    }
}

/// The protocol JSON an entrance publishes.
///
/// WireGuard with `client_private_hex` is the server's copy of the client's
/// key. The artefact carries the client view: that private key, the public
/// key of `static_private_hex`, and the server-only field removed. Nothing
/// about the key is written into an error.
fn entrance_protocol(protocol: &Protocol, port: u16) -> Result<Value, ArtefactError> {
    let view = wireguard_client_view(protocol, port)?;
    let mut value = serde_json::to_value(&view).map_err(|err| ArtefactError::Encode {
        reason: err.to_string(),
    })?;
    if let Some(object) = value.as_object_mut() {
        object.remove("client_private_hex");
    }
    Ok(value)
}

/// Client view of a WireGuard or AmneziaWG link. Every other link is unchanged.
fn wireguard_client_view(protocol: &Protocol, port: u16) -> Result<Protocol, ArtefactError> {
    match protocol {
        Protocol::WireGuard {
            static_private_hex,
            preshared_key_hex,
            client_private_hex: Some(client_private),
            ..
        } => {
            let (static_private_hex, peer_public_hex, preshared_key_hex) =
                published_tunnel_keys(static_private_hex, preshared_key_hex, client_private, port)?;
            Ok(Protocol::WireGuard {
                static_private_hex,
                peer_public_hex,
                preshared_key_hex,
                client_private_hex: None,
            })
        }
        Protocol::AmneziaWg {
            static_private_hex,
            preshared_key_hex,
            client_private_hex: Some(client_private),
            jc,
            jmin,
            jmax,
            s1,
            s2,
            s3,
            s4,
            h1,
            h2,
            h3,
            h4,
            ..
        } => {
            let (static_private_hex, peer_public_hex, preshared_key_hex) =
                published_tunnel_keys(static_private_hex, preshared_key_hex, client_private, port)?;
            Ok(Protocol::AmneziaWg {
                static_private_hex,
                peer_public_hex,
                preshared_key_hex,
                client_private_hex: None,
                jc: *jc,
                jmin: *jmin,
                jmax: *jmax,
                s1: *s1,
                s2: *s2,
                s3: *s3,
                s4: *s4,
                h1: h1.clone(),
                h2: h2.clone(),
                h3: h3.clone(),
                h4: h4.clone(),
            })
        }
        _ => Ok(protocol.clone()),
    }
}

/// Client private key in, server public key out. The key bytes stay out of the error.
fn published_tunnel_keys(
    static_private_hex: &str,
    preshared_key_hex: &Option<String>,
    client_private: &str,
    port: u16,
) -> Result<(String, String, Option<String>), ArtefactError> {
    let server_public = x25519_public_hex(static_private_hex).map_err(|_| ArtefactError::WireGuardKey { port })?;
    if x25519_public_hex(client_private).is_err() {
        return Err(ArtefactError::WireGuardKey { port });
    }
    Ok((client_private.to_owned(), server_public, preshared_key_hex.clone()))
}

/// The hex public key of a 32-byte hex X25519 private key.
fn x25519_public_hex(private_hex: &str) -> Result<String, ()> {
    let bytes = hex::decode(private_hex).map_err(|_| ())?;
    let bytes: [u8; 32] = bytes.try_into().map_err(|_| ())?;
    let pair = mirage_core::crypto::KeyPair::from_secret(bytes);
    Ok(hex::encode(pair.public.as_bytes()))
}

/// `true` for a plain `host:port` pair — a non-empty host and a port that
/// parses as a `u16`. Mirrors the client's own check, so an artefact this
/// crate writes is one the client accepts.
fn looks_like_host_port(s: &str) -> bool {
    match s.rsplit_once(':') {
        Some((host, port)) => !host.is_empty() && port.parse::<u16>().is_ok(),
        None => false,
    }
}

/// Check that a hex-carrying field decodes to exactly `expected_bytes`.
///
/// The field's *value* never appears in the error — only its name and the
/// shape of the problem.
fn check_hex_field(field: &str, value: &str, expected_bytes: usize) -> Result<(), ArtefactError> {
    let bytes = hex::decode(value).map_err(|e| ArtefactError::MalformedHex {
        field: field.to_owned(),
        reason: e.to_string(),
    })?;
    if bytes.len() != expected_bytes {
        return Err(ArtefactError::WrongHexLength {
            field: field.to_owned(),
            expected_bytes,
            got_bytes: bytes.len(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    /// The exact field set of the panel's `EntranceArtefact` — the reference
    /// this crate's output must match, field for field.
    const PANEL_ARTEFACT_FIELDS: &[&str] = &[
        "entrances",
        "issued_at_ms",
        "label",
        "mesh_id",
        "mode",
        "private_key_hex",
        "v",
    ];

    /// The exact field set of the panel's `ArtefactEntrance`.
    const PANEL_ENTRANCE_FIELDS: &[&str] = &["addr", "protocol", "server_pubkey_hex"];

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(tag: &str) -> Self {
            use std::sync::atomic::{AtomicU64, Ordering};
            static COUNTER: AtomicU64 = AtomicU64::new(0);
            let path = std::env::temp_dir().join(format!(
                "mirage-standalone-art-{}-{}-{}",
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
        use mirage_core::mirage::wire::Protocol;
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

    #[test]
    fn the_artefact_has_exactly_the_panel_field_set() {
        let id = ServerIdentity::mint();
        let artefact = EntranceArtefact::build(
            &id,
            "203.0.113.7",
            &faces(),
            ArtefactMode::FullAuto,
            "standalone",
            1_700_000_000_000,
        )
        .expect("build");

        let value = serde_json::to_value(&artefact).expect("value");
        let mut keys: Vec<&str> = value.as_object().expect("object").keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(keys, PANEL_ARTEFACT_FIELDS);

        let entrance = value["entrances"][0].as_object().expect("entrance object");
        let mut ekeys: Vec<&str> = entrance.keys().map(String::as_str).collect();
        ekeys.sort_unstable();
        assert_eq!(ekeys, PANEL_ENTRANCE_FIELDS);
    }

    #[test]
    fn the_encoded_artefact_is_exactly_one_line() {
        let id = ServerIdentity::mint();
        let artefact = EntranceArtefact::build(
            &id,
            "203.0.113.7",
            &faces(),
            ArtefactMode::FullAuto,
            "standalone",
            1_700_000_000_000,
        )
        .expect("build");
        let json = artefact.to_json_line().expect("encode");
        assert!(!json.contains('\n'));
        assert!(!json.contains('\r'));
        assert_eq!(json.lines().count(), 1);
        serde_json::from_str::<Value>(&json).expect("valid JSON");
    }

    #[test]
    fn the_written_file_is_one_line_of_valid_json() {
        let id = ServerIdentity::mint();
        let dir = TempDir::new("write");
        let artefact = EntranceArtefact::build(
            &id,
            "203.0.113.7",
            &faces(),
            ArtefactMode::FullAuto,
            "standalone",
            1_700_000_000_000,
        )
        .expect("build");
        let path = EntranceArtefact::write_client_link(dir.path(), &artefact).expect("write");

        let raw = fs::read(&path).expect("read");
        let text = String::from_utf8(raw).expect("utf8");
        assert_eq!(text.lines().count(), 1);
        assert_eq!(text, artefact.to_json_line().expect("encode"));

        let parsed: Value = serde_json::from_str(&text).expect("valid JSON");
        let mut keys: Vec<&str> = parsed.as_object().expect("object").keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(keys, PANEL_ARTEFACT_FIELDS);
    }

    #[test]
    fn the_artefact_carries_the_subscribers_own_key_and_the_boxs_public_key() {
        let id = ServerIdentity::mint();
        let artefact = EntranceArtefact::build(
            &id,
            "203.0.113.7",
            &faces(),
            ArtefactMode::FullAuto,
            "standalone",
            1_700_000_000_000,
        )
        .expect("build");
        assert_eq!(artefact.private_key_hex, id.subscriber_secret_hex());
        assert_eq!(artefact.mesh_id, id.mesh_id());
        for entrance in &artefact.entrances {
            assert_eq!(entrance.server_pubkey_hex, id.node_wire_pubkey_hex());
        }
    }

    #[test]
    fn the_artefact_addresses_are_host_port() {
        let id = ServerIdentity::mint();
        let artefact = EntranceArtefact::build(
            &id,
            "203.0.113.7",
            &faces(),
            ArtefactMode::FullAuto,
            "standalone",
            1_700_000_000_000,
        )
        .expect("build");
        assert_eq!(artefact.entrances[0].addr, "203.0.113.7:443");
        assert_eq!(artefact.entrances[1].addr, "203.0.113.7:80");
    }

    #[test]
    fn an_artefact_with_no_faces_is_refused() {
        let id = ServerIdentity::mint();
        let err = EntranceArtefact::build(
            &id,
            "203.0.113.7",
            &[],
            ArtefactMode::FullAuto,
            "standalone",
            1,
        )
        .expect_err("must refuse");
        assert!(matches!(err, ArtefactError::NoFaces));
    }

    #[test]
    fn the_protocol_is_carried_as_json_without_a_port() {
        let id = ServerIdentity::mint();
        let artefact = EntranceArtefact::build(
            &id,
            "203.0.113.7",
            &faces(),
            ArtefactMode::FullAuto,
            "standalone",
            1,
        )
        .expect("build");
        let back: mirage_core::mirage::wire::Protocol =
            serde_json::from_value(artefact.entrances[0].protocol.clone()).expect("typed protocol");
        assert!(matches!(back, mirage_core::mirage::wire::Protocol::Tls { .. }));
        assert!(artefact.entrances[0].protocol.get("port").is_none());
    }

    #[test]
    fn a_guest_artefact_carries_the_guests_key_and_the_boxs_doors() {
        let id = ServerIdentity::mint();
        let owner = EntranceArtefact::build(
            &id,
            "203.0.113.7",
            &faces(),
            ArtefactMode::FullAuto,
            "standalone",
            1,
        )
        .expect("build");
        let guest = EntranceArtefact::build_for_subscriber(
            &id,
            "203.0.113.7",
            &faces(),
            ArtefactMode::FullAuto,
            "alice",
            2,
            &hex::encode([7u8; 32]),
        )
        .expect("build for the guest");

        assert_eq!(guest.private_key_hex, hex::encode([7u8; 32]));
        assert_ne!(guest.private_key_hex, owner.private_key_hex);
        assert_eq!(guest.mesh_id, id.mesh_id());
        assert_eq!(guest.entrances, owner.entrances);
        assert_eq!(guest.label, "alice");
        assert_eq!(guest.issued_at_ms, 2);
    }

    #[test]
    fn a_guest_artefact_with_a_malformed_key_is_refused() {
        let id = ServerIdentity::mint();
        let err = EntranceArtefact::build_for_subscriber(
            &id,
            "203.0.113.7",
            &faces(),
            ArtefactMode::FullAuto,
            "alice",
            1,
            "not-hex",
        )
        .expect_err("must refuse");
        assert!(matches!(err, ArtefactError::MalformedHex { .. }));
    }

    #[test]
    fn a_well_formed_artefact_validates() {
        let id = ServerIdentity::mint();
        let artefact = EntranceArtefact::build(
            &id,
            "203.0.113.7",
            &faces(),
            ArtefactMode::FullAuto,
            "standalone",
            1,
        )
        .expect("build");
        artefact.validate().expect("a well-formed artefact must validate");
    }

    #[test]
    fn validate_refuses_a_malformed_private_key() {
        let id = ServerIdentity::mint();
        let mut artefact = EntranceArtefact::build(
            &id,
            "203.0.113.7",
            &faces(),
            ArtefactMode::FullAuto,
            "standalone",
            1,
        )
        .expect("build");
        artefact.private_key_hex = "not-hex".to_owned();
        assert!(matches!(
            artefact.validate(),
            Err(ArtefactError::MalformedHex { .. })
        ));
    }

    #[test]
    fn validate_refuses_an_artefact_without_entrances() {
        let id = ServerIdentity::mint();
        let mut artefact = EntranceArtefact::build(
            &id,
            "203.0.113.7",
            &faces(),
            ArtefactMode::FullAuto,
            "standalone",
            1,
        )
        .expect("build");
        artefact.entrances.clear();
        assert!(matches!(artefact.validate(), Err(ArtefactError::NoEntrances)));
    }

    #[test]
    fn debug_never_shows_the_subscribers_private_key() {
        let id = ServerIdentity::mint();
        let artefact = EntranceArtefact::build(
            &id,
            "203.0.113.7",
            &faces(),
            ArtefactMode::FullAuto,
            "standalone",
            1,
        )
        .expect("build");
        let text = format!("{:?}", artefact);
        assert!(!text.contains(&id.subscriber_secret_hex()));
        assert!(text.contains("mesh_id"));
    }
}
