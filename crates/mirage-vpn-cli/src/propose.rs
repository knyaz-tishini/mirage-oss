//! What a box publishes about itself.
//!
//! # Why this exists
//!
//! The fleet's boxes publish their faces: which ports they can be reached
//! on, what each face wears, and why the face is offered. The panel turns
//! those faces into entrances and issues the subscriber an artefact.
//!
//! A self-assembled box has no panel -- the **operator is the client**. So
//! the box has to publish the same thing by itself, and the operator has to
//! be able to read it.
//!
//! This module is that publication. It answers one question: **what can a
//! client dial here, and under which camouflage?**
//!
//! # The shape
//!
//! ```json
//! {
//!   "v": 1,
//!   "server_public_key_hex": "...64 hex...",
//!   "mesh_id": "mirage-vpn",
//!   "faces": [
//!     { "port": 41444, "transport": "udp",
//!       "mask": { "type": "quic", "alpn": ["h3"], ... },
//!       "why": "UDP -- MirageQUIC." },
//!     { "port": 41445, "transport": "tcp",
//!       "mask": null,
//!       "why": "TCP -- the SOCKS5 tube." }
//!   ]
//! }
//! ```
//!
//! The `mask` is a [`TransportCamouflage`] -- **the same type the fleet's
//! artefacts carry**, so one client can read a fleet entrance and a
//! self-assembled one with the same code.
//!
//! A face without a mask (the SOCKS5 tube) is published too, with
//! `mask: null`: it is a real door, but it is not a camouflage axis, so a
//! client cannot enter through it directly -- only through a proxy in the
//! path.

use mirage_core::config::TransportCamouflage;
use serde::Serialize;

use crate::config::{ServerConfig, decode_keypair};

/// The version of this proposal's shape.
pub const PROPOSAL_VERSION: u32 = 1;

/// What a box publishes about itself.
#[derive(Debug, Clone, Serialize)]
pub struct Proposal {
    /// The version of this shape.
    pub v: u32,
    /// The box's own static public key, hex -- the key a client verifies it
    /// is talking to *this* box and not something standing in front of it.
    pub server_public_key_hex: String,
    /// The id both ends bake into the handshake.
    pub mesh_id: String,
    /// The faces the box can be reached on.
    pub faces: Vec<Face>,
}

/// One door of the box.
#[derive(Debug, Clone, Serialize)]
pub struct Face {
    /// The port the face sits on.
    pub port: u16,
    /// `udp` or `tcp`.
    pub transport: &'static str,
    /// The camouflage the face wears. `None` for a door that is not a
    /// camouflage axis.
    pub mask: Option<TransportCamouflage>,
    /// Why the face is offered, in the operator's language.
    pub why: String,
}

impl Proposal {
    /// Build the proposal of a box from its config.
    ///
    /// The key is read from the config: the box publishes its **public**
    /// key, and never its secret.
    pub fn of(config: &ServerConfig) -> Result<Self, crate::Error> {
        let keypair = decode_keypair(&config.private_key)?;
        let mut faces = Vec::new();

        if let Some(mkvik) = &config.listeners.mkvik {
            faces.push(Face {
                port: mkvik.bind.port(),
                transport: "udp",
                mask: Some(mkvik.camouflage()),
                why: "UDP - the MirageKVIC carrier.".to_owned(),
            });
        }
        if let Some(tunnel) = &config.listeners.tunnel {
            faces.push(Face {
                port: tunnel.port(),
                transport: "tcp",
                mask: None,
                why: "TCP - the SOCKS5 tube: a session arrives through a proxy in the path."
                    .to_owned(),
            });
        }

        Ok(Proposal {
            v: PROPOSAL_VERSION,
            server_public_key_hex: hex::encode(keypair.public.as_bytes()),
            mesh_id: config.mesh_id.clone(),
            faces,
        })
    }

    /// The proposal as JSON.
    pub fn to_json(&self) -> Result<String, crate::Error> {
        Ok(serde_json::to_string_pretty(self)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config_with_both_carriers() -> ServerConfig {
        let text = r#"{
            "private_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            "peers": [ { "name": "laptop", "public_key": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=" } ],
            "listeners": {
                "mkvik": { "bind": "0.0.0.0:41444", "alpn": ["h3"] },
                "tunnel": "0.0.0.0:41445"
            },
            "mesh_id": "mirage-vpn",
            "exit": { "mode": "direct" }
        }"#;
        serde_json::from_str(text).expect("config")
    }

    #[test]
    fn a_box_publishes_every_face_it_has() {
        let proposal = Proposal::of(&config_with_both_carriers()).expect("proposal");
        assert_eq!(proposal.v, PROPOSAL_VERSION);
        assert_eq!(proposal.mesh_id, "mirage-vpn");
        assert_eq!(proposal.faces.len(), 2);
        assert_eq!(proposal.faces[0].port, 41444);
        assert_eq!(proposal.faces[1].port, 41445);
    }

    #[test]
    fn the_carrier_faces_carry_their_camouflage_and_the_tube_does_not() {
        let proposal = Proposal::of(&config_with_both_carriers()).expect("proposal");
        let mkvik = proposal.faces[0].mask.clone().expect("mkvik mask");
        assert!(matches!(mkvik, TransportCamouflage::Quic { .. }));
        assert!(proposal.faces[1].mask.is_none());
        assert_eq!(proposal.faces[1].transport, "tcp");
    }

    #[test]
    fn the_public_key_is_published_and_the_secret_is_not() {
        let config = config_with_both_carriers();
        let proposal = Proposal::of(&config).expect("proposal");
        let keypair = decode_keypair(&config.private_key).expect("keypair");
        assert_eq!(proposal.server_public_key_hex.len(), 64);
        assert_eq!(
            proposal.server_public_key_hex,
            hex::encode(keypair.public.as_bytes())
        );
        let json = proposal.to_json().expect("json");
        assert!(!json.contains(&config.private_key), "the secret leaked");
    }

    #[test]
    fn the_proposal_is_json_and_carries_the_camouflage_type_tag() {
        let proposal = Proposal::of(&config_with_both_carriers()).expect("proposal");
        let json = proposal.to_json().expect("json");
        let value: serde_json::Value = serde_json::from_str(&json).expect("parses");
        assert_eq!(value["v"], 1);
        // The tag is the variant name in snake_case: `Quic` -> "quic".
        assert_eq!(value["faces"][0]["mask"]["type"], "quic");
        assert!(value["faces"][1]["mask"].is_null());
    }
}
