//! `server.env` — the box's own configuration file.
//!
//! The installer writes one env file onto the box (`/opt/m1r4g3/server.env`)
//! and the box reads it. Its shape is fixed by the client that writes it
//! (`mirage2app/crates/client-gui/src/oasis/stand.rs` and
//! `oasis/provision.rs`):
//!
//! ```text
//! STACK=auto
//! PROTOCOLS=cloak,shadowsocks,xray
//! CLOAK_PORT=443
//! SHADOWSOCKS_PORT=443
//! XRAY_PORT=443
//! AWG_MTU=1280
//! CLOAK_MASK={"type":"tls_real","sni":"web1.example.net","alpn":["h2"]}
//! DNS=1.1.1.1
//! ```
//!
//! # Format
//!
//! One `KEY=VALUE` per line. Blank lines and lines starting with `#` are
//! skipped. A value may be wrapped in matching single or double quotes.
//! Unknown keys are ignored — the file is shared with other tooling and a
//! stray key is not this box's business. A repeated key takes its last value,
//! the same way a shell would.
//!
//! # What this module refuses, and why
//!
//! * **More than [`MAX_FACES`] faces.** The subscriber client offers at most
//!   that many TCP ports in its hello (`EdgeHello::MAX_OFFERED_PORTS`), so a
//!   box publishing more would have faces the client can never dial. Only a
//!   perimeter face counts: `{ID}_ROLE` is terminator (or absent) and the
//!   link is Mirage over TCP. A relay, Mirage over UDP, and every foreign
//!   door do not count.
//! * **Two protocols on one port ON THE SAME TRANSPORT.** The perimeter
//!   routes by port, so two TCP protocols on one port is one of them
//!   silently losing. The same port number on TCP and on UDP is NOT a
//!   collision: they are separate socket spaces, and an ordinary server
//!   serves HTTPS on TCP 443 and QUIC on UDP 443.
//! * **Port 22.** The box's own standard SSH already answers there, so a
//!   face on 22 would fight the operator's own login.
//! * **A box with no door at all.** Mirage over TCP is a perimeter face.
//!   Mirage over UDP is a node endpoint. Every other protocol is its own
//!   door. A relay is a fourth list: it forwards, it does not speak the
//!   protocol. `NoTcpFace` is the refusal when all four lists are empty.
//!
//! # The mask table
//!
//! A face wears the mask its port's protocol implies — the same rule the
//! fleet's own [`mirage_core::persona`] module follows. The table is
//! documented on [`fallback_mask_for_port`].
//!
//! # The link
//!
//! `{ID}_PROTOCOL` is the link, as the JSON [`Protocol`] serializes to.
//! The port stays `{ID}_PORT`. It is not inside the protocol. `{ID}_MASK`
//! is not a link: a file that sets the mask and not the protocol is refused.
//!
//! A listed id with no `{ID}_PROTOCOL` does not start. The id and the port
//! do not imply Mirage, TLS, or anything else. An empty `PROTOCOLS` list
//! does not start either.
//!
//! Where the door is bound follows from the link:
//!
//! * **Mirage over TCP** is a face the **perimeter** binds.
//! * **Mirage over UDP** (no camouflage, or junk) is an endpoint the
//!   **node** holds. The Mirage handshake stays there.
//! * Every other protocol is its own door. The perimeter and the node
//!   binder do not speak it.
//! * **`{ID}_ROLE=relay`** is none of those. The body must still parse.
//!   Only its type picks the socket: ICMP is raw ICMP, anything else
//!   `is_udp()` is UDP, and the rest is TCP. The relay reads one preamble
//!   and forwards the bytes after it. It does not become a face.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, UdpSocket};

use mirage_core::mirage::wire::{MirageCarrier, Protocol, TransportCamouflage};
use mirage_core::persona::Persona;
use thiserror::Error;

/// The most faces the subscriber client will ever offer.
///
/// The client's hello carries at most this many TCP ports
/// (`mirage_control_plane::EdgeHello::MAX_OFFERED_PORTS`) — the constant is
/// taken from there rather than restated, so the two cannot drift.
pub const MAX_FACES: usize = mirage_control_plane::EdgeHello::MAX_OFFERED_PORTS;

/// The port the box's own standard SSH answers on.
///
/// A standalone box never takes it: the operator's own login is there.
pub const SSH_PORT: u16 = 22;

/// The port a box publishes when its configuration names no protocol at all.
pub const DEFAULT_PORT: u16 = 443;

/// The default chain id — a box that belongs to no named chain.
pub const DEFAULT_CHAIN_ID: &str = "solo";

/// Everything that can go wrong while reading `server.env`.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum EnvError {
    /// A line was neither blank, nor a comment, nor `KEY=VALUE`.
    #[error("server.env line {line}: expected KEY=VALUE")]
    MalformedLine {
        /// The one-based line number.
        line: usize,
    },

    /// A `*_PORT` value is not a port number.
    #[error("server.env: {key} is not a valid port number")]
    BadPort {
        /// The offending key.
        key: String,
    },

    /// A `*_MTU` value is not a number.
    #[error("server.env: {key} is not a valid MTU")]
    BadMtu {
        /// The offending key.
        key: String,
    },

    /// A protocol named in `PROTOCOLS` has no port.
    #[error("server.env: protocol '{protocol}' has no {key}")]
    MissingPort {
        /// The protocol that lost its port.
        protocol: String,
        /// The key that was expected.
        key: String,
    },

    /// Two protocols claim the same port on the same transport.
    ///
    /// The same port number on TCP and on UDP is NOT this error: those are
    /// separate socket spaces, and an ordinary server serves HTTPS on TCP
    /// 443 and QUIC on UDP 443.
    #[error("server.env: port {port} is claimed twice on {transport} — by '{first}' and '{second}'")]
    DuplicatePort {
        /// The contested port.
        port: u16,
        /// The transport both protocols claimed it on (`tcp` or `udp`).
        transport: &'static str,
        /// The protocol that claimed it first.
        first: String,
        /// The protocol that claimed it second.
        second: String,
    },

    /// A protocol asked for the port the box's own SSH answers on.
    #[error(
        "server.env: port {port} is the box's own standard SSH — the login the operator uses \
         already answers there, so the box must not take it"
    )]
    ReservedPort {
        /// The reserved port.
        port: u16,
    },

    /// More faces than the client can be offered.
    #[error("server.env: {count} faces requested, the subscriber client accepts at most {max}")]
    TooManyFaces {
        /// How many were requested.
        count: usize,
        /// The client-side limit.
        max: usize,
    },

    /// The box publishes nothing a subscriber can dial.
    #[error("server.env: no door — the box publishes nothing a subscriber can dial")]
    NoTcpFace,

    /// A key that must be hex is not.
    #[error("server.env: {key} must be 64 hex characters")]
    BadHex {
        /// The offending key.
        key: String,
    },

    /// A camouflage mask is not a mask this build understands.
    #[error("server.env: {key} is not a valid camouflage mask ({reason})")]
    BadMask {
        /// The offending key.
        key: String,
        /// Why it was refused.
        reason: String,
    },

    /// `{ID}_PROTOCOL` is not a [`Protocol`].
    #[error("server.env: {key} is not a protocol ({reason})")]
    BadProtocol {
        /// The offending key.
        key: String,
        /// Why it was refused.
        reason: String,
    },

    /// `{ID}_MASK` was set and `{ID}_PROTOCOL` was not.
    #[error("server.env: {key} is a mask, and a mask is not a protocol")]
    MaskIsNotProtocol {
        /// The offending key.
        key: String,
    },

    /// A listed door has no `{ID}_PROTOCOL`. It does not start.
    #[error("server.env: {key} is missing — a door without a protocol does not start")]
    ProtocolRequired {
        /// `{ID}_PROTOCOL`.
        key: String,
    },

    /// `{ID}_ROLE` is not `terminator` or `relay`.
    #[error("server.env: {key} must be 'terminator' or 'relay'")]
    BadDoorRole {
        /// `{ID}_ROLE`.
        key: String,
    },

    /// The chain role is not one of the two this build knows.
    #[error("server.env: {key} must be 'entry' or 'exit'")]
    BadRole {
        /// The offending key.
        key: String,
    },

    /// Some of the next-hop keys are present and some are not.
    #[error("server.env: the next hop is incomplete — missing {missing}")]
    IncompleteNextHop {
        /// The keys that were missing.
        missing: String,
    },

    /// The chain's position or length is not a usable number.
    #[error("server.env: {key} is not a usable chain position ({reason})")]
    BadChainPosition {
        /// The offending key.
        key: String,
        /// Why it was refused.
        reason: String,
    },

    /// A hop of the chain is missing its address or its key.
    #[error("server.env: chain hop {index} is incomplete — missing {missing}")]
    IncompleteHop {
        /// The hop's index.
        index: usize,
        /// The keys that were missing.
        missing: String,
    },

    /// The chain is described twice — the short way and the whole way.
    #[error("server.env: the chain is described twice — {key} belongs to the short description")]
    ChainDescribedTwice {
        /// The key that does not belong.
        key: String,
    },

    /// The short chain description cannot say "middle".
    #[error("server.env: {key}=middle needs the whole chain — describe it with MIRAGE_CHAIN_POSITION and MIRAGE_CHAIN_LENGTH")]
    MiddleNeedsFullChain {
        /// The offending key.
        key: String,
    },
}

/// Whether a configured row speaks its protocol or only forwards.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DoorRole {
    /// The row is the protocol. This is the value when `{ID}_ROLE` is absent.
    #[default]
    Terminator,
    /// The row reads one preamble and forwards bytes to that host.
    Relay,
}

/// One protocol the box publishes, with the port it publishes it on.
///
/// `Debug` names the link and does not print it: a WireGuard or Shadowsocks
/// body carries key material.
#[derive(Clone, PartialEq, Eq)]
pub struct ProtocolConfig {
    /// The protocol id, lower-case (`cloak`, `shadowsocks`, `xray`, …).
    pub id: String,
    /// The port the protocol speaks on.
    pub port: u16,
    /// The MTU the protocol wants, when the configuration named one.
    pub mtu: Option<u16>,
    /// The link named by `{ID}_PROTOCOL`.
    ///
    /// Parse refuses a listed id that has no body. `None` is not a door.
    pub protocol: Option<Protocol>,
    /// `terminator` speaks the protocol. `relay` only forwards.
    ///
    /// Absent in the file is [`DoorRole::Terminator`].
    pub role: DoorRole,
}

impl std::fmt::Debug for ProtocolConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProtocolConfig")
            .field("id", &self.id)
            .field("port", &self.port)
            .field("mtu", &self.mtu)
            .field("role", &self.role)
            .field("protocol", &self.protocol.as_ref().map(Protocol::label))
            .finish()
    }
}

/// The socket a relay binds. Chosen from the protocol type, not from the bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayTransport {
    /// A TCP byte stream.
    Tcp,
    /// One UDP datagram in, one UDP datagram out.
    Udp,
    /// Raw ICMP Echo. Not a UDP socket. `Protocol::is_udp` is true for ICMP
    /// and that fact is ignored here.
    Icmp,
}

/// A relay in front of a terminator.
///
/// The protocol body is not stored. [`Self::transport`] is the only fact
/// the binder needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayDoor {
    /// The port named by `{ID}_PORT`. ICMP does not bind it.
    pub port: u16,
    /// The protocol id from `PROTOCOLS`.
    pub id: String,
    /// How this relay listens.
    pub transport: RelayTransport,
}

/// One published door: a port plus a [`Protocol`].
///
/// A Mirage-over-TCP face is what the perimeter binds. Any other link in
/// this shape is a protocol door. The protocol id from `PROTOCOLS` stays
/// on [`Self::id`] so a log line can name the row the operator wrote.
/// `Debug` prints the link's name, not its body.
#[derive(Clone, PartialEq, Eq)]
pub struct Face {
    /// The port the face is on.
    pub port: u16,
    /// The protocol id from `PROTOCOLS` (`cloak`, `xray`, …).
    pub id: String,
    /// The link this door speaks.
    pub protocol: Protocol,
}

impl std::fmt::Debug for Face {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Face")
            .field("port", &self.port)
            .field("id", &self.id)
            .field("protocol", &self.protocol.label())
            .finish()
    }
}

/// One Mirage-over-UDP endpoint the **node** holds.
///
/// No camouflage is raw UDP. Junk is the old junk mask. `Debug` prints the
/// link's name, not its body.
#[derive(Clone, PartialEq, Eq)]
pub struct UdpEndpoint {
    /// The port the endpoint is on.
    pub port: u16,
    /// The protocol id from `PROTOCOLS`.
    pub id: String,
    /// The link this endpoint speaks.
    pub protocol: Protocol,
}

impl std::fmt::Debug for UdpEndpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UdpEndpoint")
            .field("port", &self.port)
            .field("id", &self.id)
            .field("protocol", &self.protocol.label())
            .finish()
    }
}

/// What this box is in its chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainRole {
    /// The box **owns** the chain: the customer knocks on its door, and it
    /// walks the chain to the exit.
    ///
    /// The edge is not a hop of its own chain. That is the fleet's rule — the
    /// edge dials the chain's first hop, and the chain's hops are the boxes
    /// that relay onward — and it is the rule that keeps the two ends apart:
    /// the edge knows the chain's first hop, the exit knows the whole chain.
    Edge,
    /// The box receives the leg and relays onward.
    Entry,
    /// The box relays onward, and the chain continues past it.
    Middle,
    /// The box is the end of the chain.
    Exit,
}

impl ChainRole {
    /// The role a box plays at `position` in a chain of `length` hops.
    ///
    /// The first hop receives the client, the last one sends it out to the
    /// internet, and everything between relays onward. A chain of one hop is
    /// the exit: it receives the client and exits by itself.
    pub fn for_position(position: usize, length: usize) -> Self {
        if length <= 1 {
            ChainRole::Exit
        } else if position == 0 {
            ChainRole::Entry
        } else if position + 1 == length {
            ChainRole::Exit
        } else {
            ChainRole::Middle
        }
    }
}

/// The hop after this one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NextHop {
    /// `host:port` of the next hop.
    pub addr: String,
    /// The next hop's X25519 public key, hex.
    pub public_key: String,
    /// The mask the next hop wears, when the configuration named one.
    pub camouflage: Option<TransportCamouflage>,
}

/// One hop of a chain, as the env file names it.
///
/// The whole chain is written to EVERY box in it: each box reads the same
/// list and knows its own place in it by position. That is what lets the
/// exit box recognise the entry box that will knock on its door — an exit
/// box told only about "the hop after me" has never heard of the one before.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainHopEnv {
    /// `host:port` of the hop.
    pub addr: String,
    /// The hop's X25519 public key, hex.
    pub public_key: String,
    /// The mask the hop wears, when the configuration named one.
    pub camouflage: Option<TransportCamouflage>,
    /// `host:port` of the hop's DATAGRAM door — the port its datagram-native
    /// chain leg is answered on.
    ///
    /// Separate from [`Self::addr`] because TCP and UDP have separate port
    /// spaces: a hop can answer the chain's streams on 443/tcp and its
    /// datagrams on 443/udp without either moving. Absent means the hop has
    /// no datagram door, and the chain carries TCP only.
    pub udp_addr: Option<String>,
}

/// The chain this box belongs to, as the env file describes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainEnv {
    /// The chain's id.
    pub chain_id: String,
    /// What this box is in that chain.
    pub role: ChainRole,
    /// The hop after this one, when the box has one.
    pub next_hop: Option<NextHop>,
    /// This box's own place in the chain, zero-based.
    ///
    /// `None` when the box is the chain's **edge** — the box that owns the
    /// chain and dials it, and is not a hop of it — and also when the chain
    /// was described the short way, with only the next hop named.
    pub position: Option<usize>,
    /// How many hops the chain has.
    pub length: Option<usize>,
    /// The chain's hops, in order, when the whole chain was described.
    pub hops: Vec<ChainHopEnv>,
    /// The chain's operator public key, hex.
    ///
    /// This is the anchor the chain's legs are signed with: the hop that
    /// receives a leg verifies the leg's signature against this key, not
    /// against its own operator key. It is the chain's trust, and it is
    /// shared by every box of the chain.
    pub operator_pubkey_hex: Option<String>,
    /// The chain's operator secret seed, hex.
    ///
    /// Only the edge holds it — only the edge signs the legs it sends. A hop
    /// never needs it, and never receives it.
    pub operator_secret_hex: Option<String>,
    /// The chain's shared mesh id, hex.
    ///
    /// The leg's credential carries a mesh id, and the hop that receives it
    /// compares that id with its own, byte for byte. The boxes of one chain
    /// therefore share one mesh id — the edge's, because that is the id the
    /// customer's own link carries.
    pub mesh_id: Option<String>,
    /// The UDP port this box binds for the chain's DATAGRAM door.
    ///
    /// Only a hop that carries datagrams needs one: the edge dials it with a
    /// native UDP socket and runs the V9 datagram handshake on it, so the
    /// chain's datagrams are datagrams all the way down — never a datagram
    /// carried over a stream. The port may equal a TCP face's port number:
    /// TCP and UDP have separate port spaces.
    ///
    /// `None` means this box has no datagram door, and a chain that reaches
    /// it carries TCP only.
    pub udp_port: Option<u16>,
}

/// The box's whole configuration, read from `server.env`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerEnv {
    /// The stack id the box runs.
    pub stack: String,
    /// The protocols the box publishes.
    pub protocols: Vec<ProtocolConfig>,
    /// The resolver the box hands its clients, when one was named.
    pub dns: Option<String>,
    /// The chain this box belongs to.
    pub chain: ChainEnv,
    /// The host the customer dials, when the configuration named one.
    pub public_host: Option<String>,
    /// The country this box exits from, when the configuration named one.
    ///
    /// A client may ask for a specific exit country. A box that does not name
    /// its own country serves only the "auto" choice — it cannot honestly
    /// claim to be anywhere in particular, and a client that asked for
    /// Germany is refused rather than sent somewhere the box cannot name.
    pub exit_country: Option<String>,
    /// Whether private address ranges are valid exit targets.
    ///
    /// The SAME knob the node has (`NodeToml.allow_private_exit_targets`).
    /// Off by default: the SSRF guard is the safe state, and a box that
    /// serves private ranges only does so because the operator said so.
    pub allow_private_exit_targets: bool,
}

impl ServerEnv {
    /// Read a `server.env` body.
    ///
    /// Every refusal is by name: the error says which key or which protocol
    /// is wrong, so an operator can fix the file without reading this
    /// module's source.
    pub fn parse(text: &str) -> Result<Self, EnvError> {
        let values = parse_values(text)?;

        let stack = values
            .get("STACK")
            .cloned()
            .unwrap_or_else(|| "auto".to_owned());

        let protocols = parse_protocols(&values)?;

        let dns = values
            .get("DNS")
            .map(|v| v.trim().to_owned())
            .filter(|v| !v.is_empty());

        let public_host = values
            .get("MIRAGE_PUBLIC_HOST")
            .map(|v| v.trim().to_owned())
            .filter(|v| !v.is_empty());

        let exit_country = values
            .get("MIRAGE_EXIT_COUNTRY")
            .map(|v| v.trim().to_owned())
            .filter(|v| !v.is_empty());

        // The SSRF guard stays ON unless the operator says otherwise. Only
        // `true`/`1`/`yes` turn it off, and anything else — including a
        // misspelled value — leaves it ON: a setting that fails open is
        // worse than a setting that fails closed.
        let allow_private_exit_targets = values
            .get("MIRAGE_ALLOW_PRIVATE_EXIT_TARGETS")
            .map(|v| {
                let v = v.trim().to_ascii_lowercase();
                matches!(v.as_str(), "true" | "1" | "yes")
            })
            .unwrap_or(false);

        let chain = parse_chain(&values)?;

        Ok(Self {
            stack,
            protocols,
            dns,
            chain,
            public_host,
            exit_country,
            allow_private_exit_targets,
        })
    }

    /// The faces the **perimeter** binds: Mirage over TCP.
    ///
    /// Empty is a valid answer when the box still has a node endpoint, a
    /// protocol door, or a relay. [`EnvError::NoTcpFace`] is only the case
    /// where the box would publish nothing.
    pub fn faces(&self, persona: &Persona) -> Result<Vec<Face>, EnvError> {
        Ok(self.classify(persona)?.faces)
    }

    /// Mirage over UDP, held by the node.
    pub fn udp_endpoints(&self, persona: &Persona) -> Result<Vec<UdpEndpoint>, EnvError> {
        Ok(self.classify(persona)?.endpoints)
    }

    /// Every link that is not Mirage and not a relay.
    ///
    /// TLS, QUIC, DNS, WireGuard, Shadowsocks and the rest. Each one is its
    /// own door. The artefact publishes them beside the perimeter faces.
    /// A [`DoorRole::Relay`] row is not here — see [`Self::relays`].
    pub fn protocol_doors(&self, persona: &Persona) -> Result<Vec<Face>, EnvError> {
        Ok(self.classify(persona)?.doors)
    }

    /// Relays. A row with [`DoorRole::Relay`] is only this, never a face,
    /// a node endpoint, or a protocol door.
    pub fn relays(&self, persona: &Persona) -> Result<Vec<RelayDoor>, EnvError> {
        Ok(self.classify(persona)?.relays)
    }

    fn classify(&self, _persona: &Persona) -> Result<Classified, EnvError> {
        let mut faces = Vec::new();
        let mut endpoints = Vec::new();
        let mut doors = Vec::new();
        let mut relays = Vec::new();
        if self.protocols.is_empty() {
            return Err(EnvError::NoTcpFace);
        }
        for protocol in &self.protocols {
            let link = protocol_for(protocol)?;
            if protocol.role == DoorRole::Relay {
                // A relay must not become a perimeter face or a node endpoint,
                // including a Mirage relay. The body was parsed; only its type
                // picks the socket.
                relays.push(RelayDoor {
                    port: protocol.port,
                    id: protocol.id.clone(),
                    transport: relay_transport(&link),
                });
                continue;
            }
            place_link(
                &mut faces,
                &mut endpoints,
                &mut doors,
                protocol.port,
                &protocol.id,
                link,
            )?;
        }
        if faces.is_empty() && endpoints.is_empty() && doors.is_empty() && relays.is_empty() {
            return Err(EnvError::NoTcpFace);
        }
        Ok(Classified {
            faces,
            endpoints,
            doors,
            relays,
        })
    }
}

struct Classified {
    faces: Vec<Face>,
    endpoints: Vec<UdpEndpoint>,
    doors: Vec<Face>,
    relays: Vec<RelayDoor>,
}

/// ICMP is raw ICMP even though [`Protocol::is_udp`] is true for it.
/// Anything else datagram is UDP. The rest is TCP.
fn relay_transport(link: &Protocol) -> RelayTransport {
    if matches!(link, Protocol::Icmp { .. }) {
        RelayTransport::Icmp
    } else if link.is_udp() {
        RelayTransport::Udp
    } else {
        RelayTransport::Tcp
    }
}

fn place_link(
    faces: &mut Vec<Face>,
    endpoints: &mut Vec<UdpEndpoint>,
    doors: &mut Vec<Face>,
    port: u16,
    id: &str,
    link: Protocol,
) -> Result<(), EnvError> {
    match &link {
        Protocol::Mirage {
            carrier: MirageCarrier::Tcp,
            ..
        } => faces.push(Face {
            port,
            id: id.to_owned(),
            protocol: link,
        }),
        Protocol::Mirage {
            carrier: MirageCarrier::Udp,
            ..
        } => {
            let mask = link.to_mask(port).map_err(|reason| EnvError::BadProtocol {
                key: protocol_key(id, "PROTOCOL"),
                reason,
            })?;
            if !is_node_udp_endpoint(&mask) {
                return Err(EnvError::BadProtocol {
                    key: protocol_key(id, "PROTOCOL"),
                    reason: "not a mirage udp endpoint".to_owned(),
                });
            }
            endpoints.push(UdpEndpoint {
                port,
                id: id.to_owned(),
                protocol: link,
            });
        }
        _ => doors.push(Face {
            port,
            id: id.to_owned(),
            protocol: link,
        }),
    }
    Ok(())
}

/// Every door this box publishes, as one list.
///
/// The perimeter's faces, the node's Mirage UDP endpoints and the protocol
/// doors are different binders. To a customer they are the same thing: a
/// place to dial. The artefact carries all of them.
pub fn published_faces(faces: &[Face], endpoints: &[UdpEndpoint], doors: &[Face]) -> Vec<Face> {
    let mut all = faces.to_vec();
    all.extend(endpoints.iter().map(|endpoint| Face {
        port: endpoint.port,
        id: endpoint.id.clone(),
        protocol: endpoint.protocol.clone(),
    }));
    all.extend(doors.iter().cloned());
    all
}

/// Whether a mask is Mirage over UDP, which the node binder holds.
///
/// Raw UDP, and the junk mask. QUIC, DNS and ICMP are protocol doors.
pub fn is_node_udp_endpoint(mask: &TransportCamouflage) -> bool {
    matches!(
        mask,
        TransportCamouflage::WireGuard { .. } | TransportCamouflage::RawUdp { .. }
    )
}

/// The link a configured protocol speaks.
///
/// `{ID}_PROTOCOL` is required. A missing body is not Mirage and not the
/// port table. The door does not start.
pub fn protocol_for(protocol: &ProtocolConfig) -> Result<Protocol, EnvError> {
    protocol.protocol.clone().ok_or_else(|| EnvError::ProtocolRequired {
        key: protocol_key(&protocol.id, "PROTOCOL"),
    })
}

/// Translate a port's old mask into a [`Protocol`].
///
/// The running box does not call this. A door starts only from `{ID}_PROTOCOL`.
pub fn protocol_for_port(port: u16, persona: &Persona) -> Result<Protocol, EnvError> {
    let mask = mask_for_port(port, persona);
    Protocol::try_from(&mask).map_err(|reason| EnvError::BadProtocol {
        key: format!("port {port}"),
        reason,
    })
}

/// The mask a port wears.
///
/// The port's protocol decides the mask — the same rule the fleet's own
/// persona module follows. When this box's persona publishes that port, the
/// persona's own mask is used verbatim; otherwise the static table in
/// [`fallback_mask_for_port`] applies.
pub fn mask_for_port(port: u16, persona: &Persona) -> TransportCamouflage {
    if let Some(face) = persona
        .faces
        .iter()
        .find(|f| f.port == port && !f.camouflage.is_udp())
    {
        return face.camouflage.clone();
    }
    fallback_mask_for_port(port, &persona.hostname)
}

/// The static port-to-mask table, for a port this box's persona does not
/// publish.
///
/// | port | mask | shape |
/// |---|---|---|
/// | 22 | raw TCP | `None` |
/// | 80 | HTTP/1.1 WebSocket | `WebSocket` |
/// | 443 | real TLS 1.3 | `TlsReal` |
/// | 8080 | HTTP/1.1 `Upgrade` to a raw stream | `Xhttp` |
/// | 8443 | real TLS 1.3 | `TlsReal` |
/// | 2083 | real TLS 1.3 | `TlsReal` |
/// | 2087 | real TLS 1.3 | `TlsReal` |
/// | 3000 | HTTP/1.1 WebSocket | `WebSocket` |
/// | 5000 | HTTP/1.1 WebSocket | `WebSocket` |
/// | 8000 | HTTP/1.1 `Upgrade` to a raw stream | `Xhttp` |
/// | 10000 | real TLS 1.3 | `TlsReal` |
/// | anything else | real TLS 1.3 | `TlsReal` |
///
/// The first eleven rows are exactly the port-to-shape table
/// [`mirage_core::persona`] derives for a box; the last row is the fallback
/// for a port that table does not name. `hostname` is the name the box
/// presents as SNI and as the HTTP `Host` — the persona's own, so the two
/// never disagree.
pub fn fallback_mask_for_port(port: u16, hostname: &str) -> TransportCamouflage {
    match port {
        22 => TransportCamouflage::None,
        80 | 3000 | 5000 => TransportCamouflage::WebSocket {
            path: "/".to_owned(),
            host: hostname.to_owned(),
        },
        8080 | 8000 => TransportCamouflage::Xhttp {
            path: "/".to_owned(),
            host: hostname.to_owned(),
        },
        _ => TransportCamouflage::TlsReal {
            sni: hostname.to_owned(),
            alpn: vec!["h2".to_owned()],
        },
    }
}

/// Read the box's public IPv4 address, if it has one.
///
/// Used only as a fallback when the configuration names no public host: the
/// box opens a UDP socket and *connects* it, which sends no packet at all —
/// it just asks the OS which local address would be used to reach the far
/// side. A box behind NAT still reports its own address, so this is a
/// best-effort hint and never a substitute for a configured host.
pub fn discover_public_ipv4() -> Option<Ipv4Addr> {
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("1.1.1.1:53").ok()?;
    let addr = socket.local_addr().ok()?;
    match addr.ip() {
        IpAddr::V4(v4) if !v4.is_loopback() && !v4.is_unspecified() => Some(v4),
        _ => None,
    }
}

/// Split the file into key/value pairs.
///
/// A byte-order mark at the head of the file is dropped: an editor that
/// writes UTF-8 with a BOM would otherwise make the FIRST key unreadable,
/// and the first key is the one that says which protocols the box
/// publishes — a file that silently publishes the wrong faces is worse than
/// a file that is refused.
fn parse_values(text: &str) -> Result<BTreeMap<String, String>, EnvError> {
    let mut values = BTreeMap::new();
    for (index, raw_line) in text.lines().enumerate() {
        let line = raw_line.trim().trim_start_matches('\u{feff}');
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (key, value) = line
            .split_once('=')
            .ok_or(EnvError::MalformedLine { line: index + 1 })?;
        let key = key.trim().to_ascii_uppercase();
        if key.is_empty() {
            return Err(EnvError::MalformedLine { line: index + 1 });
        }
        values.insert(key, unquote(value.trim()));
    }
    Ok(values)
}

/// Strip one layer of matching quotes.
fn unquote(value: &str) -> String {
    let bytes = value.as_bytes();
    if bytes.len() >= 2 {
        let first = bytes[0];
        let last = bytes[bytes.len() - 1];
        if (first == b'"' || first == b'\'') && first == last {
            return value[1..value.len() - 1].to_owned();
        }
    }
    value.to_owned()
}

/// The key a protocol's port (or MTU) lives under.
fn protocol_key(id: &str, suffix: &str) -> String {
    format!("{}_{}", id.to_ascii_uppercase().replace('-', "_"), suffix)
}

/// Read the protocol list and each protocol's port, MTU and mask.
///
/// Two rules the box enforces on the list itself:
///
/// * **One port number per transport.** TCP 443 and UDP 443 are two
///   different ports to the kernel, so the same number on the two
///   transports is allowed — an ordinary server serves HTTPS and QUIC side
///   by side. The same number twice on ONE transport is refused: one of the
///   two would silently lose the port.
/// * **Never port 22.** The box's own standard SSH answers there.
fn parse_protocols(values: &BTreeMap<String, String>) -> Result<Vec<ProtocolConfig>, EnvError> {
    let list = values.get("PROTOCOLS").cloned().unwrap_or_default();
    let mut protocols = Vec::new();
    let mut seen_tcp: BTreeMap<u16, String> = BTreeMap::new();
    let mut seen_udp: BTreeMap<u16, String> = BTreeMap::new();

    for raw_id in list.split(',') {
        let id = raw_id.trim().to_ascii_lowercase();
        if id.is_empty() {
            continue;
        }
        let port_key = protocol_key(&id, "PORT");
        let port_raw = values
            .get(&port_key)
            .ok_or_else(|| EnvError::MissingPort {
                protocol: id.clone(),
                key: port_key.clone(),
            })?;
        let port: u16 = port_raw
            .trim()
            .parse()
            .map_err(|_| EnvError::BadPort { key: port_key.clone() })?;
        if port == 0 {
            return Err(EnvError::BadPort { key: port_key });
        }
        if port == SSH_PORT {
            return Err(EnvError::ReservedPort { port });
        }

        let protocol = match parse_explicit_protocol(values, &id)? {
            Some(link) => link,
            None => {
                return Err(EnvError::ProtocolRequired {
                    key: protocol_key(&id, "PROTOCOL"),
                });
            }
        };
        let role = parse_door_role(values, &id)?;
        let udp = protocol.is_udp();
        let seen = if udp { &mut seen_udp } else { &mut seen_tcp };
        if let Some(first) = seen.get(&port) {
            return Err(EnvError::DuplicatePort {
                port,
                transport: if udp { "udp" } else { "tcp" },
                first: first.clone(),
                second: id.clone(),
            });
        }
        seen.insert(port, id.clone());

        let mtu_key = protocol_key(&id, "MTU");
        let mtu = match values.get(&mtu_key) {
            Some(raw) if !raw.trim().is_empty() => Some(
                raw.trim()
                    .parse::<u16>()
                    .map_err(|_| EnvError::BadMtu { key: mtu_key.clone() })?,
            ),
            _ => None,
        };

        protocols.push(ProtocolConfig {
            id,
            port,
            mtu,
            protocol: Some(protocol),
            role,
        });
    }

    // The subscriber hello offers perimeter faces only. A relay, Mirage over
    // UDP, and every foreign door are not in that hello.
    let offered = protocols.iter().filter(|row| is_perimeter_face(row)).count();
    if offered > MAX_FACES {
        return Err(EnvError::TooManyFaces {
            count: offered,
            max: MAX_FACES,
        });
    }

    Ok(protocols)
}

/// A perimeter face: the row speaks Mirage over TCP.
///
/// Relays, Mirage over UDP, and every foreign door are not offered in the
/// subscriber hello, so they do not count toward [`MAX_FACES`].
fn is_perimeter_face(row: &ProtocolConfig) -> bool {
    row.role == DoorRole::Terminator
        && matches!(
            &row.protocol,
            Some(Protocol::Mirage {
                carrier: MirageCarrier::Tcp,
                ..
            })
        )
}

/// `{ID}_ROLE`. Absent or empty or `terminator` is today's door.
/// `relay` is the wrapper. Anything else names the key and stops.
fn parse_door_role(values: &BTreeMap<String, String>, id: &str) -> Result<DoorRole, EnvError> {
    let key = protocol_key(id, "ROLE");
    let Some(raw) = values.get(&key) else {
        return Ok(DoorRole::Terminator);
    };
    match raw.trim().to_ascii_lowercase().as_str() {
        "" | "terminator" => Ok(DoorRole::Terminator),
        "relay" => Ok(DoorRole::Relay),
        _ => Err(EnvError::BadDoorRole { key }),
    }
}

/// Read `{ID}_PROTOCOL`, if the operator named one.
///
/// `{ID}_MASK` alone is refused. The flat mask enum is not a link, and it
/// is not parsed as one.
fn parse_explicit_protocol(
    values: &BTreeMap<String, String>,
    id: &str,
) -> Result<Option<Protocol>, EnvError> {
    let link_key = protocol_key(id, "PROTOCOL");
    let mask_key = protocol_key(id, "MASK");
    let protocol_raw = values
        .get(&link_key)
        .map(|value| value.trim())
        .filter(|value| !value.is_empty());
    let mask_present = values
        .get(&mask_key)
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
        .is_some();
    match protocol_raw {
        None if mask_present => Err(EnvError::MaskIsNotProtocol { key: mask_key }),
        None => Ok(None),
        Some(raw) => {
            let protocol = serde_json::from_str::<Protocol>(raw).map_err(|err| {
                EnvError::BadProtocol {
                    key: link_key,
                    reason: err.to_string(),
                }
            })?;
            Ok(Some(protocol))
        }
    }
}

/// Read the chain's position or its length — a plain number, or nothing.
fn parse_chain_number(
    values: &BTreeMap<String, String>,
    key: &str,
) -> Result<Option<usize>, EnvError> {
    let Some(raw) = values.get(key) else {
        return Ok(None);
    };
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    trimmed
        .parse::<usize>()
        .map(Some)
        .map_err(|e| EnvError::BadChainPosition {
            key: key.to_owned(),
            reason: e.to_string(),
        })
}

/// Read the chain's hops, in order.
///
/// Every hop must name its address and its key: a hop missing either would be
/// a hop the chain silently drops, and a dropped hop is a chain that sends
/// the client's traffic nowhere.
fn parse_chain_hops(
    values: &BTreeMap<String, String>,
    length: usize,
) -> Result<Vec<ChainHopEnv>, EnvError> {
    let mut hops = Vec::with_capacity(length);
    for index in 0..length {
        let addr_key = format!("MIRAGE_CHAIN_HOP_{index}_ADDR");
        let pubkey_key = format!("MIRAGE_CHAIN_HOP_{index}_PUBKEY");
        let mask_key = format!("MIRAGE_CHAIN_HOP_{index}_MASK");
        let udp_addr_key = format!("MIRAGE_CHAIN_HOP_{index}_UDP_ADDR");

        let addr = values
            .get(&addr_key)
            .map(|v| v.trim())
            .filter(|v| !v.is_empty());
        let public_key = values
            .get(&pubkey_key)
            .map(|v| v.trim())
            .filter(|v| !v.is_empty());

        let mut missing = Vec::new();
        if addr.is_none() {
            missing.push(addr_key.clone());
        }
        if public_key.is_none() {
            missing.push(pubkey_key.clone());
        }
        if !missing.is_empty() {
            return Err(EnvError::IncompleteHop {
                index,
                missing: missing.join(", "),
            });
        }

        let public_key = public_key.expect("the key was checked above");
        if public_key.len() != 64 || hex::decode(public_key).is_err() {
            return Err(EnvError::BadHex { key: pubkey_key });
        }
        let camouflage = match values
            .get(&mask_key)
            .map(|v| v.trim())
            .filter(|v| !v.is_empty())
        {
            Some(raw) => Some(
                serde_json::from_str::<TransportCamouflage>(raw).map_err(|e| EnvError::BadMask {
                    key: mask_key.clone(),
                    reason: e.to_string(),
                })?,
            ),
            None => None,
        };

        hops.push(ChainHopEnv {
            addr: addr.expect("the address was checked above").to_owned(),
            public_key: public_key.to_owned(),
            camouflage,
            udp_addr: values
                .get(&udp_addr_key)
                .map(|v| v.trim())
                .filter(|v| !v.is_empty())
                .map(|v| v.to_owned()),
        });
    }

    // A hop beyond the chain's length is a hop the chain would quietly leave
    // out — and a chain with a hole in it is a chain that does not connect.
    for key in values.keys() {
        let Some(rest) = key.strip_prefix("MIRAGE_CHAIN_HOP_") else {
            continue;
        };
        let Some(index) = rest.split('_').next().and_then(|i| i.parse::<usize>().ok()) else {
            continue;
        };
        if index >= length {
            return Err(EnvError::BadChainPosition {
                key: key.clone(),
                reason: format!("the chain has {length} hop(s), so this hop is not part of it"),
            });
        }
    }

    Ok(hops)
}

/// Read the chain fields.
fn parse_chain(values: &BTreeMap<String, String>) -> Result<ChainEnv, EnvError> {
    // The whole chain, written to every box in it: each box reads the same
    // list and knows its own place in it by position.
    let position = parse_chain_number(values, "MIRAGE_CHAIN_POSITION")?;
    let length = parse_chain_number(values, "MIRAGE_CHAIN_LENGTH")?;

    let chain_id = values
        .get("MIRAGE_CHAIN_ID")
        .map(|v| v.trim().to_owned())
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| DEFAULT_CHAIN_ID.to_owned());

    let addr_key = "MIRAGE_NEXT_HOP_ADDR".to_owned();
    let pubkey_key = "MIRAGE_NEXT_HOP_PUBKEY".to_owned();
    let mask_key = "MIRAGE_NEXT_HOP_MASK".to_owned();

    let addr = values.get(&addr_key).map(|v| v.trim().to_owned()).filter(|v| !v.is_empty());
    let public_key = values
        .get(&pubkey_key)
        .map(|v| v.trim().to_owned())
        .filter(|v| !v.is_empty());
    let mask_raw = values
        .get(&mask_key)
        .map(|v| v.trim().to_owned())
        .filter(|v| !v.is_empty());

    let mut missing = Vec::new();
    if addr.is_none() {
        missing.push(addr_key.clone());
    }
    if public_key.is_none() {
        missing.push(pubkey_key.clone());
    }
    // No next hop at all is a normal configuration — a box that is the end
    // of its own chain. A half-named next hop is not: it would silently
    // drop half of what the operator wrote.
    if !missing.is_empty() && (addr.is_some() || public_key.is_some() || mask_raw.is_some()) {
        return Err(EnvError::IncompleteNextHop {
            missing: missing.join(", "),
        });
    }

    let next_hop = if let (Some(addr), Some(public_key)) = (addr, public_key) {
        if public_key.len() != 64 || hex::decode(&public_key).is_err() {
            return Err(EnvError::BadHex { key: pubkey_key });
        }
        let camouflage = match mask_raw {
            Some(raw) => Some(
                serde_json::from_str::<TransportCamouflage>(&raw).map_err(|e| EnvError::BadMask {
                    key: mask_key.clone(),
                    reason: e.to_string(),
                })?,
            ),
            None => None,
        };
        Some(NextHop {
            addr,
            public_key,
            camouflage,
        })
    } else {
        None
    };

    let role = match (position, length) {
        (Some(position), Some(length)) => {
            if next_hop.is_some() {
                return Err(EnvError::ChainDescribedTwice {
                    key: "MIRAGE_NEXT_HOP_ADDR".to_owned(),
                });
            }
            if length == 0 {
                return Err(EnvError::BadChainPosition {
                    key: "MIRAGE_CHAIN_LENGTH".to_owned(),
                    reason: "a chain has at least one hop".to_owned(),
                });
            }
            if position >= length {
                return Err(EnvError::BadChainPosition {
                    key: "MIRAGE_CHAIN_POSITION".to_owned(),
                    reason: format!("position {position} is outside a chain of {length} hop(s)"),
                });
            }
            ChainRole::for_position(position, length)
        }
        (None, Some(length)) => {
            // The chain is named in full and this box says nothing about where
            // it stands in it: this box is the chain's EDGE — it owns the
            // chain and dials it, and it is not a hop of it.
            if next_hop.is_some() {
                return Err(EnvError::ChainDescribedTwice {
                    key: "MIRAGE_NEXT_HOP_ADDR".to_owned(),
                });
            }
            if length == 0 {
                return Err(EnvError::BadChainPosition {
                    key: "MIRAGE_CHAIN_LENGTH".to_owned(),
                    reason: "a chain has at least one hop".to_owned(),
                });
            }
            ChainRole::Edge
        }
        (Some(_), None) => {
            return Err(EnvError::BadChainPosition {
                key: "MIRAGE_CHAIN_POSITION".to_owned(),
                reason: "the chain's position and its length go together".to_owned(),
            })
        }
        (None, None) => match values.get("MIRAGE_CHAIN_ROLE").map(|v| v.trim().to_ascii_lowercase()) {
            Some(v) if v == "entry" => ChainRole::Entry,
            Some(v) if v == "exit" => ChainRole::Exit,
            Some(v) if v == "middle" => {
                return Err(EnvError::MiddleNeedsFullChain {
                    key: "MIRAGE_CHAIN_ROLE".to_owned(),
                })
            }
            Some(_) => {
                return Err(EnvError::BadRole {
                    key: "MIRAGE_CHAIN_ROLE".to_owned(),
                })
            }
            None => {
                // A box that has a next hop is relaying; a box without one is the
                // end of the line.
                if next_hop.is_some() {
                    ChainRole::Entry
                } else {
                    ChainRole::Exit
                }
            }
        },
    };

    let hops = match length {
        Some(length) => parse_chain_hops(values, length)?,
        None => Vec::new(),
    };

    // The chain's shared key material and mesh id. A malformed key is a
    // refusal, not a warning: a chain whose legs are signed with a key the
    // hop cannot read is a chain that does not work, and the operator has to
    // hear about it at once.
    let operator_pubkey_hex = read_hex_key(values, "MIRAGE_OPERATOR_PUBKEY_HEX", 64)?;
    let operator_secret_hex = read_hex_key(values, "MIRAGE_CHAIN_OPERATOR_SECRET_HEX", 64)?;
    let mesh_id = read_hex_key(values, "MIRAGE_MESH_ID", 64)?;

    // The port this box binds for the chain's datagram door. A malformed port
    // is refused: a door that silently binds the wrong port is a door nobody
    // knocks on, and the chain's datagrams would go nowhere while the box
    // looked healthy.
    let udp_port = match values
        .get("MIRAGE_CHAIN_UDP_PORT")
        .map(|v| v.trim())
        .filter(|v| !v.is_empty())
    {
        Some(raw) => match raw.parse::<u16>() {
            Ok(0) => {
                return Err(EnvError::BadPort {
                    key: "MIRAGE_CHAIN_UDP_PORT".to_owned(),
                })
            }
            Ok(port) => Some(port),
            Err(_) => {
                return Err(EnvError::BadPort {
                    key: "MIRAGE_CHAIN_UDP_PORT".to_owned(),
                })
            }
        },
        None => None,
    };

    Ok(ChainEnv {
        chain_id,
        role,
        next_hop,
        position,
        length,
        hops,
        operator_pubkey_hex,
        operator_secret_hex,
        mesh_id,
        udp_port,
    })
}

/// Read a hex key of an exact length out of the env values.
///
/// `None` when the key is absent — an absent key is a normal configuration.
/// A present but malformed key is refused: a half-written key is a key that
/// will not verify, and the box that has to refuse the leg would fail with a
/// far less obvious reason.
fn read_hex_key(
    values: &BTreeMap<String, String>,
    key: &str,
    length: usize,
) -> Result<Option<String>, EnvError> {
    let Some(raw) = values.get(key).map(|v| v.trim().to_owned()) else {
        return Ok(None);
    };
    if raw.is_empty() {
        return Ok(None);
    }
    if raw.len() != length || hex::decode(&raw).is_err() {
        return Err(EnvError::BadHex {
            key: key.to_owned(),
        });
    }
    Ok(Some(raw))
}

#[cfg(test)]
mod tests {
    use super::*;

    const MIRAGE_TCP: &str = r#"{"type":"mirage","carrier":"tcp","camouflage":{"type":"none"}}"#;
    const MIRAGE_UDP: &str = r#"{"type":"mirage","carrier":"udp","camouflage":{"type":"none"}}"#;
    const QUIC_BODY: &str = r#"{"type":"quic","alpn":["h3"]}"#;

    #[test]
    fn a_full_environment_is_read() {
        let env = ServerEnv::parse(&format!(
            "# written by the installer\n\
             STACK=auto\n\
             PROTOCOLS=cloak,shadowsocks\n\
             CLOAK_PORT=443\n\
             CLOAK_MTU=1280\n\
             CLOAK_PROTOCOL={MIRAGE_TCP}\n\
             SHADOWSOCKS_PORT=8443\n\
             SHADOWSOCKS_PROTOCOL={MIRAGE_TCP}\n\
             DNS=1.1.1.1\n"
        ))
        .expect("parse");
        assert_eq!(env.stack, "auto");
        assert_eq!(env.protocols.len(), 2);
        assert_eq!(env.protocols[0].id, "cloak");
        assert_eq!(env.protocols[0].port, 443);
        assert_eq!(env.protocols[0].mtu, Some(1280));
        assert_eq!(env.protocols[1].id, "shadowsocks");
        assert_eq!(env.protocols[1].port, 8443);
        assert_eq!(env.protocols[1].mtu, None);
        assert_eq!(env.dns.as_deref(), Some("1.1.1.1"));
    }

    #[test]
    fn comments_and_blank_lines_are_skipped() {
        let env = ServerEnv::parse(&format!(
            "# a comment\n\n   \nSTACK=plain\nPROTOCOLS=cloak\nCLOAK_PORT=443\nCLOAK_PROTOCOL={MIRAGE_TCP}\n"
        ))
        .expect("parse");
        assert_eq!(env.stack, "plain");
        assert_eq!(env.protocols.len(), 1);
    }

    #[test]
    fn quoted_values_are_unwrapped() {
        let env = ServerEnv::parse(&format!(
            "STACK=\"auto\"\nPROTOCOLS='cloak'\nCLOAK_PORT=\"443\"\nCLOAK_PROTOCOL={MIRAGE_TCP}\n"
        ))
        .expect("parse");
        assert_eq!(env.stack, "auto");
        assert_eq!(env.protocols[0].id, "cloak");
        assert_eq!(env.protocols[0].port, 443);
    }

    #[test]
    fn unknown_keys_are_ignored() {
        let env = ServerEnv::parse(&format!(
            "STACK=auto\nSOMETHING_ELSE=1\nPROTOCOLS=cloak\nCLOAK_PORT=443\nCLOAK_PROTOCOL={MIRAGE_TCP}\n"
        ))
        .expect("parse");
        assert_eq!(env.protocols.len(), 1);
    }

    #[test]
    fn a_line_without_an_equals_sign_is_refused_by_line_number() {
        let err = ServerEnv::parse("STACK=auto\nthis is not a pair\n").expect_err("must refuse");
        assert_eq!(
            err,
            EnvError::MalformedLine {
                line: 2
            }
        );
    }

    #[test]
    fn a_protocol_without_a_port_is_refused_by_name() {
        let err =
            ServerEnv::parse("PROTOCOLS=cloak\n").expect_err("must refuse");
        assert_eq!(
            err,
            EnvError::MissingPort {
                protocol: "cloak".to_owned(),
                key: "CLOAK_PORT".to_owned()
            }
        );
    }

    #[test]
    fn a_bad_port_is_refused_by_key() {
        let err = ServerEnv::parse("PROTOCOLS=cloak\nCLOAK_PORT=not-a-port\n")
            .expect_err("must refuse");
        assert_eq!(err, EnvError::BadPort { key: "CLOAK_PORT".to_owned() });
    }

    #[test]
    fn a_zero_port_is_refused() {
        let err = ServerEnv::parse("PROTOCOLS=cloak\nCLOAK_PORT=0\n").expect_err("must refuse");
        assert_eq!(err, EnvError::BadPort { key: "CLOAK_PORT".to_owned() });
    }

    #[test]
    fn a_bad_mtu_is_refused_by_key() {
        let err = ServerEnv::parse(&format!(
            "PROTOCOLS=cloak\nCLOAK_PORT=443\nCLOAK_PROTOCOL={MIRAGE_TCP}\nCLOAK_MTU=big\n"
        ))
            .expect_err("must refuse");
        assert_eq!(err, EnvError::BadMtu { key: "CLOAK_MTU".to_owned() });
    }

    #[test]
    fn a_byte_order_mark_does_not_hide_the_first_key() {
        let env = ServerEnv::parse(&format!("\u{feff}PROTOCOLS=cloak\nCLOAK_PORT=8443\nCLOAK_PROTOCOL={MIRAGE_TCP}\n"))
            .expect("a file written with a BOM still parses");
        assert_eq!(env.protocols.len(), 1);
        assert_eq!(env.protocols[0].id, "cloak");
        assert_eq!(env.protocols[0].port, 8443);
    }

    #[test]
    fn two_protocols_on_one_port_are_refused() {
        let err = ServerEnv::parse(&format!(
            "PROTOCOLS=cloak,xray\nCLOAK_PORT=443\nCLOAK_PROTOCOL={MIRAGE_TCP}\nXRAY_PORT=443\nXRAY_PROTOCOL={MIRAGE_TCP}\n"
        ))
        .expect_err("must refuse");
        assert_eq!(
            err,
            EnvError::DuplicatePort {
                port: 443,
                transport: "tcp",
                first: "cloak".to_owned(),
                second: "xray".to_owned()
            }
        );
    }

    /// The refusal names the port AND the transport — a duplicate on TCP and
    /// a duplicate on UDP are different problems, and the operator has to be
    /// able to tell which one they have.
    #[test]
    fn the_duplicate_refusal_names_the_transport() {
        let err = ServerEnv::parse(&format!(
            "PROTOCOLS=awg,quic\nAWG_PORT=853\nAWG_PROTOCOL={MIRAGE_UDP}\nQUIC_PORT=853\nQUIC_PROTOCOL={QUIC_BODY}\n"
        ))
        .expect_err("must refuse");
        let text = err.to_string();
        assert!(text.contains("853"), "the message names the port: {text}");
        assert!(text.contains("udp"), "the message names the transport: {text}");
    }

    /// The same port NUMBER on two transports is not a duplicate: TCP and
    /// UDP are separate socket spaces, and an ordinary server serves HTTPS
    /// on TCP 443 and QUIC on UDP 443.
    #[test]
    fn one_port_number_on_two_transports_is_allowed() {
        let env = ServerEnv::parse(&format!(
            "PROTOCOLS=cloak,quic\nCLOAK_PORT=443\nCLOAK_PROTOCOL={MIRAGE_TCP}\nQUIC_PORT=443\nQUIC_PROTOCOL={QUIC_BODY}\n"
        ))
        .expect("the same number on two transports is not a collision");
        assert_eq!(env.protocols.len(), 2);
        assert_eq!(env.protocols[0].port, 443);
        assert_eq!(env.protocols[1].port, 443);
    }

    /// Port 22 is the box's own standard SSH. The operator's login answers
    /// there, so the box must not take it — and the refusal says so.
    #[test]
    fn port_22_is_refused_with_a_reason() {
        let err = ServerEnv::parse("PROTOCOLS=cloak\nCLOAK_PORT=22\n").expect_err("must refuse");
        assert_eq!(err, EnvError::ReservedPort { port: 22 });
        let text = err.to_string();
        assert!(text.contains("SSH"), "the message says why: {text}");
    }

    #[test]
    fn port_22_is_refused_for_a_udp_protocol_too() {
        let err = ServerEnv::parse("PROTOCOLS=awg\nAWG_PORT=22\nCLOAK_PORT=443\n")
            .expect_err("must refuse");
        assert_eq!(err, EnvError::ReservedPort { port: 22 });
    }

    /// An explicit protocol is the link. The port stays beside it, and the
    /// binder's mask is pointed at that port.
    #[test]
    fn an_explicit_protocol_is_the_link_and_the_mask_uses_the_door_port() {
        let env = ServerEnv::parse(
            "PROTOCOLS=cloak\nCLOAK_PORT=8443\n\
             CLOAK_PROTOCOL={\"type\":\"quic\",\"alpn\":[\"h3\"]}\n",
        )
        .expect("parse");
        let link = env.protocols[0].protocol.as_ref().expect("the protocol");
        assert!(matches!(link, Protocol::Quic { alpn } if alpn == &["h3".to_owned()]));
        let doors = env.protocol_doors(&test_persona()).expect("doors");
        assert_eq!(doors.len(), 1);
        let mask = doors[0]
            .protocol
            .to_mask(doors[0].port)
            .expect("quic is a mask");
        match mask {
            TransportCamouflage::Quic { bind_addr, .. } => {
                assert_eq!(bind_addr.port(), 8443, "the mask binds the door's own port");
            }
            other => panic!("expected a QUIC mask, got {other:?}"),
        }
    }

    /// A mask is not a protocol. The old flat enum is not parsed as the link.
    #[test]
    fn a_mask_without_a_protocol_is_refused() {
        let err = ServerEnv::parse(
            "PROTOCOLS=cloak\nCLOAK_PORT=443\n\
             CLOAK_MASK={\"type\":\"tls_real\",\"sni\":\"a.example\",\"alpn\":[\"h2\"]}\n",
        )
        .expect_err("must refuse");
        assert!(matches!(err, EnvError::MaskIsNotProtocol { .. }), "got {err:?}");
        let text = err.to_string();
        assert!(text.contains("mask"), "the message says a mask is not a protocol: {text}");
    }

    /// QUIC is its own door — it is not a perimeter face and not a Mirage UDP endpoint.
    #[test]
    fn a_udp_protocol_with_a_real_mask_is_a_protocol_door_not_a_face() {
        let env = ServerEnv::parse(
            "PROTOCOLS=cloak,quic\nCLOAK_PORT=443\n\
             CLOAK_PROTOCOL={\"type\":\"mirage\",\"carrier\":\"tcp\",\"camouflage\":{\"type\":\"none\"}}\n\
             QUIC_PORT=443\n\
             QUIC_PROTOCOL={\"type\":\"quic\",\"alpn\":[\"h3\"]}\n",
        )
        .expect("parse");
        let persona = test_persona();

        let faces = env.faces(&persona).expect("faces");
        assert!(
            faces.iter().all(|f| f.id != "quic"),
            "the perimeter must not be handed a QUIC face: {faces:?}"
        );
        assert!(faces.iter().any(|f| f.id == "cloak"));

        let endpoints = env.udp_endpoints(&persona).expect("endpoints");
        assert!(endpoints.is_empty(), "quic is not a mirage udp endpoint");
        let doors = env.protocol_doors(&persona).expect("doors");
        assert_eq!(doors.len(), 1);
        assert_eq!(doors[0].port, 443);
        assert!(matches!(doors[0].protocol, Protocol::Quic { .. }));
    }

    /// The doors the CUSTOMER may dial: the perimeter's faces AND the
    /// node's own UDP endpoints. The client dials every door it is given, so
    /// a box that publishes a QUIC endpoint has to be reachable over QUIC —
    /// or publishing it is a lie.
    #[test]
    fn the_published_doors_include_the_nodes_own_udp_endpoints() {
        let env = ServerEnv::parse(
            "PROTOCOLS=cloak,quic\nCLOAK_PORT=443\n\
             CLOAK_PROTOCOL={\"type\":\"mirage\",\"carrier\":\"tcp\",\"camouflage\":{\"type\":\"none\"}}\n\
             QUIC_PORT=443\n\
             QUIC_PROTOCOL={\"type\":\"quic\",\"alpn\":[\"h3\"]}\n",
        )
        .expect("parse");
        let persona = test_persona();

        let faces = env.faces(&persona).expect("faces");
        let endpoints = env.udp_endpoints(&persona).expect("endpoints");
        let doors = env.protocol_doors(&persona).expect("doors");
        let published = published_faces(&faces, &endpoints, &doors);

        assert_eq!(
            published.len(),
            faces.len() + endpoints.len() + doors.len(),
            "every published door is a perimeter face, a node endpoint, or a protocol door"
        );
        assert!(
            published.iter().any(|f| f.id == "quic"),
            "the QUIC endpoint must be a door the customer can dial: {published:?}"
        );
        assert!(
            published.iter().any(|f| f.id == "cloak"),
            "the perimeter's face must stay a door too: {published:?}"
        );
    }

    /// A listed id with no body does not become Mirage, and it does not start.
    #[test]
    fn a_listed_id_without_a_protocol_body_does_not_start() {
        let err = ServerEnv::parse("PROTOCOLS=awg,cloak\nAWG_PORT=853\nCLOAK_PORT=443\n")
            .expect_err("must refuse");
        assert_eq!(
            err,
            EnvError::ProtocolRequired {
                key: "AWG_PROTOCOL".to_owned()
            }
        );
    }

    /// The first face is always a TCP one — it is the face the node's own
    /// listener wears, and the listener is a TCP listener.
    #[test]
    fn the_first_face_is_always_a_tcp_face() {
        let env = ServerEnv::parse(&format!(
            "PROTOCOLS=awg,cloak\nAWG_PORT=853\nAWG_PROTOCOL={MIRAGE_UDP}\nCLOAK_PORT=443\n\
             CLOAK_PROTOCOL={MIRAGE_TCP}\n"
        ))
        .expect("parse");
        let persona = test_persona();
        let faces = env.faces(&persona).expect("faces");
        assert!(!faces[0].protocol.is_udp(), "the first face must be TCP");
        assert!(matches!(faces[0].protocol, Protocol::Mirage { .. }));
    }

    #[test]
    fn more_faces_than_the_client_accepts_are_refused() {
        let mut text = String::from("PROTOCOLS=");
        let mut ids = Vec::new();
        for i in 0..=MAX_FACES {
            let id = format!("p{i}");
            ids.push(id.clone());
            text.push_str(&id);
            text.push(',');
        }
        text.pop();
        for (i, id) in ids.iter().enumerate() {
            let key = id.to_uppercase();
            text.push_str(&format!(
                "\n{key}_PORT={}\n{key}_PROTOCOL={MIRAGE_TCP}",
                10000 + i
            ));
        }
        let err = ServerEnv::parse(&text).expect_err("must refuse");
        assert_eq!(
            err,
            EnvError::TooManyFaces {
                count: MAX_FACES + 1,
                max: MAX_FACES
            }
        );
    }

    /// Foreign doors are not perimeter faces. One Mirage TCP face plus more
    /// of them than the client can offer still parses.
    #[test]
    fn foreign_doors_past_the_face_cap_still_parse() {
        let extra = MAX_FACES + 1;
        let mut ids = vec!["cloak".to_owned()];
        for i in 0..extra {
            ids.push(format!("d{i}"));
        }
        let mut text = format!("PROTOCOLS={}\n", ids.join(","));
        text.push_str(&format!("CLOAK_PORT=443\nCLOAK_PROTOCOL={MIRAGE_TCP}\n"));
        for i in 0..extra {
            let key = format!("D{i}");
            let port = 20000 + i as u16;
            if i % 2 == 0 {
                text.push_str(&format!("{key}_PORT={port}\n{key}_PROTOCOL={QUIC_BODY}\n"));
            } else {
                text.push_str(&format!(
                    "{key}_PORT={port}\n{key}_PROTOCOL={{\"type\":\"tls\",\"sni\":\"h\",\"alpn\":[\"h2\"]}}\n"
                ));
            }
        }
        let env = ServerEnv::parse(&text).expect("foreign doors are not faces");
        let persona = test_persona();
        assert_eq!(env.faces(&persona).expect("faces").len(), 1);
        assert_eq!(env.protocol_doors(&persona).expect("doors").len(), extra);
    }

    #[test]
    fn an_explicit_mirage_udp_is_a_node_endpoint() {
        let env = ServerEnv::parse(&format!(
            "PROTOCOLS=raw,cloak\nRAW_PORT=853\nRAW_PROTOCOL={MIRAGE_UDP}\n\
             CLOAK_PORT=443\nCLOAK_PROTOCOL={MIRAGE_TCP}\n"
        ))
        .expect("parse");
        let persona = test_persona();
        let faces = env.faces(&persona).expect("faces");
        assert!(faces.iter().all(|face| face.id != "raw"));
        let endpoints = env.udp_endpoints(&persona).expect("endpoints");
        let udp = endpoints
            .iter()
            .find(|endpoint| endpoint.id == "raw")
            .expect("mirage udp is a node endpoint");
        assert!(udp.protocol.is_udp());
        assert_eq!(udp.port, 853);
        assert!(env.protocol_doors(&persona).expect("doors").is_empty());
    }

    #[test]
    fn a_box_with_only_mirage_udp_has_no_perimeter_face() {
        let env = ServerEnv::parse(&format!("PROTOCOLS=raw\nRAW_PORT=853\nRAW_PROTOCOL={MIRAGE_UDP}\n"))
            .expect("parses");
        let persona = test_persona();
        let faces = env.faces(&persona).expect("a mirage udp door is enough");
        assert!(faces.is_empty());
        let endpoints = env.udp_endpoints(&persona).expect("endpoints");
        assert_eq!(endpoints.len(), 1);
        assert!(env.protocol_doors(&persona).expect("doors").is_empty());
    }

    #[test]
    fn the_no_tcp_face_refusal_says_what_is_missing() {
        let text = EnvError::NoTcpFace.to_string();
        assert!(text.contains("door"), "the message names the missing door: {text}");
    }

    #[test]
    fn the_chain_defaults_to_solo_and_to_exit() {
        let env = ServerEnv::parse("STACK=auto\n").expect("parse");
        assert_eq!(env.chain.chain_id, "solo");
        assert_eq!(env.chain.role, ChainRole::Exit);
        assert!(env.chain.next_hop.is_none());
    }

    #[test]
    fn the_chain_fields_are_read() {
        let env = ServerEnv::parse(&format!(
            "MIRAGE_CHAIN_ID=mychain\n\
             MIRAGE_CHAIN_ROLE=entry\n\
             MIRAGE_NEXT_HOP_ADDR=10.0.0.5:443\n\
             MIRAGE_NEXT_HOP_PUBKEY={}\n",
            hex::encode([7u8; 32])
        ))
        .expect("parse");
        assert_eq!(env.chain.chain_id, "mychain");
        assert_eq!(env.chain.role, ChainRole::Entry);
        let hop = env.chain.next_hop.as_ref().expect("next hop");
        assert_eq!(hop.addr, "10.0.0.5:443");
    }

    #[test]
    fn the_whole_chain_is_read() {
        let env = ServerEnv::parse(&format!(
            "MIRAGE_CHAIN_ID=stand-2hop\n\
             MIRAGE_CHAIN_POSITION=1\n\
             MIRAGE_CHAIN_LENGTH=2\n\
             MIRAGE_CHAIN_HOP_0_ADDR=10.0.0.1:443\n\
             MIRAGE_CHAIN_HOP_0_PUBKEY={}\n\
             MIRAGE_CHAIN_HOP_1_ADDR=10.0.0.2:443\n\
             MIRAGE_CHAIN_HOP_1_PUBKEY={}\n\
             MIRAGE_CHAIN_HOP_1_MASK={{\"type\":\"tls_real\",\"sni\":\"a.example\"}}\n",
            hex::encode([1u8; 32]),
            hex::encode([2u8; 32])
        ))
        .expect("parse");
        assert_eq!(env.chain.chain_id, "stand-2hop");
        assert_eq!(env.chain.position, Some(1));
        assert_eq!(env.chain.length, Some(2));
        // The last hop of a two-hop chain is the exit — the role follows from
        // where the box stands, not from what it was told to be.
        assert_eq!(env.chain.role, ChainRole::Exit);
        assert_eq!(env.chain.hops.len(), 2);
        assert_eq!(env.chain.hops[0].addr, "10.0.0.1:443");
        assert_eq!(env.chain.hops[1].addr, "10.0.0.2:443");
        assert!(env.chain.hops[1].camouflage.is_some());
        assert!(env.chain.hops[0].camouflage.is_none());
    }

    #[test]
    fn a_hop_without_its_key_is_refused() {
        let err = ServerEnv::parse(
            "MIRAGE_CHAIN_ID=c\nMIRAGE_CHAIN_POSITION=0\nMIRAGE_CHAIN_LENGTH=1\nMIRAGE_CHAIN_HOP_0_ADDR=10.0.0.1:443\n",
        )
        .expect_err("must refuse");
        assert_eq!(
            err,
            EnvError::IncompleteHop {
                index: 0,
                missing: "MIRAGE_CHAIN_HOP_0_PUBKEY".to_owned()
            }
        );
    }

    #[test]
    fn a_position_outside_the_chain_is_refused() {
        let err = ServerEnv::parse(&format!(
            "MIRAGE_CHAIN_ID=c\nMIRAGE_CHAIN_POSITION=2\nMIRAGE_CHAIN_LENGTH=2\nMIRAGE_CHAIN_HOP_0_ADDR=10.0.0.1:443\nMIRAGE_CHAIN_HOP_0_PUBKEY={}\nMIRAGE_CHAIN_HOP_1_ADDR=10.0.0.2:443\nMIRAGE_CHAIN_HOP_1_PUBKEY={}\n",
            hex::encode([1u8; 32]),
            hex::encode([2u8; 32])
        ))
        .expect_err("must refuse");
        assert_eq!(
            err,
            EnvError::BadChainPosition {
                key: "MIRAGE_CHAIN_POSITION".to_owned(),
                reason: "position 2 is outside a chain of 2 hop(s)".to_owned()
            }
        );
    }

    #[test]
    fn a_chain_described_twice_is_refused() {
        let err = ServerEnv::parse(&format!(
            "MIRAGE_CHAIN_ID=c\nMIRAGE_CHAIN_POSITION=0\nMIRAGE_CHAIN_LENGTH=1\nMIRAGE_CHAIN_HOP_0_ADDR=10.0.0.1:443\nMIRAGE_CHAIN_HOP_0_PUBKEY={}\nMIRAGE_NEXT_HOP_ADDR=10.0.0.2:443\nMIRAGE_NEXT_HOP_PUBKEY={}\n",
            hex::encode([1u8; 32]),
            hex::encode([2u8; 32])
        ))
        .expect_err("must refuse");
        assert_eq!(
            err,
            EnvError::ChainDescribedTwice {
                key: "MIRAGE_NEXT_HOP_ADDR".to_owned()
            }
        );
    }

    #[test]
    fn a_hop_beyond_the_chain_is_refused() {
        let err = ServerEnv::parse(&format!(
            "MIRAGE_CHAIN_ID=c\nMIRAGE_CHAIN_POSITION=0\nMIRAGE_CHAIN_LENGTH=1\nMIRAGE_CHAIN_HOP_0_ADDR=10.0.0.1:443\nMIRAGE_CHAIN_HOP_0_PUBKEY={}\nMIRAGE_CHAIN_HOP_1_ADDR=10.0.0.2:443\nMIRAGE_CHAIN_HOP_1_PUBKEY={}\n",
            hex::encode([1u8; 32]),
            hex::encode([2u8; 32])
        ))
        .expect_err("must refuse");
        assert!(matches!(err, EnvError::BadChainPosition { .. }));
    }

    #[test]
    fn the_position_and_the_length_go_together() {
        let err = ServerEnv::parse("MIRAGE_CHAIN_ID=c\nMIRAGE_CHAIN_POSITION=0\n")
            .expect_err("must refuse");
        assert!(matches!(err, EnvError::BadChainPosition { .. }));
    }

    #[test]
    fn an_unknown_chain_role_is_refused() {
        let err = ServerEnv::parse("MIRAGE_CHAIN_ROLE=whatever\n").expect_err("must refuse");
        assert_eq!(
            err,
            EnvError::BadRole {
                key: "MIRAGE_CHAIN_ROLE".to_owned()
            }
        );
    }

    #[test]
    fn a_middle_role_needs_the_whole_chain() {
        // The short description can say "entry" and "exit" — a middle hop is
        // only meaningful when the whole chain is named, because a middle box
        // has to know both the hop before it and the hop after it.
        let err = ServerEnv::parse("MIRAGE_CHAIN_ROLE=middle\n").expect_err("must refuse");
        assert_eq!(
            err,
            EnvError::MiddleNeedsFullChain {
                key: "MIRAGE_CHAIN_ROLE".to_owned()
            }
        );
    }

    #[test]
    fn a_next_hop_without_a_public_key_is_refused() {
        let err = ServerEnv::parse("MIRAGE_NEXT_HOP_ADDR=10.0.0.5:443\n").expect_err("must refuse");
        assert_eq!(
            err,
            EnvError::IncompleteNextHop {
                missing: "MIRAGE_NEXT_HOP_PUBKEY".to_owned()
            }
        );
    }

    #[test]
    fn a_next_hop_with_a_short_public_key_is_refused() {
        let err = ServerEnv::parse(
            "MIRAGE_NEXT_HOP_ADDR=10.0.0.5:443\nMIRAGE_NEXT_HOP_PUBKEY=aabb\n",
        )
        .expect_err("must refuse");
        assert_eq!(
            err,
            EnvError::BadHex {
                key: "MIRAGE_NEXT_HOP_PUBKEY".to_owned()
            }
        );
    }

    #[test]
    fn a_next_hop_mask_is_read_as_a_typed_camouflage() {
        let env = ServerEnv::parse(&format!(
            "MIRAGE_NEXT_HOP_ADDR=10.0.0.5:443\n\
             MIRAGE_NEXT_HOP_PUBKEY={}\n\
             MIRAGE_NEXT_HOP_MASK={{\"type\":\"tls_real\",\"sni\":\"example.com\"}}\n",
            hex::encode([8u8; 32])
        ))
        .expect("parse");
        let hop = env.chain.next_hop.as_ref().expect("next hop");
        assert!(matches!(
            hop.camouflage,
            Some(TransportCamouflage::TlsReal { .. })
        ));
    }

    #[test]
    fn a_broken_next_hop_mask_is_refused() {
        let err = ServerEnv::parse(&format!(
            "MIRAGE_NEXT_HOP_ADDR=10.0.0.5:443\n\
             MIRAGE_NEXT_HOP_PUBKEY={}\n\
             MIRAGE_NEXT_HOP_MASK={{\"type\":\"nope\"}}\n",
            hex::encode([9u8; 32])
        ))
        .expect_err("must refuse");
        assert!(matches!(err, EnvError::BadMask { .. }));
    }

    #[test]
    fn the_mask_table_follows_the_port_protocol() {
        assert!(matches!(
            fallback_mask_for_port(22, "host"),
            TransportCamouflage::None
        ));
        assert!(matches!(
            fallback_mask_for_port(80, "host"),
            TransportCamouflage::WebSocket { .. }
        ));
        assert!(matches!(
            fallback_mask_for_port(443, "host"),
            TransportCamouflage::TlsReal { .. }
        ));
        assert!(matches!(
            fallback_mask_for_port(8080, "host"),
            TransportCamouflage::Xhttp { .. }
        ));
        assert!(matches!(
            fallback_mask_for_port(9999, "host"),
            TransportCamouflage::TlsReal { .. }
        ));
    }

    #[test]
    fn a_box_with_no_protocol_does_not_start() {
        let env = ServerEnv::parse("STACK=auto\n").expect("parse");
        let err = env.faces(&test_persona()).expect_err("nothing was chosen");
        assert_eq!(err, EnvError::NoTcpFace);
    }

    #[test]
    fn a_configured_id_without_a_protocol_does_not_start() {
        let err = ServerEnv::parse("PROTOCOLS=cloak\nCLOAK_PORT=443\n").expect_err("must refuse");
        assert_eq!(
            err,
            EnvError::ProtocolRequired {
                key: "CLOAK_PROTOCOL".to_owned()
            }
        );
    }

    /// Absent `{ID}_ROLE` stays a terminator. `relay` is not a face and not
    /// a protocol door. ICMP stays ICMP even though `is_udp` is true.
    /// Anything else names the key.
    #[test]
    fn a_relay_role_is_not_a_face_or_a_protocol_door() {
        let persona = test_persona();
        let absent = ServerEnv::parse(&format!(
            "PROTOCOLS=cloak\nCLOAK_PORT=443\nCLOAK_PROTOCOL={MIRAGE_TCP}\n"
        ))
        .expect("parse");
        assert_eq!(absent.protocols[0].role, DoorRole::Terminator);
        assert!(absent.relays(&persona).expect("relays").is_empty());

        let relay = ServerEnv::parse(
            "PROTOCOLS=quic\nQUIC_PORT=443\nQUIC_ROLE=relay\n\
             QUIC_PROTOCOL={\"type\":\"quic\",\"alpn\":[\"h3\"]}\n",
        )
        .expect("parse");
        assert!(relay.faces(&persona).expect("faces").is_empty());
        assert!(relay.udp_endpoints(&persona).expect("endpoints").is_empty());
        assert!(relay.protocol_doors(&persona).expect("doors").is_empty());
        let relays = relay.relays(&persona).expect("a relay-only box is a door");
        assert_eq!(relays.len(), 1);
        assert_eq!(relays[0].id, "quic");
        assert_eq!(relays[0].port, 443);
        assert_eq!(relays[0].transport, RelayTransport::Udp);

        let mirage = ServerEnv::parse(&format!(
            "PROTOCOLS=cloak\nCLOAK_PORT=8443\nCLOAK_ROLE=relay\nCLOAK_PROTOCOL={MIRAGE_TCP}\n"
        ))
        .expect("parse");
        assert!(mirage.faces(&persona).expect("faces").is_empty());
        assert!(mirage.protocol_doors(&persona).expect("doors").is_empty());
        assert_eq!(
            mirage.relays(&persona).expect("relays")[0].transport,
            RelayTransport::Tcp
        );

        let icmp = ServerEnv::parse(
            "PROTOCOLS=ping\nPING_PORT=443\nPING_ROLE=relay\n\
             PING_PROTOCOL={\"type\":\"icmp\",\"peer_addr\":\"203.0.113.5\",\"identifier\":7}\n",
        )
        .expect("parse");
        assert!(icmp.faces(&persona).expect("faces").is_empty());
        assert!(icmp.protocol_doors(&persona).expect("doors").is_empty());
        assert_eq!(
            icmp.relays(&persona).expect("relays")[0].transport,
            RelayTransport::Icmp
        );

        let err = ServerEnv::parse(
            "PROTOCOLS=quic\nQUIC_PORT=443\nQUIC_ROLE=nope\n\
             QUIC_PROTOCOL={\"type\":\"quic\"}\n",
        )
        .expect_err("must refuse");
        assert_eq!(
            err,
            EnvError::BadDoorRole {
                key: "QUIC_ROLE".to_owned()
            }
        );
    }

    /// A persona for the tests — the fleet's own derivation, off a fixed id.
    fn test_persona() -> Persona {
        let machine =
            mirage_core::ids::MachineId::new("ru-hostkey-203.0.113.15").expect("machine id");
        mirage_core::persona::persona_for(&machine)
    }
}
