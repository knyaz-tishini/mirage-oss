//! The client<->edge session wire — what a customer's client speaks to its
//! own `mirage-edge` box, and nothing else (see
//! `docs/mirage/plans/2026-09-24-edge-as-entry.md`, PART TWO "Wire shape").
//!
//! ## Sequence on an established V9 tunnel
//!
//! 1. The client dials the edge's published face and completes the ordinary
//!    V9 handshake, presenting its persistent static key exactly as any
//!    subscriber does today.
//! 2. **Client -> edge**: [`EdgeHello`] — the client's exit preference
//!    ("auto" or a specific country). Version 2 and version 3 also offer
//!    the client's TCP entrance ports and a commit flag. Version 1 is the
//!    original 4 bytes and carries neither.
//! 3. **Edge -> client**: [`EdgeWelcome`] — the countries this edge can
//!    serve, plus the outcome (accepted, with the exit the edge actually
//!    fulfils, or a named refusal). Version 2 appends the face port the
//!    edge assigned. Version 3 appends that port and one flags byte: bit 0
//!    means this exit carries datagrams. Version 1 has no port trailer, and
//!    a version-1 or version-2 welcome does not say the exit carries
//!    datagrams. Version 4 appends the address the box assigned to this
//!    client: the packet plane gives every client behind one box its own
//!    address, and the client puts that address on its tunnel adapter.
//! 4. On [`EdgeOutcome::Accepted`], both sides upgrade the SAME tunnel to a
//!    mux session — the existing onion-exit primitive
//!    [`crate::tunnel::ONION_MUX_MAGIC`] plus `mirage_mux::SessionHandle`
//!    (`SessionHandle::client` on the client side, mirroring
//!    `SessionHandle::server` at
//!    `mirage2node::family::mirage::exit::{onion,onion_fs}`'s own mux
//!    upgrade of an accepted tunnel) — never a fresh V9 handshake per flow.
//! 5. Every subsequent logical flow is one mux stream, opened with a
//!    [`StreamOpen`] header as its first bytes, then carrying that flow's
//!    raw bytes (TCP) or [`encode_udp_datagram_frame`]-framed datagrams
//!    (UDP).
//!
//! ## Why a TCP `StreamOpen`'s target is a bare `host:port` string
//!
//! The edge's mesh leg carries an accepted stream into
//! `mirage_mesh_client::ChainMuxPool::open_stream(dest: &str)`, which writes
//! `dest` verbatim (length-prefixed) as the first bytes of the chain-side mux
//! stream — read on the exit end by
//! `mirage2node::family::mirage::exit::onion_fs::read_mux_stream_target`,
//! which expects exactly a UTF-8 `host:port` string, no scheme prefix
//! (`resolve_target_to_addr` parses it as a bare socket address or DNS
//! name:port). [`StreamTarget`] carries that exact string — a `StreamOpen`
//! with `kind: StreamKind::Tcp` hands `target.as_str()` straight to
//! `open_stream` with no transformation, so the bytes the client asked for
//! are the bytes the exit dials.
//!
//! A UDP open reuses the same [`StreamTarget`] (the client's own
//! `host:port` UDP destination) — disambiguated from TCP by the explicit
//! `kind` tag on `StreamOpen` itself, never by a string prefix inside the
//! target. Which prefix (if any) a future UDP-carrying mesh leg wants at
//! ITS OWN boundary (the classic single-envelope exit already uses a
//! `udp:` string prefix, see `mirage2node::family::mirage::exit::direct`'s
//! `parse_exit_target`) is that leg's own choice to make when it exists —
//! not this module's concern, and not decided here.
//!
//! ## UDP datagram framing
//!
//! Once a `StreamKind::Udp` stream is open, individual datagrams ride it as
//! `[2B BE len][payload]` frames — [`encode_udp_datagram_frame`] /
//! [`decode_udp_datagram_frame`] define that codec as pure byte-buffer
//! functions (no I/O), matching the shape
//! [`crate::udp_framing::write_udp_frame`] /
//! [`crate::udp_framing::read_udp_frame`] already use for the async-I/O
//! side of the identical framing elsewhere in this crate. That frame codec
//! is what the edge datagram leg already carries.
//!
//! ## Scope
//!
//! Every type here is a pure, bounded encode/decode pair over byte buffers —
//! no `AsyncRead`/`AsyncWrite`, no `Tunnel`, no network code. Decoding is
//! bounded on every variable-length field (counts, lengths) and every error
//! names the offending input.

use std::error::Error as StdError;
use std::fmt;
use std::net::Ipv4Addr;

use mirage_core::config::{TransportCamouflage, TransportKind};
use mirage_protocol::client_transport::camouflage_transport;

// ── Errors ──────────────────────────────────────────────────────────────

/// Decode/construction errors for every type in this module. Every variant
/// names the offending input so a caller can log or reject a peer without
/// re-deriving what went wrong from a bare string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EdgeSessionError {
    /// The buffer ran out mid-parse. `context` names which field or message
    /// was being read when it did.
    Truncated {
        context: &'static str,
        need: usize,
        have: usize,
    },
    /// [`ExitPreference`]'s tag byte was neither `Auto` (0x00) nor `Country`
    /// (0x01).
    UnsupportedExitTag { tag: u8 },
    /// [`ExitPreference::Auto`] was decoded with non-zero trailing bytes —
    /// rejected so `Auto` has exactly one valid wire representation.
    NonCanonicalAutoPadding { bytes: [u8; 2] },
    /// A 2-byte country code was not two uppercase ASCII letters.
    InvalidCountryCode { input: String },
    /// [`EdgeWelcome`]'s advertised country count exceeds
    /// [`EdgeWelcome::MAX_COUNTRIES`].
    TooManyCountries { count: usize, max: usize },
    /// [`EdgeOutcome`]'s tag byte was neither `Accepted` (0x00) nor
    /// `Refused` (0x01).
    UnsupportedOutcomeTag { tag: u8 },
    /// [`EdgeRefusal`]'s tag byte matched none of the named refusals.
    UnsupportedRefusalTag { tag: u8 },
    /// [`StreamOpen`]'s kind tag was neither `Tcp` (0x00) nor `Udp` (0x01).
    UnsupportedStreamKind { tag: u8 },
    /// A [`StreamTarget`] was empty.
    EmptyTarget,
    /// A [`StreamTarget`] exceeded [`StreamTarget::MAX_LEN`].
    TargetTooLong { len: usize, max: usize },
    /// A stream target's bytes were not valid UTF-8.
    TargetNotUtf8 { bytes: Vec<u8> },
    /// A UDP datagram frame's payload exceeded the largest UDP datagram
    /// representable at all ([`crate::udp_framing::MAX_UDP_DATAGRAM`],
    /// 65507 bytes).
    DatagramTooLarge { len: usize, max: usize },
    /// [`EdgeHello`] version 2 or 3 set a flag bit other than bit 0 (commit).
    ReservedHelloFlags { flags: u8 },
    /// [`EdgeHello`] version 2 or 3 offered more than [`EdgeHello::MAX_OFFERED_PORTS`]
    /// TCP ports.
    TooManyOfferedPorts { count: usize, max: usize },
    /// [`EdgeWelcome`] version 2 or later was encoded without
    /// [`EdgeWelcome::assigned_face_port`].
    MissingAssignedFacePort,
    /// [`EdgeWelcome`] version 3 was encoded without [`EdgeWelcome::carries_datagrams`].
    MissingDatagramFlag,
    /// [`EdgeWelcome`] version 3 set a flag bit other than bit 0 (carries datagrams).
    ReservedWelcomeFlags { flags: u8 },
}

impl fmt::Display for EdgeSessionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EdgeSessionError::Truncated { context, need, have } => {
                write!(f, "edge-session: {context}: need {need} bytes, have {have}")
            }
            EdgeSessionError::UnsupportedExitTag { tag } => {
                write!(f, "edge-session: unsupported ExitPreference tag 0x{tag:02x}")
            }
            EdgeSessionError::NonCanonicalAutoPadding { bytes } => write!(
                f,
                "edge-session: ExitPreference::Auto encoded with non-zero padding {bytes:?}"
            ),
            EdgeSessionError::InvalidCountryCode { input } => {
                write!(f, "edge-session: invalid country code {input:?}")
            }
            EdgeSessionError::TooManyCountries { count, max } => write!(
                f,
                "edge-session: EdgeWelcome advertises {count} countries, exceeds max {max}"
            ),
            EdgeSessionError::UnsupportedOutcomeTag { tag } => {
                write!(f, "edge-session: unsupported EdgeOutcome tag 0x{tag:02x}")
            }
            EdgeSessionError::UnsupportedRefusalTag { tag } => {
                write!(f, "edge-session: unsupported EdgeRefusal tag 0x{tag:02x}")
            }
            EdgeSessionError::UnsupportedStreamKind { tag } => {
                write!(f, "edge-session: unsupported StreamKind tag 0x{tag:02x}")
            }
            EdgeSessionError::EmptyTarget => write!(f, "edge-session: target must not be empty"),
            EdgeSessionError::TargetTooLong { len, max } => {
                write!(f, "edge-session: target is {len} bytes, exceeds max {max}")
            }
            EdgeSessionError::TargetNotUtf8 { bytes } => {
                write!(f, "edge-session: target is not valid UTF-8: {bytes:?}")
            }
            EdgeSessionError::DatagramTooLarge { len, max } => write!(
                f,
                "edge-session: UDP datagram payload is {len} bytes, exceeds max {max}"
            ),
            EdgeSessionError::ReservedHelloFlags { flags } => {
                write!(f, "edge-session: EdgeHello flags 0x{flags:02x} set reserved bits")
            }
            EdgeSessionError::TooManyOfferedPorts { count, max } => write!(
                f,
                "edge-session: EdgeHello offers {count} ports, exceeds max {max}"
            ),
            EdgeSessionError::MissingAssignedFacePort => {
                write!(
                    f,
                    "edge-session: EdgeWelcome version 2 or later requires an assigned face port"
                )
            }
            EdgeSessionError::MissingDatagramFlag => {
                write!(f, "edge-session: EdgeWelcome version 3 requires the datagram flag")
            }
            EdgeSessionError::ReservedWelcomeFlags { flags } => {
                write!(f, "edge-session: EdgeWelcome flags 0x{flags:02x} set reserved bits")
            }
        }
    }
}

impl StdError for EdgeSessionError {}

// ── CountryCode ─────────────────────────────────────────────────────────

/// An ISO 3166-1 alpha-2 country code — exactly two uppercase ASCII letters.
/// Validated at construction; nothing else can build one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CountryCode([u8; 2]);

impl CountryCode {
    /// Build from a 2-character string. Rejects anything not exactly two
    /// uppercase ASCII letters.
    pub fn new(code: &str) -> Result<Self, EdgeSessionError> {
        let bytes = code.as_bytes();
        if bytes.len() != 2 || !bytes.iter().all(|b| b.is_ascii_uppercase()) {
            return Err(EdgeSessionError::InvalidCountryCode {
                input: code.to_string(),
            });
        }
        Ok(Self([bytes[0], bytes[1]]))
    }

    /// Decode from the 2 raw wire bytes. Rejects anything not exactly two
    /// uppercase ASCII letters.
    pub fn decode(bytes: [u8; 2]) -> Result<Self, EdgeSessionError> {
        if !bytes.iter().all(|b| b.is_ascii_uppercase()) {
            return Err(EdgeSessionError::InvalidCountryCode {
                input: String::from_utf8_lossy(&bytes).into_owned(),
            });
        }
        Ok(Self(bytes))
    }

    /// Encode to the 2 raw wire bytes.
    pub fn encode(&self) -> [u8; 2] {
        self.0
    }

    /// Borrow as `&str`.
    pub fn as_str(&self) -> &str {
        // Safety-by-construction: `new`/`decode` are the only ways to build
        // a `CountryCode`, and both reject anything outside `b'A'..=b'Z'`.
        std::str::from_utf8(&self.0)
            .expect("CountryCode only ever holds validated ASCII uppercase bytes")
    }
}

impl fmt::Display for CountryCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ── ExitPreference ──────────────────────────────────────────────────────

/// What exit the client wants — carried in [`EdgeHello`] and, once fulfilled,
/// echoed back inside [`EdgeOutcome::Accepted`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitPreference {
    /// Let the edge pick — its own box-level default intent.
    Auto,
    /// Exit through this specific country, if the edge can serve it.
    Country(CountryCode),
}

impl ExitPreference {
    const TAG_AUTO: u8 = 0x00;
    const TAG_COUNTRY: u8 = 0x01;

    /// Fixed 3-byte wire form: `[1B tag][2B country]` (country bytes are
    /// `[0, 0]` for `Auto`).
    pub const ENCODED_LEN: usize = 3;

    pub fn encode(&self) -> [u8; Self::ENCODED_LEN] {
        match self {
            ExitPreference::Auto => [Self::TAG_AUTO, 0, 0],
            ExitPreference::Country(cc) => {
                let bytes = cc.encode();
                [Self::TAG_COUNTRY, bytes[0], bytes[1]]
            }
        }
    }

    /// Decode from the front of `buf`. Returns `(Self, 3)` — this type is
    /// always fixed-length.
    pub fn decode(buf: &[u8]) -> Result<(Self, usize), EdgeSessionError> {
        if buf.len() < Self::ENCODED_LEN {
            return Err(EdgeSessionError::Truncated {
                context: "ExitPreference",
                need: Self::ENCODED_LEN,
                have: buf.len(),
            });
        }
        match buf[0] {
            Self::TAG_AUTO => {
                if buf[1] != 0 || buf[2] != 0 {
                    return Err(EdgeSessionError::NonCanonicalAutoPadding {
                        bytes: [buf[1], buf[2]],
                    });
                }
                Ok((ExitPreference::Auto, Self::ENCODED_LEN))
            }
            Self::TAG_COUNTRY => {
                let cc = CountryCode::decode([buf[1], buf[2]])?;
                Ok((ExitPreference::Country(cc), Self::ENCODED_LEN))
            }
            other => Err(EdgeSessionError::UnsupportedExitTag { tag: other }),
        }
    }
}

// ── EdgeHello ───────────────────────────────────────────────────────────

/// The wire versions whose hello carries the tail.
///
/// The tail is the flags byte, the port count and the offered ports: version
/// 2 introduced it, version 3 kept it, and version 4 -- the packet plane --
/// kept it as well. Any other version consumes the original four bytes, even
/// when the buffer behind them looks like a tail.
const HELLO_TAIL_VERSIONS: std::ops::RangeInclusive<u8> = 2..=4;

/// Client -> edge, first message on a freshly established V9 tunnel.
///
/// Version 1 is exactly [`Self::ENCODED_LEN`] bytes. Version 2 and version 3
/// append one flags byte, a port count `n` (0..=[`Self::MAX_OFFERED_PORTS`]),
/// and `n` big-endian `u16` ports. Bit 0 of `flags` is [`Self::FLAG_COMMIT`],
/// bit 1 is [`Self::FLAG_ACCEPTS_ASSIGNMENT`]. Every other bit must be 0.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EdgeHello {
    /// This wire's own protocol version (independent of the V9 tunnel
    /// version underneath it).
    pub version: u8,
    pub exit: ExitPreference,
    /// Version-2 and version-3 flags. Not written on version 1. Bit 0 is commit.
    pub flags: u8,
    /// Version-2 and version-3 offered TCP ports, in the order the client
    /// listed them. Not written on version 1.
    pub offered_ports: Vec<u16>,
}

impl EdgeHello {
    /// Version-1 size: `[1B version][3B ExitPreference]`. Version 2 is longer.
    pub const ENCODED_LEN: usize = 1 + ExitPreference::ENCODED_LEN;
    /// Bit 0: this dial is the face the edge already assigned.
    pub const FLAG_COMMIT: u8 = 0x01;
    /// Bit 1: this client can take the address the box assigns it.
    ///
    /// The packet plane gives every client behind one box its OWN address,
    /// and the client has to put that address on its tunnel adapter. An
    /// older client cannot: it keeps the address it always had. The flag
    /// tells the box which kind of client it is talking to -- the box
    /// assigns an address only to a client that asked for one, so an older
    /// client and a new box still work together.
    pub const FLAG_ACCEPTS_ASSIGNMENT: u8 = 0x02;
    /// Largest `n` a version-2 or version-3 hello may carry.
    pub const MAX_OFFERED_PORTS: usize = 8;

    /// Encode. The version-2 tail is written when the version is one of
    /// [`HELLO_TAIL_VERSIONS`].
    pub fn encode(&self) -> Result<Vec<u8>, EdgeSessionError> {
        let pref = self.exit.encode();
        let mut out = Vec::with_capacity(Self::ENCODED_LEN + 2 + self.offered_ports.len() * 2);
        out.push(self.version);
        out.extend_from_slice(&pref);
        if HELLO_TAIL_VERSIONS.contains(&self.version) {
            if self.flags & !(Self::FLAG_COMMIT | Self::FLAG_ACCEPTS_ASSIGNMENT) != 0 {
                return Err(EdgeSessionError::ReservedHelloFlags { flags: self.flags });
            }
            if self.offered_ports.len() > Self::MAX_OFFERED_PORTS {
                return Err(EdgeSessionError::TooManyOfferedPorts {
                    count: self.offered_ports.len(),
                    max: Self::MAX_OFFERED_PORTS,
                });
            }
            out.push(self.flags);
            out.push(self.offered_ports.len() as u8);
            for port in &self.offered_ports {
                out.extend_from_slice(&port.to_be_bytes());
            }
        }
        Ok(out)
    }

    /// Decode from the front of `buf`. Version 1 consumes exactly 4 bytes.
    /// Every version from 2 up returns [`EdgeSessionError::Truncated`] until
    /// the tail is complete. Any other version consumes exactly 4 bytes,
    /// same as version 1.
    pub fn decode(buf: &[u8]) -> Result<(Self, usize), EdgeSessionError> {
        if buf.len() < Self::ENCODED_LEN {
            return Err(EdgeSessionError::Truncated {
                context: "EdgeHello",
                need: Self::ENCODED_LEN,
                have: buf.len(),
            });
        }
        let version = buf[0];
        let (exit, _) = ExitPreference::decode(&buf[1..Self::ENCODED_LEN])?;
        if !HELLO_TAIL_VERSIONS.contains(&version) {
            return Ok((
                EdgeHello {
                    version,
                    exit,
                    flags: 0,
                    offered_ports: Vec::new(),
                },
                Self::ENCODED_LEN,
            ));
        }
        if buf.len() < Self::ENCODED_LEN + 2 {
            return Err(EdgeSessionError::Truncated {
                context: "EdgeHello flags",
                need: Self::ENCODED_LEN + 2,
                have: buf.len(),
            });
        }
        let flags = buf[Self::ENCODED_LEN];
        if flags & !(Self::FLAG_COMMIT | Self::FLAG_ACCEPTS_ASSIGNMENT) != 0 {
            return Err(EdgeSessionError::ReservedHelloFlags { flags });
        }
        let n = buf[Self::ENCODED_LEN + 1] as usize;
        if n > Self::MAX_OFFERED_PORTS {
            return Err(EdgeSessionError::TooManyOfferedPorts {
                count: n,
                max: Self::MAX_OFFERED_PORTS,
            });
        }
        let total = Self::ENCODED_LEN + 2 + n * 2;
        if buf.len() < total {
            return Err(EdgeSessionError::Truncated {
                context: "EdgeHello ports",
                need: total,
                have: buf.len(),
            });
        }
        let mut offered_ports = Vec::with_capacity(n);
        for i in 0..n {
            let off = Self::ENCODED_LEN + 2 + i * 2;
            offered_ports.push(u16::from_be_bytes([buf[off], buf[off + 1]]));
        }
        Ok((
            EdgeHello {
                version,
                exit,
                flags,
                offered_ports,
            },
            total,
        ))
    }
}

// ── Offered-face transport filtering ─────────────────────────────────────

/// The transport a face's outer camouflage rides on the wire.
///
/// This is the SAME rule the client dialer applies
/// ([`mirage_protocol::client_transport::camouflage_transport`]): a face
/// wearing a datagram camouflage is dialled over datagrams, a face wearing
/// a stream camouflage over a stream. A caller that assembles an
/// [`EdgeHello`] asks this question so that the faces it offers and the
/// transport its session actually rides can never disagree.
pub fn face_transport(camouflage: &TransportCamouflage) -> TransportKind {
    camouflage_transport(camouflage)
}

/// Whether this camouflage has a port namespace a face could be offered in.
///
/// ICMP has none — it identifies a peer by address, not by port — so an
/// ICMP face cannot be advertised in an [`EdgeHello`], which carries bare
/// port numbers.
fn has_port_namespace(camouflage: &TransportCamouflage) -> bool {
    !matches!(camouflage, TransportCamouflage::Icmp { .. })
}

/// Keep only the offered faces that ride `transport`.
///
/// The [`EdgeHello`] wire format carries bare port numbers and NO
/// transport tag, so the edge cannot tell a TCP port from a UDP one. The
/// client therefore MUST offer only faces of the transport its session
/// actually rides: a client whose session rides datagrams must not also
/// offer its stream faces, or the edge may assign one of them back — the
/// follow-up dial would then be a stream dial on a datagram session and
/// would break.
///
/// `faces` — `(index, camouflage, port)` triples in the caller's own
/// entrance order. `index` is the caller's own index into its entrance
/// list and is carried through unchanged, so the caller can map a returned
/// face back to the entrance it came from.
///
/// A face whose camouflage has no port namespace (ICMP) is never offered,
/// whatever `transport` says — there is no port to put in the hello.
///
/// The result preserves the input order and is NOT capped at
/// [`EdgeHello::MAX_OFFERED_PORTS`]: that cap is a wire-format limit the
/// caller must check before encoding.
pub fn filter_offered_faces_by_transport(
    faces: &[(usize, &TransportCamouflage, u16)],
    transport: TransportKind,
) -> Vec<(usize, u16)> {
    faces
        .iter()
        .filter(|(_, camouflage, _)| {
            has_port_namespace(camouflage) && face_transport(camouflage) == transport
        })
        .map(|(index, _, port)| (*index, *port))
        .collect()
}

// ── EdgeRefusal ─────────────────────────────────────────────────────────

/// Named reasons an edge refuses an [`EdgeHello`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EdgeRefusal {
    /// The client's [`EdgeHello::version`] is not one this edge speaks.
    UnsupportedVersion { requested: u8, supported: u8 },
    /// The client asked for a specific country this edge cannot serve.
    CountryUnavailable { requested: CountryCode },
}

impl EdgeRefusal {
    const TAG_UNSUPPORTED_VERSION: u8 = 0x00;
    const TAG_COUNTRY_UNAVAILABLE: u8 = 0x01;

    /// Fixed 3-byte wire form: `[1B tag][2B payload]`.
    pub const ENCODED_LEN: usize = 3;

    pub fn encode(&self) -> [u8; Self::ENCODED_LEN] {
        match self {
            EdgeRefusal::UnsupportedVersion { requested, supported } => {
                [Self::TAG_UNSUPPORTED_VERSION, *requested, *supported]
            }
            EdgeRefusal::CountryUnavailable { requested } => {
                let bytes = requested.encode();
                [Self::TAG_COUNTRY_UNAVAILABLE, bytes[0], bytes[1]]
            }
        }
    }

    /// Decode from the front of `buf`. Returns `(Self, 3)`.
    pub fn decode(buf: &[u8]) -> Result<(Self, usize), EdgeSessionError> {
        if buf.len() < Self::ENCODED_LEN {
            return Err(EdgeSessionError::Truncated {
                context: "EdgeRefusal",
                need: Self::ENCODED_LEN,
                have: buf.len(),
            });
        }
        match buf[0] {
            Self::TAG_UNSUPPORTED_VERSION => Ok((
                EdgeRefusal::UnsupportedVersion {
                    requested: buf[1],
                    supported: buf[2],
                },
                Self::ENCODED_LEN,
            )),
            Self::TAG_COUNTRY_UNAVAILABLE => {
                let cc = CountryCode::decode([buf[1], buf[2]])?;
                Ok((EdgeRefusal::CountryUnavailable { requested: cc }, Self::ENCODED_LEN))
            }
            other => Err(EdgeSessionError::UnsupportedRefusalTag { tag: other }),
        }
    }
}

// ── EdgeOutcome ─────────────────────────────────────────────────────────

/// What the edge decided about the client's [`EdgeHello`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EdgeOutcome {
    /// Admitted — `exit` is what the edge will actually fulfil (may differ
    /// from the request only in that `Auto` resolves to the box's own
    /// default intent server-side; the client never learns which node).
    Accepted { exit: ExitPreference },
    Refused(EdgeRefusal),
}

impl EdgeOutcome {
    const TAG_ACCEPTED: u8 = 0x00;
    const TAG_REFUSED: u8 = 0x01;

    /// Fixed 4-byte wire form: `[1B tag][3B payload]`.
    pub const ENCODED_LEN: usize = 1 + ExitPreference::ENCODED_LEN;

    pub fn encode(&self) -> [u8; Self::ENCODED_LEN] {
        match self {
            EdgeOutcome::Accepted { exit } => {
                let e = exit.encode();
                [Self::TAG_ACCEPTED, e[0], e[1], e[2]]
            }
            EdgeOutcome::Refused(refusal) => {
                let r = refusal.encode();
                [Self::TAG_REFUSED, r[0], r[1], r[2]]
            }
        }
    }

    /// Decode from the front of `buf`. Returns `(Self, 4)`.
    pub fn decode(buf: &[u8]) -> Result<(Self, usize), EdgeSessionError> {
        if buf.len() < Self::ENCODED_LEN {
            return Err(EdgeSessionError::Truncated {
                context: "EdgeOutcome",
                need: Self::ENCODED_LEN,
                have: buf.len(),
            });
        }
        match buf[0] {
            Self::TAG_ACCEPTED => {
                let (exit, _) = ExitPreference::decode(&buf[1..Self::ENCODED_LEN])?;
                Ok((EdgeOutcome::Accepted { exit }, Self::ENCODED_LEN))
            }
            Self::TAG_REFUSED => {
                let (refusal, _) = EdgeRefusal::decode(&buf[1..Self::ENCODED_LEN])?;
                Ok((EdgeOutcome::Refused(refusal), Self::ENCODED_LEN))
            }
            other => Err(EdgeSessionError::UnsupportedOutcomeTag { tag: other }),
        }
    }
}

// ── EdgeWelcome ─────────────────────────────────────────────────────────

/// The address the box assigned to this client.
///
/// The box is an L3 forwarder: every client behind it needs its OWN address
/// in the client network, or two of them would collide on one address. The
/// box hands the address out when the peer joins and tells the peer which one
/// it got; the peer puts exactly that address on its tunnel adapter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientAssignment {
    /// The address the client must put on its tunnel adapter.
    pub addr: Ipv4Addr,
    /// The prefix length of the client's network.
    pub prefix: u8,
}

/// Edge -> client, in answer to [`EdgeHello`].
///
/// Version 1 has no trailer. Version 2 appends the assigned face port.
/// Version 3 appends that port and one flags byte.
/// Version 4 appends the address the box assigned to this client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EdgeWelcome {
    /// This wire's own protocol version, as understood by the edge.
    pub version: u8,
    /// Countries this edge can serve — never nodes, never topology.
    pub countries: Vec<CountryCode>,
    pub outcome: EdgeOutcome,
    /// Version 2 and version 3: the TCP face port the edge assigned for this
    /// session. `None` on version 1, which has no port trailer.
    pub assigned_face_port: Option<u16>,
    /// `Some` only on version 3. `Some(true)` means this exit accepts `StreamKind::Udp`.
    pub carries_datagrams: Option<bool>,
    /// Version 4: the address the box assigned to this client. `None` on the
    /// older versions, which have no such trailer, and `None` on a version-4
    /// welcome that carries the unspecified address -- the box assigned
    /// nothing, which is what the mux path says.
    pub assigned_client: Option<ClientAssignment>,
}

impl EdgeWelcome {
    /// Upper bound on `countries.len()`. ISO 3166-1 assigns 249 alpha-2
    /// codes; 250 leaves a single slot of slack while still catching a
    /// malformed or hostile count long before the wire's 1-byte count field
    /// (max 255) would.
    pub const MAX_COUNTRIES: usize = 250;
    /// Bit 0 of the version-3 flags byte: this exit accepts `StreamKind::Udp`.
    pub const FLAG_CARRIES_DATAGRAMS: u8 = 0x01;

    pub fn encode(&self) -> Result<Vec<u8>, EdgeSessionError> {
        if self.countries.len() > Self::MAX_COUNTRIES {
            return Err(EdgeSessionError::TooManyCountries {
                count: self.countries.len(),
                max: Self::MAX_COUNTRIES,
            });
        }
        let mut out = Vec::with_capacity(
            1 + 1 + self.countries.len() * 2 + EdgeOutcome::ENCODED_LEN + 8,
        );
        out.push(self.version);
        out.push(self.countries.len() as u8);
        for cc in &self.countries {
            out.extend_from_slice(&cc.encode());
        }
        out.extend_from_slice(&self.outcome.encode());
        // Version 1 ignores `carries_datagrams`.
        if self.version >= 2 {
            let port = self.assigned_face_port.ok_or(EdgeSessionError::MissingAssignedFacePort)?;
            out.extend_from_slice(&port.to_be_bytes());
        }
        if self.version >= 3 {
            let carries = self.carries_datagrams.ok_or(EdgeSessionError::MissingDatagramFlag)?;
            // A bool only writes bit 0. A reserved bit cannot be represented
            // here; decode rejects any other bit.
            out.push(if carries { Self::FLAG_CARRIES_DATAGRAMS } else { 0 });
        }
        if self.version >= 4 {
            // Version 4 is the packet plane: the box names the address this
            // client owns. The unspecified address means the box assigned
            // nothing -- the mux path has no tunnel address to hand out.
            let (addr, prefix) = match self.assigned_client {
                Some(assignment) => (assignment.addr, assignment.prefix),
                None => (Ipv4Addr::UNSPECIFIED, 0),
            };
            out.extend_from_slice(&addr.octets());
            out.push(prefix);
        }
        Ok(out)
    }

    /// Decode from the front of `buf`. Returns `(Self, bytes_consumed)`.
    pub fn decode(buf: &[u8]) -> Result<(Self, usize), EdgeSessionError> {
        if buf.len() < 2 {
            return Err(EdgeSessionError::Truncated {
                context: "EdgeWelcome header",
                need: 2,
                have: buf.len(),
            });
        }
        let version = buf[0];
        let count = buf[1] as usize;
        if count > Self::MAX_COUNTRIES {
            return Err(EdgeSessionError::TooManyCountries {
                count,
                max: Self::MAX_COUNTRIES,
            });
        }
        let countries_end = 2 + count * 2;
        if buf.len() < countries_end {
            return Err(EdgeSessionError::Truncated {
                context: "EdgeWelcome countries",
                need: countries_end,
                have: buf.len(),
            });
        }
        let mut countries = Vec::with_capacity(count);
        for i in 0..count {
            let off = 2 + i * 2;
            countries.push(CountryCode::decode([buf[off], buf[off + 1]])?);
        }
        if buf.len() < countries_end + EdgeOutcome::ENCODED_LEN {
            return Err(EdgeSessionError::Truncated {
                context: "EdgeWelcome outcome",
                need: countries_end + EdgeOutcome::ENCODED_LEN,
                have: buf.len(),
            });
        }
        let (outcome, consumed) = EdgeOutcome::decode(&buf[countries_end..])?;
        let mut total = countries_end + consumed;
        let mut assigned_face_port = None;
        let mut carries_datagrams = None;
        let mut assigned_client = None;
        if version >= 2 {
            if buf.len() < total + 2 {
                return Err(EdgeSessionError::Truncated {
                    context: "EdgeWelcome assigned_face_port",
                    need: total + 2,
                    have: buf.len(),
                });
            }
            assigned_face_port = Some(u16::from_be_bytes([buf[total], buf[total + 1]]));
            total += 2;
        }
        if version >= 3 {
            if buf.len() < total + 1 {
                return Err(EdgeSessionError::Truncated {
                    context: "EdgeWelcome flags",
                    need: total + 1,
                    have: buf.len(),
                });
            }
            let flags = buf[total];
            if flags & !Self::FLAG_CARRIES_DATAGRAMS != 0 {
                return Err(EdgeSessionError::ReservedWelcomeFlags { flags });
            }
            carries_datagrams = Some(flags & Self::FLAG_CARRIES_DATAGRAMS != 0);
            total += 1;
        }
        if version >= 4 {
            // The address the box assigned to this client: four octets of
            // address and one octet of prefix. The unspecified address means
            // the box assigned nothing.
            if buf.len() < total + 5 {
                return Err(EdgeSessionError::Truncated {
                    context: "EdgeWelcome assigned_client",
                    need: total + 5,
                    have: buf.len(),
                });
            }
            let addr = Ipv4Addr::new(buf[total], buf[total + 1], buf[total + 2], buf[total + 3]);
            let prefix = buf[total + 4];
            total += 5;
            if !addr.is_unspecified() {
                assigned_client = Some(ClientAssignment { addr, prefix });
            }
        }
        Ok((
            EdgeWelcome {
                version,
                countries,
                outcome,
                assigned_face_port,
                carries_datagrams,
                assigned_client,
            },
            total,
        ))
    }
}

// ── StreamKind / StreamTarget / StreamOpen ─────────────────────────────

/// What kind of flow a mux stream carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamKind {
    Tcp,
    Udp,
}

impl StreamKind {
    const TAG_TCP: u8 = 0x00;
    const TAG_UDP: u8 = 0x01;

    pub fn encode(&self) -> u8 {
        match self {
            StreamKind::Tcp => Self::TAG_TCP,
            StreamKind::Udp => Self::TAG_UDP,
        }
    }

    pub fn decode(tag: u8) -> Result<Self, EdgeSessionError> {
        match tag {
            Self::TAG_TCP => Ok(StreamKind::Tcp),
            Self::TAG_UDP => Ok(StreamKind::Udp),
            other => Err(EdgeSessionError::UnsupportedStreamKind { tag: other }),
        }
    }
}

/// A validated stream destination — the exact `host:port` ASCII string the
/// client asked for. See the module doc for why a TCP `StreamOpen`'s target
/// bytes are handed to `ChainMuxPool::open_stream` unmodified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamTarget(String);

impl StreamTarget {
    /// Matches the 512-byte address buffer the mesh's onion exit reads a mux
    /// stream target into
    /// (`mirage2node::family::mirage::exit::{onion,direct}`'s `addr_buf`) —
    /// a target this module admits can never be too large for that exit to
    /// hold.
    pub const MAX_LEN: usize = 512;

    /// Validate and wrap a target string: non-empty, at most
    /// [`Self::MAX_LEN`] bytes.
    pub fn new(target: impl Into<String>) -> Result<Self, EdgeSessionError> {
        let target = target.into();
        if target.is_empty() {
            return Err(EdgeSessionError::EmptyTarget);
        }
        if target.len() > Self::MAX_LEN {
            return Err(EdgeSessionError::TargetTooLong {
                len: target.len(),
                max: Self::MAX_LEN,
            });
        }
        Ok(Self(target))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for StreamTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// The first bytes of every mux stream the edge accepts from the client —
/// what kind of flow this is and where it goes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamOpen {
    pub kind: StreamKind,
    pub target: StreamTarget,
}

impl StreamOpen {
    /// `[1B kind][2B BE target_len][target bytes]`.
    pub fn encode(&self) -> Vec<u8> {
        let target_bytes = self.target.as_str().as_bytes();
        let mut out = Vec::with_capacity(1 + 2 + target_bytes.len());
        out.push(self.kind.encode());
        out.extend_from_slice(&(target_bytes.len() as u16).to_be_bytes());
        out.extend_from_slice(target_bytes);
        out
    }

    /// Decode from the front of `buf`. Returns `(Self, bytes_consumed)`.
    pub fn decode(buf: &[u8]) -> Result<(Self, usize), EdgeSessionError> {
        if buf.len() < 3 {
            return Err(EdgeSessionError::Truncated {
                context: "StreamOpen header",
                need: 3,
                have: buf.len(),
            });
        }
        let kind = StreamKind::decode(buf[0])?;
        let target_len = u16::from_be_bytes([buf[1], buf[2]]) as usize;
        if target_len == 0 {
            return Err(EdgeSessionError::EmptyTarget);
        }
        if target_len > StreamTarget::MAX_LEN {
            return Err(EdgeSessionError::TargetTooLong {
                len: target_len,
                max: StreamTarget::MAX_LEN,
            });
        }
        let need = 3 + target_len;
        if buf.len() < need {
            return Err(EdgeSessionError::Truncated {
                context: "StreamOpen target",
                need,
                have: buf.len(),
            });
        }
        let target_bytes = &buf[3..need];
        let target_str = std::str::from_utf8(target_bytes).map_err(|_| EdgeSessionError::TargetNotUtf8 {
            bytes: target_bytes.to_vec(),
        })?;
        let target = StreamTarget::new(target_str)?;
        Ok((StreamOpen { kind, target }, need))
    }
}

// ── UDP datagram-on-stream codec ────────────────────────────────────────

/// Largest UDP datagram payload the framing carries — the largest UDP
/// payload representable at all over IPv4, matching
/// [`crate::udp_framing::MAX_UDP_DATAGRAM`].
pub const MAX_UDP_DATAGRAM_PAYLOAD: usize = crate::udp_framing::MAX_UDP_DATAGRAM;

/// Encode one UDP datagram as `[2B BE len][payload]` — the pure byte-buffer
/// form of the same frame shape
/// [`crate::udp_framing::write_udp_frame`] writes over an `AsyncWrite`. A
/// zero-length payload is not rejected here (it is left un-special-cased —
/// whatever relay eventually carries these decides what, if anything, a
/// zero-length datagram means).
pub fn encode_udp_datagram_frame(payload: &[u8]) -> Result<Vec<u8>, EdgeSessionError> {
    if payload.len() > MAX_UDP_DATAGRAM_PAYLOAD {
        return Err(EdgeSessionError::DatagramTooLarge {
            len: payload.len(),
            max: MAX_UDP_DATAGRAM_PAYLOAD,
        });
    }
    let mut out = Vec::with_capacity(2 + payload.len());
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

/// Decode one `[2B BE len][payload]` UDP datagram frame from the front of
/// `buf`. Returns the payload slice and the total bytes consumed
/// (`2 + len`), leaving any trailing bytes in `buf` untouched.
pub fn decode_udp_datagram_frame(buf: &[u8]) -> Result<(&[u8], usize), EdgeSessionError> {
    if buf.len() < 2 {
        return Err(EdgeSessionError::Truncated {
            context: "udp datagram frame header",
            need: 2,
            have: buf.len(),
        });
    }
    let len = u16::from_be_bytes([buf[0], buf[1]]) as usize;
    if len > MAX_UDP_DATAGRAM_PAYLOAD {
        return Err(EdgeSessionError::DatagramTooLarge {
            len,
            max: MAX_UDP_DATAGRAM_PAYLOAD,
        });
    }
    let need = 2 + len;
    if buf.len() < need {
        return Err(EdgeSessionError::Truncated {
            context: "udp datagram frame payload",
            need,
            have: buf.len(),
        });
    }
    Ok((&buf[2..need], need))
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── CountryCode ─────────────────────────────────────────────────────

    #[test]
    fn country_code_round_trip() {
        let cc = CountryCode::new("US").expect("valid code");
        assert_eq!(cc.as_str(), "US");
        let encoded = cc.encode();
        let decoded = CountryCode::decode(encoded).expect("valid bytes");
        assert_eq!(cc, decoded);
    }

    #[test]
    fn country_code_rejects_lowercase() {
        assert_eq!(
            CountryCode::new("us"),
            Err(EdgeSessionError::InvalidCountryCode {
                input: "us".to_string()
            })
        );
    }

    #[test]
    fn country_code_rejects_wrong_length() {
        assert_eq!(
            CountryCode::new("USA"),
            Err(EdgeSessionError::InvalidCountryCode {
                input: "USA".to_string()
            })
        );
    }

    #[test]
    fn country_code_decode_rejects_non_ascii_uppercase_bytes() {
        let err = CountryCode::decode([0xC3, 0x9F]).unwrap_err();
        assert!(matches!(err, EdgeSessionError::InvalidCountryCode { .. }));
    }

    // ── ExitPreference ──────────────────────────────────────────────────

    #[test]
    fn exit_preference_auto_round_trip() {
        let pref = ExitPreference::Auto;
        let encoded = pref.encode();
        let (decoded, consumed) = ExitPreference::decode(&encoded).expect("decodes");
        assert_eq!(decoded, pref);
        assert_eq!(consumed, ExitPreference::ENCODED_LEN);
    }

    #[test]
    fn exit_preference_country_round_trip() {
        let pref = ExitPreference::Country(CountryCode::new("DE").expect("valid"));
        let encoded = pref.encode();
        let (decoded, consumed) = ExitPreference::decode(&encoded).expect("decodes");
        assert_eq!(decoded, pref);
        assert_eq!(consumed, ExitPreference::ENCODED_LEN);
    }

    #[test]
    fn exit_preference_rejects_bad_tag() {
        let err = ExitPreference::decode(&[0x02, 0, 0]).unwrap_err();
        assert_eq!(err, EdgeSessionError::UnsupportedExitTag { tag: 0x02 });
    }

    #[test]
    fn exit_preference_rejects_non_canonical_auto_padding() {
        let err = ExitPreference::decode(&[0x00, 0x41, 0x00]).unwrap_err();
        assert_eq!(
            err,
            EdgeSessionError::NonCanonicalAutoPadding { bytes: [0x41, 0x00] }
        );
    }

    #[test]
    fn exit_preference_decode_truncated() {
        let err = ExitPreference::decode(&[0x00, 0x00]).unwrap_err();
        assert_eq!(
            err,
            EdgeSessionError::Truncated {
                context: "ExitPreference",
                need: 3,
                have: 2
            }
        );
    }

    // ── EdgeHello ───────────────────────────────────────────────────────

    #[test]
    fn edge_hello_round_trip_auto() {
        let hello = EdgeHello {
            version: 1,
            exit: ExitPreference::Auto,
            flags: 0,
            offered_ports: Vec::new(),
        };
        let encoded = hello.encode().expect("encodes");
        assert_eq!(encoded, vec![1, 0, 0, 0]);
        let (decoded, consumed) = EdgeHello::decode(&encoded).expect("decodes");
        assert_eq!(decoded, hello);
        assert_eq!(consumed, EdgeHello::ENCODED_LEN);
    }

    #[test]
    fn edge_hello_round_trip_country() {
        let hello = EdgeHello {
            version: 1,
            exit: ExitPreference::Country(CountryCode::new("NL").expect("valid")),
            flags: 0,
            offered_ports: Vec::new(),
        };
        let encoded = hello.encode().expect("encodes");
        assert_eq!(encoded, vec![1, 1, b'N', b'L']);
        let (decoded, _) = EdgeHello::decode(&encoded).expect("decodes");
        assert_eq!(decoded, hello);
    }

    #[test]
    fn edge_hello_decode_truncated() {
        let err = EdgeHello::decode(&[1, 0]).unwrap_err();
        assert_eq!(
            err,
            EdgeSessionError::Truncated {
                context: "EdgeHello",
                need: 4,
                have: 2
            }
        );
    }

    #[test]
    fn edge_hello_ignores_trailing_bytes() {
        let hello = EdgeHello {
            version: 1,
            exit: ExitPreference::Auto,
            flags: 0,
            offered_ports: Vec::new(),
        };
        let mut buf = hello.encode().expect("encodes");
        buf.extend_from_slice(b"trailing garbage");
        let (decoded, consumed) = EdgeHello::decode(&buf).expect("decodes");
        assert_eq!(decoded, hello);
        assert_eq!(consumed, EdgeHello::ENCODED_LEN);
    }

    #[test]
    fn edge_hello_version_2_round_trip_commit_and_ports() {
        let hello = EdgeHello {
            version: 2,
            exit: ExitPreference::Auto,
            flags: EdgeHello::FLAG_COMMIT,
            offered_ports: vec![80, 443, 8080],
        };
        let encoded = hello.encode().expect("encodes");
        assert_eq!(
            encoded,
            vec![2, 0, 0, 0, 0x01, 3, 0x00, 0x50, 0x01, 0xBB, 0x1F, 0x90]
        );
        let (decoded, consumed) = EdgeHello::decode(&encoded).expect("decodes");
        assert_eq!(decoded, hello);
        assert_eq!(consumed, encoded.len());
    }

    #[test]
    fn edge_hello_version_2_zero_ports_is_six_bytes() {
        let hello = EdgeHello {
            version: 2,
            exit: ExitPreference::Auto,
            flags: 0,
            offered_ports: Vec::new(),
        };
        let encoded = hello.encode().expect("encodes");
        assert_eq!(encoded, vec![2, 0, 0, 0, 0, 0]);
        let (decoded, consumed) = EdgeHello::decode(&encoded).expect("decodes");
        assert_eq!(decoded, hello);
        assert_eq!(consumed, 6);
    }

    #[test]
    fn edge_hello_version_2_truncated_until_tail_is_complete() {
        let err = EdgeHello::decode(&[2, 0, 0, 0]).unwrap_err();
        assert_eq!(
            err,
            EdgeSessionError::Truncated {
                context: "EdgeHello flags",
                need: 6,
                have: 4
            }
        );
        // n = 2, only one of the four port bytes is present.
        let err = EdgeHello::decode(&[2, 0, 0, 0, 0, 2, 0x00]).unwrap_err();
        assert_eq!(
            err,
            EdgeSessionError::Truncated {
                context: "EdgeHello ports",
                need: 10,
                have: 7
            }
        );
    }

    #[test]
    fn edge_hello_version_2_rejects_reserved_flags_and_too_many_ports() {
        // Bit 2 is still reserved: only the commit bit and the assignment
        // bit are spoken for.
        let err = EdgeHello::decode(&[2, 0, 0, 0, 0x04, 0]).unwrap_err();
        assert_eq!(err, EdgeSessionError::ReservedHelloFlags { flags: 0x04 });
        let err = EdgeHello::decode(&[2, 0, 0, 0, 0, 9]).unwrap_err();
        assert_eq!(
            err,
            EdgeSessionError::TooManyOfferedPorts {
                count: 9,
                max: EdgeHello::MAX_OFFERED_PORTS
            }
        );
        let hello = EdgeHello {
            version: 2,
            exit: ExitPreference::Auto,
            flags: 0x04,
            offered_ports: Vec::new(),
        };
        assert_eq!(
            hello.encode().unwrap_err(),
            EdgeSessionError::ReservedHelloFlags { flags: 0x04 }
        );
        let hello = EdgeHello {
            version: 2,
            exit: ExitPreference::Auto,
            flags: 0,
            offered_ports: vec![1, 2, 3, 4, 5, 6, 7, 8, 9],
        };
        assert_eq!(
            hello.encode().unwrap_err(),
            EdgeSessionError::TooManyOfferedPorts {
                count: 9,
                max: EdgeHello::MAX_OFFERED_PORTS
            }
        );
    }

    #[test]
    fn edge_hello_version_other_than_2_ignores_a_tail() {
        // A version other than 2 or 3 still consumes the original 4 bytes,
        // even when the buffer looks like it might have a version-2 tail.
        let buf = [9u8, 0, 0, 0, 0x01, 1, 0x00, 0x50];
        let (decoded, consumed) = EdgeHello::decode(&buf).expect("decodes");
        assert_eq!(consumed, 4);
        assert_eq!(decoded.version, 9);
        assert_eq!(decoded.flags, 0);
        assert!(decoded.offered_ports.is_empty());
    }

    /// The hello carries the flag that says the client can take an address
    /// the box assigns it.
    #[test]
    fn edge_hello_version_4_carries_the_assignment_flag() {
        let hello = EdgeHello {
            version: 4,
            exit: ExitPreference::Auto,
            flags: EdgeHello::FLAG_ACCEPTS_ASSIGNMENT,
            offered_ports: Vec::new(),
        };
        let encoded = hello.encode().expect("encodes");
        let (decoded, consumed) = EdgeHello::decode(&encoded).expect("decodes");
        assert_eq!(decoded, hello);
        assert_eq!(consumed, encoded.len());
    }

    #[test]
    fn edge_hello_version_3_round_trip_commit_and_one_port() {
        let hello = EdgeHello {
            version: 3,
            exit: ExitPreference::Auto,
            flags: EdgeHello::FLAG_COMMIT,
            offered_ports: vec![443],
        };
        let encoded = hello.encode().expect("encodes");
        assert_eq!(encoded, vec![3, 0, 0, 0, 0x01, 1, 0x01, 0xBB]);
        let (decoded, consumed) = EdgeHello::decode(&encoded).expect("decodes");
        assert_eq!(decoded, hello);
        assert_eq!(consumed, encoded.len());
    }

    #[test]
    fn edge_hello_version_3_reserved_flag_fails_encode_and_decode() {
        let err = EdgeHello::decode(&[3, 0, 0, 0, 0x04, 0]).unwrap_err();
        assert_eq!(err, EdgeSessionError::ReservedHelloFlags { flags: 0x04 });
        let hello = EdgeHello {
            version: 3,
            exit: ExitPreference::Auto,
            flags: 0x04,
            offered_ports: Vec::new(),
        };
        assert_eq!(hello.encode().unwrap_err(), EdgeSessionError::ReservedHelloFlags { flags: 0x04 });
    }

    // ── EdgeRefusal / EdgeOutcome ───────────────────────────────────────

    #[test]
    fn edge_refusal_unsupported_version_round_trip() {
        let refusal = EdgeRefusal::UnsupportedVersion {
            requested: 9,
            supported: 1,
        };
        let encoded = refusal.encode();
        let (decoded, _) = EdgeRefusal::decode(&encoded).expect("decodes");
        assert_eq!(decoded, refusal);
    }

    #[test]
    fn edge_refusal_country_unavailable_round_trip() {
        let refusal = EdgeRefusal::CountryUnavailable {
            requested: CountryCode::new("JP").expect("valid"),
        };
        let encoded = refusal.encode();
        let (decoded, _) = EdgeRefusal::decode(&encoded).expect("decodes");
        assert_eq!(decoded, refusal);
    }

    #[test]
    fn edge_refusal_rejects_bad_tag() {
        let err = EdgeRefusal::decode(&[0x02, 0, 0]).unwrap_err();
        assert_eq!(err, EdgeSessionError::UnsupportedRefusalTag { tag: 0x02 });
    }

    #[test]
    fn edge_outcome_accepted_round_trip() {
        let outcome = EdgeOutcome::Accepted {
            exit: ExitPreference::Country(CountryCode::new("FR").expect("valid")),
        };
        let encoded = outcome.encode();
        let (decoded, consumed) = EdgeOutcome::decode(&encoded).expect("decodes");
        assert_eq!(decoded, outcome);
        assert_eq!(consumed, EdgeOutcome::ENCODED_LEN);
    }

    #[test]
    fn edge_outcome_refused_round_trip() {
        let outcome = EdgeOutcome::Refused(EdgeRefusal::UnsupportedVersion {
            requested: 5,
            supported: 1,
        });
        let encoded = outcome.encode();
        let (decoded, _) = EdgeOutcome::decode(&encoded).expect("decodes");
        assert_eq!(decoded, outcome);
    }

    #[test]
    fn edge_outcome_rejects_bad_tag() {
        let err = EdgeOutcome::decode(&[0x02, 0, 0, 0]).unwrap_err();
        assert_eq!(err, EdgeSessionError::UnsupportedOutcomeTag { tag: 0x02 });
    }

    // ── EdgeWelcome ─────────────────────────────────────────────────────

    #[test]
    fn edge_welcome_round_trip_accepted_with_countries() {
        let welcome = EdgeWelcome {
            version: 1,
            countries: vec![
                CountryCode::new("US").expect("valid"),
                CountryCode::new("DE").expect("valid"),
                CountryCode::new("NL").expect("valid"),
            ],
            outcome: EdgeOutcome::Accepted {
                exit: ExitPreference::Country(CountryCode::new("NL").expect("valid")),
            },
            assigned_face_port: None,
            carries_datagrams: None,
            assigned_client: None,
        };
        let encoded = welcome.encode().expect("encodes");
        assert_eq!(
            encoded,
            vec![1, 3, b'U', b'S', b'D', b'E', b'N', b'L', 0, 1, b'N', b'L']
        );
        let (decoded, consumed) = EdgeWelcome::decode(&encoded).expect("decodes");
        assert_eq!(decoded, welcome);
        assert_eq!(consumed, encoded.len());
    }

    #[test]
    fn edge_welcome_round_trip_refused_no_countries() {
        let welcome = EdgeWelcome {
            version: 1,
            countries: vec![],
            outcome: EdgeOutcome::Refused(EdgeRefusal::CountryUnavailable {
                requested: CountryCode::new("ZZ").expect("valid"),
            }),
            assigned_face_port: None,
            carries_datagrams: None,
            assigned_client: None,
        };
        let encoded = welcome.encode().expect("encodes");
        assert_eq!(encoded, vec![1, 0, 1, 1, b'Z', b'Z']);
        let (decoded, consumed) = EdgeWelcome::decode(&encoded).expect("decodes");
        assert_eq!(decoded, welcome);
        assert_eq!(consumed, encoded.len());
    }

    #[test]
    fn edge_welcome_version_1_does_not_consume_a_port_trailer() {
        let mut buf = vec![1, 3, b'U', b'S', b'D', b'E', b'N', b'L', 0, 1, b'N', b'L'];
        let v1_len = buf.len();
        buf.extend_from_slice(&443u16.to_be_bytes());
        let (decoded, consumed) = EdgeWelcome::decode(&buf).expect("decodes");
        assert_eq!(consumed, v1_len);
        assert_eq!(decoded.version, 1);
        assert_eq!(decoded.assigned_face_port, None);
        assert_eq!(decoded.carries_datagrams, None);
    }

    #[test]
    fn edge_welcome_version_1_encode_ignores_a_port() {
        let welcome = EdgeWelcome {
            version: 1,
            countries: vec![],
            outcome: EdgeOutcome::Accepted { exit: ExitPreference::Auto },
            assigned_face_port: Some(443),
            carries_datagrams: None,
            assigned_client: None,
        };
        let encoded = welcome.encode().expect("version 1 does not write the port");
        assert_eq!(encoded, vec![1, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn edge_welcome_version_2_round_trip_appends_assigned_port() {
        let welcome = EdgeWelcome {
            version: 2,
            countries: vec![
                CountryCode::new("US").expect("valid"),
                CountryCode::new("DE").expect("valid"),
                CountryCode::new("NL").expect("valid"),
            ],
            outcome: EdgeOutcome::Accepted {
                exit: ExitPreference::Country(CountryCode::new("NL").expect("valid")),
            },
            assigned_face_port: Some(443),
            carries_datagrams: None,
            assigned_client: None,
        };
        let encoded = welcome.encode().expect("encodes");
        assert_eq!(
            encoded,
            vec![2, 3, b'U', b'S', b'D', b'E', b'N', b'L', 0, 1, b'N', b'L', 0x01, 0xBB]
        );
        let (decoded, consumed) = EdgeWelcome::decode(&encoded).expect("decodes");
        assert_eq!(decoded, welcome);
        assert_eq!(consumed, encoded.len());
    }

    #[test]
    fn edge_welcome_version_2_truncated_without_the_port() {
        let buf = vec![2, 3, b'U', b'S', b'D', b'E', b'N', b'L', 0, 1, b'N', b'L'];
        let err = EdgeWelcome::decode(&buf).unwrap_err();
        assert_eq!(
            err,
            EdgeSessionError::Truncated {
                context: "EdgeWelcome assigned_face_port",
                need: buf.len() + 2,
                have: buf.len()
            }
        );
    }

    #[test]
    fn edge_welcome_version_2_encode_requires_a_port() {
        let welcome = EdgeWelcome {
            version: 2,
            countries: vec![],
            outcome: EdgeOutcome::Accepted { exit: ExitPreference::Auto },
            assigned_face_port: None,
            carries_datagrams: None,
            assigned_client: None,
        };
        assert_eq!(welcome.encode().unwrap_err(), EdgeSessionError::MissingAssignedFacePort);
    }

    #[test]
    fn edge_welcome_version_3_round_trip_datagram_bit_set_and_clear() {
        let mut set = EdgeWelcome {
            version: 3,
            countries: vec![
                CountryCode::new("US").expect("valid"),
                CountryCode::new("DE").expect("valid"),
                CountryCode::new("NL").expect("valid"),
            ],
            outcome: EdgeOutcome::Accepted {
                exit: ExitPreference::Country(CountryCode::new("NL").expect("valid")),
            },
            assigned_face_port: Some(443),
            carries_datagrams: Some(true),
            assigned_client: None,
        };
        let encoded = set.encode().expect("encodes");
        assert_eq!(
            encoded,
            vec![3, 3, b'U', b'S', b'D', b'E', b'N', b'L', 0, 1, b'N', b'L', 0x01, 0xBB, 0x01]
        );
        let (decoded, consumed) = EdgeWelcome::decode(&encoded).expect("decodes");
        assert_eq!(decoded, set);
        assert_eq!(consumed, encoded.len());

        set.carries_datagrams = Some(false);
        let encoded = set.encode().expect("encodes");
        assert_eq!(
            encoded,
            vec![3, 3, b'U', b'S', b'D', b'E', b'N', b'L', 0, 1, b'N', b'L', 0x01, 0xBB, 0x00]
        );
        let (decoded, consumed) = EdgeWelcome::decode(&encoded).expect("decodes");
        assert_eq!(decoded, set);
        assert_eq!(consumed, encoded.len());
    }

    #[test]
    fn edge_welcome_version_3_truncated_after_the_port_on_the_flag_byte() {
        let buf = vec![3, 3, b'U', b'S', b'D', b'E', b'N', b'L', 0, 1, b'N', b'L', 0x01, 0xBB];
        let err = EdgeWelcome::decode(&buf).unwrap_err();
        assert_eq!(
            err,
            EdgeSessionError::Truncated {
                context: "EdgeWelcome flags",
                need: buf.len() + 1,
                have: buf.len()
            }
        );
    }

    #[test]
    fn edge_welcome_version_3_reserved_flag_fails_decode() {
        let buf = vec![3, 0, 0, 0, 0, 0, 0x00, 0x01, 0x02];
        assert_eq!(
            EdgeWelcome::decode(&buf).unwrap_err(),
            EdgeSessionError::ReservedWelcomeFlags { flags: 0x02 }
        );
        let buf = vec![3, 0, 0, 0, 0, 0, 0x00, 0x01, 0x03];
        assert_eq!(
            EdgeWelcome::decode(&buf).unwrap_err(),
            EdgeSessionError::ReservedWelcomeFlags { flags: 0x03 }
        );
    }

    #[test]
    fn edge_welcome_version_3_encode_requires_a_port() {
        let welcome = EdgeWelcome {
            version: 3,
            countries: vec![],
            outcome: EdgeOutcome::Accepted { exit: ExitPreference::Auto },
            assigned_face_port: None,
            carries_datagrams: Some(true),
            assigned_client: None,
        };
        assert_eq!(welcome.encode().unwrap_err(), EdgeSessionError::MissingAssignedFacePort);
    }

    #[test]
    fn edge_welcome_version_3_encode_requires_the_datagram_flag() {
        let welcome = EdgeWelcome {
            version: 3,
            countries: vec![],
            outcome: EdgeOutcome::Accepted { exit: ExitPreference::Auto },
            assigned_face_port: Some(443),
            carries_datagrams: None,
            assigned_client: None,
        };
        assert_eq!(welcome.encode().unwrap_err(), EdgeSessionError::MissingDatagramFlag);
    }

    #[test]
    fn edge_welcome_version_2_does_not_consume_a_datagram_flag_byte() {
        let mut buf = vec![2, 3, b'U', b'S', b'D', b'E', b'N', b'L', 0, 1, b'N', b'L', 0x01, 0xBB];
        let v2_len = buf.len();
        buf.push(0x01);
        let (decoded, consumed) = EdgeWelcome::decode(&buf).expect("decodes");
        assert_eq!(consumed, v2_len);
        assert_eq!(decoded.version, 2);
        assert_eq!(decoded.assigned_face_port, Some(443));
        assert_eq!(decoded.carries_datagrams, None);
    }

    #[test]
    fn edge_welcome_encode_rejects_too_many_countries() {
        let countries = (0..=EdgeWelcome::MAX_COUNTRIES)
            .map(|_| CountryCode::new("US").expect("valid"))
            .collect::<Vec<_>>();
        let welcome = EdgeWelcome {
            version: 1,
            countries,
            outcome: EdgeOutcome::Accepted {
                exit: ExitPreference::Auto,
            },
            assigned_face_port: None,
            carries_datagrams: None,
            assigned_client: None,
        };
        let err = welcome.encode().unwrap_err();
        assert_eq!(
            err,
            EdgeSessionError::TooManyCountries {
                count: EdgeWelcome::MAX_COUNTRIES + 1,
                max: EdgeWelcome::MAX_COUNTRIES
            }
        );
    }

    /// The version-4 welcome names the address the box assigned to this
    /// client: five bytes, four of address and one of prefix.
    #[test]
    fn edge_welcome_version_4_round_trip_carries_the_assigned_client() {
        let welcome = EdgeWelcome {
            version: 4,
            countries: vec![],
            outcome: EdgeOutcome::Accepted { exit: ExitPreference::Auto },
            assigned_face_port: Some(443),
            carries_datagrams: Some(true),
            assigned_client: Some(ClientAssignment {
                addr: Ipv4Addr::new(10, 77, 0, 7),
                prefix: 24,
            }),
        };
        let encoded = welcome.encode().expect("encodes");
        assert_eq!(
            encoded,
            vec![4, 0, 0, 0, 0, 0, 0x01, 0xBB, 0x01, 10, 77, 0, 7, 24]
        );
        let (decoded, consumed) = EdgeWelcome::decode(&encoded).expect("decodes");
        assert_eq!(decoded, welcome);
        assert_eq!(consumed, encoded.len());
    }

    /// The version-3 welcome keeps the bytes it always had: the address
    /// trailer is a version-4 thing, and an old box must still meet an old
    /// client.
    #[test]
    fn edge_welcome_version_3_carries_no_assigned_client() {
        let welcome = EdgeWelcome {
            version: 3,
            countries: vec![],
            outcome: EdgeOutcome::Accepted { exit: ExitPreference::Auto },
            assigned_face_port: Some(443),
            carries_datagrams: Some(true),
            assigned_client: None,
        };
        let encoded = welcome.encode().expect("encodes");
        assert_eq!(encoded, vec![3, 0, 0, 0, 0, 0, 0x01, 0xBB, 0x01]);
        let (decoded, consumed) = EdgeWelcome::decode(&encoded).expect("decodes");
        assert_eq!(decoded.assigned_client, None);
        assert_eq!(consumed, encoded.len());
    }

    /// A version-4 welcome with no assignment writes the unspecified
    /// address: the mux path has no tunnel address to hand out.
    #[test]
    fn edge_welcome_version_4_without_an_assignment_writes_the_unspecified_address() {
        let welcome = EdgeWelcome {
            version: 4,
            countries: vec![],
            outcome: EdgeOutcome::Accepted { exit: ExitPreference::Auto },
            assigned_face_port: Some(443),
            carries_datagrams: Some(true),
            assigned_client: None,
        };
        let encoded = welcome.encode().expect("encodes");
        assert_eq!(
            encoded,
            vec![4, 0, 0, 0, 0, 0, 0x01, 0xBB, 0x01, 0, 0, 0, 0, 0]
        );
        let (decoded, consumed) = EdgeWelcome::decode(&encoded).expect("decodes");
        assert_eq!(decoded.assigned_client, None);
        assert_eq!(consumed, encoded.len());
    }

    #[test]
    fn edge_welcome_version_4_truncated_in_the_assigned_client() {
        let buf = vec![4, 0, 0, 0, 0, 0, 0x01, 0xBB, 0x01, 10, 77, 0];
        let err = EdgeWelcome::decode(&buf).unwrap_err();
        assert_eq!(
            err,
            EdgeSessionError::Truncated {
                context: "EdgeWelcome assigned_client",
                need: buf.len() + 2,
                have: buf.len()
            }
        );
    }

    #[test]
    fn edge_welcome_decode_rejects_too_many_countries_in_header() {
        // count byte = 255, far above MAX_COUNTRIES, with no country bytes
        // following at all — must be rejected on the count check, not by
        // running out of buffer first.
        let buf = [1u8, 255];
        let err = EdgeWelcome::decode(&buf).unwrap_err();
        assert_eq!(
            err,
            EdgeSessionError::TooManyCountries {
                count: 255,
                max: EdgeWelcome::MAX_COUNTRIES
            }
        );
    }

    #[test]
    fn edge_welcome_decode_truncated_countries() {
        // Claims 2 countries but supplies only 1.
        let mut buf = vec![1u8, 2];
        buf.extend_from_slice(&CountryCode::new("US").expect("valid").encode());
        let err = EdgeWelcome::decode(&buf).unwrap_err();
        assert_eq!(
            err,
            EdgeSessionError::Truncated {
                context: "EdgeWelcome countries",
                need: 6,
                have: 4
            }
        );
    }

    #[test]
    fn edge_welcome_decode_truncated_outcome() {
        let mut buf = vec![1u8, 1];
        buf.extend_from_slice(&CountryCode::new("US").expect("valid").encode());
        // No outcome bytes at all.
        let err = EdgeWelcome::decode(&buf).unwrap_err();
        assert_eq!(
            err,
            EdgeSessionError::Truncated {
                context: "EdgeWelcome outcome",
                need: 8,
                have: 4
            }
        );
    }

    // ── StreamTarget / StreamOpen ───────────────────────────────────────

    #[test]
    fn stream_target_rejects_empty() {
        assert_eq!(StreamTarget::new(""), Err(EdgeSessionError::EmptyTarget));
    }

    #[test]
    fn stream_target_accepts_max_len() {
        let target = "a".repeat(StreamTarget::MAX_LEN);
        assert!(StreamTarget::new(target).is_ok());
    }

    #[test]
    fn stream_target_rejects_over_max_len() {
        let target = "a".repeat(StreamTarget::MAX_LEN + 1);
        let err = StreamTarget::new(target).unwrap_err();
        assert_eq!(
            err,
            EdgeSessionError::TargetTooLong {
                len: StreamTarget::MAX_LEN + 1,
                max: StreamTarget::MAX_LEN
            }
        );
    }

    #[test]
    fn stream_open_tcp_target_bytes_match_chain_mux_pool_dest() {
        // The exact string ChainMuxPool::open_stream's `dest: &str` would
        // receive for this flow — no scheme prefix, no transformation.
        let raw_dest = "93.184.216.34:443";
        let open = StreamOpen {
            kind: StreamKind::Tcp,
            target: StreamTarget::new(raw_dest).expect("valid"),
        };
        assert_eq!(open.target.as_str(), raw_dest);
    }

    #[test]
    fn stream_open_round_trip_tcp() {
        let open = StreamOpen {
            kind: StreamKind::Tcp,
            target: StreamTarget::new("example.com:443").expect("valid"),
        };
        let encoded = open.encode();
        let (decoded, consumed) = StreamOpen::decode(&encoded).expect("decodes");
        assert_eq!(decoded, open);
        assert_eq!(consumed, encoded.len());
    }

    #[test]
    fn stream_open_round_trip_udp() {
        let open = StreamOpen {
            kind: StreamKind::Udp,
            target: StreamTarget::new("1.1.1.1:53").expect("valid"),
        };
        let encoded = open.encode();
        let (decoded, consumed) = StreamOpen::decode(&encoded).expect("decodes");
        assert_eq!(decoded, open);
        assert_eq!(consumed, encoded.len());
    }

    #[test]
    fn stream_open_decode_rejects_bad_kind_tag() {
        let mut buf = vec![0x02u8];
        buf.extend_from_slice(&3u16.to_be_bytes());
        buf.extend_from_slice(b"abc");
        let err = StreamOpen::decode(&buf).unwrap_err();
        assert_eq!(err, EdgeSessionError::UnsupportedStreamKind { tag: 0x02 });
    }

    #[test]
    fn stream_open_decode_rejects_empty_target() {
        let mut buf = vec![StreamKind::Tcp.encode()];
        buf.extend_from_slice(&0u16.to_be_bytes());
        let err = StreamOpen::decode(&buf).unwrap_err();
        assert_eq!(err, EdgeSessionError::EmptyTarget);
    }

    #[test]
    fn stream_open_decode_rejects_oversized_target_length() {
        let mut buf = vec![StreamKind::Tcp.encode()];
        buf.extend_from_slice(&((StreamTarget::MAX_LEN as u16) + 1).to_be_bytes());
        let err = StreamOpen::decode(&buf).unwrap_err();
        assert_eq!(
            err,
            EdgeSessionError::TargetTooLong {
                len: StreamTarget::MAX_LEN + 1,
                max: StreamTarget::MAX_LEN
            }
        );
    }

    #[test]
    fn stream_open_decode_rejects_truncated_target() {
        let mut buf = vec![StreamKind::Tcp.encode()];
        buf.extend_from_slice(&10u16.to_be_bytes());
        buf.extend_from_slice(b"short"); // only 5 of the claimed 10 bytes
        let err = StreamOpen::decode(&buf).unwrap_err();
        assert_eq!(
            err,
            EdgeSessionError::Truncated {
                context: "StreamOpen target",
                need: 13,
                have: 8
            }
        );
    }

    #[test]
    fn stream_open_decode_rejects_non_utf8_target() {
        let mut buf = vec![StreamKind::Tcp.encode()];
        buf.extend_from_slice(&2u16.to_be_bytes());
        buf.extend_from_slice(&[0xFF, 0xFE]);
        let err = StreamOpen::decode(&buf).unwrap_err();
        assert_eq!(
            err,
            EdgeSessionError::TargetNotUtf8 {
                bytes: vec![0xFF, 0xFE]
            }
        );
    }

    // ── UDP datagram frame codec ────────────────────────────────────────

    #[test]
    fn udp_datagram_frame_round_trip() {
        let payload = b"hello udp world";
        let encoded = encode_udp_datagram_frame(payload).expect("encodes");
        let (decoded, consumed) = decode_udp_datagram_frame(&encoded).expect("decodes");
        assert_eq!(decoded, payload);
        assert_eq!(consumed, encoded.len());
    }

    #[test]
    fn udp_datagram_frame_round_trip_empty_payload() {
        let encoded = encode_udp_datagram_frame(&[]).expect("encodes");
        let (decoded, consumed) = decode_udp_datagram_frame(&encoded).expect("decodes");
        assert!(decoded.is_empty());
        assert_eq!(consumed, 2);
    }

    #[test]
    fn udp_datagram_frame_encode_rejects_oversized_payload() {
        let payload = vec![0u8; MAX_UDP_DATAGRAM_PAYLOAD + 1];
        let err = encode_udp_datagram_frame(&payload).unwrap_err();
        assert_eq!(
            err,
            EdgeSessionError::DatagramTooLarge {
                len: MAX_UDP_DATAGRAM_PAYLOAD + 1,
                max: MAX_UDP_DATAGRAM_PAYLOAD
            }
        );
    }

    #[test]
    fn udp_datagram_frame_decode_rejects_truncated_payload() {
        let mut buf = 10u16.to_be_bytes().to_vec();
        buf.extend_from_slice(b"short"); // only 5 of the claimed 10 bytes
        let err = decode_udp_datagram_frame(&buf).unwrap_err();
        assert_eq!(
            err,
            EdgeSessionError::Truncated {
                context: "udp datagram frame payload",
                need: 12,
                have: 7
            }
        );
    }

    #[test]
    fn udp_datagram_frame_decode_leaves_trailing_bytes() {
        let mut buf = encode_udp_datagram_frame(b"one").expect("encodes");
        buf.extend_from_slice(b"trailing");
        let (decoded, consumed) = decode_udp_datagram_frame(&buf).expect("decodes");
        assert_eq!(decoded, b"one");
        assert_eq!(consumed, 5);
        assert_eq!(&buf[consumed..], b"trailing");
    }

    #[test]
    fn udp_datagram_frame_decode_rejects_truncated_header() {
        let err = decode_udp_datagram_frame(&[0x00]).unwrap_err();
        assert_eq!(
            err,
            EdgeSessionError::Truncated {
                context: "udp datagram frame header",
                need: 2,
                have: 1
            }
        );
    }

    // ── Offered-face transport filtering ────────────────────────────────

    fn raw_tcp_camouflage() -> TransportCamouflage {
        TransportCamouflage::None
    }

    fn tls_camouflage() -> TransportCamouflage {
        TransportCamouflage::TlsReal {
            sni: "example.com".to_string(),
            alpn: Vec::new(),
        }
    }

    fn raw_udp_camouflage() -> TransportCamouflage {
        TransportCamouflage::RawUdp {
            bind_addr: "0.0.0.0:0".parse().expect("valid socket addr"),
        }
    }

    fn quic_camouflage() -> TransportCamouflage {
        TransportCamouflage::Quic {
            alpn: vec!["h3".to_string()],
            bind_addr: "0.0.0.0:0".parse().expect("valid socket addr"),
        }
    }

    fn icmp_camouflage() -> TransportCamouflage {
        TransportCamouflage::Icmp {
            peer_addr: "203.0.113.1".parse().expect("valid ip"),
            identifier: 1,
            mtu: 1400,
        }
    }

    #[test]
    fn face_transport_classifies_stream_and_datagram_camouflages() {
        assert_eq!(face_transport(&raw_tcp_camouflage()), TransportKind::Tcp);
        assert_eq!(face_transport(&tls_camouflage()), TransportKind::Tcp);
        assert_eq!(face_transport(&raw_udp_camouflage()), TransportKind::Udp);
        assert_eq!(face_transport(&quic_camouflage()), TransportKind::Udp);
    }

    #[test]
    fn filter_keeps_only_the_faces_of_the_requested_transport() {
        let tcp = raw_tcp_camouflage();
        let tls = tls_camouflage();
        let udp = raw_udp_camouflage();
        let quic = quic_camouflage();
        let faces = vec![
            (0usize, &tcp, 443u16),
            (1usize, &udp, 8443u16),
            (2usize, &tls, 8444u16),
            (3usize, &quic, 4433u16),
        ];

        let tcp_faces = filter_offered_faces_by_transport(&faces, TransportKind::Tcp);
        assert_eq!(tcp_faces, vec![(0usize, 443u16), (2usize, 8444u16)]);

        let udp_faces = filter_offered_faces_by_transport(&faces, TransportKind::Udp);
        assert_eq!(udp_faces, vec![(1usize, 8443u16), (3usize, 4433u16)]);
    }

    #[test]
    fn filter_never_offers_a_face_without_a_port_namespace() {
        let icmp = icmp_camouflage();
        let tcp = raw_tcp_camouflage();
        let faces = vec![(0usize, &icmp, 0u16), (1usize, &tcp, 443u16)];

        assert_eq!(
            filter_offered_faces_by_transport(&faces, TransportKind::Udp),
            Vec::<(usize, u16)>::new(),
            "an ICMP face has no port and must never be offered"
        );
        assert_eq!(
            filter_offered_faces_by_transport(&faces, TransportKind::Tcp),
            vec![(1usize, 443u16)]
        );
    }

    #[test]
    fn filter_preserves_order_and_returns_empty_when_nothing_matches() {
        let udp = raw_udp_camouflage();
        let quic = quic_camouflage();
        let faces = vec![
            (7usize, &udp, 5000u16),
            (3usize, &quic, 5001u16),
            (5usize, &udp, 5002u16),
        ];

        assert_eq!(
            filter_offered_faces_by_transport(&faces, TransportKind::Udp),
            vec![(7usize, 5000u16), (3usize, 5001u16), (5usize, 5002u16)],
            "the filter must not reorder the caller's faces"
        );
        assert!(filter_offered_faces_by_transport(&faces, TransportKind::Tcp).is_empty());
    }

    #[test]
    fn filtered_ports_fit_the_edge_hello_wire_format() {
        let tcp = raw_tcp_camouflage();
        let udp = raw_udp_camouflage();
        let faces = vec![
            (0usize, &tcp, 443u16),
            (1usize, &udp, 8443u16),
            (2usize, &tcp, 8444u16),
        ];
        let offered: Vec<u16> = filter_offered_faces_by_transport(&faces, TransportKind::Tcp)
            .into_iter()
            .map(|(_, port)| port)
            .collect();

        let hello = EdgeHello {
            version: 3,
            exit: ExitPreference::Auto,
            flags: 0,
            offered_ports: offered,
        };
        let encoded = hello.encode().expect("encodes");
        let (decoded, consumed) = EdgeHello::decode(&encoded).expect("decodes");
        assert_eq!(consumed, encoded.len());
        assert_eq!(decoded, hello);
        assert_eq!(decoded.offered_ports, vec![443u16, 8444u16]);
    }
}
