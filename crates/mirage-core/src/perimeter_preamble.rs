//! What the perimeter tells an inward destination about the connection it
//! is handing over.
//!
//! # The debt this pays
//!
//! The perimeter is the only process on the box that ever sees a real
//! client. Everything behind it — the monitor, mshd — has a peer of
//! `127.0.0.1` and knows nothing. That was worked around rather than
//! fixed: the perimeter reported the address to `mirage-secd`, the
//! destination reported the authentication, and secd JOINED the two on
//! **the loopback ephemeral port**, because the splice carried no
//! identity of its own. mshd's splice carried literally nothing.
//!
//! Moving these channels to unix sockets ([`crate::local_endpoint`])
//! removes the ephemeral port, so the join has no key. That is not a
//! casualty of the move — the move forces a fix that was owed. The
//! perimeter is the WAF; it should SAY what it saw, in the same message as
//! the connection, rather than have a third daemon reassemble it from two
//! timing-correlated reports.
//!
//! # Why this needs no signature
//!
//! The monitor's PROXY v2 header had to be signed, because it arrived over
//! loopback TCP and anything on the box could open that port and claim any
//! address. This preamble arrives over a unix socket whose directory and
//! mode admit root and the perimeter's own uid, verified by `SO_PEERCRED`
//! at accept — see [`crate::local_endpoint`]'s module doc. **The socket is
//! the authentication.** A peer that could forge a preamble here is already
//! root or already the perimeter, and either can read the box's keys
//! directly. Signing it would spend CPU to restate a fact the kernel has
//! already established.
//!
//! # Framing
//!
//! ```text
//! MIRPRE          6 bytes, ASCII magic
//! version         1 byte
//! length          4 bytes, big-endian, <= MAX_PREAMBLE_LEN
//! body            JSON PerimeterPreamble
//! ```
//!
//! Length-prefixed because the reader must consume EXACTLY the preamble and
//! not one byte more: what follows is the client's own first bytes, and
//! mshd hands the remainder straight to an SSH server that will reject a
//! corrupted identification string. A newline-delimited encoding would work
//! until the day a field carries one.
//!
//! The magic exists so a reader can tell "the perimeter spoke first" from
//! "somebody connected to this socket and started talking protocol". Both
//! are possible: the recovery path allows root to dial the same socket
//! directly, and a reader that assumed a preamble would misparse it.

use serde::{Deserialize, Serialize};

/// ASCII magic opening every preamble.
pub const PREAMBLE_MAGIC: [u8; 6] = *b"MIRPRE";

/// Framing version. Bump when the JSON body's REQUIRED fields change in a
/// way an older reader cannot ignore; serde's `#[serde(default)]` covers
/// additive fields without a bump.
pub const PREAMBLE_VERSION: u8 = 1;

/// Bytes before the JSON body: magic + version + length.
pub const PREAMBLE_HEADER_LEN: usize = PREAMBLE_MAGIC.len() + 1 + 4;

/// Upper bound on the JSON body. Generous for the fields below with
/// [`MAX_FIRST_BYTES`] at its limit, and small enough that a peer cannot
/// make a reader allocate on its say-so.
pub const MAX_PREAMBLE_LEN: u32 = 8 * 1024;

/// How much of the client's opening bytes travel with the connection.
///
/// The point is to carry what the CLASSIFIER DECIDED ON, not to mirror the
/// stream: 8 bytes settle SSH-vs-wire and 97 are a whole V9 hello, so this
/// holds either with room to spare. It is bounded because these bytes are
/// attacker-chosen and end up in a log.
pub const MAX_FIRST_BYTES: usize = 128;

/// Which inward destination a connection was routed to, and therefore what
/// the perimeter decided the opening bytes were.
///
/// Deliberately the same vocabulary as
/// [`crate::local_security_event::InwardDest`] rather than a second enum
/// with the same shape — the report to the arbiter and the preamble to the
/// destination are two audiences for one decision.
pub use crate::local_security_event::InwardDest as Verdict;

/// The WAF's record of one admitted connection, delivered with it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PerimeterPreamble {
    /// The client's REAL source address, `ip:port`. The whole reason this
    /// type exists.
    pub peer: String,
    /// The public port the connection arrived on.
    pub face_port: u16,
    /// That face's camouflage label (`none`, `tls_real`, …) — which
    /// disguise the client got through, not merely which port.
    pub face_camouflage: String,
    /// What the perimeter classified the opening bytes as.
    pub verdict: Verdict,
    /// The classification-deciding prefix, bounded by [`MAX_FIRST_BYTES`].
    ///
    /// Carried so the destination and the arbiter can see what the decision
    /// was made ON, instead of trusting that it was made well. Attacker-
    /// chosen bytes: treat as data, never as a code path.
    #[serde(with = "crate::b64_serde::b64_vec")]
    pub first_bytes: Vec<u8>,
    /// The box's clock at accept.
    pub observed_at_ms: u64,
}

impl PerimeterPreamble {
    /// Encode with its frame header. Truncates `first_bytes` to
    /// [`MAX_FIRST_BYTES`] rather than refusing — a connection must not be
    /// dropped because its own opening was long.
    pub fn encode(&self) -> Result<Vec<u8>, PreambleError> {
        let mut me = self.clone();
        me.first_bytes.truncate(MAX_FIRST_BYTES);
        let body = serde_json::to_vec(&me).map_err(|e| PreambleError::Encode(e.to_string()))?;
        let len = u32::try_from(body.len()).map_err(|_| PreambleError::TooLong(body.len()))?;
        if len > MAX_PREAMBLE_LEN {
            return Err(PreambleError::TooLong(body.len()));
        }
        let mut out = Vec::with_capacity(PREAMBLE_HEADER_LEN + body.len());
        out.extend_from_slice(&PREAMBLE_MAGIC);
        out.push(PREAMBLE_VERSION);
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(&body);
        Ok(out)
    }

    /// Decode a body already read out of the frame.
    pub fn decode_body(body: &[u8]) -> Result<Self, PreambleError> {
        serde_json::from_slice(body).map_err(|e| PreambleError::Decode(e.to_string()))
    }

    /// Parse the fixed header. Returns the body length still to be read.
    ///
    /// Separate from [`Self::decode_body`] so a reader can do the two
    /// bounded reads a stream needs without this module owning the I/O —
    /// mshd reads from a `LocalStream`, a test reads from a slice, and
    /// neither should have to hand this module an `AsyncRead`.
    pub fn parse_header(header: &[u8; PREAMBLE_HEADER_LEN]) -> Result<u32, PreambleError> {
        if header[..PREAMBLE_MAGIC.len()] != PREAMBLE_MAGIC {
            return Err(PreambleError::NotAPreamble);
        }
        let version = header[PREAMBLE_MAGIC.len()];
        if version != PREAMBLE_VERSION {
            return Err(PreambleError::Version(version));
        }
        let mut len_bytes = [0u8; 4];
        len_bytes.copy_from_slice(&header[PREAMBLE_MAGIC.len() + 1..]);
        let len = u32::from_be_bytes(len_bytes);
        if len > MAX_PREAMBLE_LEN {
            return Err(PreambleError::TooLong(len as usize));
        }
        Ok(len)
    }

    /// The client's address without its port, for the arbiter — which keys
    /// its trust and ban ledgers by address, never by port.
    pub fn client_ip(&self) -> Option<std::net::IpAddr> {
        if let Ok(sa) = self.peer.parse::<std::net::SocketAddr>() {
            return Some(sa.ip());
        }
        self.peer.parse::<std::net::IpAddr>().ok()
    }
}

/// What can go wrong reading a preamble.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PreambleError {
    /// The opening bytes are not this frame — the peer dialled the socket
    /// and started speaking something else. A distinct outcome, not an
    /// error to bury: root is allowed to dial these sockets directly.
    NotAPreamble,
    /// A frame version this build does not read.
    Version(u8),
    TooLong(usize),
    Encode(String),
    Decode(String),
}

impl std::fmt::Display for PreambleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PreambleError::NotAPreamble => write!(f, "no perimeter preamble on this connection"),
            PreambleError::Version(v) => write!(f, "unreadable preamble version {v}"),
            PreambleError::TooLong(n) => write!(f, "preamble body {n} exceeds {MAX_PREAMBLE_LEN}"),
            PreambleError::Encode(e) => write!(f, "encoding a preamble: {e}"),
            PreambleError::Decode(e) => write!(f, "decoding a preamble: {e}"),
        }
    }
}

impl std::error::Error for PreambleError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> PerimeterPreamble {
        PerimeterPreamble {
            peer: "203.0.113.9:51234".into(),
            face_port: 22,
            face_camouflage: "none".into(),
            verdict: Verdict::Mshd,
            first_bytes: b"SSH-2.0-".to_vec(),
            observed_at_ms: 1_700_000_000_000,
        }
    }

    #[test]
    fn a_preamble_round_trips_through_its_frame() {
        let p = sample();
        let framed = p.encode().expect("encodes");
        let header: [u8; PREAMBLE_HEADER_LEN] = framed[..PREAMBLE_HEADER_LEN].try_into().unwrap();
        let len = PerimeterPreamble::parse_header(&header).expect("header parses");
        let body = &framed[PREAMBLE_HEADER_LEN..];
        assert_eq!(body.len(), len as usize, "the length must bound the body exactly");
        assert_eq!(PerimeterPreamble::decode_body(body).unwrap(), p);
    }

    #[test]
    fn the_frame_ends_exactly_where_it_says_it_does() {
        // The property mshd depends on: what follows the preamble is the
        // client's own first bytes, handed to an SSH server that will refuse
        // a corrupted identification string. One byte of over-read is a
        // broken session, not a warning.
        let mut framed = sample().encode().unwrap();
        let trailer = b"SSH-2.0-OpenSSH_9.6\r\n";
        framed.extend_from_slice(trailer);

        let header: [u8; PREAMBLE_HEADER_LEN] = framed[..PREAMBLE_HEADER_LEN].try_into().unwrap();
        let len = PerimeterPreamble::parse_header(&header).unwrap() as usize;
        let end = PREAMBLE_HEADER_LEN + len;
        assert_eq!(&framed[end..], trailer, "the client's bytes must survive intact");
    }

    #[test]
    fn a_connection_that_opens_with_something_else_is_not_a_malformed_preamble() {
        // Root may dial these sockets directly. That must read as "no
        // preamble", a distinct outcome the caller can act on, not as a
        // parse failure that gets logged as an attack.
        let mut ssh = *b"SSH-2.0-OpenSS";
        let header: [u8; PREAMBLE_HEADER_LEN] = ssh[..PREAMBLE_HEADER_LEN].try_into().unwrap();
        assert_eq!(
            PerimeterPreamble::parse_header(&header),
            Err(PreambleError::NotAPreamble)
        );
        ssh[0] = b'X';
        let _ = ssh;
    }

    #[test]
    fn a_version_this_build_cannot_read_is_named_not_guessed() {
        let mut framed = sample().encode().unwrap();
        framed[PREAMBLE_MAGIC.len()] = 99;
        let header: [u8; PREAMBLE_HEADER_LEN] = framed[..PREAMBLE_HEADER_LEN].try_into().unwrap();
        assert_eq!(
            PerimeterPreamble::parse_header(&header),
            Err(PreambleError::Version(99))
        );
    }

    #[test]
    fn a_declared_length_past_the_bound_is_refused_before_any_allocation() {
        let mut header = [0u8; PREAMBLE_HEADER_LEN];
        header[..PREAMBLE_MAGIC.len()].copy_from_slice(&PREAMBLE_MAGIC);
        header[PREAMBLE_MAGIC.len()] = PREAMBLE_VERSION;
        header[PREAMBLE_MAGIC.len() + 1..].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(matches!(
            PerimeterPreamble::parse_header(&header),
            Err(PreambleError::TooLong(_))
        ));
    }

    #[test]
    fn an_overlong_opening_is_truncated_rather_than_dropping_the_connection() {
        let mut p = sample();
        p.first_bytes = vec![0x41; MAX_FIRST_BYTES * 4];
        let framed = p.encode().expect("a long opening must still encode");
        let body = &framed[PREAMBLE_HEADER_LEN..];
        let back = PerimeterPreamble::decode_body(body).unwrap();
        assert_eq!(back.first_bytes.len(), MAX_FIRST_BYTES);
    }

    #[test]
    fn the_address_the_arbiter_keys_on_drops_the_port() {
        assert_eq!(
            sample().client_ip().unwrap().to_string(),
            "203.0.113.9",
            "trust and ban ledgers are keyed by address, never by port"
        );
        // v6, and a bare address with no port, both of which a face can see.
        let mut p = sample();
        p.peer = "[2001:db8::5]:443".into();
        assert_eq!(p.client_ip().unwrap().to_string(), "2001:db8::5");
        p.peer = "198.51.100.7".into();
        assert_eq!(p.client_ip().unwrap().to_string(), "198.51.100.7");
        p.peer = "not-an-address".into();
        assert_eq!(p.client_ip(), None);
    }
}
