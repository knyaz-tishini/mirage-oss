// ── The three layers ─────────────────────────────────────────────────────────
//
//   cores/  — the protocol cores: handshake, session, carriers, onion.
//             They know nothing about the variant and nothing about the mode.
//   modes/  — the client and the server: how the same core is driven from
//             each side.
//   the variants live outside this crate:
//     · mirage-vpn      — the VPN variant (client ↔ terminator, no onion)
//     · mirage-vpn-mesh — the mesh variant (the session inside an onion chain)
pub mod cores;
pub mod modes;

// ── The axes and the plumbing that stayed where they were ────────────────────
pub mod auth;
pub mod camouflage;
pub mod protocols;
pub mod transport;
pub mod endpoint_protocol;

pub mod byte_cipher;
pub mod frame_obfuscation;
pub mod negotiation;
pub mod traits;
pub mod plane;

pub mod prefix_stream;
pub use prefix_stream::PrefixStream;

pub mod preamble;

// ── The mshd plumbing and the compatibility facade over the cores ────────────
//
// `core` still exists as a module: it holds the mshd transport and re-exports
// the cores under their old names, so the fleet's paths keep working.
pub mod core;

// ── Compatibility facades over the moved modules ────────────────────────────
//
// The paths below are the ones the fleet has used since the beginning. They
// still resolve, so the layers could be introduced without touching a single
// consumer; new code should use `mirage_protocol::cores` and
// `mirage_protocol::modes`.

/// The client mode lives in [`modes`].
pub mod client_transport {
    pub use crate::modes::client_transport::*;
}

/// The client and server modes live in [`modes`].
pub mod driver {
    pub use crate::modes::driver::*;
}

/// The onion core lives in [`cores`].
pub mod onion {
    pub use crate::cores::onion::*;
}

pub use cores::handshake::ClientAuthContext;
pub use modes::driver::ClientCredential;

// ── Shared hex utilities ─────────────────────────────────────────────────────

/// Decode a hexadecimal string into bytes without external crate dependencies.
pub(crate) fn decode_hex(s: &str) -> Result<Vec<u8>, String> {
    if s.len() % 2 != 0 {
        return Err(format!("odd hex string length: {}", s.len()));
    }
    s.as_bytes()
        .chunks(2)
        .map(|pair| {
            let hi = hex_nibble(pair[0])?;
            let lo = hex_nibble(pair[1])?;
            Ok((hi << 4) | lo)
        })
        .collect()
}

/// Convert a single ASCII hex character to its nibble value.
fn hex_nibble(b: u8) -> Result<u8, String> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(format!("invalid hex character: '{}'", b as char)),
    }
}
