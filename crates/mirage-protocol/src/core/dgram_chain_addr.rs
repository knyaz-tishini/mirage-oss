//! How a datagram session says which chain hop it is addressing.
//!
//! # Why this exists
//!
//! The stream chain plane addresses a hop by a selector the hop reads out of
//! the frame: since 2026-09-09 that is a minted per-hop token, and before it
//! was `{chain_id}-h{position}` derived from a 32-bit chain id. Either way the
//! node knows WHICH listener's keys should decode what follows.
//!
//! The datagram plane had nothing. `ChainRouting::single_udp_direct_exit`
//! resolves a listener from the `mesh_id` alone — so every client of the mesh
//! reaches the one registered datagram exit, there is no way to name a
//! different hop, and a chain deeper than one hop cannot be expressed at all.
//! That is not a missing detail of multi-hop; it is the absence of addressing,
//! and it is why the client refuses `hops > 1` before it opens a socket.
//!
//! # Wire carriage, and why it rides the hello rather than the tunnel
//!
//! This block travels appended to the datagram `ClientHello`, in the same
//! datagram, before the credential:
//!
//! ```text
//! [97B ClientHello][2B chain_len BE][chain block][credential bytes]
//! ```
//!
//! It does NOT ride `MirageCoreUdpTunnel`'s data phase. That codec pads every
//! frame up to `CHUNK_SIZES = [1024, 4096, 16384]`, so a 30-byte control
//! message would go out as a 1046-byte datagram — 87% of the 1200-byte payload
//! this handshake is sized never to fragment across — and anything past 1019
//! bytes of content would become a 4118-byte datagram needing IP
//! fragmentation. Addressing belongs to the handshake, where the frame is
//! written raw and the size is what it says it is.
//!
//! # How the server knows the block is there
//!
//! The datagram hello's contract is "everything past byte 97 is the
//! credential" — no length prefix, because a datagram already carries its own
//! boundary. A second variable-length field cannot be appended to that
//! without a length, and a length cannot be added without telling the reader
//! it is coming.
//!
//! So the hello's own `cred_scheme` byte declares the shape:
//! [`CHAIN_ADDRESSED_FLAG`] set means a chain block precedes the credential.
//! The flag is stripped before the scheme reaches credential verification, so
//! that dispatch is untouched. A peer that predates this sees a scheme byte it
//! does not know and refuses the handshake by name — which is the point of
//! putting the signal in a field that is already validated, rather than in a
//! magic suffix that an old reader would silently feed to its credential
//! verifier.
//!
//! No magic constant appears in the plaintext. A fixed marker at a fixed
//! offset in a datagram anyone can observe is a landmark, and this hello is
//! observable — the same objection the face hello's doc makes about leaving
//! unread fields zeroed.

use mirage_core::error::MirageError;

/// Set in a datagram `ClientHello`'s `cred_scheme` byte when a chain block
/// precedes the credential. The low seven bits keep their existing meaning as
/// the credential scheme.
pub const CHAIN_ADDRESSED_FLAG: u8 = 0x80;

/// Largest chain id this carriage accepts, in bytes. `mint_chain_id` produces
/// `auto-{8hex}` — 13 bytes — and an operator-managed catalogue entry is a
/// short handle by the same doc's reasoning. The cap exists so a malformed
/// length cannot make the parser read past the datagram.
pub const MAX_CHAIN_ID_LEN: usize = 32;

/// Largest selector token this carriage accepts. The monitor mints 16 bytes.
pub const MAX_SELECTOR_TOKEN_LEN: usize = 32;

/// Largest encoded block, over every input the caps above admit — the four
/// length/position bytes plus both variable fields at their maximum.
///
/// This is not decoration. The block shares one datagram with a 97-byte hello
/// and a credential capped at 1024 bytes, under a payload ceiling this
/// handshake never fragments across, and `udp_handshake` turns those four
/// numbers into a compile-time assertion. The caps above are 32 rather than
/// the 64 they were first written as for exactly that reason: at 64 the
/// worst case overran the ceiling by 55 bytes — a bound that only ever fails
/// on unusually long inputs, which is to say on the inputs nobody tests.
/// 32 bytes is still 2.5x what `mint_chain_id` emits and 2x the token the
/// monitor mints.
pub const MAX_ENCODED_BLOCK_LEN: usize = 4 + MAX_CHAIN_ID_LEN + MAX_SELECTOR_TOKEN_LEN;

/// Which hop of which chain a datagram session is addressing.
///
/// `selector_token` empty means the monitor minted none and the hop falls back
/// to the derived `{chain_id}-h{position}`, exactly as the stream side does —
/// absent is a state, not an error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DatagramChainAddress {
    pub chain_id: Vec<u8>,
    pub chain_position: u8,
    pub chain_length: u8,
    pub selector_token: Vec<u8>,
}

impl DatagramChainAddress {
    /// `[1B chain_id_len][chain_id][1B position][1B length][1B token_len][token]`
    pub fn encode(&self) -> Result<Vec<u8>, MirageError> {
        if self.chain_id.is_empty() || self.chain_id.len() > MAX_CHAIN_ID_LEN {
            return Err(MirageError::Protocol(format!(
                "datagram chain address: chain_id must be 1..={MAX_CHAIN_ID_LEN} bytes, got {}",
                self.chain_id.len()
            )));
        }
        if self.selector_token.len() > MAX_SELECTOR_TOKEN_LEN {
            return Err(MirageError::Protocol(format!(
                "datagram chain address: selector_token must be at most \
                 {MAX_SELECTOR_TOKEN_LEN} bytes, got {}",
                self.selector_token.len()
            )));
        }
        let mut out = Vec::with_capacity(4 + self.chain_id.len() + self.selector_token.len());
        out.push(self.chain_id.len() as u8);
        out.extend_from_slice(&self.chain_id);
        out.push(self.chain_position);
        out.push(self.chain_length);
        out.push(self.selector_token.len() as u8);
        out.extend_from_slice(&self.selector_token);
        Ok(out)
    }

    /// Parse the block. Every truncation is an error naming which field ran
    /// off the end — a datagram that claims a chain block and does not carry
    /// one is malformed, and must not be read as "no chain block", or a
    /// mangled datagram would resolve to whatever the mesh's single exit
    /// happens to be.
    pub fn decode(buf: &[u8]) -> Result<Self, MirageError> {
        let mut off = 0usize;
        let need = |off: usize, n: usize, what: &str| -> Result<(), MirageError> {
            if buf.len() < off + n {
                return Err(MirageError::Protocol(format!(
                    "datagram chain address: truncated {what}"
                )));
            }
            Ok(())
        };

        need(off, 1, "chain_id length")?;
        let id_len = buf[off] as usize;
        off += 1;
        if id_len == 0 || id_len > MAX_CHAIN_ID_LEN {
            return Err(MirageError::Protocol(format!(
                "datagram chain address: chain_id length {id_len} outside 1..={MAX_CHAIN_ID_LEN}"
            )));
        }
        need(off, id_len, "chain_id")?;
        let chain_id = buf[off..off + id_len].to_vec();
        off += id_len;

        need(off, 1, "chain_position")?;
        let chain_position = buf[off];
        off += 1;

        need(off, 1, "chain_length")?;
        let chain_length = buf[off];
        off += 1;

        need(off, 1, "selector_token length")?;
        let tok_len = buf[off] as usize;
        off += 1;
        if tok_len > MAX_SELECTOR_TOKEN_LEN {
            return Err(MirageError::Protocol(format!(
                "datagram chain address: selector_token length {tok_len} exceeds \
                 {MAX_SELECTOR_TOKEN_LEN}"
            )));
        }
        need(off, tok_len, "selector_token")?;
        let selector_token = buf[off..off + tok_len].to_vec();
        off += tok_len;

        if off != buf.len() {
            return Err(MirageError::Protocol(format!(
                "datagram chain address: {} trailing bytes after the block",
                buf.len() - off
            )));
        }

        if chain_length == 0 || chain_position >= chain_length {
            return Err(MirageError::Protocol(format!(
                "datagram chain address: position {chain_position} outside a chain of \
                 length {chain_length}"
            )));
        }

        Ok(Self {
            chain_id,
            chain_position,
            chain_length,
            selector_token,
        })
    }

    /// The selector bytes this address resolves to — the minted token when
    /// there is one, else the derived `{chain_id}-h{position}` every hop
    /// answered to before tokens existed. Mirrors `ChainSelector::from_frame`
    /// on the stream side so one chain cannot be addressed two ways depending
    /// on its transport.
    pub fn selector_bytes(&self) -> Vec<u8> {
        if !self.selector_token.is_empty() {
            return self.selector_token.clone();
        }
        let mut out = Vec::with_capacity(self.chain_id.len() + 4);
        out.extend_from_slice(&self.chain_id);
        out.extend_from_slice(b"-h");
        out.extend_from_slice(self.chain_position.to_string().as_bytes());
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr() -> DatagramChainAddress {
        DatagramChainAddress {
            chain_id: b"auto-deadbeef".to_vec(),
            chain_position: 1,
            chain_length: 3,
            selector_token: vec![0xABu8; 16],
        }
    }

    #[test]
    fn a_block_round_trips() {
        let a = addr();
        assert_eq!(DatagramChainAddress::decode(&a.encode().expect("encode")).expect("decode"), a);
    }

    /// A truncation must not read as "no chain block". If it did, a mangled
    /// datagram would fall through to whichever exit the mesh happens to have
    /// registered — which is exactly the addressing hole this block closes.
    #[test]
    fn a_truncated_block_is_an_error_not_an_absence() {
        let bytes = addr().encode().expect("encode");
        for cut in 1..bytes.len() {
            assert!(
                DatagramChainAddress::decode(&bytes[..cut]).is_err(),
                "a block cut to {cut} bytes decoded instead of failing"
            );
        }
    }

    #[test]
    fn a_position_outside_the_chain_is_refused() {
        let mut a = addr();
        a.chain_position = 3;
        let bytes = a.encode().expect("encode");
        assert!(DatagramChainAddress::decode(&bytes).is_err());
    }

    /// The stated maximum has to be the real one, because `udp_handshake`
    /// asserts the datagram budget against it at compile time. If `encode`
    /// could ever produce more than this, that proof would be resting on a
    /// number nothing checks.
    #[test]
    fn no_admissible_block_encodes_larger_than_the_stated_maximum() {
        let widest = DatagramChainAddress {
            chain_id: vec![b'c'; MAX_CHAIN_ID_LEN],
            chain_position: 254,
            chain_length: 255,
            selector_token: vec![0xFFu8; MAX_SELECTOR_TOKEN_LEN],
        };
        let bytes = widest.encode().expect("the widest admissible address must encode");
        assert_eq!(bytes.len(), MAX_ENCODED_BLOCK_LEN);
        assert_eq!(DatagramChainAddress::decode(&bytes).expect("decode"), widest);
    }

    /// Same rule as the stream side: a minted token IS the selector, and
    /// without one the derived name is used, so a chain is addressed the same
    /// way on both transports.
    #[test]
    fn the_selector_follows_the_token_when_there_is_one() {
        let mut a = addr();
        assert_eq!(a.selector_bytes(), vec![0xABu8; 16]);
        a.selector_token.clear();
        assert_eq!(a.selector_bytes(), b"auto-deadbeef-h1".to_vec());
    }
}
