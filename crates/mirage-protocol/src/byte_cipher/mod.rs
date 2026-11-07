//! Byte-level cipher layer (stream cipher + magic/junk variants).
//!
//! Slots above transport/camouflage (layer 2). Operates on raw byte streams
//! without knowing frame boundaries. Four modes:
//!   - `Raw`: no-op passthrough
//!   - `ValidateFirst`: check 16-byte magic on first packet
//!   - `StripFirst`: strip magic + junk prefix on first packet
//!   - `ObfuscateAll`: XOR stream cipher (BLAKE3 keystream or ChaCha8) on every packet

pub mod wrapper;

pub use wrapper::*;
