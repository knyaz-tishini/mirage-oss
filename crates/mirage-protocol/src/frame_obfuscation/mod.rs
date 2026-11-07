//! Frame obfuscation layer (layer 4).
//!
//! Wraps individual plaintext frames before they enter the AEAD tunnel.
//! Operates on frame granularity — knows frame boundaries.
//!
//! - `wrap`: per-frame JSON/gRPC/H2 envelope (obfuscates AEAD ciphertext to
//!   resemble API traffic when L1 decrypts and peeks)
//! - `shaping`: padding/timing control per-frame (burst patterns, cover delays)
//! - `patterns`: traffic pattern presets (Yandex Cloud, web browsing, streaming)
//! - `probe_resist`: forwards unauthenticated connections to a fallback dest

pub mod wrap;
pub mod shaping;
pub mod patterns;
pub mod probe_resist;
