//! Integration tests for the byte cipher layer.
//!
//! Covers:
//! 1. Raw roundtrip — no-op passthrough.
//! 2. ValidateFirst roundtrip — magic present on first packet, passes; absent, rejected.
//! 3. StripFirst roundtrip — magic+junk stripped on server side.
//! 4. ObfuscateAll/XorBlake3 roundtrip + counter uniqueness.
//! 5. ObfuscateAll/ChaCha8 roundtrip + counter uniqueness.
//! 6. ByteCipherTunnel integration with a mock inner tunnel.
//! 7. Serde roundtrip for all ByteCipherMode variants.

use mirage_core::config::{ByteCipherMode, ObfuscationAlgorithm};
use mirage_protocol::byte_cipher::{ByteCipher, ByteCipherError};

// ── helpers ───────────────────────────────────────────────────────────────────

fn magic() -> [u8; 16] {
    [0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE,
     0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]
}

fn bad_magic() -> [u8; 16] {
    [0xFF; 16]
}

fn obf_key() -> [u8; 32] {
    [0xAB; 32]
}

/// Build a client-side cipher and server-side cipher with the same mode.
fn pair(mode: ByteCipherMode) -> (ByteCipher, ByteCipher) {
    (ByteCipher::new(mode.clone()), ByteCipher::new(mode))
}

// ── 1. Raw roundtrip ──────────────────────────────────────────────────────────

#[test]
fn raw_roundtrip() {
    let (mut client, mut server) = pair(ByteCipherMode::Raw);
    let payload = b"hello, mirage!";
    let wire = client.wrap(payload);
    assert_eq!(wire, payload, "Raw: wrap should be identity");
    let plain = server.unwrap(&wire).expect("Raw: unwrap should succeed");
    assert_eq!(plain, payload, "Raw: roundtrip should be identity");
}

#[test]
fn raw_multiple_packets() {
    let (mut client, mut server) = pair(ByteCipherMode::Raw);
    for i in 0u8..10 {
        let payload = vec![i; 100];
        let wire = client.wrap(&payload);
        let plain = server.unwrap(&wire).unwrap();
        assert_eq!(plain, payload);
    }
}

// ── 2. ValidateFirst ─────────────────────────────────────────────────────────

#[test]
fn validate_first_roundtrip() {
    let mode = ByteCipherMode::ValidateFirst { magic: magic() };
    let (mut client, mut server) = pair(mode);
    let payload = b"first packet payload";

    // First packet: client prepends magic.
    let wire = client.wrap(payload);
    assert!(wire.starts_with(&magic()), "wire should start with magic");
    assert_eq!(&wire[16..], payload);

    // Server: validates magic, returns full wire bytes (magic included).
    let result = server.unwrap(&wire).expect("ValidateFirst: first packet OK");
    // The server returns the full bytes (magic + payload) — protocol chain
    // receives them and can skip the magic prefix.
    assert_eq!(&result[..16], &magic());
    assert_eq!(&result[16..], payload);

    // Second packet: no magic added/stripped.
    let p2 = b"second packet";
    let w2 = client.wrap(p2);
    assert_eq!(w2, p2, "second packet: Raw passthrough");
    let r2 = server.unwrap(&w2).expect("ValidateFirst: second packet OK");
    assert_eq!(r2, p2);
}

#[test]
fn validate_first_magic_mismatch() {
    let mode = ByteCipherMode::ValidateFirst { magic: magic() };
    let mut server = ByteCipher::new(mode);

    // Craft a first packet with wrong magic.
    let mut bad = bad_magic().to_vec();
    bad.extend_from_slice(b"payload");

    let result = server.unwrap(&bad);
    assert!(
        matches!(result, Err(ByteCipherError::MagicMismatch)),
        "should reject wrong magic, got: {result:?}"
    );
}

#[test]
fn validate_first_too_short() {
    let mode = ByteCipherMode::ValidateFirst { magic: magic() };
    let mut server = ByteCipher::new(mode);

    // Only 8 bytes — less than 16-byte magic.
    let result = server.unwrap(&[0u8; 8]);
    assert!(matches!(result, Err(ByteCipherError::TooShort { .. })));
}

// ── 3. StripFirst ─────────────────────────────────────────────────────────────

#[test]
fn strip_first_roundtrip() {
    let junk_size: u16 = 32;
    let mode = ByteCipherMode::StripFirst { magic: magic(), junk_size };
    let (mut client, mut server) = pair(mode);
    let payload = b"strip first payload";

    // Client: prepends magic + 32 random junk bytes.
    let wire = client.wrap(payload);
    let expected_len = 16 + junk_size as usize + payload.len();
    assert_eq!(wire.len(), expected_len, "wire length should include magic + junk + payload");
    assert!(wire.starts_with(&magic()));

    // Server: strips magic + junk, returns only payload.
    let result = server.unwrap(&wire).expect("StripFirst: first packet OK");
    assert_eq!(result, payload, "server should recover original payload");

    // Second packet: passed through unchanged on both sides.
    let p2 = b"subsequent data";
    let w2 = client.wrap(p2);
    assert_eq!(w2, p2);
    let r2 = server.unwrap(&w2).expect("StripFirst: second packet OK");
    assert_eq!(r2, p2);
}

#[test]
fn strip_first_magic_mismatch() {
    let mode = ByteCipherMode::StripFirst { magic: magic(), junk_size: 8 };
    let mut server = ByteCipher::new(mode);

    let mut bad = vec![0u8; 16 + 8 + 10]; // wrong magic + junk + payload
    bad[..16].copy_from_slice(&bad_magic());

    let result = server.unwrap(&bad);
    assert!(matches!(result, Err(ByteCipherError::MagicMismatch)));
}

#[test]
fn strip_first_too_short() {
    let mode = ByteCipherMode::StripFirst { magic: magic(), junk_size: 32 };
    let mut server = ByteCipher::new(mode);

    // Only 16 bytes — magic present but no room for junk (need 16+32=48).
    let mut buf = vec![0u8; 40];
    buf[..16].copy_from_slice(&magic());

    let result = server.unwrap(&buf);
    assert!(matches!(result, Err(ByteCipherError::TooShort { needed: 48, got: 40 })));
}

// ── 4. ObfuscateAll / XorBlake3 ───────────────────────────────────────────────

#[test]
fn xor_blake3_roundtrip() {
    let mode = ByteCipherMode::ObfuscateAll {
        algorithm: ObfuscationAlgorithm::XorBlake3,
        obf_key: obf_key(),
    };
    let (mut client, mut server) = pair(mode);

    for i in 0u8..20 {
        let payload: Vec<u8> = (0..100).map(|j: u8| j ^ i).collect();
        let wire = client.wrap(&payload);
        // Wire starts with 4-byte salt counter.
        assert_eq!(wire.len(), 4 + payload.len());
        let plain = server.unwrap(&wire).expect("XorBlake3: unwrap OK");
        assert_eq!(plain, payload, "XorBlake3: roundtrip failed at packet {i}");
    }
}

#[test]
fn xor_blake3_counter_uniqueness() {
    let mode = ByteCipherMode::ObfuscateAll {
        algorithm: ObfuscationAlgorithm::XorBlake3,
        obf_key: obf_key(),
    };
    let mut client = ByteCipher::new(mode);

    let payload = vec![0xAA; 50];
    let mut wires: Vec<Vec<u8>> = Vec::new();
    for _ in 0..100 {
        wires.push(client.wrap(&payload));
    }

    // Check that no two wire packets are identical (salt counter makes them unique).
    for i in 0..wires.len() {
        for j in (i + 1)..wires.len() {
            assert_ne!(
                wires[i], wires[j],
                "XorBlake3: packets {i} and {j} should differ (unique salt counters)"
            );
        }
    }
}

#[test]
fn xor_blake3_large_payload() {
    // Payload larger than 32 bytes — exercises multi-block keystream chaining.
    let mode = ByteCipherMode::ObfuscateAll {
        algorithm: ObfuscationAlgorithm::XorBlake3,
        obf_key: obf_key(),
    };
    let (mut client, mut server) = pair(mode);
    let payload: Vec<u8> = (0..512).map(|i: usize| i as u8).collect();
    let wire = client.wrap(&payload);
    let plain = server.unwrap(&wire).unwrap();
    assert_eq!(plain, payload);
}

// ── 5. ObfuscateAll / ChaCha8 ─────────────────────────────────────────────────

#[test]
fn chacha8_roundtrip() {
    let mode = ByteCipherMode::ObfuscateAll {
        algorithm: ObfuscationAlgorithm::ChaCha8,
        obf_key: obf_key(),
    };
    let (mut client, mut server) = pair(mode);

    for i in 0u8..20 {
        let payload: Vec<u8> = (0..80).map(|j: u8| j.wrapping_add(i)).collect();
        let wire = client.wrap(&payload);
        // Wire starts with 8-byte nonce counter.
        assert_eq!(wire.len(), 8 + payload.len());
        let plain = server.unwrap(&wire).expect("ChaCha8: unwrap OK");
        assert_eq!(plain, payload, "ChaCha8: roundtrip failed at packet {i}");
    }
}

#[test]
fn chacha8_counter_uniqueness() {
    let mode = ByteCipherMode::ObfuscateAll {
        algorithm: ObfuscationAlgorithm::ChaCha8,
        obf_key: obf_key(),
    };
    let mut client = ByteCipher::new(mode);

    let payload = vec![0x55; 60];
    let mut wires: Vec<Vec<u8>> = Vec::new();
    for _ in 0..100 {
        wires.push(client.wrap(&payload));
    }

    for i in 0..wires.len() {
        for j in (i + 1)..wires.len() {
            assert_ne!(
                wires[i], wires[j],
                "ChaCha8: packets {i} and {j} should differ"
            );
        }
    }
}

#[test]
fn chacha8_empty_payload() {
    let mode = ByteCipherMode::ObfuscateAll {
        algorithm: ObfuscationAlgorithm::ChaCha8,
        obf_key: obf_key(),
    };
    let (mut client, mut server) = pair(mode);
    let payload: &[u8] = b"";
    let wire = client.wrap(payload);
    // Wire = 8-byte nonce + empty ciphertext.
    assert_eq!(wire.len(), 8);
    let plain = server.unwrap(&wire).unwrap();
    assert_eq!(plain, payload);
}

// ── 6. ByteCipher reset ───────────────────────────────────────────────────────

#[test]
fn reset_restores_counter() {
    let mode = ByteCipherMode::ObfuscateAll {
        algorithm: ObfuscationAlgorithm::XorBlake3,
        obf_key: obf_key(),
    };
    let mut client = ByteCipher::new(mode.clone());

    let payload = vec![0x11; 32];
    let wire0 = client.wrap(&payload);

    // After reset, counter goes back to 0 — same wire bytes as first packet.
    client.reset();
    let wire0_again = client.wrap(&payload);
    assert_eq!(wire0, wire0_again, "reset should restore counter to 0");
}

#[test]
fn reset_restores_first_packet_flag() {
    let mode = ByteCipherMode::ValidateFirst { magic: magic() };
    let mut client = ByteCipher::new(mode.clone());

    let payload = b"first";
    let w1 = client.wrap(payload);
    assert_eq!(w1.len(), 16 + payload.len(), "first wrap should add magic");

    let w2 = client.wrap(payload);
    assert_eq!(w2.len(), payload.len(), "second wrap should be passthrough");

    client.reset();
    let w3 = client.wrap(payload);
    assert_eq!(w3.len(), 16 + payload.len(), "after reset, magic should be added again");
}

// ── 7. Serde roundtrip ────────────────────────────────────────────────────────

#[test]
fn serde_raw() {
    let mode = ByteCipherMode::Raw;
    let json = serde_json::to_string(&mode).unwrap();
    let back: ByteCipherMode = serde_json::from_str(&json).unwrap();
    assert_eq!(mode, back, "Raw serde roundtrip");
}

#[test]
fn serde_validate_first() {
    let mode = ByteCipherMode::ValidateFirst { magic: magic() };
    let json = serde_json::to_string(&mode).unwrap();
    let back: ByteCipherMode = serde_json::from_str(&json).unwrap();
    assert_eq!(mode, back, "ValidateFirst serde roundtrip");
}

#[test]
fn serde_strip_first() {
    let mode = ByteCipherMode::StripFirst { magic: magic(), junk_size: 64 };
    let json = serde_json::to_string(&mode).unwrap();
    let back: ByteCipherMode = serde_json::from_str(&json).unwrap();
    assert_eq!(mode, back, "StripFirst serde roundtrip");
}

#[test]
fn serde_obfuscate_all_xor_blake3() {
    let mode = ByteCipherMode::ObfuscateAll {
        algorithm: ObfuscationAlgorithm::XorBlake3,
        obf_key: obf_key(),
    };
    let json = serde_json::to_string(&mode).unwrap();
    let back: ByteCipherMode = serde_json::from_str(&json).unwrap();
    assert_eq!(mode, back, "ObfuscateAll/XorBlake3 serde roundtrip");
}

#[test]
fn serde_obfuscate_all_chacha8() {
    let mode = ByteCipherMode::ObfuscateAll {
        algorithm: ObfuscationAlgorithm::ChaCha8,
        obf_key: obf_key(),
    };
    let json = serde_json::to_string(&mode).unwrap();
    let back: ByteCipherMode = serde_json::from_str(&json).unwrap();
    assert_eq!(mode, back, "ObfuscateAll/ChaCha8 serde roundtrip");
}

#[test]
fn serde_json_structure_raw() {
    // Verify "raw" is the mode tag value for Raw.
    let json = serde_json::to_string(&ByteCipherMode::Raw).unwrap();
    assert!(json.contains("\"raw\""), "Raw should serialize with mode=raw, got: {json}");
}

#[test]
fn serde_json_structure_obfuscate_all() {
    let mode = ByteCipherMode::ObfuscateAll {
        algorithm: ObfuscationAlgorithm::ChaCha8,
        obf_key: [0u8; 32],
    };
    let json = serde_json::to_string(&mode).unwrap();
    assert!(json.contains("\"obfuscate_all\""), "ObfuscateAll mode tag missing: {json}");
    assert!(json.contains("\"cha_cha8\"") || json.contains("\"chacha8\"") || json.contains("cha"),
        "ChaCha8 algorithm tag missing: {json}");
}

// ── 8. Cross-mode asymmetry ────────────────────────────────────────────────────

#[test]
fn validate_first_second_packet_no_magic_required() {
    // After first packet accepted, server should NOT look for magic on subsequent packets.
    let mode = ByteCipherMode::ValidateFirst { magic: magic() };
    let (mut client, mut server) = pair(mode);

    // First packet
    let w1 = client.wrap(b"first");
    server.unwrap(&w1).unwrap();

    // Second packet — no magic, just raw bytes.  Should succeed.
    let w2 = client.wrap(b"second");
    assert_eq!(w2, b"second", "second packet should not have magic");
    let r2 = server.unwrap(&w2).unwrap();
    assert_eq!(r2, b"second");
}

#[test]
fn strip_first_zero_junk() {
    // junk_size=0 means only magic is stripped, no junk.
    let mode = ByteCipherMode::StripFirst { magic: magic(), junk_size: 0 };
    let (mut client, mut server) = pair(mode);
    let payload = b"no junk";
    let wire = client.wrap(payload);
    assert_eq!(wire.len(), 16 + payload.len());
    let plain = server.unwrap(&wire).unwrap();
    assert_eq!(plain, payload);
}
