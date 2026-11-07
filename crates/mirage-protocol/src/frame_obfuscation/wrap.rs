use mirage_core::error::MirageError;

// ---------------------------------------------------------------------------
// Base64 encoding — inline implementation, no external crate.
// ---------------------------------------------------------------------------

const BASE64_CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn base64_encode(input: &[u8]) -> String {
    let mut out = Vec::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0] as usize;
        let b1 = chunk.get(1).copied().unwrap_or(0) as usize;
        let b2 = chunk.get(2).copied().unwrap_or(0) as usize;

        out.push(BASE64_CHARS[b0 >> 2]);
        out.push(BASE64_CHARS[((b0 & 0x03) << 4) | (b1 >> 4)]);
        if chunk.len() > 1 {
            out.push(BASE64_CHARS[((b1 & 0x0f) << 2) | (b2 >> 6)]);
        } else {
            out.push(b'=');
        }
        if chunk.len() > 2 {
            out.push(BASE64_CHARS[b2 & 0x3f]);
        } else {
            out.push(b'=');
        }
    }
    // SAFETY: BASE64_CHARS is ASCII so output is valid UTF-8.
    unsafe { String::from_utf8_unchecked(out) }
}

const BASE64_DECODE: [i8; 256] = {
    let mut table = [-1i8; 256];
    let mut i = 0usize;
    while i < 64 {
        table[BASE64_CHARS[i] as usize] = i as i8;
        i += 1;
    }
    table
};

fn base64_decode(input: &[u8]) -> Option<Vec<u8>> {
    let input: Vec<u8> = input.iter().copied().filter(|&b| b != b'=').collect();
    let mut out = Vec::with_capacity(input.len() * 3 / 4);
    for chunk in input.chunks(4) {
        let v: Vec<u8> = chunk
            .iter()
            .map(|&b| {
                let v = BASE64_DECODE[b as usize];
                if v < 0 { 255u8 } else { v as u8 }
            })
            .collect();
        if v.contains(&255) {
            return None;
        }
        out.push((v[0] << 2) | (v[1] >> 4));
        if chunk.len() >= 3 {
            out.push((v[1] << 4) | (v[2] >> 2));
        }
        if chunk.len() >= 4 {
            out.push((v[2] << 6) | v[3]);
        }
    }
    Some(out)
}

// ---------------------------------------------------------------------------
// UUID-like random hex generation (no uuid crate needed).
// ---------------------------------------------------------------------------

fn random_request_id() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let a: u32 = rng.gen();
    let b: u16 = rng.gen();
    let c: u16 = (rng.gen::<u16>() & 0x0fff) | 0x4000; // version 4
    let d: u16 = (rng.gen::<u16>() & 0x3fff) | 0x8000; // variant bits
    let e: u64 = rng.gen::<u64>() & 0x0000_ffff_ffff_ffff;
    format!("{a:08x}-{b:04x}-{c:04x}-{d:04x}-{e:012x}")
}

fn unix_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// ---------------------------------------------------------------------------
// JSON API camouflage
// ---------------------------------------------------------------------------

/// Wrap `data` as a base64 payload inside a fake JSON API response envelope.
///
/// Output format:
/// ```json
/// {"status":200,"data":"<base64>","request_id":"<uuid>","timestamp":<unix_ts>}
/// ```
pub fn wrap_json_api(data: &[u8]) -> Vec<u8> {
    let encoded = base64_encode(data);
    let request_id = random_request_id();
    let timestamp = unix_timestamp();
    let json = format!(
        r#"{{"status":200,"data":"{encoded}","request_id":"{request_id}","timestamp":{timestamp}}}"#
    );
    json.into_bytes()
}

/// Extract data from a JSON API camouflage wrapper produced by [`wrap_json_api`].
pub fn unwrap_json_api(wrapped: &[u8]) -> Result<Vec<u8>, MirageError> {
    let v: serde_json::Value = serde_json::from_slice(wrapped)
        .map_err(|e| MirageError::Protocol(format!("json parse error: {e}")))?;

    let encoded = v
        .get("data")
        .and_then(|d| d.as_str())
        .ok_or_else(|| MirageError::Protocol("missing 'data' field in JSON wrapper".into()))?;

    base64_decode(encoded.as_bytes())
        .ok_or_else(|| MirageError::Protocol("base64 decode failed in JSON wrapper".into()))
}

// ---------------------------------------------------------------------------
// gRPC camouflage
// ---------------------------------------------------------------------------

/// Wrap `data` as a standard gRPC DATA frame.
///
/// Wire layout:
/// ```text
/// [1B: compressed flag = 0x00][4B big-endian: payload length][payload]
/// ```
pub fn wrap_grpc(data: &[u8]) -> Vec<u8> {
    let len = data.len() as u32;
    let mut out = Vec::with_capacity(5 + data.len());
    out.push(0x00); // compressed flag: not compressed
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(data);
    out
}

/// Extract data from a gRPC frame wrapper produced by [`wrap_grpc`].
pub fn unwrap_grpc(wrapped: &[u8]) -> Result<Vec<u8>, MirageError> {
    if wrapped.len() < 5 {
        return Err(MirageError::Protocol(
            "gRPC frame too short: need at least 5 bytes".into(),
        ));
    }
    let _compressed = wrapped[0];
    let payload_len = u32::from_be_bytes([wrapped[1], wrapped[2], wrapped[3], wrapped[4]]) as usize;
    let payload = wrapped.get(5..5 + payload_len).ok_or_else(|| {
        MirageError::Protocol(format!(
            "gRPC frame truncated: expected {payload_len} payload bytes, got {}",
            wrapped.len().saturating_sub(5)
        ))
    })?;
    Ok(payload.to_vec())
}

// ---------------------------------------------------------------------------
// HTTP/2 DATA frame camouflage
// ---------------------------------------------------------------------------

/// Wrap `data` as an HTTP/2 DATA frame.
///
/// Wire layout per RFC 7540 §4.1:
/// ```text
/// [3B big-endian: payload length][1B type = 0x00 (DATA)][1B flags = 0x00][4B stream_id][payload]
/// ```
pub fn wrap_h2_data(data: &[u8], stream_id: u32) -> Vec<u8> {
    let len = data.len() as u32;
    let mut out = Vec::with_capacity(9 + data.len());
    // 3-byte big-endian length
    out.push(((len >> 16) & 0xff) as u8);
    out.push(((len >> 8) & 0xff) as u8);
    out.push((len & 0xff) as u8);
    out.push(0x00); // frame type: DATA
    out.push(0x00); // flags: none
    // stream_id: 31-bit field (MSB reserved = 0)
    out.extend_from_slice(&(stream_id & 0x7fff_ffff).to_be_bytes());
    out.extend_from_slice(data);
    out
}

/// Extract data from an HTTP/2 DATA frame wrapper produced by [`wrap_h2_data`].
pub fn unwrap_h2_data(wrapped: &[u8]) -> Result<Vec<u8>, MirageError> {
    if wrapped.len() < 9 {
        return Err(MirageError::Protocol(
            "HTTP/2 frame too short: need at least 9 bytes".into(),
        ));
    }
    let payload_len =
        ((wrapped[0] as usize) << 16) | ((wrapped[1] as usize) << 8) | (wrapped[2] as usize);
    let frame_type = wrapped[3];
    if frame_type != 0x00 {
        return Err(MirageError::Protocol(format!(
            "unexpected HTTP/2 frame type: 0x{frame_type:02X}, expected 0x00 (DATA)"
        )));
    }
    let payload = wrapped.get(9..9 + payload_len).ok_or_else(|| {
        MirageError::Protocol(format!(
            "HTTP/2 frame truncated: expected {payload_len} payload bytes, got {}",
            wrapped.len().saturating_sub(9)
        ))
    })?;
    Ok(payload.to_vec())
}
