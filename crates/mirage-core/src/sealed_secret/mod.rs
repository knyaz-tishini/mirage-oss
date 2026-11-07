//! Device-fingerprint-derived sealed secrets (ChaCha20-Poly1305).
//!
//! A `SealedSecret` binds encrypted bytes to the hardware of the machine that
//! sealed them. Moving the sealed blob to a different device causes
//! `unseal` to fail with `UnsealError::WrongDevice` because the AEAD tag
//! covers the device fingerprint as AAD.
//!
//! # Fingerprint inputs
//!
//! | Platform | Inputs |
//! |----------|--------|
//! | Linux    | `/etc/machine-id` or `/var/lib/dbus/machine-id` + `/sys/class/dmi/id/product_uuid` + `getuid()` |
//! | macOS    | `IOPlatformUUID` via `ioreg` subprocess (already firmware-stable) + `getuid()` |
//! | Windows  | `HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid` (registry, stable) + current-user SID |
//!
//! All inputs are hashed together via BLAKE3 with domain prefix
//! `b"mirage-device-fp-v2"`. Output is 32 bytes.
//!
//! MAC addresses were removed in v2 because cloud-VPS NICs change their MAC on
//! reboot or migration, which invalidated sealed secrets. `dmi_product_uuid` on
//! Linux anchors to the DMI firmware table which survives reboots.
//!
//! NEVER writes fingerprint to disk. Computed on every call (< 1 ms).
//!
//! # Byte layout of `SealedSecret`
//!
//! ```text
//! [12B nonce][4B BE aad_len][aad bytes][4B BE ciphertext_len][ciphertext bytes]
//! ```
//! AAD = the 32-byte fingerprint used at seal time (supplied by `seal`).

use chacha20poly1305::{
    aead::{Aead, KeyInit, OsRng, Payload},
    ChaCha20Poly1305, Key, Nonce,
};
use rand::RngCore;
use thiserror::Error;

// ── Error types ───────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum FingerprintError {
    #[error("OS hardware query failed: {0}")]
    OsQuery(String),
}

#[derive(Debug, Error)]
pub enum SealError {
    #[error("fingerprint: {0}")]
    Fingerprint(#[from] FingerprintError),
    #[error("AEAD encrypt failed")]
    Aead,
}

#[derive(Debug, Error)]
pub enum UnsealError {
    #[error("wrong device — AEAD tag mismatch (device fingerprint differs)")]
    WrongDevice,
    #[error("corrupt sealed blob: {0}")]
    CorruptBlob(String),
    #[error("fingerprint: {0}")]
    Fingerprint(#[from] FingerprintError),
}

// ── SealedSecret ─────────────────────────────────────────────────────────────

/// An encrypted blob bound to the device fingerprint used at seal time.
pub struct SealedSecret {
    pub nonce: [u8; 12],
    /// AAD = the 32-byte device fingerprint used at seal time.
    pub aad: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

impl SealedSecret {
    /// Serialize to `[12B nonce][4B BE aad_len][aad][4B BE ct_len][ciphertext]`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(12 + 4 + self.aad.len() + 4 + self.ciphertext.len());
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&(self.aad.len() as u32).to_be_bytes());
        out.extend_from_slice(&self.aad);
        out.extend_from_slice(&(self.ciphertext.len() as u32).to_be_bytes());
        out.extend_from_slice(&self.ciphertext);
        out
    }

    /// Deserialize from the wire format produced by `to_bytes`.
    pub fn from_bytes(buf: &[u8]) -> Result<Self, UnsealError> {
        if buf.len() < 12 + 4 {
            return Err(UnsealError::CorruptBlob("too short for nonce+aad_len".into()));
        }
        let nonce: [u8; 12] = buf[..12].try_into().unwrap();
        let aad_len = u32::from_be_bytes(buf[12..16].try_into().unwrap()) as usize;
        let after_aad = 16 + aad_len;
        if buf.len() < after_aad + 4 {
            return Err(UnsealError::CorruptBlob("too short for aad+ct_len".into()));
        }
        let aad = buf[16..after_aad].to_vec();
        let ct_len = u32::from_be_bytes(buf[after_aad..after_aad + 4].try_into().unwrap()) as usize;
        let after_ct = after_aad + 4 + ct_len;
        if buf.len() < after_ct {
            return Err(UnsealError::CorruptBlob("too short for ciphertext".into()));
        }
        let ciphertext = buf[after_aad + 4..after_ct].to_vec();
        Ok(SealedSecret { nonce, aad, ciphertext })
    }
}

// ── Device fingerprint ────────────────────────────────────────────────────────

/// Derive a 32-byte device fingerprint from stable hardware identifiers.
///
/// Inputs are hashed together with BLAKE3 under domain prefix
/// `b"mirage-device-fp-v2"`. Never written to disk. Recomputed on every call.
///
/// v2 replaces the first-non-loopback MAC (unstable on cloud-VPS reboot /
/// migration) with `dmi_product_uuid` on Linux. macOS and Windows already
/// anchor on firmware/registry IDs that survive reboots.
pub fn device_fingerprint() -> Result<[u8; 32], FingerprintError> {
    let mut h = blake3::Hasher::new();
    h.update(b"mirage-device-fp-v2");
    h.update(&os_unique_id()?);
    h.update(&dmi_product_uuid());
    h.update(&user_account_id());
    Ok(*h.finalize().as_bytes())
}

// ── Platform helpers ──────────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
fn os_unique_id() -> Result<Vec<u8>, FingerprintError> {
    for path in &["/etc/machine-id", "/var/lib/dbus/machine-id"] {
        if let Ok(s) = std::fs::read_to_string(path) {
            let trimmed = s.trim();
            if !trimmed.is_empty() {
                return Ok(trimmed.as_bytes().to_vec());
            }
        }
    }
    Err(FingerprintError::OsQuery(
        "neither /etc/machine-id nor /var/lib/dbus/machine-id readable".into(),
    ))
}

#[cfg(target_os = "macos")]
fn os_unique_id() -> Result<Vec<u8>, FingerprintError> {
    // Parse IOPlatformUUID from ioreg output.
    // Output line looks like: "IOPlatformUUID" = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
    let out = std::process::Command::new("ioreg")
        .args(["-rd1", "-c", "IOPlatformExpertDevice"])
        .output()
        .map_err(|e| FingerprintError::OsQuery(format!("ioreg exec: {e}")))?;
    let text = String::from_utf8_lossy(&out.stdout);
    for line in text.lines() {
        if line.contains("IOPlatformUUID") {
            // Extract the quoted UUID value.
            if let Some(start) = line.rfind('"') {
                let after = &line[..start];
                if let Some(start2) = after.rfind('"') {
                    let uuid = &after[start2 + 1..];
                    if !uuid.is_empty() {
                        return Ok(uuid.as_bytes().to_vec());
                    }
                }
            }
        }
    }
    Err(FingerprintError::OsQuery("IOPlatformUUID not found in ioreg output".into()))
}

#[cfg(target_os = "windows")]
fn os_unique_id() -> Result<Vec<u8>, FingerprintError> {
    // Read MachineGuid from registry: HKLM\SOFTWARE\Microsoft\Cryptography
    use winreg::enums::HKEY_LOCAL_MACHINE;
    use winreg::RegKey;
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let key = hklm
        .open_subkey(r"SOFTWARE\Microsoft\Cryptography")
        .map_err(|e| FingerprintError::OsQuery(format!("open Cryptography key: {e}")))?;
    let guid: String = key
        .get_value("MachineGuid")
        .map_err(|e| FingerprintError::OsQuery(format!("read MachineGuid: {e}")))?;
    Ok(guid.into_bytes())
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn os_unique_id() -> Result<Vec<u8>, FingerprintError> {
    // Unsupported platform — return a fixed domain-specific constant so the
    // fingerprint is at least unique per-binary rather than per-device.
    // This is a stub: device binding is not enforced on unknown platforms.
    Ok(b"mirage-unknown-platform-stub-v1".to_vec())
}

// ── DMI product_uuid helper ───────────────────────────────────────────────────

/// Returns the DMI `product_uuid` bytes for fingerprint anchoring.
///
/// Linux: reads `/sys/class/dmi/id/product_uuid` (trim whitespace). Falls back
/// to a fixed domain constant if the file is absent or empty (some containers
/// lack DMI; the `machine-id` component still binds the fingerprint).
///
/// macOS / Windows: returns an empty `Vec` — their `os_unique_id` already
/// provides a stable firmware/registry identifier, so no additional DMI anchor
/// is needed.
fn dmi_product_uuid() -> Vec<u8> {
    #[cfg(target_os = "linux")]
    {
        if let Ok(s) = std::fs::read_to_string("/sys/class/dmi/id/product_uuid") {
            let trimmed = s.trim();
            if !trimmed.is_empty() {
                return trimmed.as_bytes().to_vec();
            }
        }
        // Fallback: no DMI available (container / old kernel). machine-id still binds.
        b"mirage-no-dmi-product-uuid".to_vec()
    }
    #[cfg(not(target_os = "linux"))]
    {
        // macOS: IOPlatformUUID is firmware-stable — no extra anchor needed.
        // Windows: MachineGuid is registry-persistent — no extra anchor needed.
        Vec::new()
    }
}

// ── User account id ───────────────────────────────────────────────────────────

fn user_account_id() -> Vec<u8> {
    #[cfg(unix)]
    {
        // SAFETY: getuid() is always safe.
        let uid = unsafe { libc::getuid() };
        uid.to_le_bytes().to_vec()
    }
    #[cfg(target_os = "windows")]
    {
        windows_user_sid()
    }
    #[cfg(not(any(unix, target_os = "windows")))]
    {
        b"unknown-uid".to_vec()
    }
}

#[cfg(target_os = "windows")]
fn windows_user_sid() -> Vec<u8> {
    use windows_sys::Win32::Security::{
        GetTokenInformation, TokenUser, TOKEN_QUERY, TOKEN_USER,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
    use windows_sys::Win32::Foundation::{CloseHandle, LocalFree};

    let mut token = std::ptr::null_mut();
    // SAFETY: standard Windows API call.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return b"windows-sid-unknown".to_vec();
    }

    let mut needed: u32 = 0;
    // First call to get size.
    unsafe { GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut needed) };
    if needed == 0 {
        unsafe { CloseHandle(token) };
        return b"windows-sid-unknown".to_vec();
    }

    let mut buf = vec![0u8; needed as usize];
    if unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            buf.as_mut_ptr() as *mut _,
            needed,
            &mut needed,
        )
    } == 0
    {
        unsafe { CloseHandle(token) };
        return b"windows-sid-unknown".to_vec();
    }

    // SAFETY: GetTokenInformation filled the buffer with TOKEN_USER.
    let tu = unsafe { &*(buf.as_ptr() as *const TOKEN_USER) };
    let sid_ptr = tu.User.Sid;

    let mut str_sid: *mut u16 = std::ptr::null_mut();
    if unsafe { ConvertSidToStringSidW(sid_ptr, &mut str_sid) } == 0 {
        unsafe { CloseHandle(token) };
        return b"windows-sid-unknown".to_vec();
    }

    // Convert wide string to UTF-8.
    let result = {
        let mut len = 0usize;
        while unsafe { *str_sid.add(len) } != 0 {
            len += 1;
        }
        let wide: Vec<u16> = (0..len).map(|i| unsafe { *str_sid.add(i) }).collect();
        String::from_utf16_lossy(&wide).into_bytes()
    };

    unsafe { LocalFree(str_sid as _) };
    unsafe { CloseHandle(token) };
    result
}

// ── Key derivation helper ─────────────────────────────────────────────────────

/// Derive a 32-byte ChaCha20-Poly1305 key from the device fingerprint.
/// Uses BLAKE3 keyed-hash with a 32-byte domain key padded to exact length.
fn derive_key(fingerprint: &[u8; 32]) -> Key {
    // Domain label padded to exactly 32 bytes for BLAKE3 keyed_hash.
    let domain: [u8; 32] = *b"mirage-sealed-secret-v1\0\0\0\0\0\0\0\0\0";
    let hash = blake3::keyed_hash(&domain, fingerprint);
    *Key::from_slice(&hash.as_bytes()[..32])
}

// ── seal / unseal ─────────────────────────────────────────────────────────────

/// Encrypt `plaintext` with ChaCha20-Poly1305 bound to the current device fingerprint.
///
/// Key = `BLAKE3_KDF(fingerprint, "mirage-sealed-secret-v1")`.
/// Nonce = random 12 bytes from `OsRng`.
/// AAD = the 32-byte fingerprint (so any modified fingerprint at unseal time
/// fails the AEAD tag check — no separate comparison step needed).
pub fn seal(plaintext: &[u8]) -> Result<SealedSecret, SealError> {
    let fp = device_fingerprint()?;
    seal_with_fingerprint(plaintext, &fp)
}

/// Seal using a caller-supplied fingerprint (for cross-device sealing in the
/// operator tool: operator runs `seal-tool dump-fp` on the target, then seals
/// on the dev box using that fingerprint hex).
pub fn seal_with_fingerprint(
    plaintext: &[u8],
    fingerprint: &[u8; 32],
) -> Result<SealedSecret, SealError> {
    let key = derive_key(fingerprint);
    let cipher = ChaCha20Poly1305::new(&key);

    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let payload = Payload {
        msg: plaintext,
        aad: fingerprint.as_slice(),
    };
    let ciphertext = cipher.encrypt(nonce, payload).map_err(|_| SealError::Aead)?;

    Ok(SealedSecret {
        nonce: nonce_bytes,
        aad: fingerprint.to_vec(),
        ciphertext,
    })
}

/// Decrypt a `SealedSecret`. Fails with `UnsealError::WrongDevice` if the
/// current device's fingerprint does not match the one used at seal time.
pub fn unseal(sealed: &SealedSecret) -> Result<Vec<u8>, UnsealError> {
    let fp = device_fingerprint()?;
    // AEAD tag covers fp-as-AAD — if fp differs the tag check fails.
    let key = derive_key(&fp);
    let cipher = ChaCha20Poly1305::new(&key);
    let nonce = Nonce::from_slice(&sealed.nonce);
    let payload = Payload {
        msg: &sealed.ciphertext,
        aad: &sealed.aad,
    };
    cipher
        .decrypt(nonce, payload)
        .map_err(|_| UnsealError::WrongDevice)
}

