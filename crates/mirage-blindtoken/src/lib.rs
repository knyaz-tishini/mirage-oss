//! RFC 9474 blind token issuance primitive (RSABSSA-SHA384-PSS-Randomized).
//!
//! Wraps `blind-rsa-signatures` 0.17.2 behind a fixed-size-byte API so
//! callers never import the upstream crate directly.
//!
//! Role split:
//! - **Issuer** (opbox): holds [`IssuerSecretKey`]; calls [`blind_sign`].
//! - **Client**: calls [`blind`] → [`unblind`]; retains the [`ClientBlind`] state
//!   between the two steps.
//! - **Verifier** (node): holds [`IssuerPublicKey`]; calls [`verify`].

use blind_rsa_signatures::{
    BlindSignature, DefaultRng, KeyPairSha384PSSRandomized, MessageRandomizer,
    PublicKeySha384PSSRandomized, SecretKeySha384PSSRandomized, Signature,
};

// ── constants ────────────────────────────────────────────────────────────────

/// RSA modulus size used throughout this crate.
pub const RSA_BITS: usize = 2048;

/// Byte length of a 2048-bit RSA signature / blinded message / blind signature.
pub const SIG_LEN: usize = 256;

/// Byte length of a blinded token message (same as modulus bytes for RSA-2048).
pub const BLINDED_LEN: usize = 256;

/// Byte length of the `MessageRandomizer` produced by the Randomized variant.
pub const RANDOMIZER_LEN: usize = 32;

/// Byte length of a token message (a 32-byte nonce or commitment).
pub const MSG_LEN: usize = 32;

// ── fixed-size type aliases ──────────────────────────────────────────────────

/// A 32-byte token message (input to [`blind`]).
pub type TokenMsg = [u8; MSG_LEN];

/// The 32-byte message randomizer produced during blinding; required for
/// verification. Store alongside the final signature when redeeming.
pub type Randomizer = [u8; RANDOMIZER_LEN];

/// A 256-byte final (unblinded) token signature. Produced by [`unblind`],
/// verified by [`verify`].
pub type TokenSig = [u8; SIG_LEN];

// ── error type ───────────────────────────────────────────────────────────────

#[derive(thiserror::Error, Debug)]
pub enum BlindTokenError {
    #[error("key generation failed: {0}")]
    Keygen(String),

    #[error("blinding failed: {0}")]
    Blind(String),

    #[error("blind signing failed: {0}")]
    BlindSign(String),

    #[error("unblinding failed: {0}")]
    Unblind(String),

    #[error("token verification failed: {0}")]
    Verify(String),

    #[error("key encoding/decoding failed: {0}")]
    Encoding(String),

    #[error("byte slice has wrong length: expected {expected}, got {got}")]
    BadLength { expected: usize, got: usize },
}

// ── key types ────────────────────────────────────────────────────────────────

/// Issuer signing key (RSA-2048 secret key, RSABSSA-SHA384-PSS-Randomized).
///
/// Must reside only with the issuing authority (opbox). Never distribute or
/// log this value. `Debug` intentionally redacts all key material.
pub struct IssuerSecretKey(SecretKeySha384PSSRandomized);

impl std::fmt::Debug for IssuerSecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("IssuerSecretKey(<redacted>)")
    }
}

/// Public verification key (RSA-2048 public key, RSABSSA-SHA384-PSS-Randomized).
///
/// Distribute to nodes that need to verify tokens. `Debug` shows the DER
/// byte length only — no key material.
#[derive(Clone)]
pub struct IssuerPublicKey(PublicKeySha384PSSRandomized);

impl std::fmt::Debug for IssuerPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let len = self.0.to_der().map(|d| d.len()).unwrap_or(0);
        write!(f, "IssuerPublicKey(der_len={})", len)
    }
}

// ── client blinding state ────────────────────────────────────────────────────

/// Client-held state for one in-flight blinding operation.
///
/// Created by [`blind`]; consumed by [`unblind`]. Do not reuse for a
/// second message — call [`blind`] again instead.
pub struct ClientBlind {
    result: blind_rsa_signatures::BlindingResult,
}

// ── keygen ───────────────────────────────────────────────────────────────────

/// Generate a fresh RSA-2048 issuer key pair.
///
/// Returns `(secret_key, public_key)`. The secret key stays with the issuer;
/// the public key is distributed to verifiers.
///
/// Internally uses [`DefaultRng`] (OS entropy via `rand`).
pub fn issuer_keygen() -> Result<(IssuerSecretKey, IssuerPublicKey), BlindTokenError> {
    let mut rng = DefaultRng;
    let kp = KeyPairSha384PSSRandomized::generate(&mut rng, RSA_BITS)
        .map_err(|e| BlindTokenError::Keygen(e.to_string()))?;
    Ok((IssuerSecretKey(kp.sk), IssuerPublicKey(kp.pk)))
}

// ── IssuerPublicKey methods ───────────────────────────────────────────────────

impl IssuerPublicKey {
    /// Encode the public key as DER bytes (SPKI/PKCS#8 public key format).
    ///
    /// Suitable for storage in node config or an epoch entry.
    pub fn to_der(&self) -> Result<Vec<u8>, BlindTokenError> {
        self.0
            .to_der()
            .map_err(|e| BlindTokenError::Encoding(e.to_string()))
    }

    /// Decode a public key from DER bytes produced by [`IssuerPublicKey::to_der`].
    pub fn from_der(der: &[u8]) -> Result<Self, BlindTokenError> {
        PublicKeySha384PSSRandomized::from_der(der)
            .map(IssuerPublicKey)
            .map_err(|e| BlindTokenError::Encoding(e.to_string()))
    }
}

// ── IssuerSecretKey methods ───────────────────────────────────────────────────

impl IssuerSecretKey {
    /// Encode the secret key as DER bytes (PKCS#8 private key format).
    ///
    /// Keep this sealed — it is the capability to issue tokens.
    pub fn to_der(&self) -> Result<Vec<u8>, BlindTokenError> {
        self.0
            .to_der()
            .map_err(|e| BlindTokenError::Encoding(e.to_string()))
    }

    /// Decode a secret key from DER bytes produced by [`IssuerSecretKey::to_der`].
    pub fn from_der(der: &[u8]) -> Result<Self, BlindTokenError> {
        SecretKeySha384PSSRandomized::from_der(der)
            .map(IssuerSecretKey)
            .map_err(|e| BlindTokenError::Encoding(e.to_string()))
    }

    /// Derive the corresponding public key from this secret key.
    ///
    /// Useful when only the secret key was persisted and the public key is
    /// needed for distribution or consistency checks.
    pub fn public_key(&self) -> Result<IssuerPublicKey, BlindTokenError> {
        self.0
            .public_key()
            .map(IssuerPublicKey)
            .map_err(|e| BlindTokenError::Encoding(e.to_string()))
    }
}

// ── protocol functions ────────────────────────────────────────────────────────

/// **CLIENT**: Blind a 32-byte token message.
///
/// Returns the bytes to forward to the issuer and the [`ClientBlind`] state
/// that must be retained until [`unblind`] is called. The issuer never sees
/// the original `msg` or the blinding secret inside `ClientBlind`.
///
/// The returned `Vec<u8>` has length [`BLINDED_LEN`] (256 bytes for RSA-2048).
pub fn blind(
    pk: &IssuerPublicKey,
    msg: &TokenMsg,
) -> Result<(Vec<u8>, ClientBlind), BlindTokenError> {
    let mut rng = DefaultRng;
    let result = pk
        .0
        .blind(&mut rng, msg.as_ref())
        .map_err(|e| BlindTokenError::Blind(e.to_string()))?;
    let blinded_bytes = result.blind_message.0.clone();
    Ok((blinded_bytes, ClientBlind { result }))
}

/// **ISSUER** (stateless): Sign a blinded message received from a client.
///
/// Returns the 256-byte blind signature. The issuer retains no per-token
/// state — calling this twice with the same input yields the same bytes.
///
/// `blinded` must be exactly [`BLINDED_LEN`] bytes.
pub fn blind_sign(
    sk: &IssuerSecretKey,
    blinded: &[u8],
) -> Result<Vec<u8>, BlindTokenError> {
    if blinded.len() != BLINDED_LEN {
        return Err(BlindTokenError::BadLength {
            expected: BLINDED_LEN,
            got: blinded.len(),
        });
    }
    let blind_sig = sk
        .0
        .blind_sign(blinded)
        .map_err(|e| BlindTokenError::BlindSign(e.to_string()))?;
    Ok(blind_sig.0)
}

/// **CLIENT**: Unblind the issuer's response into a final token.
///
/// Returns `(signature, randomizer)` — a [`TokenSig`] and [`Randomizer`] pair.
/// Both must be stored and presented together at verification time.
///
/// `blind_sig` must be exactly [`SIG_LEN`] bytes.
pub fn unblind(
    pk: &IssuerPublicKey,
    blind_sig: &[u8],
    state: &ClientBlind,
    msg: &TokenMsg,
) -> Result<(TokenSig, Randomizer), BlindTokenError> {
    if blind_sig.len() != SIG_LEN {
        return Err(BlindTokenError::BadLength {
            expected: SIG_LEN,
            got: blind_sig.len(),
        });
    }
    let bs = BlindSignature(blind_sig.to_vec());
    let sig: Signature = pk
        .0
        .finalize(&bs, &state.result, msg.as_ref())
        .map_err(|e| BlindTokenError::Unblind(e.to_string()))?;

    // Convert signature bytes to fixed-size array.
    let sig_bytes: [u8; SIG_LEN] = sig.0.as_slice().try_into().map_err(|_| {
        BlindTokenError::BadLength {
            expected: SIG_LEN,
            got: sig.0.len(),
        }
    })?;

    // Extract the 32-byte message randomizer (always Some for Randomized variant).
    let randomizer: [u8; RANDOMIZER_LEN] = match state.result.msg_randomizer {
        Some(MessageRandomizer(r)) => r,
        None => {
            // The Randomized variant always produces a randomizer; this path
            // is unreachable for the compile-time type we use.
            return Err(BlindTokenError::Unblind(
                "randomizer absent on Randomized variant".into(),
            ));
        }
    };

    Ok((sig_bytes, randomizer))
}

/// **VERIFIER** (node): Verify a final token using the public key only.
///
/// Returns `Ok(())` iff the signature is valid for `(msg, randomizer)` under
/// `pk`. Any modification of any of the three inputs causes `Err`.
///
/// This is the only operation a verifier node needs to perform; it cannot
/// issue new tokens.
pub fn verify(
    pk: &IssuerPublicKey,
    msg: &TokenMsg,
    randomizer: &Randomizer,
    sig: &TokenSig,
) -> Result<(), BlindTokenError> {
    let signature = Signature(sig.to_vec());
    let msg_randomizer = Some(MessageRandomizer(*randomizer));
    pk.0
        .verify(&signature, msg_randomizer, msg.as_ref())
        .map_err(|e| BlindTokenError::Verify(e.to_string()))
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// End-to-end issuance roundtrip: keygen → blind → sign → unblind → verify.
    #[test]
    fn roundtrip_ok() {
        let (sk, pk) = issuer_keygen().unwrap();
        let msg: TokenMsg = [0x42u8; MSG_LEN];

        let (blinded, state) = blind(&pk, &msg).unwrap();
        let blind_sig = blind_sign(&sk, &blinded).unwrap();
        let (sig, randomizer) = unblind(&pk, &blind_sig, &state, &msg).unwrap();

        verify(&pk, &msg, &randomizer, &sig).unwrap();
    }

    /// Verify rejects a different message (wrong `msg` input at verify).
    #[test]
    fn verify_rejects_wrong_msg() {
        let (sk, pk) = issuer_keygen().unwrap();
        let msg: TokenMsg = [0x01u8; MSG_LEN];
        let wrong_msg: TokenMsg = [0x02u8; MSG_LEN];

        let (blinded, state) = blind(&pk, &msg).unwrap();
        let blind_sig = blind_sign(&sk, &blinded).unwrap();
        let (sig, randomizer) = unblind(&pk, &blind_sig, &state, &msg).unwrap();

        assert!(verify(&pk, &wrong_msg, &randomizer, &sig).is_err());
    }

    /// Verify rejects a signature with one flipped byte.
    #[test]
    fn verify_rejects_modified_sig() {
        let (sk, pk) = issuer_keygen().unwrap();
        let msg: TokenMsg = [0xABu8; MSG_LEN];

        let (blinded, state) = blind(&pk, &msg).unwrap();
        let blind_sig = blind_sign(&sk, &blinded).unwrap();
        let (mut sig, randomizer) = unblind(&pk, &blind_sig, &state, &msg).unwrap();

        sig[0] ^= 0xFF;
        assert!(verify(&pk, &msg, &randomizer, &sig).is_err());
    }

    /// Verify rejects a token presented to a different issuer's public key.
    #[test]
    fn verify_rejects_wrong_pubkey() {
        let (sk, pk) = issuer_keygen().unwrap();
        let (_sk2, pk2) = issuer_keygen().unwrap();
        let msg: TokenMsg = [0x55u8; MSG_LEN];

        let (blinded, state) = blind(&pk, &msg).unwrap();
        let blind_sig = blind_sign(&sk, &blinded).unwrap();
        let (sig, randomizer) = unblind(&pk, &blind_sig, &state, &msg).unwrap();

        assert!(verify(&pk2, &msg, &randomizer, &sig).is_err());
    }

    /// Public key DER round-trip: the decoded key still verifies a token.
    #[test]
    fn pubkey_der_roundtrip() {
        let (sk, pk) = issuer_keygen().unwrap();
        let msg: TokenMsg = [0x11u8; MSG_LEN];

        let (blinded, state) = blind(&pk, &msg).unwrap();
        let blind_sig = blind_sign(&sk, &blinded).unwrap();
        let (sig, randomizer) = unblind(&pk, &blind_sig, &state, &msg).unwrap();

        let der = pk.to_der().unwrap();
        let pk2 = IssuerPublicKey::from_der(&der).unwrap();
        verify(&pk2, &msg, &randomizer, &sig).unwrap();
    }

    /// Secret key DER round-trip: the reloaded key can still issue tokens.
    #[test]
    fn seckey_der_roundtrip() {
        let (sk, pk) = issuer_keygen().unwrap();
        let msg: TokenMsg = [0x22u8; MSG_LEN];

        let sk_der = sk.to_der().unwrap();
        let sk2 = IssuerSecretKey::from_der(&sk_der).unwrap();

        let (blinded, state) = blind(&pk, &msg).unwrap();
        // Sign using the reloaded secret key.
        let blind_sig = blind_sign(&sk2, &blinded).unwrap();
        let (sig, randomizer) = unblind(&pk, &blind_sig, &state, &msg).unwrap();
        verify(&pk, &msg, &randomizer, &sig).unwrap();
    }

    /// One issuer key, two independently blinded messages — both verify, no
    /// shared per-token state on the issuer side.
    #[test]
    fn stateless_issuer_two_tokens() {
        let (sk, pk) = issuer_keygen().unwrap();

        let msg1: TokenMsg = [0xAAu8; MSG_LEN];
        let msg2: TokenMsg = [0xBBu8; MSG_LEN];

        let (blinded1, state1) = blind(&pk, &msg1).unwrap();
        let (blinded2, state2) = blind(&pk, &msg2).unwrap();

        // Issue both blind signatures from the same sk.
        let bsig1 = blind_sign(&sk, &blinded1).unwrap();
        let bsig2 = blind_sign(&sk, &blinded2).unwrap();

        let (sig1, rand1) = unblind(&pk, &bsig1, &state1, &msg1).unwrap();
        let (sig2, rand2) = unblind(&pk, &bsig2, &state2, &msg2).unwrap();

        verify(&pk, &msg1, &rand1, &sig1).unwrap();
        verify(&pk, &msg2, &rand2, &sig2).unwrap();
    }

    /// The finalized signature is exactly `SIG_LEN` bytes.
    #[test]
    fn sig_len_is_256() {
        let (sk, pk) = issuer_keygen().unwrap();
        let msg: TokenMsg = [0xCCu8; MSG_LEN];

        let (blinded, state) = blind(&pk, &msg).unwrap();
        let blind_sig = blind_sign(&sk, &blinded).unwrap();
        let (sig, _) = unblind(&pk, &blind_sig, &state, &msg).unwrap();

        assert_eq!(sig.len(), SIG_LEN);
    }

    /// Public key recovered from `IssuerSecretKey::public_key()` verifies a
    /// token that was blinded under the standalone public key. Confirms
    /// consistency between the two key handles.
    #[test]
    fn public_key_recovered_from_secret() {
        let (sk, pk) = issuer_keygen().unwrap();
        let msg: TokenMsg = [0xDDu8; MSG_LEN];

        // Blind under the standalone pk.
        let (blinded, state) = blind(&pk, &msg).unwrap();
        let blind_sig = blind_sign(&sk, &blinded).unwrap();
        let (sig, randomizer) = unblind(&pk, &blind_sig, &state, &msg).unwrap();

        // Recover pk from sk and verify.
        let recovered_pk = sk.public_key().unwrap();
        verify(&recovered_pk, &msg, &randomizer, &sig).unwrap();
    }
}
