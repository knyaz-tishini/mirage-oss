//! Camouflage layer — real TLS 1.3 outer wrapping via rustls.
//!
//! Client: opens a genuine TLS 1.3 session to the server (configurable SNI / ALPN)
//! and hands the TLS stream to the inner Mirage handshake.
//!
//! # Certificate verification
//!
//! The TLS peer certificate is **NOT validated by PKI** — security lives in the
//! Mirage handshake (X25519 + BLAKE3).  `NoopCertVerifier` is intentional here
//! and mirrors the design of the QUIC layer (`l2/udp/mirage_quic.rs`).
//! DPI sees a legitimate TLS 1.3 handshake to the configured SNI; active probers
//! that complete TLS but skip the Mirage inner handshake receive a graceful close.
//!
//! # Server certificate
//!
//! Server: accepts TLS 1.3 with a self-signed cert generated at startup via `rcgen`,
//! **issued to the configured SNI**. Callers may supply their own DER-encoded cert
//! + key pair via `new()` when a real CA-issued certificate is available.
//!
//! What the generated certificate says is camouflage, not credential — nothing
//! validates it (see above). That is exactly why it has to be plausible: it is
//! the one thing every passive TLS scanner on the internet records about this
//! port, and until 2026-08-04 it said `mirage.local`, with a validity window of
//! 1975 → 4096, on every box in the fleet. One string and one absurd date range,
//! shared fleet-wide, is a better fingerprint than the port number it was hiding.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use mirage_core::error::MirageError;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio_rustls::{client, server, TlsAcceptor, TlsConnector};

use crate::camouflage::{private, CamouflageLayer};

// ─────────────────────────────────────────────────────────────────────────────
// TLS config builders
// ─────────────────────────────────────────────────────────────────────────────

/// How far back the generated certificate's validity starts. A `not_before` of
/// exactly now is unusual — real issuance backdates slightly for clock skew —
/// and a certificate that became valid the same second a scanner saw it is a
/// tell that the process just started.
const CERT_BACKDATE_DAYS: i64 = 2;

/// Validity length. 90 days is what the overwhelming majority of certificates
/// on the public internet carry, because that is Let's Encrypt's lifetime.
const CERT_VALID_DAYS: i64 = 90;

/// Days since the Unix epoch → `(year, month, day)` in the civil calendar.
///
/// Howard Hinnant's `civil_from_days`, written out rather than pulled in as a
/// dependency: setting two certificate dates is the only calendar arithmetic
/// this crate does, and `rcgen::date_time_ymd` takes the parts directly, so a
/// date crate would be carried through the whole tree for fifteen lines.
fn civil_from_days(days: i64) -> (i32, u8, u8) {
    // Shift the epoch to 0000-03-01 so leap days land at the end of the cycle.
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11], March-based
    let day = (doy - (153 * mp + 2) / 5 + 1) as u8;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u8;
    let year = yoe + era * 400 + i64::from(month <= 2);
    (year as i32, month, day)
}

/// Generate a fresh self-signed TLS certificate **issued to `name`**.
///
/// `name` becomes both the subject CN and the SAN, because a scanner reads
/// both and a certificate whose subject and SAN disagree is itself unusual.
/// An empty name is refused rather than silently substituted: a `tls_real` face
/// with no SNI cannot be dialled either (`ServerName::try_from("")` fails), so
/// accepting one here would bind a listener wearing a costume nobody asked for
/// — the same "report healthy while serving something else" shape the perimeter
/// refuses at config parse.
///
/// Returns `(cert_der, key_der)`.
fn generate_self_signed_cert(
    name: &str,
) -> Result<(CertificateDer<'static>, PrivateKeyDer<'static>), MirageError> {
    if name.is_empty() {
        return Err(MirageError::Config(
            "tls_real needs an SNI to issue its certificate to; an empty one cannot be dialled \
             and must not be served"
                .into(),
        ));
    }

    let today = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| (d.as_secs() / 86_400) as i64)
        // A box whose clock is before 1970 is broken in ways a certificate
        // cannot fix; fall back to a fixed recent day rather than panicking on
        // the accept path.
        .unwrap_or(20_000);
    let (y0, m0, d0) = civil_from_days(today - CERT_BACKDATE_DAYS);
    let (y1, m1, d1) = civil_from_days(today + CERT_VALID_DAYS);

    let mut params = rcgen::CertificateParams::new(vec![name.to_string()])
        .map_err(|e| MirageError::Config(format!("rcgen params for '{name}': {e}")))?;
    let mut dn = rcgen::DistinguishedName::new();
    dn.push(rcgen::DnType::CommonName, name);
    params.distinguished_name = dn;
    params.not_before = rcgen::date_time_ymd(y0, m0, d0);
    params.not_after = rcgen::date_time_ymd(y1, m1, d1);

    let key = rcgen::KeyPair::generate()
        .map_err(|e| MirageError::Config(format!("rcgen keypair: {e}")))?;
    let cert = params
        .self_signed(&key)
        .map_err(|e| MirageError::Config(format!("rcgen self-signed for '{name}': {e}")))?;

    let cert_der = CertificateDer::from(cert.der().to_vec());
    let key_der = PrivateKeyDer::try_from(key.serialize_der())
        .map_err(|e| MirageError::Config(format!("rcgen private key: {e}")))?;
    Ok((cert_der, key_der))
}

fn build_server_tls_config(
    cert: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
    alpn: &[Vec<u8>],
) -> Result<rustls::ServerConfig, MirageError> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut cfg = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| MirageError::Config(format!("rustls server config: {e}")))?
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .map_err(|e| MirageError::Config(format!("rustls single_cert: {e}")))?;
    if !alpn.is_empty() {
        cfg.alpn_protocols = alpn.to_vec();
    }
    Ok(cfg)
}

/// Build a `rustls::ClientConfig` that accepts **any** server certificate.
///
/// # Security note
///
/// `NoopCertVerifier` is intentional — this is **by design**.
/// Security is provided by the inner Mirage X25519 + BLAKE3 handshake, not TLS PKI.
/// The outer TLS session is purely for traffic camouflage / DPI evasion.
fn build_client_tls_config(alpn: &[Vec<u8>]) -> Result<rustls::ClientConfig, MirageError> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut cfg = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| MirageError::Config(format!("rustls client config: {e}")))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoopCertVerifier))
        .with_no_client_auth();
    if !alpn.is_empty() {
        cfg.alpn_protocols = alpn.to_vec();
    }
    Ok(cfg)
}

// ─────────────────────────────────────────────────────────────────────────────
// NoopCertVerifier — intentional, by design
// ─────────────────────────────────────────────────────────────────────────────

/// Certificate verifier that accepts any certificate.
///
/// This is intentional — security is provided by the Mirage inner handshake
/// (X25519 ECDH + BLAKE3 auth), not TLS PKI.  Probe resistance comes from
/// the Mirage auth layer, not from certificate validation.
#[derive(Debug)]
struct NoopCertVerifier;

impl rustls::client::danger::ServerCertVerifier for NoopCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
            rustls::SignatureScheme::ED25519,
        ]
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TlsRealCamouflage
// ─────────────────────────────────────────────────────────────────────────────

/// TLS 1.3 transport-level camouflage.
///
/// Wraps a raw `TcpStream` in a genuine TLS 1.3 session before the Mirage ECDH
/// handshake.  DPI observers see a standard TLS 1.3 handshake to the configured
/// SNI (e.g. `cloudflare.com`).
///
/// # Example
///
/// ```rust,no_run
/// use mirage_protocol::protocols::l5::tls::TlsRealCamouflage;
///
/// let layer = TlsRealCamouflage::new(
///     "cloudflare.com".to_string(),
///     vec!["h2".to_string(), "http/1.1".to_string()],
///     None, // generate self-signed cert for server
///     None,
/// ).unwrap();
/// ```
pub struct TlsRealCamouflage {
    client_config: Arc<rustls::ClientConfig>,
    /// `None` when the face carries no SNI of its own.
    ///
    /// A client dial builds this type too and never touches the certificate —
    /// it presents `HopConfig.sni` if it has one. So refusing an empty name at
    /// construction would break dials that work today, while a server with no
    /// name has nothing legitimate to put in a certificate. The refusal
    /// therefore lives at [`CamouflageLayer::wrap_server`], where it is
    /// actually true.
    server_config: Option<Arc<rustls::ServerConfig>>,
    sni: String,
}

impl TlsRealCamouflage {
    /// Create a new `TlsRealCamouflage`.
    ///
    /// * `sni` — SNI hostname used by the client TLS session.
    /// * `alpn` — ALPN protocol identifiers (e.g. `["h2", "http/1.1"]`).
    /// * `server_cert_der` — optional DER-encoded server certificate.
    ///   If `None`, a fresh self-signed certificate is generated.
    /// * `server_key_der` — optional DER-encoded private key matching the cert.
    ///   Must be `Some` when `server_cert_der` is `Some`.
    pub fn new(
        sni: String,
        alpn: Vec<String>,
        server_cert_der: Option<Vec<u8>>,
        server_key_der: Option<Vec<u8>>,
    ) -> Result<Self, MirageError> {
        let alpn_bytes: Vec<Vec<u8>> = alpn.into_iter().map(|s| s.into_bytes()).collect();

        let pair = match (server_cert_der, server_key_der) {
            (Some(cert_bytes), Some(key_bytes)) => {
                let cert = CertificateDer::from(cert_bytes);
                let key = PrivateKeyDer::try_from(key_bytes)
                    .map_err(|e| MirageError::Config(format!("server key DER error: {e}")))?;
                Some((cert, key))
            }
            // No name to issue to — see the `server_config` field.
            (None, None) if sni.is_empty() => None,
            // Issued to the face's own SNI, so what the server presents and
            // what the client asks for are the same name by construction.
            (None, None) => Some(generate_self_signed_cert(&sni)?),
            _ => {
                return Err(MirageError::Config(
                    "server_cert_der and server_key_der must both be Some or both None".into(),
                ))
            }
        };

        let server_config = pair
            .map(|(cert, key)| build_server_tls_config(cert, key, &alpn_bytes))
            .transpose()?
            .map(Arc::new);
        let client_config = build_client_tls_config(&alpn_bytes)?;

        Ok(Self {
            client_config: Arc::new(client_config),
            server_config,
            sni,
        })
    }

    /// Returns the configured SNI hostname.
    pub fn sni(&self) -> &str {
        &self.sni
    }
}

impl private::Sealed for TlsRealCamouflage {}

#[async_trait]
impl CamouflageLayer for TlsRealCamouflage {
    type Stream = TlsStreamInner;

    async fn wrap_client(
        &self,
        stream: TcpStream,
        sni: &str,
    ) -> Result<TlsStreamInner, MirageError> {
        // Use caller-supplied SNI if non-empty, otherwise fall back to the
        // configured default.
        let sni_str = if sni.is_empty() { self.sni.as_str() } else { sni };

        let server_name = ServerName::try_from(sni_str.to_string())
            .map_err(|e| MirageError::Handshake(format!("invalid SNI '{}': {e}", sni_str)))?;

        let connector = TlsConnector::from(Arc::clone(&self.client_config));
        let tls = connector
            .connect(server_name, stream)
            .await
            .map_err(|e| MirageError::Handshake(format!("TLS client handshake failed: {e}")))?;

        Ok(TlsStreamInner::Client(tls))
    }

    async fn wrap_server(
        &self,
        stream: TcpStream,
    ) -> Result<Option<TlsStreamInner>, MirageError> {
        // A face with no SNI has no name to issue a certificate to, and a
        // certificate is the one thing every passive scanner records about
        // this port. Refusing here is louder than binding and presenting
        // whatever placeholder happened to be compiled in — which is the
        // failure this whole change exists to undo.
        let Some(server_config) = self.server_config.as_ref() else {
            return Err(MirageError::Config(
                "tls_real cannot serve without an SNI to issue its certificate to".into(),
            ));
        };
        let acceptor = TlsAcceptor::from(Arc::clone(server_config));
        match acceptor.accept(stream).await {
            Ok(tls) => Ok(Some(TlsStreamInner::Server(tls))),
            // TLS handshake failure — not our client (forward to fallback).
            Err(_) => Ok(None),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TlsStreamInner — unified AsyncRead + AsyncWrite over client/server TLS streams
// ─────────────────────────────────────────────────────────────────────────────

/// Unified wrapper over `tokio_rustls` client and server TLS streams.
///
/// Both variants implement `AsyncRead + AsyncWrite + Unpin`, which is required
/// by `core::handshake::run_*_handshake` and `MirageCoreTunnel`.
pub enum TlsStreamInner {
    Client(client::TlsStream<TcpStream>),
    Server(server::TlsStream<TcpStream>),
}

impl AsyncRead for TlsStreamInner {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            TlsStreamInner::Client(s) => std::pin::Pin::new(s).poll_read(cx, buf),
            TlsStreamInner::Server(s) => std::pin::Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for TlsStreamInner {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        match self.get_mut() {
            TlsStreamInner::Client(s) => std::pin::Pin::new(s).poll_write(cx, buf),
            TlsStreamInner::Server(s) => std::pin::Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            TlsStreamInner::Client(s) => std::pin::Pin::new(s).poll_flush(cx),
            TlsStreamInner::Server(s) => std::pin::Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            TlsStreamInner::Client(s) => std::pin::Pin::new(s).poll_shutdown(cx),
            TlsStreamInner::Server(s) => std::pin::Pin::new(s).poll_shutdown(cx),
        }
    }
}

impl Unpin for TlsStreamInner {}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pins the calendar arithmetic against dates computed by hand, including
    /// the two cases the algorithm exists for: a leap day, and a century year
    /// that is not a leap year.
    #[test]
    fn civil_from_days_matches_known_dates() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(-1), (1969, 12, 31));
        assert_eq!(civil_from_days(59), (1970, 3, 1));
        // 2000-02-29 — a leap day in a century year that IS a leap year.
        assert_eq!(civil_from_days(11_016), (2000, 2, 29));
        // 2100 is a century year that is NOT a leap year, so February ends on
        // the 28th and the 1st of March lands a day earlier than a naive
        // every-fourth-year rule would put it.
        assert_eq!(civil_from_days(47_540), (2100, 2, 28));
        assert_eq!(civil_from_days(47_541), (2100, 3, 1));
        assert_eq!(civil_from_days(20_000), (2024, 10, 4));
    }

    /// The certificate must name the face, and must no longer name the fleet.
    ///
    /// Read out of the DER by byte search rather than with an X.509 parser: the
    /// CN and the SAN are stored as plain ASCII, and this crate is not going to
    /// carry a certificate parser to assert one string.
    #[test]
    fn the_certificate_is_issued_to_the_configured_name() {
        let (cert, _key) =
            generate_self_signed_cert("face.example.net").expect("generate");
        let der = cert.as_ref();
        let name = b"face.example.net";
        assert!(
            der.windows(name.len()).any(|w| w == name),
            "the name the face presents must be in its certificate"
        );
        let old = b"mirage.local";
        assert!(
            !der.windows(old.len()).any(|w| w == old),
            "no certificate may still say mirage.local"
        );
    }

    /// rcgen's default validity runs 1975 → 4096. A two-thousand-year
    /// certificate is a fleet-wide tell on its own, so the window is set
    /// explicitly and this refuses to let the default come back.
    #[test]
    fn the_certificate_does_not_carry_rcgens_default_validity() {
        let (cert, _key) = generate_self_signed_cert("box.example.net").expect("generate");
        let der = cert.as_ref();
        for absurd in [b"4096".as_slice(), b"1975".as_slice()] {
            assert!(
                !der.windows(absurd.len()).any(|w| w == absurd),
                "the default validity window must not survive into the certificate"
            );
        }
    }

    /// The fleet's faces carried a bare IP as their SNI until the personas
    /// landed. Whatever else that is, it must not stop a perimeter from
    /// binding — a config change and a code change must not have to land in
    /// the same second.
    #[test]
    fn an_ip_literal_name_still_produces_a_certificate() {
        generate_self_signed_cert("203.0.113.15").expect("an IP-literal SNI must still serve");
    }

    /// An empty SNI cannot be dialled, so it must not be served either.
    #[test]
    fn an_empty_name_is_refused_rather_than_substituted() {
        match generate_self_signed_cert("") {
            Err(MirageError::Config(msg)) => assert!(msg.contains("SNI")),
            other => panic!("an empty SNI must be refused: {other:?}"),
        }
    }
}

#[cfg(test)]
mod server_name_gate {
    use super::*;

    /// A client dial builds this type and never uses the certificate. An empty
    /// SNI on the variant is a real configuration today — `HopConfig.sni`
    /// supplies the name instead — so construction must keep working.
    #[test]
    fn a_nameless_face_still_constructs_for_a_client_dial() {
        let layer = TlsRealCamouflage::new(String::new(), vec!["h2".to_string()], None, None)
            .expect("a client dial must not need a certificate");
        assert!(
            layer.server_config.is_none(),
            "there is no name to issue a certificate to"
        );
    }

    /// …and must refuse to SERVE, because what it would present is the
    /// fleet-wide placeholder this change exists to remove.
    #[tokio::test]
    async fn a_nameless_face_refuses_to_serve() {
        let layer = TlsRealCamouflage::new(String::new(), Vec::new(), None, None).expect("build");
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        let accept = tokio::spawn(async move { listener.accept().await });
        let _client = tokio::net::TcpStream::connect(addr).await.expect("connect");
        let (server_stream, _) = accept.await.expect("join").expect("accept");

        match layer.wrap_server(server_stream).await {
            Err(MirageError::Config(msg)) => assert!(msg.contains("SNI")),
            other => panic!("a nameless face must refuse to serve: {:?}", other.map(|_| ())),
        }
    }

    /// A named face serves normally — the gate must not have made every face
    /// refuse.
    #[test]
    fn a_named_face_carries_a_certificate() {
        let layer = TlsRealCamouflage::new(
            "box.example.net".to_string(),
            vec!["h2".to_string()],
            None,
            None,
        )
        .expect("build");
        assert!(layer.server_config.is_some());
        assert_eq!(layer.sni(), "box.example.net");
    }
}
