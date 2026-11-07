//! End-to-end session helper for the operator→mshd control channel.
//!
//! Runs the existing V9 handshake over an abstract byte channel.  The caller
//! owns all framing (e.g. base64+JSON over a WebSocket relay); this module
//! carries only raw bytes.
//!
//! ## Domain separation
//!
//! [`MESH_E2E_LABEL`] is passed as the handshake `mesh_id` argument so a
//! session authenticated for the operator→mshd E2E channel can never
//! cross-authenticate a real mesh session (whose mesh_id is the live mesh
//! identifier string).
//!
//! ## Operator pinning
//!
//! [`mshd_accept_session`] pins the operator's static public key inside the
//! `client_auth` closure — any other static key is rejected before session
//! keys are derived.

use std::{
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll},
};

use anyhow::{anyhow, Result};
use mirage_core::crypto::{AeadSuite, KeyPair};
use serde::{Deserialize, Serialize};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::mpsc::{UnboundedReceiver, UnboundedSender},
};

use crate::{
    auth::AuthMode,
    core::handshake::{run_client_handshake_v9, run_server_handshake_v9},
    core::tunnel::MirageCoreTunnel,
    traits::TransportInfo,
};

// ─────────────────────────────────────────────────────────────────────────────
// Domain-separation label
// ─────────────────────────────────────────────────────────────────────────────

/// Handshake `mesh_id` used exclusively for operator→mshd E2E sessions.
///
/// Prevents cross-authentication between an E2E session and a real Mirage mesh
/// session (whose `mesh_id` is the live mesh identifier, e.g. `"v3-staging"`).
pub const MESH_E2E_LABEL: &[u8] = b"mirage-mshd-e2e-v1";

/// Default AEAD suite preference list for E2E sessions.
const E2E_SUITE_PREFS: &[AeadSuite] = &[AeadSuite::ChaCha20Poly1305];

// ─────────────────────────────────────────────────────────────────────────────
// Relay framing — session-addressed, blind to payload
// ─────────────────────────────────────────────────────────────────────────────

/// Identifies one operator↔mshd E2E session on a shared relay channel.
///
/// One persistent mshd control-WS serves many operator sessions over its
/// lifetime. The id is minted by the operator box at shell-open and carried in
/// every relay frame, so the mshd attributes each frame to the right session
/// (and can run several concurrently), and a late `e2e_close` for a dead
/// session is a no-op instead of tearing down a fresh one. This is what
/// replaced the connect-time reset hack: sessions are self-delimiting.
pub type SessionId = u64;

/// A frame on the operator↔monitor↔mshd relay channel.
///
/// The monitor is a BLIND relay: it parses only `kind` + `sid` to route a
/// frame to the matching session pipe and NEVER base64-decodes `b64` (the
/// opaque nested-V9 session bytes). `#[serde(tag = "kind")]` pins the wire
/// shape to `{"kind":"e2e","sid":N,"b64":"…"}` /
/// `{"kind":"e2e_close","sid":N}`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RelayFrame {
    /// Opaque session bytes, base64-encoded. `b64` is never decoded by the relay.
    E2e { sid: SessionId, b64: String },
    /// Tear down a single session by id. Unknown / stale ids are no-ops.
    E2eClose { sid: SessionId },
}

impl RelayFrame {
    /// The session id this frame addresses.
    pub fn sid(&self) -> SessionId {
        match self {
            RelayFrame::E2e { sid, .. } | RelayFrame::E2eClose { sid } => *sid,
        }
    }

    /// Serialise to the JSON text carried over the relay WS.
    ///
    /// Infallible in practice: the variants are plain owned scalars/strings.
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).expect("RelayFrame always serialises")
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// RelayE2eStream
// ─────────────────────────────────────────────────────────────────────────────

/// A transport-neutral byte stream backed by two `tokio::sync::mpsc` channels.
///
/// The caller wires these channels to an actual relay transport (e.g. a
/// WebSocket with base64 framing).  This struct does **not** do any
/// base64/JSON encoding — it carries raw bytes only.
///
/// - `out_tx`: bytes written here should be forwarded to the remote peer.
/// - `in_rx`:  bytes received from the remote peer must be pushed into here.
pub struct RelayE2eStream {
    out_tx: UnboundedSender<Vec<u8>>,
    in_rx: UnboundedReceiver<Vec<u8>>,
    /// Leftover bytes from a previous chunk that did not fit into the caller's
    /// `AsyncRead` buffer.
    read_buf: Vec<u8>,
    /// Read cursor into `read_buf`.
    read_pos: usize,
}

impl RelayE2eStream {
    /// Construct a new relay stream.
    ///
    /// `out_tx` — send channel: bytes written through `AsyncWrite` are sent here.
    /// `in_rx`  — receive channel: bytes polled through `AsyncRead` come from here.
    pub fn new(out_tx: UnboundedSender<Vec<u8>>, in_rx: UnboundedReceiver<Vec<u8>>) -> Self {
        Self {
            out_tx,
            in_rx,
            read_buf: Vec::new(),
            read_pos: 0,
        }
    }
}

// ── AsyncRead ────────────────────────────────────────────────────────────────

impl AsyncRead for RelayE2eStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        loop {
            // Drain buffered leftover first.
            if self.read_pos < self.read_buf.len() {
                let available = self.read_buf.len() - self.read_pos;
                let n = available.min(buf.remaining());
                let start = self.read_pos;
                buf.put_slice(&self.read_buf[start..start + n]);
                self.read_pos += n;
                // Drop fully consumed buffer to free memory.
                if self.read_pos >= self.read_buf.len() {
                    self.read_buf.clear();
                    self.read_pos = 0;
                }
                return Poll::Ready(Ok(()));
            }

            // No leftover — pull next chunk from the channel.
            match self.in_rx.poll_recv(cx) {
                Poll::Pending => return Poll::Pending,
                // Channel closed with no data → EOF.
                Poll::Ready(None) => return Poll::Ready(Ok(())),
                Poll::Ready(Some(chunk)) if chunk.is_empty() => {
                    // Empty chunk is a no-op; loop again.
                    continue;
                }
                Poll::Ready(Some(chunk)) => {
                    let n = chunk.len().min(buf.remaining());
                    buf.put_slice(&chunk[..n]);
                    if chunk.len() > n {
                        // Stash the unconsumed tail.
                        self.read_buf = chunk[n..].to_vec();
                        self.read_pos = 0;
                    }
                    return Poll::Ready(Ok(()));
                }
            }
        }
    }
}

// ── AsyncWrite ───────────────────────────────────────────────────────────────

impl AsyncWrite for RelayE2eStream {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        // Send the bytes as a single chunk; ignore send error (closed channel).
        let _ = self.out_tx.send(buf.to_vec());
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl Unpin for RelayE2eStream {}

// SAFETY: `Sync` means `&RelayE2eStream` is `Send`.  Every field is private and
// the only inherent/trait methods (`new`, `AsyncRead`/`AsyncWrite`) take `&mut
// self` (via `Pin<&mut Self>`).  There is **no** `&self` accessor that reaches the
// `!Sync` `UnboundedReceiver`, so a shared `&RelayE2eStream` exposes nothing that
// could race.  Sharing `&Self` across threads is therefore sound regardless of the
// receiver's conservative `!Sync`.  (`MirageCoreTunnel`'s `Tunnel` impl is bounded
// `S: Send + Sync`; this unsafe satisfies it locally instead of widening that
// shared bound across every tunnel consumer.)
unsafe impl Sync for RelayE2eStream {}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: build a dummy TransportInfo for an in-process / relay session.
// ─────────────────────────────────────────────────────────────────────────────

fn e2e_transport_info() -> TransportInfo {
    // A real SocketAddr is not available for relay-carried sessions.
    // Use the unspecified address as a sentinel.
    let addr: SocketAddr = "0.0.0.0:0".parse().expect("static literal is valid");
    TransportInfo::tcp_raw(addr)
}

// ─────────────────────────────────────────────────────────────────────────────
// opbox_open_session — operator (client) side
// ─────────────────────────────────────────────────────────────────────────────

/// Open an E2E session from the operator box toward an mshd binary.
///
/// Runs the V9 client handshake over `stream`.  After a successful handshake
/// the returned [`MirageCoreTunnel`] is a plaintext bidirectional duplex
/// suitable for shell I/O.
///
/// # Arguments
/// - `stream` — the transport channel (e.g. a [`RelayE2eStream`]).
/// - `mshd_static_pub` — the target mshd's declared static X25519 public key
///   (32 bytes).  The handshake verifies the server holds the matching secret.
/// - `operator_static_priv` — operator's own static X25519 private key (32
///   bytes).  Used to prove identity to mshd's `client_auth` closure.
pub async fn opbox_open_session<S>(
    mut stream: S,
    mshd_static_pub: [u8; 32],
    operator_static_priv: [u8; 32],
) -> Result<MirageCoreTunnel<S>>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let result = run_client_handshake_v9(
        &mut stream,
        &mshd_static_pub,
        &operator_static_priv,
        MESH_E2E_LABEL,
        E2E_SUITE_PREFS,
    )
    .await
    .map_err(|e| anyhow!("mshd E2E client handshake failed: {e:?}"))?;

    let tunnel = MirageCoreTunnel::new(
        stream,
        &result.session_keys,
        true, // is_client
        e2e_transport_info(),
        AuthMode::V9MutualFs,
    );

    Ok(tunnel)
}

// ─────────────────────────────────────────────────────────────────────────────
// mshd_accept_session — mshd (server) side
// ─────────────────────────────────────────────────────────────────────────────

/// Accept an E2E session from the operator box on the mshd side.
///
/// Runs the V9 server handshake over `stream`.  The `client_auth` closure
/// **pins** `operator_static_pub` — any other client static key is rejected
/// before session keys are derived.
///
/// # Arguments
/// - `stream` — the transport channel (e.g. a [`RelayE2eStream`]).
/// - `mshd_static_priv` — mshd's own static X25519 private key (32 bytes).
/// - `operator_static_pub` — the operator's expected static X25519 public key
///   (32 bytes).  Exactly this key must authenticate or the handshake returns
///   an error.
pub async fn mshd_accept_session<S>(
    mut stream: S,
    mshd_static_priv: [u8; 32],
    operator_static_pub: [u8; 32],
) -> Result<MirageCoreTunnel<S>>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let keypair = KeyPair::from_secret(mshd_static_priv);

    let result = run_server_handshake_v9(
        &mut stream,
        &keypair,
        MESH_E2E_LABEL,
        E2E_SUITE_PREFS,
        move |ctx| ctx.static_pub == &operator_static_pub,
    )
    .await
    .map_err(|e| anyhow!("mshd E2E server handshake I/O error: {e:?}"))?
    .ok_or_else(|| anyhow!("mshd E2E: operator pin failed"))?;

    let tunnel = MirageCoreTunnel::new(
        stream,
        &result.session_keys,
        false, // is_client = false (server side)
        e2e_transport_info(),
        AuthMode::V9MutualFs,
    );

    Ok(tunnel)
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::{mshd_accept_session, opbox_open_session, RelayFrame};
    use crate::traits::Tunnel;
    use mirage_core::crypto::KeyPair;

    // ── Relay frame wire shape ────────────────────────────────────────────────

    /// The frame serialises to the exact `{kind,sid,b64}` shape both ends parse,
    /// round-trips, and exposes its session id.
    #[test]
    fn relay_frame_round_trip() {
        let e2e = RelayFrame::E2e { sid: 42, b64: "aGVsbG8=".to_string() };
        let json = e2e.to_json();
        assert_eq!(json, r#"{"kind":"e2e","sid":42,"b64":"aGVsbG8="}"#);
        assert_eq!(e2e.sid(), 42);

        let close = RelayFrame::E2eClose { sid: 42 };
        assert_eq!(close.to_json(), r#"{"kind":"e2e_close","sid":42}"#);

        // Decode back from text (the monitor / mshd inbound path).
        match serde_json::from_str::<RelayFrame>(&json).unwrap() {
            RelayFrame::E2e { sid, b64 } => {
                assert_eq!(sid, 42);
                assert_eq!(b64, "aGVsbG8=");
            }
            other => panic!("expected E2e, got {other:?}"),
        }
    }

    /// Generate a raw 32-byte static key from a seed byte.
    fn seed_key(seed: u8) -> [u8; 32] {
        [seed; 32]
    }

    /// Derive the public key bytes from a raw 32-byte private key.
    fn pub_from_priv(priv_bytes: [u8; 32]) -> [u8; 32] {
        let kp = KeyPair::from_secret(priv_bytes);
        kp.public.to_bytes()
    }

    // ── Happy-path round-trip ─────────────────────────────────────────────────

    /// V9 E2E session: both sides complete the handshake, write plaintext in each
    /// direction, and the data arrives intact on the other end.
    #[tokio::test]
    async fn e2e_round_trip() {
        let op_priv = seed_key(0x01);
        let op_pub = pub_from_priv(op_priv);
        let mshd_priv = seed_key(0x02);
        let mshd_pub = pub_from_priv(mshd_priv);

        let (client_half, server_half) = tokio::io::duplex(8192);

        let server_task = tokio::spawn(async move {
            mshd_accept_session(server_half, mshd_priv, op_pub).await
        });
        let client_task = tokio::spawn(async move {
            opbox_open_session(client_half, mshd_pub, op_priv).await
        });

        let (server_res, client_res) = tokio::join!(server_task, client_task);
        let mut server_tunnel = server_res.unwrap().expect("server tunnel must open");
        let mut client_tunnel = client_res.unwrap().expect("client tunnel must open");

        // Client → Server
        let payload = b"hello from operator";
        client_tunnel
            .send(payload)
            .await
            .expect("client send must succeed");

        let mut recv_buf = vec![0u8; 256];
        let n = server_tunnel
            .recv(&mut recv_buf)
            .await
            .expect("server recv must succeed");
        assert_eq!(&recv_buf[..n], payload, "server must receive client payload intact");

        // Server → Client
        let reply = b"hello from mshd";
        server_tunnel
            .send(reply)
            .await
            .expect("server send must succeed");

        let n = client_tunnel
            .recv(&mut recv_buf)
            .await
            .expect("client recv must succeed");
        assert_eq!(&recv_buf[..n], reply, "client must receive server reply intact");
    }

    // ── Negative case: wrong operator public key ──────────────────────────────

    /// When mshd is given the wrong `operator_static_pub`, `mshd_accept_session`
    /// must return an error — the operator-pin closure rejects the connection.
    #[tokio::test]
    async fn e2e_wrong_operator_pub_rejected() {
        let op_priv = seed_key(0x01);
        let mshd_priv = seed_key(0x02);
        let mshd_pub = pub_from_priv(mshd_priv);

        // A different "wrong" public key — not derived from op_priv.
        let wrong_op_pub = pub_from_priv(seed_key(0xAA));

        let (client_half, server_half) = tokio::io::duplex(8192);

        // Server expects wrong_op_pub but client authenticates with op_priv → mismatch.
        let server_task = tokio::spawn(async move {
            mshd_accept_session(server_half, mshd_priv, wrong_op_pub).await
        });
        let client_task = tokio::spawn(async move {
            opbox_open_session(client_half, mshd_pub, op_priv).await
        });

        let (server_res, _client_res) = tokio::join!(server_task, client_task);
        let server_result = server_res.unwrap();

        assert!(
            server_result.is_err(),
            "mshd must reject when operator_static_pub does not match the connecting client"
        );
    }
}
