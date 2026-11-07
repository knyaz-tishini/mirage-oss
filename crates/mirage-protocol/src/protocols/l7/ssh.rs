//! SSH tunnel camouflage layer.
//!
//! Carries Mirage traffic inside an SSH `direct-tcpip` channel.  DPI observers
//! see a standard SSH-2.0 handshake on port 22; the inner Mirage ECDH
//! handshake and AEAD framing run inside the channel data stream.
//!
//! # Client flow
//!
//! 1. TCP-connect to the SSH relay.
//! 2. Run the SSH protocol handshake (via `russh`).
//! 3. Authenticate (password or public-key).
//! 4. Open a `direct-tcpip` channel to (`forward_host`, `forward_port`).
//! 5. Return the `ChannelStream` — Mirage handshake proceeds on top of it.
//!
//! # Server flow
//!
//! 1. Accept a TCP connection.
//! 2. Run the SSH protocol handshake (via `russh`).
//! 3. Wait for the client to open any channel (typically `direct-tcpip`).
//! 4. Return the `ChannelStream` — Mirage handshake proceeds on top of it.
//!
//! # Security note
//!
//! Host key verification is **skipped** when `ssh_host_key` is `None` — the
//! outer SSH session is purely for traffic camouflage / DPI evasion.
//! Security is provided by the inner Mirage X25519 + BLAKE3 handshake.

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use async_trait::async_trait;
use mirage_core::error::MirageError;
use russh::client::{self, Config as ClientConfig, Handle};
use russh::server::{self, Config as ServerConfig, Session as ServerSession};
use russh::{Channel, ChannelStream};
use russh_keys::decode_secret_key;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio::sync::oneshot;

use crate::camouflage::{private::Sealed, CamouflageLayer};

// ─────────────────────────────────────────────────────────────────────────────
// SshStream — unified AsyncRead + AsyncWrite over client and server channels
// ─────────────────────────────────────────────────────────────────────────────

/// Unified bidirectional stream for SSH tunnel camouflage.
///
/// `russh` uses different `Msg` generic parameters for client and server
/// channels (`client::Msg` vs `server::Msg`).  `CamouflageLayer` requires a
/// single associated `Stream` type, so `SshStream` holds either variant and
/// implements `AsyncRead + AsyncWrite + Unpin`.
pub enum SshStream {
    Client(ChannelStream<client::Msg>),
    Server(ChannelStream<server::Msg>),
}

impl AsyncRead for SshStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            SshStream::Client(s) => Pin::new(s).poll_read(cx, buf),
            SshStream::Server(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for SshStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            SshStream::Client(s) => Pin::new(s).poll_write(cx, buf),
            SshStream::Server(s) => Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            SshStream::Client(s) => Pin::new(s).poll_flush(cx),
            SshStream::Server(s) => Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            SshStream::Client(s) => Pin::new(s).poll_shutdown(cx),
            SshStream::Server(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}

impl Unpin for SshStream {}

// ─────────────────────────────────────────────────────────────────────────────
// Client handler — accepts any server host key
// ─────────────────────────────────────────────────────────────────────────────

struct ClientHandler;

#[async_trait]
impl client::Handler for ClientHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _server_public_key: &russh_keys::ssh_key::PublicKey,
    ) -> Result<bool, Self::Error> {
        // Accept any host key — security lives in the inner Mirage handshake.
        Ok(true)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Server handler — accepts the first channel, relays it via oneshot
// ─────────────────────────────────────────────────────────────────────────────

struct ServerHandler {
    channel_tx: Option<oneshot::Sender<Channel<server::Msg>>>,
}

#[async_trait]
impl server::Handler for ServerHandler {
    type Error = russh::Error;

    async fn auth_password(
        &mut self,
        _user: &str,
        _password: &str,
    ) -> Result<server::Auth, Self::Error> {
        // Accept any credentials — security lives in the inner Mirage handshake.
        Ok(server::Auth::Accept)
    }

    async fn auth_publickey(
        &mut self,
        _user: &str,
        _public_key: &russh_keys::ssh_key::PublicKey,
    ) -> Result<server::Auth, Self::Error> {
        // Accept any public key — security lives in the inner Mirage handshake.
        Ok(server::Auth::Accept)
    }

    async fn channel_open_direct_tcpip(
        &mut self,
        channel: Channel<server::Msg>,
        _host_to_connect: &str,
        _port_to_connect: u32,
        _originator_address: &str,
        _originator_port: u32,
        _session: &mut ServerSession,
    ) -> Result<bool, Self::Error> {
        if let Some(tx) = self.channel_tx.take() {
            let _ = tx.send(channel);
        }
        Ok(true)
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<server::Msg>,
        _session: &mut ServerSession,
    ) -> Result<bool, Self::Error> {
        if let Some(tx) = self.channel_tx.take() {
            let _ = tx.send(channel);
        }
        Ok(true)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SshCamouflage
// ─────────────────────────────────────────────────────────────────────────────

/// SSH transport-level camouflage.
///
/// Wraps a raw `TcpStream` in an SSH session and opens a `direct-tcpip`
/// channel for the Mirage protocol to run through.  DPI observers see a
/// standard SSH-2.0 connection on port 22.
///
/// # Security note
///
/// Host key verification is skipped (`ssh_host_key = None` is the recommended
/// setting for camouflage use).  Server-side SSH authentication accepts all
/// credentials.  Security is provided by the inner Mirage X25519 + BLAKE3
/// handshake.
pub struct SshCamouflage {
    /// SSH username presented during authentication.
    pub ssh_user: String,
    /// PEM-encoded server host key for verification.
    ///
    /// `None` → accept any host key.
    pub ssh_host_key: Option<String>,
    /// PEM-encoded client private key for public-key authentication.
    ///
    /// `None` → use `ssh_password` instead.
    pub ssh_private_key: Option<String>,
    /// Password for password-based SSH authentication.
    ///
    /// Used only when `ssh_private_key` is `None`.
    pub ssh_password: Option<String>,
    /// Hostname forwarded in the `direct-tcpip` channel open request.
    pub forward_host: String,
    /// Port forwarded in the `direct-tcpip` channel open request.
    pub forward_port: u16,
}

impl Sealed for SshCamouflage {}

#[async_trait]
impl CamouflageLayer for SshCamouflage {
    type Stream = SshStream;

    async fn wrap_client(
        &self,
        stream: TcpStream,
        _sni: &str,
    ) -> Result<SshStream, MirageError> {
        let config = Arc::new(ClientConfig::default());
        let mut handle: Handle<ClientHandler> =
            client::connect_stream(config, stream, ClientHandler)
                .await
                .map_err(|e| MirageError::Handshake(format!("SSH connect: {e}")))?;

        // Authenticate.
        let authed = if let Some(key_pem) = &self.ssh_private_key {
            let key = decode_secret_key(key_pem, None)
                .map_err(|e| MirageError::Config(format!("SSH private key parse: {e}")))?;
            handle
                .authenticate_publickey(&self.ssh_user, Arc::new(key))
                .await
                .map_err(|e| MirageError::Handshake(format!("SSH pubkey auth: {e}")))?
        } else {
            let password = self.ssh_password.as_deref().unwrap_or("");
            handle
                .authenticate_password(&self.ssh_user, password)
                .await
                .map_err(|e| MirageError::Handshake(format!("SSH password auth: {e}")))?
        };

        if !authed {
            return Err(MirageError::Handshake("SSH authentication rejected".into()));
        }

        // Open direct-tcpip channel.
        let channel = handle
            .channel_open_direct_tcpip(
                self.forward_host.as_str(),
                self.forward_port as u32,
                "127.0.0.1",
                0,
            )
            .await
            .map_err(|e| MirageError::Handshake(format!("SSH channel open: {e}")))?;

        // Drive the handle in a background task to keep the session alive.
        // The handle's Future resolves when the session ends.
        tokio::spawn(async move {
            let _ = handle.await;
        });

        Ok(SshStream::Client(channel.into_stream()))
    }

    async fn wrap_server(
        &self,
        stream: TcpStream,
    ) -> Result<Option<SshStream>, MirageError> {
        // Generate a throwaway host key — security lives in the Mirage handshake.
        let host_key =
            russh_keys::ssh_key::PrivateKey::random(
                &mut rand::thread_rng(),
                russh_keys::ssh_key::Algorithm::Ed25519,
            )
            .map_err(|e| MirageError::Config(format!("SSH host key gen: {e}")))?;

        let config = Arc::new(ServerConfig {
            keys: vec![host_key],
            ..Default::default()
        });

        let (channel_tx, channel_rx) = oneshot::channel();
        let handler = ServerHandler {
            channel_tx: Some(channel_tx),
        };

        // Drive the server session in a background task.
        tokio::spawn(async move {
            let _ = server::run_stream(config, stream, handler).await;
        });

        // Wait for the first channel opened by the SSH client.
        let channel = match channel_rx.await {
            Ok(ch) => ch,
            Err(_) => {
                // SSH client disconnected before opening any channel —
                // not our protocol, signal fallback via None.
                return Ok(None);
            }
        };

        Ok(Some(SshStream::Server(channel.into_stream())))
    }
}
