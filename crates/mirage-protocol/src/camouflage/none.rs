//! No-op camouflage — returns the raw `TcpStream` without any wrapping.

use async_trait::async_trait;
use mirage_core::error::MirageError;
use tokio::net::TcpStream;

use super::private::Sealed;
use super::CamouflageLayer;

/// Raw TCP passthrough — no transport-level camouflage.
pub struct NoCamouflage;

impl Sealed for NoCamouflage {}

#[async_trait]
impl CamouflageLayer for NoCamouflage {
    type Stream = TcpStream;

    async fn wrap_client(
        &self,
        stream: TcpStream,
        _sni: &str,
    ) -> Result<TcpStream, MirageError> {
        Ok(stream)
    }

    async fn wrap_server(
        &self,
        stream: TcpStream,
    ) -> Result<Option<TcpStream>, MirageError> {
        Ok(Some(stream))
    }
}
