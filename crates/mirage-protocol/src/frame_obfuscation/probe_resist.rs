use mirage_core::error::MirageError;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Handles unauthenticated connections by transparently proxying them to a real
/// server, making the mirage endpoint indistinguishable from a legitimate service.
pub struct ProbeResistance {
    /// Real destination to proxy unauthenticated traffic to (e.g. `"api.cloud.yandex.net:443"`).
    pub fallback_dest: String,
}

impl ProbeResistance {
    /// Create a new probe-resistance handler that proxies to `fallback_dest`.
    pub fn new(fallback_dest: String) -> Self {
        Self { fallback_dest }
    }

    /// Forward an unauthenticated client connection to the fallback destination.
    ///
    /// `already_read` contains bytes that were already consumed from the client
    /// stream during protocol detection and must be forwarded verbatim.
    pub async fn handle(
        &self,
        mut client: TcpStream,
        already_read: &[u8],
    ) -> Result<(), MirageError> {
        let mut fallback = TcpStream::connect(&self.fallback_dest)
            .await
            .map_err(|e| {
                MirageError::NodeUnreachable(format!(
                    "probe-resist: cannot reach {}: {e}",
                    self.fallback_dest
                ))
            })?;

        // Replay the bytes that were read during protocol detection.
        if !already_read.is_empty() {
            fallback.write_all(already_read).await?;
        }

        // Bidirectional proxy: copy both halves concurrently.
        let (mut client_rd, mut client_wr) = client.split();
        let (mut fallback_rd, mut fallback_wr) = fallback.split();

        let client_to_fallback = async {
            let mut buf = vec![0u8; 8192];
            loop {
                let n = client_rd.read(&mut buf).await?;
                if n == 0 {
                    break;
                }
                fallback_wr.write_all(&buf[..n]).await?;
            }
            fallback_wr.shutdown().await?;
            Ok::<_, std::io::Error>(())
        };

        let fallback_to_client = async {
            let mut buf = vec![0u8; 8192];
            loop {
                let n = fallback_rd.read(&mut buf).await?;
                if n == 0 {
                    break;
                }
                client_wr.write_all(&buf[..n]).await?;
            }
            client_wr.shutdown().await?;
            Ok::<_, std::io::Error>(())
        };

        // Run both directions concurrently; finish as soon as either side closes.
        tokio::select! {
            res = client_to_fallback => res?,
            res = fallback_to_client => res?,
        }

        Ok(())
    }
}
