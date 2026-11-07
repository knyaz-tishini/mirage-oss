//! The target preamble a protocol door speaks after its own handshake.
//!
//! One byte of host length (1..=255), that many UTF-8 host bytes, then a
//! big-endian port. The bytes after that are the raw flow. A bad preamble
//! is an error; the caller closes the stream.

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Write the target preamble.
pub async fn write_preamble<W>(writer: &mut W, host: &str, port: u16) -> std::io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let bytes = host.as_bytes();
    if bytes.is_empty() || bytes.len() > 255 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "preamble host length must be 1..=255",
        ));
    }
    writer.write_u8(bytes.len() as u8).await?;
    writer.write_all(bytes).await?;
    writer.write_u16(port).await?;
    writer.flush().await?;
    Ok(())
}

/// Read the target preamble.
///
/// A zero length, a short read, or a host that is not UTF-8 is rejected.
pub async fn read_preamble<R>(reader: &mut R) -> std::io::Result<(String, u16)>
where
    R: AsyncRead + Unpin,
{
    let len = reader.read_u8().await?;
    if len == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "preamble host is empty",
        ));
    }
    let mut host = vec![0u8; len as usize];
    reader.read_exact(&mut host).await?;
    let host = String::from_utf8(host).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "preamble host is not utf-8",
        )
    })?;
    let port = reader.read_u16().await?;
    Ok((host, port))
}
