use tokio::io::{AsyncRead, AsyncWrite, AsyncReadExt, AsyncWriteExt};

pub const MAX_UDP_DATAGRAM: usize = 65507;

/// Write one UDP datagram as a length-prefixed frame.
pub async fn write_udp_frame<W: AsyncWrite + Unpin>(
    w: &mut W,
    datagram: &[u8],
) -> std::io::Result<()> {
    let len = datagram.len();
    if len > MAX_UDP_DATAGRAM {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("UDP datagram too large: {len} > {MAX_UDP_DATAGRAM}"),
        ));
    }
    w.write_all(&(len as u16).to_be_bytes()).await?;
    if len > 0 {
        w.write_all(datagram).await?;
    }
    w.flush().await?;
    Ok(())
}

/// Read one UDP datagram frame. Returns number of bytes read into `buf`.
/// Returns Ok(0) on EOF frame (zero-length).
pub async fn read_udp_frame<R: AsyncRead + Unpin>(
    r: &mut R,
    buf: &mut Vec<u8>,
) -> std::io::Result<usize> {
    let mut len_buf = [0u8; 2];
    r.read_exact(&mut len_buf).await?;
    let len = u16::from_be_bytes(len_buf) as usize;
    if len == 0 {
        return Ok(0);
    }
    if len > MAX_UDP_DATAGRAM {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("UDP frame too large: {len} > {MAX_UDP_DATAGRAM}"),
        ));
    }
    buf.resize(len, 0);
    r.read_exact(&mut buf[..len]).await?;
    Ok(len)
}
