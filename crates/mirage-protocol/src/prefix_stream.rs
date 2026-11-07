//! `PrefixStream` — replay a byte prefix then delegate to the inner stream.
//!
//! Used by a node that has already read (and stripped) the byte-cipher skin
//! header from the first read.  The leftover bytes after the header are stored
//! in `read_prefix` and served to the caller before any further reads from the
//! inner stream.  Writes (replies) go straight through to the inner stream
//! without buffering.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Wraps an async bidirectional stream so that reads first drain a
/// pre-loaded byte buffer (`read_prefix`) before delegating to `inner`.
///
/// This is useful when a node has read ahead to strip a transport-level
/// header (e.g. the byte-cipher wire-skin) and needs to hand the remainder
/// of the first read + the rest of the stream back to the protocol layer.
///
/// Writes (`poll_write` / `poll_flush` / `poll_shutdown`) are always forwarded
/// directly to `inner` — they are never buffered.
///
/// # Bounds
/// `S` must be `Unpin` so that `Pin::new(&mut self.inner)` is valid.
pub struct PrefixStream<S> {
    inner: S,
    read_prefix: Vec<u8>,
    read_pos: usize,
}

impl<S> PrefixStream<S> {
    /// Create a new `PrefixStream`.
    ///
    /// `read_prefix` will be served byte-for-byte to the first callers of
    /// `poll_read`; once exhausted, reads are delegated to `inner`.
    pub fn new(inner: S, read_prefix: Vec<u8>) -> Self {
        Self {
            inner,
            read_prefix,
            read_pos: 0,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for PrefixStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // While the prefix hasn't been fully drained, serve from it.
        if self.read_pos < self.read_prefix.len() {
            let remaining = &self.read_prefix[self.read_pos..];
            let to_copy = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..to_copy]);
            self.read_pos += to_copy;
            return Poll::Ready(Ok(()));
        }
        // Prefix exhausted — delegate to inner.
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for PrefixStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
