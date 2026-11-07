//! The message channel over a session.
//!
//! The session is Mirage's AEAD tunnel: a byte channel without message
//! boundaries. The flow plane needs whole messages, so the channel adds a
//! two-byte length prefix — the same shape Mirage's own frame codec uses, one
//! layer up.

use mirage_protocol::traits::Tunnel;

/// The longest message the channel carries.
pub const MAX_MESSAGE: usize = 64 * 1024;

/// What can go wrong on the channel.
#[derive(Debug, thiserror::Error)]
pub enum ChannelError {
    /// The message is longer than the channel carries.
    #[error("the message is {0} bytes, and the channel carries at most {MAX_MESSAGE}")]
    TooLong(usize),

    /// The session is closed.
    #[error("the session is closed")]
    Closed,

    /// The session failed.
    #[error("the session failed: {0}")]
    Session(String),
}

/// A message channel over a session.
pub struct Channel {
    tunnel: Box<dyn Tunnel>,
    buffer: Vec<u8>,
    position: usize,
}

impl Channel {
    /// A channel over the session.
    pub fn new(tunnel: Box<dyn Tunnel>) -> Self {
        Self {
            tunnel,
            buffer: Vec::new(),
            position: 0,
        }
    }

    /// Send one message.
    pub async fn send(&mut self, message: &[u8]) -> Result<(), ChannelError> {
        if message.len() > MAX_MESSAGE {
            return Err(ChannelError::TooLong(message.len()));
        }
        let mut frame = Vec::with_capacity(2 + message.len());
        frame.extend_from_slice(&(message.len() as u16).to_be_bytes());
        frame.extend_from_slice(message);
        self.tunnel
            .send(&frame)
            .await
            .map_err(|e| ChannelError::Session(e.to_string()))
    }

    /// Receive one message.
    pub async fn recv(&mut self) -> Result<Vec<u8>, ChannelError> {
        while self.buffer.len() - self.position < 2 {
            self.fill().await?;
        }
        let length = u16::from_be_bytes([self.buffer[self.position], self.buffer[self.position + 1]])
            as usize;
        self.position += 2;
        while self.buffer.len() - self.position < length {
            self.fill().await?;
        }
        let message = self.buffer[self.position..self.position + length].to_vec();
        self.position += length;
        self.compact();
        Ok(message)
    }

    /// Read more bytes from the session.
    async fn fill(&mut self) -> Result<(), ChannelError> {
        let mut chunk = vec![0u8; 16 * 1024];
        let count = self
            .tunnel
            .recv(&mut chunk)
            .await
            .map_err(|e| ChannelError::Session(e.to_string()))?;
        if count == 0 {
            return Err(ChannelError::Closed);
        }
        chunk.truncate(count);
        self.buffer.extend_from_slice(&chunk);
        Ok(())
    }

    /// Drop the bytes that were already read.
    fn compact(&mut self) {
        if self.position == 0 {
            return;
        }
        if self.position == self.buffer.len() {
            self.buffer.clear();
            self.position = 0;
            return;
        }
        self.buffer.drain(..self.position);
        self.position = 0;
    }
}
