use crate::frame::FrameDecodeError;

/// The various error cases a session may encounter.
#[non_exhaustive]
#[derive(Debug)]
pub enum MuxError {
    /// An underlying I/O error occured.
    Io(std::io::Error),
    /// Decoding a message frame failed.
    Decode(FrameDecodeError),
    /// The whole range of stream IDs has been used up.
    NoMoreStreamIds,
    /// An operation fails because the session is closed.
    Closed,
    /// Too many streams are open, so no further ones can be opened at this time.
    TooManyStreams,
    /// A window update operation was rejected because the supplied credit
    /// is invalid for the current flow-control window (e.g. overflow).
    InvalidWindowUpdate,
}

impl std::fmt::Display for MuxError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            MuxError::Io(e) => write!(f, "i/o error: {e}"),
            MuxError::Decode(e) => write!(f, "decode error: {e}"),
            MuxError::NoMoreStreamIds => {
                f.write_str("number of stream ids has been exhausted")
            }
            MuxError::Closed => f.write_str("session is closed"),
            MuxError::TooManyStreams => f.write_str("maximum number of streams reached"),
            MuxError::InvalidWindowUpdate => {
                f.write_str("invalid window update for the current flow control window")
            }
        }
    }
}

impl std::error::Error for MuxError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            MuxError::Io(e) => Some(e),
            MuxError::Decode(e) => Some(e),
            MuxError::NoMoreStreamIds
            | MuxError::Closed
            | MuxError::TooManyStreams => None,
            MuxError::InvalidWindowUpdate => None,
        }
    }
}

impl From<std::io::Error> for MuxError {
    fn from(e: std::io::Error) -> Self {
        MuxError::Io(e)
    }
}

impl From<FrameDecodeError> for MuxError {
    fn from(e: FrameDecodeError) -> Self {
        MuxError::Decode(e)
    }
}

impl From<futures::channel::mpsc::SendError> for MuxError {
    fn from(_: futures::channel::mpsc::SendError) -> Self {
        MuxError::Closed
    }
}

impl From<futures::channel::oneshot::Canceled> for MuxError {
    fn from(_: futures::channel::oneshot::Canceled) -> Self {
        MuxError::Closed
    }
}
