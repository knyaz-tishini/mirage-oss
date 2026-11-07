//! Named errors for one wire-HTTP request attempt and for the whole
//! ordered-face walk.

use std::fmt;

/// One face's failure, kept so a total failure can name every face it tried
/// and why — mirrors `operator_box::wire_http::dial_first_answering`'s own
/// "every candidate's failure is kept, not just the last one" discipline.
#[derive(Debug, Clone)]
pub struct FaceAttempt {
    /// [`crate::WireFace::label`] of the face this attempt was against.
    pub face: String,
    pub error: String,
}

/// Failure of one [`crate::WireHttpClient::request`] call.
#[derive(Debug)]
pub enum WireHttpError {
    /// The client was built with an empty face list — never reachable
    /// through [`crate::WireHttpClient::new`], which requires at least one
    /// face; reachable only through a caller who mutates the list down to
    /// empty afterwards.
    NoFaces,
    /// Every face in the list was tried, in order, and every one failed.
    AllFacesFailed(Vec<FaceAttempt>),
}

impl fmt::Display for WireHttpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WireHttpError::NoFaces => write!(f, "[WIRE-HTTP] no faces configured for this client"),
            WireHttpError::AllFacesFailed(attempts) => {
                write!(f, "[WIRE-HTTP] all {} face(s) failed:", attempts.len())?;
                for a in attempts {
                    write!(f, " [{} -> {}]", a.face, a.error)?;
                }
                Ok(())
            }
        }
    }
}

impl std::error::Error for WireHttpError {}
