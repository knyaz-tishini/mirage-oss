use thiserror::Error;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum IdParseError {
    #[error("empty id")]
    Empty,
    #[error("id contains invalid char {0:?}: only [a-z0-9._-] allowed")]
    InvalidChar(char),
    #[error("id too long: {0} chars")]
    TooLong(usize),
    #[error("invalid uuid {0:?}: {1}")]
    BadUuid(String, uuid::Error),
    #[error("MeshScoped must contain exactly one '::' separator, got {0:?}")]
    BadScopedShape(String),
}
