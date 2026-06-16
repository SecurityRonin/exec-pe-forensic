//! Error types for pe-core.

/// Errors returned by [`crate::parse_pe`].
#[derive(Debug, thiserror::Error)]
pub enum PeError {
    #[error("not a PE file: missing or invalid MZ/PE signature")]
    NotPe,
    #[error("PE structure error: {0}")]
    Structure(String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}
