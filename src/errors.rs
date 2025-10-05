//! Custom errors for BEEF parsing, validation, and serialization.

use thiserror::Error;
use std::io;

/// Core error type for Shia operations.
#[derive(Error, Debug)]
pub enum ShiaError {
    /// IO-related errors during read/write.
    #[error("IO error: {0}")]
    Io(#[from] io::Error),
    /// Invalid compact VarInt encoding.
    #[error("Invalid VarInt")]
    InvalidVarInt,
    /// Invalid leaf flags in BUMP (must be 0,1,2).
    #[error("Invalid flags: {0}")]
    InvalidFlags(u8),
    /// BEEF version mismatch (must be 4022206465).
    #[error("Invalid version")]
    InvalidVersion,
    /// General verification failure (e.g., bad Merkle root, fee imbalance).
    #[error("Verification failed: {0}")]
    Verification(String),
    /// Atomic mode includes unrelated transactions (BRC-95 violation).
    #[error("Atomic mismatch: unrelated tx")]
    AtomicMismatch,
    /// Missing sibling hash in Merkle path.
    #[error("Missing sibling in BUMP")]
    MissingSibling,
    /// Leaf TX hash not found in BUMP level 0.
    #[error("Leaf not found in BUMP")]
    LeafNotFound,
    /// Script evaluation failed during input validation.
    #[error("Script evaluation failed: {0}")]
    ScriptEval(String),
}

/// Convenience type alias for Results.
pub type Result<T> = std::result::Result<T, ShiaError>;

impl From<anyhow::Error> for ShiaError {
    fn from(err: anyhow::Error) -> Self {
        ShiaError::Verification(err.to_string())
    }
}

impl From<hex::FromHexError> for ShiaError {
    fn from(err: hex::FromHexError) -> Self {
        ShiaError::Verification(err.to_string())
    }
}
