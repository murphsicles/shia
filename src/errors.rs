//! Custom errors for BEEF parsing, validation, and serialization.
use thiserror::Error;
use std::io;
use anyhow::Error as AnyhowError;
use hex::FromHexError;
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
    /// Invalid tree height in BUMP (>64).
    #[error("Invalid tree height: {0}")]
    InvalidTreeHeight(u8),
    /// BUMP merge mismatch (heights, roots, or conflicting leaves).
    #[error("BUMP merge mismatch: {0}")]
    MergeMismatch(&'static str),
    /// Parse error (e.g., extra bytes, invalid format).
    #[error("Parse error: {0}")]
    Parse(&'static str),
}
impl From<AnyhowError> for ShiaError {
    fn from(err: AnyhowError) -> Self {
        ShiaError::Verification(err.to_string())
    }
}
impl From<FromHexError> for ShiaError {
    fn from(err: FromHexError) -> Self {
        ShiaError::Verification(err.to_string())
    }
}
/// Convenience type alias for Results.
pub type Result<T> = std::result::Result<T, ShiaError>;
