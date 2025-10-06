//! Shia: Rust implementation of BSV BEEF protocol (BRC-62+).
//! Efficient SPV tx bundling with ancestry proofs for P2P validation.
//!
//! # Quick Start
//! ```
//! # use anyhow::Result;
//! # use shia::{Beef, Transaction, BlockHeadersClient};
//! # use std::collections::HashMap;
//! # fn example() -> Result<()> {
//! let subject_tx = Transaction::from_raw(b"dummy raw tx").unwrap(); // Replace with actual raw bytes
//! let ancestors: HashMap<[u8; 32], Transaction> = HashMap::new();
//! let bump_map: HashMap<[u8; 32], shia::bump::Bump> = HashMap::new();
//! let beef = Beef::build(subject_tx, ancestors, bump_map, false).unwrap();
//! let my_client = shia::client::MockHeadersClient;
//! beef.verify(&my_client).unwrap();
//! # Ok(())
//! # }
//! ```
//!
//! # Supported BRCs
//! | BRC | Status | Notes |
//! |-----|--------|-------|
//! | 62 | ✅ Full | Core BEEF format/validation |
//! | 95 | ✅ Full | Atomic mode |
//! | 70 | ✅ Full | Paymail envelopes (feature = "paymail") |
//! | 45 | ⏳ Planned | UTXO token checks |
//! | 96 | ⏳ Planned | TxID-only extension |
#![deny(clippy::all)]
#![warn(missing_docs)]
pub mod atomic;
pub mod beef;
pub mod bump;
pub mod client;
pub mod errors;
pub mod tx;
pub mod utils;
#[cfg(feature = "paymail")]
pub mod paymail;
/// Core BEEF struct for bundling and verification.
pub use beef::Beef;
/// BSV Transaction wrapper for parsing and script eval.
pub use tx::Transaction;
/// Pluggable trait for block headers/Merkle root checks.
pub use client::BlockHeadersClient;
/// Paymail envelope for BEEF payloads (BRC-70, feature-gated).
#[cfg(feature = "paymail")]
pub use paymail::PaymailEnvelope;
