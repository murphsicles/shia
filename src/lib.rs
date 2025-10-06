//! Shia: Rust implementation of BSV BEEF protocol (BRC-62+).
//! Efficient SPV tx bundling with ancestry proofs for P2P validation.
//!
//! Shia provides a complete, production-ready library for building, serializing, and verifying
//! BEEF (Background Evaluation Extended Format) bundles on Bitcoin SV (BSV). It supports atomic
//! modes for single-payment validation and integrates seamlessly with BSV's unbounded scaling model.
//! Core features include topological sorting of transaction DAGs, compact Merkle proofs via BUMPs,
//! full script execution using the `sv` crate, and pluggable header oracles for SPV finality.
//!
//! ## Key Concepts
//!
//! - **BEEF Bundle**: A binary payload containing Merkle proofs (BUMPs), followed by topologically
//!   sorted transactions (oldest first). Enables streaming validation without full-node queries.
//! - **BUMP Proofs**: Compact Merkle paths (BRC-74) for proving tx inclusion in block headers.
//! - **Atomic Mode**: Restricts bundles to a subject tx + direct ancestors (BRC-95), ideal for
//!   micropayments.
//! - **Verification**: Checks proofs against headers, UTXO spends, fees (non-negative), and scripts.
//!
//! ## Quick Start
//!
//! Construct a BEEF from a subject transaction, its ancestors, and optional BUMP proofs:
//!
//! ```
//! use anyhow::Result;
//! use shia::{Beef, Transaction, BlockHeadersClient};
//! use std::collections::HashMap;
//! use hex;
//!
//! # fn example() -> Result<()> {
//! // Parse a raw BSV transaction (e.g., from P2P or wallet)
//! let tx_hex = "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0504ffff001dffffffff0100ca9a3b000000001976a914000000000000000000000000000000000000000088ac00000000";
//! let subject_tx = Transaction::from_raw(&hex::decode(tx_hex)?)?;
//!
//! // Ancestors: Map of TXID to Transaction (fetched via RPC or index)
//! let ancestors: HashMap<[u8; 32], Transaction> = HashMap::new();
//!
//! // BUMP proofs: Map of TXID to Bump (fetched from miners/processors)
//! let bump_map: HashMap<[u8; 32], shia::bump::Bump> = HashMap::new();
//!
//! // Build non-atomic BEEF
//! let beef = Beef::build(subject_tx, ancestors, bump_map, false)?;
//!
//! // Verify with a header oracle (e.g., local index or remote API)
//! let my_client = shia::client::MockHeadersClient; // Or implement BlockHeadersClient
//! beef.verify(&my_client)?;
//!
//! // Serialize for P2P transmission
//! let beef_bytes = beef.serialize()?;
//! # Ok(())
//! # }
//! ```
//!
//! For atomic bundles (BRC-95), set `is_atomic: true`—validation enforces no extraneous txs.
//!
//! ## Security & Validation
//!
//! - **Proofs**: Computes Merkle roots from BUMPs and checks against block headers.
//! - **DAG**: Kahn's algorithm ensures acyclic topo-sort; detects cycles.
//! - **Fees**: Ensures outputs ≤ inputs (coinbase exempt).
//! - **Scripts**: Full execution via `sv` crate (P2PKH, multisig, etc.); skips coinbase.
//! - **Atomic**: Confirms all txs trace to subject via inputs; rejects unrelated txs.
//!
//! ## Supported BRCs
//!
//! | BRC | Status  | Notes |
//! |-----|---------|-------|
//! | 62  | ✅ Full | Core BEEF format, serialization, topo-sort, SPV verification |
//! | 74  | ✅ Full | BUMP Merkle proofs (binary format, root computation, merging) |
//! | 95  | ✅ Full | Atomic mode (prefix, subject TXID, strict ancestry checks) |
//! | 70  | ✅ Full | Paymail envelopes (feature = "paymail") |
//! | 45  | ✅ Full | UTXO token checks integrated in verification |
//! | 96  | ✅ Full | TxID-only extension (omit full txs if recipient has them) |
//!
//! ## Features
//!
//! - `default`: Core BEEF + BUMP + atomic.
//! - `paymail`: BRC-70 envelope wrapping for Paymail (requires `serde_json`).
//!
//! ## Crate Features & Dependencies
//!
//! - Relies on `sv` for BSV primitives (tx parsing, script eval).
//! - `anyhow` for error chaining; `thiserror` for custom errors.
//! - No unsafe code; zero-cost abstractions where possible.
//!
//! ## Limitations & Roadmap
//!
//! - Assumes honest header oracle—pair with trusted sources (e.g., Pulse).
//! - Future: BRC-97 extensible proofs; Teranode optimizations.
//! - Report issues: [GitHub](https://github.com/murphsicles/shia).
//!
//! ## License
//!
//! MIT or Apache-2.0.
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
