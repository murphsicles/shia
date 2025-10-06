//! Core BEEF bundling, serialization, and verification (BRC-62).
//!
//! BEEF (Background Evaluation Extended Format) is a binary protocol for bundling transactions with their
//! dependency ancestry and BUMP Merkle proofs (BRC-74), enabling efficient SPV validation (BRC-62).
//! Transactions are topologically sorted (parents first) for streaming verification: proofs first, then
//! oldest tx, dependents last. Supports atomic mode (BRC-95) for single-subject graphs.
//!
//! ## Structure (Binary Format)
//!
//! - **Atomic Prefix** (optional, BRC-95): `[0x01, 0x01, 0x01, 0x01]` (4 bytes) + subject TXID (32 bytes).
//! - **Version**: `0xf1c6c3ef` (little-endian uint32, 4 bytes).
//! - **nBumps**: VarInt (u64, 1-9 bytes), number of BUMP proofs.
//! - **Bumps**: Array of serialized BUMPs (BRC-74 binary format).
//! - **nTxs**: VarInt (u64, 1-9 bytes), number of transactions.
//! - **Txs**: For each tx:
//!   - Raw tx bytes (BRC-12 format, variable length).
//!   - HasBump: `0x00` (no proof, 1 byte) or `0x01` + Bump index (VarInt, 1-9 bytes).
//!
//! Byte order: Little-endian for fixed fields (version, tx internals); big-endian for hashes/TXIDs.
//! VarInts: Compact u64 encoding (per BSV spec).
//!
//! ## Building & Validation
//!
//! - **Build**: Inputs subject tx, ancestor map (TXID -> Tx), bump map (TXID -> Bump).
//!   - Merges unique bumps, topo-sorts via Kahn's algorithm (detects cycles).
//!   - Atomic: Sets subject TXID, enforces ancestry-only via `validate_atomic`.
//! - **Verify**: 
//!   - Computes Merkle roots from bumps, checks against headers.
//!   - Validates DAG: UTXOs match, fees non-negative (skip coinbase), scripts execute (skip coinbase).
//!   - Atomic: Ensures txs.len() == ancestors.len(), all txs trace to subject.
//!
//! ## Examples
//!
//! See `Beef::build` and `Beef::verify` for code snippets.
use crate::atomic::validate_atomic;
use crate::bump::Bump;
use crate::client::BlockHeadersClient;
use crate::errors::{Result, ShiaError};
use crate::tx::{Output, Transaction};
use crate::utils::{read_varint, write_varint};
use anyhow::anyhow;
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use hex;
use std::collections::{HashMap, HashSet};
use std::io::{Cursor, Read};

/// BEEF bundle: Transactions with ancestry and BUMP proofs.
///
/// Topo-sorted txs (parents first) with references to unique BUMPs for SPV proofs.
/// Atomic mode restricts to subject + ancestors (BRC-95).
#[derive(Debug, Clone)]
pub struct Beef {
    /// Atomic mode enabled (BRC-95): Restricts to subject tx + direct ancestors.
    pub is_atomic: bool,
    /// Subject TXID for atomic mode: Root tx all others must trace to.
    pub subject_txid: Option<[u8; 32]>,
    /// BUMP proofs: Unique Merkle paths (BRC-74) for tx inclusion.
    pub bumps: Vec<Bump>,
    /// Topo-sorted TXs with optional BUMP index: `(tx, Option<bump_idx>)`.
    /// Txs ordered parents-first for streaming UTXO validation.
    pub txs: Vec<(Transaction, Option<usize>)>,
}

impl Beef {
    /// Deserializes from hex string.
    ///
    /// Convenience wrapper over `deserialize`; hex must be even-length, valid BSV tx bytes.
    pub fn from_hex(hex: &str) -> Result<Self> {
        let bytes = hex::decode(hex)?;
        Self::deserialize(&bytes)
    }

    /// Deserializes from bytes.
    ///
    /// Parses atomic prefix (if present), version, bumps, txs.
    /// Advances cursor by tx.raw.len() for variable-length txs.
    /// Calls `validate_atomic` post-parse if atomic.
    ///
    /// # Errors
    /// - `ShiaError::InvalidVersion`: Version != 0xf1c6c3ef (LE).
    /// - IO/VarInt failures, invalid has_bump (not 0x00/0x01).
    /// - `Transaction::from_raw` errors on tx parsing.
    /// - Atomic validation fails (BRC-95).
    pub fn deserialize(bytes: &[u8]) -> Result<Self> {
        let mut cursor = Cursor::new(bytes);
        let mut is_atomic = false;
        let mut subject_txid = None;
        let mut prefix = [0u8; 4];
        if cursor.read_exact(&mut prefix).is_ok() && prefix == [1, 1, 1, 1] {
            is_atomic = true;
            let mut txid = [0u8; 32];
            cursor.read_exact(&mut txid)?;
            subject_txid = Some(txid);
        } else {
            cursor.set_position(0);
        }
        let version = cursor.read_u32::<LittleEndian>()?;
        if version != 0xf1c6c3ef { // BRC-62 magic (LE)
            return Err(ShiaError::InvalidVersion);
        }
        let n_bumps = read_varint(&mut cursor)? as usize;
        let mut bumps = Vec::with_capacity(n_bumps);
        for _ in 0..n_bumps {
            bumps.push(Bump::deserialize(&mut cursor)?);
        }
        let n_txs = read_varint(&mut cursor)? as usize;
        let mut txs = Vec::with_capacity(n_txs);
        for _ in 0..n_txs {
            let start_pos = cursor.position() as usize;
            let remaining = &bytes[start_pos..];
            let tx = Transaction::from_raw(remaining)?;
            let tx_consumed = tx.raw.len();
            cursor.set_position((start_pos + tx_consumed) as u64);
            let has_bump = cursor.read_u8()?;
            let bump_index = if has_bump == 0x01 {
                Some(read_varint(&mut cursor)? as usize)
            } else if has_bump == 0x00 {
                None
            } else {
                return Err(anyhow!("Invalid has_bump: {}", has_bump).into());
            };
            txs.push((tx, bump_index));
        }
        let beef = Self { is_atomic, subject_txid, bumps, txs };
        if beef.is_atomic {
            validate_atomic(&beef)?;
        }
        Ok(beef)
    }

    /// Serializes to bytes.
    ///
    /// Mirrors deserialize: Atomic prefix + txid (if atomic), version, bumps, txs with has_bump/index.
    /// Uses little-endian for version; VarInts for counts/indices.
    ///
    /// # Errors
    /// - Bump serialization failures.
    pub fn serialize(&self) -> Result<Vec<u8>> {
        let mut buf = Vec::new();
        if self.is_atomic {
            buf.extend_from_slice(&[1, 1, 1, 1]); // BRC-95 prefix
            if let Some(txid) = self.subject_txid {
                buf.extend_from_slice(&txid);
            }
        }
        buf.write_u32::<LittleEndian>(0xf1c6c3ef)?; // BRC-62 version
        write_varint(&mut buf, self.bumps.len() as u64)?;
        for bump in &self.bumps {
            bump.serialize(&mut buf)?;
        }
        write_varint(&mut buf, self.txs.len() as u64)?;
        for (tx, bump_index) in &self.txs {
            buf.extend_from_slice(&tx.raw); // Raw BRC-12 tx
            if let Some(idx) = bump_index {
                buf.write_u8(0x01)?;
                write_varint(&mut buf, *idx as u64)?;
            } else {
                buf.write_u8(0x00)?;
            }
        }
        Ok(buf)
    }

    /// Builds BEEF from subject TX, ancestors, and BUMP map.
    ///
    /// - Merges unique bumps (dedup by TXID reference).
    /// - Topo-sorts txs via Kahn's algorithm: Builds graph/in-degrees from inputs, queues roots (deg=0),
    ///   processes children, detects cycles if not all txs ordered.
    /// - Includes subject tx; atomic sets subject TXID and validates ancestry-only.
    ///
    /// # Errors
    /// - Cycles/missing deps in DAG (`anyhow!`).
    /// - Atomic validation fails (BRC-95: extraneous txs).
    ///
    /// # Args
    /// - `ancestors`: TXID -> Tx map (fetched via RPC/index; excludes subject).
    /// - `bump_map`: TXID -> Bump map (from miners/processors).
    /// - `is_atomic`: Enable BRC-95 mode (subject + ancestors only).
    pub fn build(
        subject_tx: Transaction,
        ancestors: HashMap<[u8; 32], Transaction>,
        bump_map: HashMap<[u8; 32], Bump>,
        is_atomic: bool,
    ) -> Result<Self> {
        let mut all_txs = ancestors;
        let subject_txid = subject_tx.txid();
        all_txs.insert(subject_txid, subject_tx.clone());
        // Build graph and in-degrees (only included ancestors)
        let mut graph: HashMap<[u8; 32], HashSet<[u8; 32]>> = HashMap::new();
        let mut in_degree: HashMap<[u8; 32], u32> = HashMap::new();
        for (&txid, tx) in &all_txs {
            graph.insert(txid, HashSet::new());
            *in_degree.entry(txid).or_insert(0) = 0;
            for input in &tx.inputs {
                if all_txs.contains_key(&input.prev_txid) {
                    graph.entry(input.prev_txid).or_default().insert(txid);
                    *in_degree.entry(txid).or_insert(0) += 1;
                }
            }
        }
        // Kahn's topo sort (parents first)
        let mut queue: Vec<_> = in_degree.iter().filter(|&(_, deg)| *deg == 0).map(|(&id, _)| id).collect();
        let mut ordered = Vec::new();
        while let Some(node) = queue.pop() {
            ordered.push(node);
            if let Some(children) = graph.get(&node) {
                for &child in children {
                    if let Some(deg) = in_degree.get_mut(&child) {
                        *deg -= 1;
                        if *deg == 0 {
                            queue.push(child);
                        }
                    }
                }
            }
        }
        if ordered.len() != all_txs.len() {
            return Err(anyhow!("Cycle or missing dependencies in tx DAG").into());
        }
        // Collect ordered TXs with unique BUMPs (dedup by TXID)
        let mut txs = Vec::new();
        let mut bumps = Vec::new();
        let mut bump_indices: HashMap<[u8; 32], usize> = HashMap::new();
        for &txid in &ordered {
            let tx = all_txs.remove(&txid).unwrap();
            let bump_index = bump_map.get(&txid).map(|bump| {
                *bump_indices.entry(txid).or_insert_with(|| {
                    let idx = bumps.len();
                    bumps.push(bump.clone());
                    idx
                })
            });
            txs.push((tx, bump_index));
        }
        let beef = Self {
            is_atomic,
            subject_txid: if is_atomic { Some(subject_txid) } else { None },
            bumps,
            txs,
        };
        if beef.is_atomic {
            validate_atomic(&beef)?;
        }
        Ok(beef)
    }

    /// Full SPV verification: BUMPs, fees, scripts, atomic checks.
    ///
    /// - **BUMPs**: Computes roots, validates against headers (skips unproven txs).
    /// - **Chain**: Simulates UTXO set: Matches inputs to prior outputs, sums values for fees.
    ///   - Fees: Outputs <= inputs (skip coinbase).
    ///   - Scripts: Executes via `sv` crate (skip coinbase).
    /// - **Atomic**: Ensures exact ancestry match (no extras/missing).
    ///
    /// # Args
    /// - `headers_client`: Implementor for `is_valid_root_for_height` (e.g., local index, remote API).
    ///
    /// # Errors
    /// - `ShiaError::Verification`: Invalid root, missing UTXO, negative fee, script fail.
    /// - Atomic mismatch.
    pub fn verify(&self, headers_client: &impl BlockHeadersClient) -> Result<()> {
        // Verify BUMPs (BRC-74 roots against headers)
        for (tx, bump_index) in &self.txs {
            if let Some(idx) = bump_index {
                let bump = &self.bumps[*idx];
                let root = bump.compute_merkle_root_for_hash(tx.merkle_hash())?;
                if !headers_client.is_valid_root_for_height(root, bump.block_height) {
                    return Err(ShiaError::Verification("Invalid Merkle root".to_string()));
                }
            }
        }
        // Validate TX chain (UTXOs, fees, scripts; BRC-62)
        let mut utxos: HashMap<([u8; 32], u32), Output> = HashMap::new();
        for (tx, _) in &self.txs {
            let mut input_value = 0u64;
            let is_coinbase = tx.inputs.iter().any(|input| input.prev_txid == [0u8; 32]);
            for input in &tx.inputs {
                if input.prev_txid != [0u8; 32] {
                    let key = (input.prev_txid, input.vout);
                    let prev_out = utxos.get(&key)
                        .ok_or_else(|| ShiaError::Verification("Missing UTXO".to_string()))?
                        .clone();
                    input_value += prev_out.value;
                }
            }
            let output_value = tx.outputs.iter().map(|o| o.value).sum::<u64>();
            if !is_coinbase && output_value > input_value {
                return Err(ShiaError::Verification("Value mismatch (negative fee)".to_string()));
            }
            if !is_coinbase {
                tx.verify_scripts(&utxos)?;
            }
            // Update UTXOs for dependents
            let txid = tx.txid();
            for (i, out) in tx.outputs.iter().enumerate() {
                utxos.insert((txid, i as u32), out.clone());
            }
        }
        if self.is_atomic {
            validate_atomic(self)?;
        }
        Ok(())
    }

    /// Wraps this BEEF in a Paymail envelope (BRC-70).
    ///
    /// Serializes BEEF to base64, embeds in JSON envelope with optional proofs/metadata.
    /// Feature-gated; requires `serde_json` for serialization.
    ///
    /// # Errors
    /// - Envelope construction fails (e.g., invalid proofs).
    #[cfg(feature = "paymail")]
    pub fn to_paymail_envelope(
        &self,
        proofs: Option<Vec<String>>,
        metadata: Option<HashMap<String, serde_json::Value>>,
    ) -> Result<crate::paymail::PaymailEnvelope> {
        crate::paymail::PaymailEnvelope::from_beef(self, proofs, metadata)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::MockHeadersClient;
    use hex;
    use std::collections::HashMap;

    /// Tests round-trip serialization/deserialization for minimal single-tx BEEF (no bumps, atomic false).
    #[test]
    fn test_beef_from_hex_serialize() {
        let tx_hex = "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0504ffff001dffffffff0100ca9a3b000000001976a914000000000000000000000000000000000000000088ac00000000";
        let minimal_beef_hex = format!("efc3c6f10001{}00", tx_hex); // Version LE + nBumps=0 + nTxs=1 + tx + hasBump=00
        let beef = Beef::from_hex(&minimal_beef_hex).expect("Deserialize failed");
        let serialized = beef.serialize().expect("Serialize failed");
        let serialized_hex = hex::encode(serialized);
        assert_eq!(serialized_hex.to_lowercase(), minimal_beef_hex.to_lowercase());
    }

    /// Tests full SPV verification on minimal coinbase tx (no bump, skips script/fee checks).
    #[test]
    fn test_beef_verify() {
        let tx_hex = "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0504ffff001dffffffff0100ca9a3b000000001976a914000000000000000000000000000000000000000088ac00000000";
        let minimal_beef_hex = format!("efc3c6f10001{}00", tx_hex);
        let beef = Beef::from_hex(&minimal_beef_hex).expect("Deserialize failed");
        let mock_client = MockHeadersClient; // Always returns true for roots
        assert!(beef.verify(&mock_client).is_ok());
    }

    /// Tests BEEF build: Single subject tx, no ancestors/bumps, verifies topo-sort (trivial) and round-trip.
    #[test]
    fn test_beef_build_simple() {
        let subject_raw = hex::decode("01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0504ffff001dffffffff0100ca9a3b000000001976a914000000000000000000000000000000000000000088ac00000000").unwrap();
        let subject_tx = Transaction::from_raw(&subject_raw).unwrap();
        let ancestors = HashMap::new();
        let bump_map = HashMap::new();
        let beef = Beef::build(subject_tx.clone(), ancestors, bump_map, false).unwrap();
        assert_eq!(beef.txs.len(), 1);
        assert_eq!(beef.txs[0].0.version, subject_tx.version);
        assert_eq!(beef.bumps.len(), 0);
        assert!(beef.txs[0].1.is_none());
        let serialized = beef.serialize().unwrap();
        let deserialized = Beef::deserialize(&serialized).unwrap();
        assert_eq!(deserialized.txs[0].0.version, subject_tx.version);
    }
}
