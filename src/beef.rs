//! Core BEEF bundling, serialization, and verification (BRC-62).

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
#[derive(Debug, Clone)]
pub struct Beef {
    /// Atomic mode enabled (BRC-95).
    pub is_atomic: bool,
    /// Subject TXID for atomic mode.
    pub subject_txid: Option<[u8; 32]>,
    /// BUMP proofs.
    pub bumps: Vec<Bump>,
    /// Topo-sorted TXs with optional BUMP index.
    pub txs: Vec<(Transaction, Option<usize>)>,
}

impl Beef {
    /// Deserializes from hex string.
    pub fn from_hex(hex: &str) -> Result<Self> {
        let bytes = hex::decode(hex)?;
        Self::deserialize(&bytes)
    }

    /// Deserializes from bytes.
    /// Handles atomic prefix if present.
    /// # Errors
    /// - Version mismatch or parse failures.
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
        if version != 0xf1c6c3ef {  // BEEF0001 as per test hex
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
    /// Includes atomic prefix if enabled.
    pub fn serialize(&self) -> Result<Vec<u8>> {
        let mut buf = Vec::new();
        if self.is_atomic {
            buf.extend_from_slice(&[1, 1, 1, 1]);
            if let Some(txid) = self.subject_txid {
                buf.extend_from_slice(&txid);
            }
        }
        buf.write_u32::<LittleEndian>(0xf1c6c3ef)?;
        write_varint(&mut buf, self.bumps.len() as u64)?;
        for bump in &self.bumps {
            bump.serialize(&mut buf)?;
        }
        write_varint(&mut buf, self.txs.len() as u64)?;
        for (tx, bump_index) in &self.txs {
            buf.extend_from_slice(&tx.raw);
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
    /// Topo-sorts via Kahn's algorithm (parents first).
    /// # Errors
    /// - Cycles in DAG or atomic validation fails.
    /// # Args
    /// - `is_atomic`: Restrict to subject + direct ancestors (BRC-95).
    pub fn build(
        subject_tx: Transaction,
        ancestors: HashMap<[u8; 32], Transaction>,
        bump_map: HashMap<[u8; 32], Bump>,
        is_atomic: bool,
    ) -> Result<Self> {
        let mut all_txs = ancestors;
        let subject_txid = subject_tx.txid();
        all_txs.insert(subject_txid, subject_tx.clone());

        // Build graph and in-degrees
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

        // Kahn's topo sort
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

        // Collect ordered TXs with unique BUMPs
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
    /// # Args
    /// - `headers_client`: For Merkle root checks.
    pub fn verify(&self, headers_client: &impl BlockHeadersClient) -> Result<()> {
        // Verify BUMPs
        for (tx, bump_index) in &self.txs {
            if let Some(idx) = bump_index {
                let bump = &self.bumps[*idx];
                let root = bump.compute_merkle_root_for_hash(tx.merkle_hash())?;
                if !headers_client.is_valid_root_for_height(root, bump.block_height) {
                    return Err(ShiaError::Verification("Invalid Merkle root".to_string()));
                }
            }
        }

        // Validate TX chain (UTXOs, fees, scripts)
        let mut utxos: HashMap<([u8; 32], u32), Output> = HashMap::new();
        for (tx, _) in &self.txs {
            let mut input_value = 0u64;
            for input in &tx.inputs {
                let key = (input.prev_txid, input.vout);
                let prev_out = utxos.get(&key)
                    .ok_or_else(|| ShiaError::Verification("Missing UTXO".to_string()))?
                    .clone();
                input_value += prev_out.value;
            }
            let output_value = tx.outputs.iter().map(|o| o.value).sum::<u64>();
            if output_value > input_value {
                return Err(ShiaError::Verification("Value mismatch (negative fee)".to_string()));
            }
            tx.verify_scripts(&utxos)?;

            // Update UTXOs
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

    #[test]
    fn test_beef_from_hex_serialize() {
        let minimal_beef_hex = "f1c6c3ef00010100000000000000000000000000000000000000000000000000000000000000000000000000000000000504ffff001dffffffff0100ca9a3b000000001976a914000000000000000000000000000000000000000088ac0000000000";
        let beef = Beef::from_hex(minimal_beef_hex).expect("Deserialize failed");
        let serialized = beef.serialize().expect("Serialize failed");
        let serialized_hex = hex::encode(serialized);
        assert_eq!(serialized_hex.to_lowercase(), minimal_beef_hex.to_lowercase());
    }

    #[test]
    fn test_beef_verify() {
        let minimal_beef_hex = "f1c6c3ef00010100000000000000000000000000000000000000000000000000000000000000000000000000000000000504ffff001dffffffff0100ca9a3b000000001976a914000000000000000000000000000000000000000088ac0000000000";
        let beef = Beef::from_hex(minimal_beef_hex).expect("Deserialize failed");
        let mock_client = MockHeadersClient;
        assert!(beef.verify(&mock_client).is_ok());
    }

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
