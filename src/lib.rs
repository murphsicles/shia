use anyhow::{anyhow, Result};
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use std::collections::{HashMap, HashSet};
use std::io::{self, Cursor, Read, Write};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum BeefError {
    #[error("IO error: {0}")]
    Io(#[from] io::Error),
    #[error("Invalid VarInt")]
    InvalidVarInt,
    #[error("Invalid flags: {0}")]
    InvalidFlags(u8),
    #[error("Invalid version")]
    InvalidVersion,
    #[error("Verification failed: {0}")]
    Verification(String),
    #[error("Atomic BEEF mismatch: unrelated tx")]
    AtomicMismatch,
}

// VarInt implementation (Bitcoin-style)
fn read_varint<R: Read>(reader: &mut R) -> Result<u64> {
    let mut b = [0u8; 1];
    reader.read_exact(&mut b)?;
    let n = b[0];
    match n {
        0..=0xfc => Ok(n as u64),
        0xfd => Ok(reader.read_u16::<LittleEndian>()? as u64),
        0xfe => Ok(reader.read_u32::<LittleEndian>()? as u64),
        0xff => Ok(reader.read_u64::<LittleEndian>()?),
    }
}

fn write_varint<W: Write>(writer: &mut W, mut n: u64) -> Result<()> {
    if n < 0xfd {
        writer.write_u8(n as u8)?;
    } else if n <= 0xffff {
        writer.write_u8(0xfd)?;
        writer.write_u16::<LittleEndian>(n as u16)?;
    } else if n <= 0xffffffff {
        writer.write_u8(0xfe)?;
        writer.write_u32::<LittleEndian>(n as u32)?;
    } else {
        writer.write_u8(0xff)?;
        writer.write_u64::<LittleEndian>(n)?;
    }
    Ok(())
}

// Simplified Transaction struct (extend for full script/sig verification in your wallet)
#[derive(Clone, Debug)]
pub struct Transaction {
    pub version: u32,
    pub inputs: Vec<Input>,
    pub outputs: Vec<Output>,
    pub locktime: u32,
    pub raw: Vec<u8>, // Raw bytes for serialization
}

#[derive(Clone, Debug)]
pub struct Input {
    pub prev_txid: [u8; 32],
    pub vout: u32,
    pub script_sig: Vec<u8>,
    pub sequence: u32,
}

#[derive(Clone, Debug)]
pub struct Output {
    pub value: u64,
    pub script_pubkey: Vec<u8>,
}

impl Transaction {
    pub fn from_raw(raw: &[u8]) -> Result<Self> {
        let mut cursor = Cursor::new(raw);
        let version = cursor.read_u32::<LittleEndian>()?;
        let num_inputs = read_varint(&mut cursor)?;
        let mut inputs = Vec::with_capacity(num_inputs as usize);
        for _ in 0..num_inputs {
            let mut prev_txid = [0u8; 32];
            cursor.read_exact(&mut prev_txid)?;
            prev_txid.reverse(); // TXID is little-endian
            let vout = cursor.read_u32::<LittleEndian>()?;
            let script_len = read_varint(&mut cursor)? as usize;
            let mut script_sig = vec![0u8; script_len];
            cursor.read_exact(&mut script_sig)?;
            let sequence = cursor.read_u32::<LittleEndian>()?;
            inputs.push(Input { prev_txid, vout, script_sig, sequence });
        }
        let num_outputs = read_varint(&mut cursor)?;
        let mut outputs = Vec::with_capacity(num_outputs as usize);
        for _ in 0..num_outputs {
            let value = cursor.read_u64::<LittleEndian>()?;
            let script_len = read_varint(&mut cursor)? as usize;
            let mut script_pubkey = vec![0u8; script_len];
            cursor.read_exact(&mut script_pubkey)?;
            outputs.push(Output { value, script_pubkey });
        }
        let locktime = cursor.read_u32::<LittleEndian>()?;
        Ok(Self { version, inputs, outputs, locktime, raw: raw.to_vec() })
    }

    pub fn txid(&self) -> [u8; 32] {
        // Simplified: hash raw bytes (double SHA256, reverse for TXID)
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(&self.raw);
        let mut hash = hasher.finalize();
        hasher = Sha256::new();
        hasher.update(hash);
        let mut txid: [u8; 32] = [0; 32];
        txid.copy_from_slice(&hasher.finalize());
        txid.reverse();
        txid
    }

    // Full script/sig verification would go here (e.g., using a script engine crate)
    fn verify_scripts(&self, _prev_outputs: &HashMap<([u8; 32], u32), Output>) -> Result<()> {
        // Placeholder: Implement full BSV script evaluation
        Ok(())
    }
}

// BUMP (BRC-74)
#[derive(Debug)]
pub struct Bump {
    pub block_height: u64,
    pub tree_height: u8,
    pub levels: Vec<Vec<Leaf>>,
}

#[derive(Debug)]
pub struct Leaf {
    pub offset: u64,
    pub flags: u8,
    pub hash: Option<[u8; 32]>,
}

impl Bump {
    pub fn deserialize(reader: &mut impl Read) -> Result<Self> {
        let block_height = read_varint(reader)?;
        let tree_height = reader.read_u8()?;
        let mut levels = Vec::with_capacity(tree_height as usize);
        for _ in 0..tree_height {
            let n_leaves = read_varint(reader)? as usize;
            let mut leaves = Vec::with_capacity(n_leaves);
            for _ in 0..n_leaves {
                let offset = read_varint(reader)?;
                let flags = reader.read_u8()?;
                let hash = match flags {
                    0x00 | 0x02 => {
                        let mut h = [0u8; 32];
                        reader.read_exact(&mut h)?;
                        Some(h)
                    }
                    0x01 => None,
                    _ => return Err(BeefError::InvalidFlags(flags).into()),
                };
                leaves.push(Leaf { offset, flags, hash });
            }
            levels.push(leaves);
        }
        Ok(Self { block_height, tree_height, levels })
    }

    pub fn serialize(&self, writer: &mut impl Write) -> Result<()> {
        write_varint(writer, self.block_height)?;
        writer.write_u8(self.tree_height)?;
        for level in &self.levels {
            write_varint(writer, level.len() as u64)?;
            for leaf in level {
                write_varint(writer, leaf.offset)?;
                writer.write_u8(leaf.flags)?;
                if let Some(h) = leaf.hash {
                    writer.write_all(&h)?;
                }
            }
        }
        Ok(())
    }

    // Compute Merkle root (simplified; full impl would verify all paths)
    pub fn compute_root(&self) -> Result<[u8; 32]> {
        // Placeholder: Implement full Merkle root calculation from leaves
        // Use sha2 crate for double SHA256
        use sha2::{Digest, Sha256};
        let mut root = [0u8; 32]; // Dummy
        // ... logic to build tree and hash ...
        Ok(root)
    }
}

// BEEF struct
#[derive(Debug)]
pub struct Beef {
    pub is_atomic: bool,
    pub subject_txid: Option<[u8; 32]>,
    pub bumps: Vec<Bump>,
    pub txs: Vec<(Transaction, Option<usize>)>, // (tx, bump_index)
}

pub trait BlockHeadersClient {
    fn is_valid_root_for_height(&self, root: [u8; 32], height: u64) -> bool;
}

impl Beef {
    pub fn from_hex(hex: &str) -> Result<Self> {
        let bytes = hex::decode(hex)?;
        Self::deserialize(&bytes)
    }

    pub fn deserialize(bytes: &[u8]) -> Result<Self> {
        let mut cursor = Cursor::new(bytes);
        let mut is_atomic = false;
        let mut subject_txid = None;

        // Check for Atomic prefix
        let mut prefix = [0u8; 4];
        if cursor.read_exact(&mut prefix).is_ok() && prefix == [0x01, 0x01, 0x01, 0x01] {
            is_atomic = true;
            let mut txid = [0u8; 32];
            cursor.read_exact(&mut txid)?;
            subject_txid = Some(txid);
        } else {
            // Reset if not atomic
            cursor.set_position(0);
        }

        let version = cursor.read_u32::<LittleEndian>()?;
        if version != 4022206465 {
            return Err(BeefError::InvalidVersion.into());
        }

        let n_bumps = read_varint(&mut cursor)? as usize;
        let mut bumps = Vec::with_capacity(n_bumps);
        for _ in 0..n_bumps {
            bumps.push(Bump::deserialize(&mut cursor)?);
        }

        let n_txs = read_varint(&mut cursor)? as usize;
        let mut txs = Vec::with_capacity(n_txs);
        for _ in 0..n_txs {
            // Read raw tx length implicitly by parsing until end
            let mut raw = Vec::new();
            // Hack: Read remaining to find tx boundary (better: read varint len if needed, but spec has no len prefix)
            // For simplicity, assume we read until parse succeeds; in practice, use a bounded reader
            let pos = cursor.position();
            let remaining = &bytes[pos as usize..];
            let tx = Transaction::from_raw(remaining)?;
            let tx_len = cursor.position() - pos; // Update after parse
            cursor.set_position(pos + tx_len);
            let has_bump = cursor.read_u8()?;
            let bump_index = if has_bump == 0x01 {
                Some(read_varint(&mut cursor)? as usize)
            } else if has_bump == 0x00 {
                None
            } else {
                return Err(anyhow!("Invalid has_bump: {}", has_bump));
            };
            txs.push((tx, bump_index));
        }

        let beef = Self { is_atomic, subject_txid, bumps, txs };

        if beef.is_atomic {
            beef.validate_atomic()?;
        }

        Ok(beef)
    }

    pub fn serialize(&self) -> Result<Vec<u8>> {
        let mut buf = Vec::new();
        if self.is_atomic {
            buf.write_all(&[0x01, 0x01, 0x01, 0x01])?;
            if let Some(txid) = self.subject_txid {
                buf.write_all(&txid)?;
            }
        }
        buf.write_u32::<LittleEndian>(4022206465)?;
        write_varint(&mut buf, self.bumps.len() as u64)?;
        for bump in &self.bumps {
            bump.serialize(&mut buf)?;
        }
        write_varint(&mut buf, self.txs.len() as u64)?;
        for (tx, bump_index) in &self.txs {
            buf.write_all(&tx.raw)?;
            if let Some(idx) = bump_index {
                buf.write_u8(0x01)?;
                write_varint(&mut buf, *idx as u64)?;
            } else {
                buf.write_u8(0x00)?;
            }
        }
        Ok(buf)
    }

    // Build BEEF from tx DAG (map of txid -> tx, and bump_map: txid -> bump)
    pub fn build(
        subject_tx: Transaction,
        ancestors: HashMap<[u8; 32], Transaction>,
        bump_map: HashMap<[u8; 32], Bump>,
        is_atomic: bool,
    ) -> Result<Self> {
        // Kahn's algorithm for topo sort
        let mut graph: HashMap<[u8; 32], HashSet<[u8; 32]>> = HashMap::new();
        let mut in_degree: HashMap<[u8; 32], u32> = HashMap::new();
        let all_txs = ancestors.clone();
        let subject_txid = subject_tx.txid();
        graph.insert(subject_txid, HashSet::new());
        in_degree.insert(subject_txid, 0);
        // Build graph: child -> parents
        // Actually, for topo: parents first
        // Inputs are parents
        for tx in all_txs.values() {
            let txid = tx.txid();
            graph.entry(txid).or_insert(HashSet::new());
            in_degree.entry(txid).or_insert(0);
            for input in &tx.inputs {
                graph.entry(txid).or_insert(HashSet::new()).insert(input.prev_txid);
                *in_degree.entry(input.prev_txid).or_insert(0) += 1;
            }
        }
        // Add subject
        for input in &subject_tx.inputs {
            graph.get_mut(&subject_txid).unwrap().insert(input.prev_txid);
            *in_degree.entry(input.prev_txid).or_insert(0) += 1;
        }

        // Kahn's
        let mut queue: Vec<[u8; 32]> = in_degree.iter().filter(|&(_, &deg)| deg == 0).map(|(&id, _)| id).collect();
        let mut ordered = Vec::new();
        while let Some(node) = queue.pop() {
            ordered.push(node);
            if let Some(children) = graph.get(&node) {
                for child in children {
                    if let Some(deg) = in_degree.get_mut(child) {
                        *deg -= 1;
                        if *deg == 0 {
                            queue.push(*child);
                        }
                    }
                }
            }
        }
        if ordered.len() != graph.len() {
            return Err(anyhow!("Cycle in tx DAG"));
        }

        // Collect txs in order
        let mut txs = Vec::new();
        let mut bumps = Vec::new();
        let mut bump_indices: HashMap<[u8; 32], usize> = HashMap::new();
        for txid in ordered {
            let tx = if txid == subject_txid { subject_tx.clone() } else { all_txs.get(&txid).cloned().unwrap() };
            let bump_index = if let Some(bump) = bump_map.get(&txid) {
                if let Some(&idx) = bump_indices.get(&txid) {
                    Some(idx)
                } else {
                    let idx = bumps.len();
                    bumps.push(bump.clone());
                    bump_indices.insert(txid, idx);
                    Some(idx)
                }
            } else {
                None
            };
            txs.push((tx, bump_index));
        }

        let mut beef = Self { is_atomic, subject_txid: if is_atomic { Some(subject_txid) } else { None }, bumps, txs };
        if is_atomic {
            beef.validate_atomic()?;
        }
        Ok(beef)
    }

    fn validate_atomic(&self) -> Result<()> {
        let subject_txid = self.subject_txid.ok_or(anyhow!("No subject TXID"))?;
        let subject_tx = self.txs.last().ok_or(anyhow!("No txs"))?.0.clone();
        if subject_tx.txid() != subject_txid {
            return Err(BeefError::AtomicMismatch.into());
        }
        // Check all txs are ancestors
        let mut ancestors = HashSet::new();
        let mut to_check = vec![subject_txid];
        while let Some(id) = to_check.pop() {
            ancestors.insert(id);
            if let Some(tx) = self.txs.iter().find(|(t, _)| t.txid() == id) {
                for input in &tx.0.inputs {
                    to_check.push(input.prev_txid);
                }
            }
        }
        if self.txs.len() != ancestors.len() {
            return Err(BeefError::AtomicMismatch.into());
        }
        Ok(())
    }

    pub fn verify(&self, headers_client: &impl BlockHeadersClient) -> Result<bool> {
        // Verify BUMPs
        for bump in &self.bumps {
            let root = bump.compute_root()?;
            if !headers_client.is_valid_root_for_height(root, bump.block_height) {
                return Err(BeefError::Verification("Invalid Merkle root".to_string()).into());
            }
        }

        // Validate tx chain
        let mut utxos: HashMap<([u8; 32], u32), Output> = HashMap::new();
        for (tx, bump_index) in &self.txs {
            if let Some(idx) = bump_index {
                // Confirmed: assume proof valid (already checked root)
                let bump = &self.bumps[*idx];
                // Full: Verify tx in bump (check if txid in level 0 with flag 0x02)
            }
            // Check inputs
            let mut input_value = 0u64;
            for input in &tx.inputs {
                let key = (input.prev_txid, input.vout);
                let prev_out = utxos.get(&key).ok_or(anyhow!("Missing UTXO"))?.clone();
                input_value += prev_out.value;
                // Sig check placeholder
            }
            let mut output_value = 0u64;
            for out in &tx.outputs {
                output_value += out.value;
            }
            if output_value > input_value {
                return Err(BeefError::Verification("Value mismatch".to_string()).into());
            }
            tx.verify_scripts(&utxos)?;

            // Add outputs to UTXOs
            let txid = tx.txid();
            for (i, out) in tx.outputs.iter().enumerate() {
                utxos.insert((txid, i as u32), out.clone());
            }
        }

        if self.is_atomic {
            self.validate_atomic()?;
        }

        Ok(true)
    }
}

// Example usage (in tests)
#[cfg(test)]
mod tests {
    use super::*;
    // Add test cases using sample BEEFHex from TS example
}
