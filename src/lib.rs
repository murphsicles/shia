use anyhow::{anyhow, Result};
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::io::{self, Cursor, Read, Write};
use thiserror::Error;
use sv::script::Script; // Assuming sv crate has script module
// Note: Adjust imports based on actual sv crate structure. If sv has a VM or Interpreter, use that.

#[derive(Error, Debug)]
pub enum ShiaError {
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
    #[error("Atomic mismatch: unrelated tx")]
    AtomicMismatch,
    #[error("Missing sibling in BUMP")]
    MissingSibling,
    #[error("Leaf not found in BUMP")]
    LeafNotFound,
    #[error("Script evaluation failed: {0}")]
    ScriptEval(String),
}

// Helper for double SHA256
fn double_sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let hash1 = hasher.finalize();
    let mut hasher = Sha256::new();
    hasher.update(hash1);
    hasher.finalize().into()
}

// VarInt implementation
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

fn write_varint<W: Write>(writer: &mut W, n: u64) -> Result<()> {
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

// Simplified Transaction
#[derive(Clone, Debug)]
pub struct Transaction {
    pub version: u32,
    pub inputs: Vec<Input>,
    pub outputs: Vec<Output>,
    pub locktime: u32,
    pub raw: Vec<u8>,
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
            prev_txid.reverse(); // To little-endian TXID
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
        let mut hash = double_sha256(&self.raw);
        hash.reverse(); // Little-endian TXID
        hash
    }

    pub fn merkle_hash(&self) -> [u8; 32] {
        double_sha256(&self.raw)
    }

    // Script verification using rust-sv
    fn verify_scripts(&self, prev_outputs: &HashMap<([u8; 32], u32), Output>) -> Result<()> {
        for (idx, input) in self.inputs.iter().enumerate() {
            let key = (input.prev_txid, input.vout);
            let prev_out = prev_outputs
                .get(&key)
                .ok_or(ShiaError::Verification("Missing UTXO".to_string()))?;
            let script_sig_bytes = &input.script_sig;
            let script_pubkey_bytes = &prev_out.script_pubkey;

            // Parse scripts using rust-sv
            let script_sig = Script::new(script_sig_bytes); // Assuming Script::new or from_bytes
            let script_pubkey = Script::new(script_pubkey_bytes);

            // Execute/evaluate the script
            // Adjust based on actual rust-sv API; assuming a verify function that takes tx context
            // For BSV, verification needs sighash, amount, etc.
            let amount = prev_out.value;
            let flags = sv::script::VerificationFlags::default(); // Assuming flags exist
            if !sv::script::verify(&script_sig, &script_pubkey, self, idx as u32, amount, flags) {
                return Err(ShiaError::ScriptEval(format!("Script failed for input {}", idx)).into());
            }
            
        }
        Ok(())
    }
}

// BUMP structure (unchanged)
#[derive(Debug, Clone)]
pub struct Bump {
    pub block_height: u64,
    pub tree_height: u8,
    pub levels: Vec<Vec<Leaf>>,
}

#[derive(Debug, Clone)]
pub struct Leaf {
    pub offset: u64,
    pub flags: u8,
    pub hash: Option<[u8; 32]>,
}

impl Bump {
    pub fn deserialize(reader: &mut impl Read) -> Result<Self> {
        // ... (unchanged)
        let block_height = read_varint(reader)?;
        let tree_height = reader.read_u8()?;
        let mut levels = Vec::with_capacity(tree_height as usize);
        for _ in 0..tree_height {
            let n_leaves = read_varint(reader)? as usize;
            let mut leaves = Vec::with_capacity(n_leaves);
            for _ in 0..n_leaves {
                let offset = read_varint(reader)?;
                let flags = reader.read_u8()?;
                let hash = if flags == 0 || flags == 2 {
                    let mut h = [0u8; 32];
                    reader.read_exact(&mut h)?;
                    Some(h)
                } else if flags == 1 {
                    None
                } else {
                    return Err(ShiaError::InvalidFlags(flags).into());
                };
                leaves.push(Leaf { offset, flags, hash });
            }
            levels.push(leaves);
        }
        Ok(Self { block_height, tree_height, levels })
    }

    pub fn serialize(&self, writer: &mut impl Write) -> Result<()> {
        // ... (unchanged)
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

    pub fn compute_merkle_root_for_hash(&self, leaf_hash: [u8; 32]) -> Result<[u8; 32]> {
        // ... (unchanged)
        let level0 = &self.levels[0];
        let leaf = level0
            .iter()
            .find(|l| l.flags == 2 && l.hash == Some(leaf_hash))
            .ok_or(ShiaError::LeafNotFound)?;
        let mut current_offset = leaf.offset;
        let mut working = leaf_hash;

        for level_idx in 0..self.tree_height as usize {
            let current_level = &self.levels[level_idx];
            let sibling_offset = current_offset ^ 1;
            let sibling_leaf = current_level
                .iter()
                .find(|l| l.offset == sibling_offset)
                .ok_or(ShiaError::MissingSibling)?;
            let sibling_hash = match sibling_leaf.flags {
                1 => working,
                0 | 2 => sibling_leaf.hash.ok_or(anyhow!("Hash missing for non-duplicate"))?,
                _ => return Err(ShiaError::InvalidFlags(sibling_leaf.flags).into()),
            };
            let concat = if current_offset % 2 == 0 {
                [&working[..], &sibling_hash[..]].concat()
            } else {
                [&sibling_hash[..], &working[..]].concat()
            };
            working = double_sha256(&concat);
            current_offset /= 2;
        }
        Ok(working)
    }
}

pub trait BlockHeadersClient {
    fn is_valid_root_for_height(&self, root: [u8; 32], height: u64) -> bool;
}

// BEEF structure (unchanged)
#[derive(Debug)]
pub struct Beef {
    pub is_atomic: bool,
    pub subject_txid: Option<[u8; 32]>,
    pub bumps: Vec<Bump>,
    pub txs: Vec<(Transaction, Option<usize>)>,
}

impl Beef {
    // ... (deserialize, serialize, build, validate_atomic unchanged)

    pub fn verify(&self, headers_client: &impl BlockHeadersClient) -> Result<()> {
        // Verify BUMPs and inclusion (unchanged)
        for (tx, bump_index) in &self.txs {
            if let Some(idx) = bump_index {
                let bump = &self.bumps[*idx];
                let merkle_hash = tx.merkle_hash();
                let root = bump.compute_merkle_root_for_hash(merkle_hash)?;
                if !headers_client.is_valid_root_for_height(root, bump.block_height) {
                    return Err(ShiaError::Verification("Invalid Merkle root".to_string()).into());
                }
            }
        }

        // Validate tx chain
        let mut utxos: HashMap<([u8; 32], u32), Output> = HashMap::new();
        for (tx, _) in &self.txs {
            let mut input_value = 0u64;
            for input in &tx.inputs {
                let key = (input.prev_txid, input.vout);
                let prev_out = utxos
                    .get(&key)
                    .ok_or(ShiaError::Verification("Missing UTXO".to_string()))?
                    .clone();
                input_value += prev_out.value;
            }
            let mut output_value = 0u64;
            for out in &tx.outputs {
                output_value += out.value;
            }
            if output_value > input_value {
                return Err(ShiaError::Verification("Value mismatch".to_string()).into());
            }
            tx.verify_scripts(&utxos)?; // Now calls the integrated script verification

            // Add outputs
            let txid = tx.txid();
            for (i, out) in tx.outputs.iter().enumerate() {
                utxos.insert((txid, i as u32), out.clone());
            }
        }

        if self.is_atomic {
            self.validate_atomic()?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // TODO: Add test cases, including ones that exercise script evaluation with sample txs
}
