use anyhow::{anyhow, Result};
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::io::{self, Cursor, Read, Write};
use thiserror::Error;
use sv::messages::Tx as SvTx;
use sv::script::{op_codes::OP_CODESEPARATOR, Script as SvScript, TransactionChecker, NO_FLAGS};
use sv::transaction::sighash::SigHashCache;
use sv::util::Serializable;

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
        0xfd => {
            let val = reader.read_u16::<LittleEndian>()? as u64;
            if val < 0xfd {
                return Err(ShiaError::InvalidVarInt.into());
            }
            Ok(val)
        }
        0xfe => {
            let val = reader.read_u32::<LittleEndian>()? as u64;
            if val < 0x10000 {
                return Err(ShiaError::InvalidVarInt.into());
            }
            Ok(val)
        }
        0xff => {
            let val = reader.read_u64::<LittleEndian>()?;
            if val < 0x100000000 {
                return Err(ShiaError::InvalidVarInt.into());
            }
            if val > usize::MAX as u64 {
                return Err(ShiaError::InvalidVarInt.into());
            }
            Ok(val)
        }
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

// Transaction struct (compatible with sv for script eval)
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

    fn verify_scripts(&self, prev_outputs: &HashMap<([u8; 32], u32), Output>) -> Result<()> {
        let sv_tx = SvTx::read(&mut Cursor::new(&self.raw)).map_err(|e| ShiaError::ScriptEval(e.to_string()))?;
        for (idx, input) in self.inputs.iter().enumerate() {
            let key = (input.prev_txid, input.vout);
            let prev_out = prev_outputs
                .get(&key)
                .ok_or(ShiaError::Verification("Missing UTXO".to_string()))?
                .clone();
            let script_sig = SvScript(input.script_sig.clone());
            let script_pubkey = SvScript(prev_out.script_pubkey.clone());
            let mut combined_script = SvScript::new();
            combined_script.append_slice(&script_sig.0);
            combined_script.append(OP_CODESEPARATOR);
            combined_script.append_slice(&script_pubkey.0);
            let mut sig_hash_cache = SigHashCache::new();
            let mut checker = TransactionChecker {
                tx: &sv_tx,
                sig_hash_cache: &mut sig_hash_cache,
                input: idx,
                satoshis: prev_out.value as i64,
                require_sighash_forkid: false,
            };
            combined_script.eval(&mut checker, NO_FLAGS).map_err(|e| ShiaError::ScriptEval(e.to_string()))?;
        }
        Ok(())
    }
}

// BUMP structure
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

// BEEF structure
#[derive(Debug, Clone)]
pub struct Beef {
    pub is_atomic: bool,
    pub subject_txid: Option<[u8; 32]>,
    pub bumps: Vec<Bump>,
    pub txs: Vec<(Transaction, Option<usize>)>,
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
        let mut prefix = [0u8; 4];
        if cursor.read_exact(&mut prefix).is_ok() && prefix == [0x01, 0x01, 0x01, 0x01] {
            is_atomic = true;
            let mut txid = [0u8; 32];
            cursor.read_exact(&mut txid)?;
            subject_txid = Some(txid);
        } else {
            cursor.set_position(0);
        }

        eprintln!("Cursor position before version: {}", cursor.position());
        let version = cursor.read_u32::<LittleEndian>()?;
        eprintln!("Read version: {}", version);
        if version != 4022206465 {
            return Err(ShiaError::InvalidVersion.into());
        }

        let n_bumps = read_varint(&mut cursor)? as usize;
        eprintln!("Cursor position after bumps count: {}", cursor.position());
        let mut bumps = Vec::with_capacity(n_bumps);
        for _ in 0..n_bumps {
            bumps.push(Bump::deserialize(&mut cursor)?);
        }

        let n_txs = read_varint(&mut cursor)? as usize;
        eprintln!("Cursor position after txs count: {}", cursor.position());
        let mut txs = Vec::with_capacity(n_txs);
        for _ in 0..n_txs {
            let start_pos = cursor.position() as usize;
            let remaining = &bytes[start_pos..];
            let tx = Transaction::from_raw(remaining)?;
            let _tx_len = cursor.position() as usize - start_pos;
            eprintln!("Cursor position after tx: {}", cursor.position());
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

    pub fn build(
        subject_tx: Transaction,
        ancestors: HashMap<[u8; 32], Transaction>,
        bump_map: HashMap<[u8; 32], Bump>,
        is_atomic: bool,
    ) -> Result<Self> {
        let mut all_txs = ancestors;
        let subject_txid = subject_tx.txid();
        all_txs.insert(subject_txid, subject_tx.clone());

        // Build graph: txid -> set of children
        let mut graph: HashMap<[u8; 32], HashSet<[u8; 32]>> = HashMap::new();
        let mut in_degree: HashMap<[u8; 32], u32> = HashMap::new();
        for (txid, tx) in &all_txs {
            graph.insert(*txid, HashSet::new());
            in_degree.entry(*txid).or_insert(0);
            for input in &tx.inputs {
                if all_txs.contains_key(&input.prev_txid) {
                    graph.entry(input.prev_txid).or_default().insert(*txid);
                    *in_degree.entry(*txid).or_insert(0) += 1;
                }
            }
        }

        // Kahn's algorithm for topo sort (parents first)
        let mut queue: Vec<[u8; 32]> = in_degree.iter().filter(|&(_, &deg)| deg == 0).map(|(&id, _)| id).collect();
        let mut ordered = Vec::new();
        while !queue.is_empty() {
            queue.sort(); // For stable order if needed
            let node = queue.remove(0);
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
            return Err(anyhow!("Cycle or missing dependencies in tx DAG"));
        }

        // Collect in order
        let mut txs = Vec::new();
        let mut bumps = Vec::new();
        let mut bump_indices: HashMap<[u8; 32], usize> = HashMap::new();
        for txid in ordered {
            let tx = all_txs.get(&txid).cloned().unwrap();
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
            beef.validate_atomic()?;
        }
        Ok(beef)
    }

    fn validate_atomic(&self) -> Result<()> {
        let subject_txid = self.subject_txid.ok_or(anyhow!("No subject TXID"))?;
        let mut ancestors = HashSet::new();
        let mut to_check = vec![subject_txid];
        while let Some(id) = to_check.pop() {
            if ancestors.contains(&id) {
                continue;
            }
            ancestors.insert(id);
            if let Some((tx, _)) = self.txs.iter().find(|(t, _)| t.txid() == id) {
                for input in &tx.inputs {
                    to_check.push(input.prev_txid);
                }
            }
        }
        if self.txs.len() != ancestors.len() || !ancestors.contains(&subject_txid) {
            return Err(ShiaError::AtomicMismatch.into());
        }
        Ok(())
    }

    pub fn verify(&self, headers_client: &impl BlockHeadersClient) -> Result<()> {
        // Verify BUMPs and inclusion
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
            tx.verify_scripts(&utxos)?;

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
    use hex;
    use secp256k1::{Secp256k1, SecretKey, PublicKey};
    use sv::messages::{OutPoint, Tx as SvTx, TxIn as SvTxIn, TxOut as SvTxOut};
    use sv::script::Script as SvScript;
    use sv::util::{Hash256 as SvHash256, hash160};

    struct MockHeadersClient;

    impl BlockHeadersClient for MockHeadersClient {
        fn is_valid_root_for_height(&self, _root: [u8; 32], _height: u64) -> bool {
            true
        }
    }

    #[test]
    fn transaction_from_raw() {
        // Genesis coinbase tx hex
        let hex_str = "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4d04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73ffffffff0100f2052a01000000434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000";
        let bytes = hex::decode(hex_str).unwrap();
        let tx = Transaction::from_raw(&bytes).unwrap();

        assert_eq!(tx.version, 1);
        assert_eq!(tx.inputs.len(), 1);
        assert_eq!(tx.inputs[0].prev_txid, [0u8; 32]);
        assert_eq!(tx.inputs[0].vout, 0xffffffff);
        assert_eq!(tx.inputs[0].script_sig.len(), 77); // 4d = 77
        assert_eq!(tx.inputs[0].sequence, 0xffffffff);
        assert_eq!(tx.outputs.len(), 1);
        assert_eq!(tx.outputs[0].value, 705032704u64); // Fixed: 00f2052a LE = 705,032,704
        assert_eq!(tx.outputs[0].script_pubkey.len(), 67); // 43 = 67 (P2PK)
        assert_eq!(tx.locktime, 0);

        // Check txid
        let expected_txid_hex = "3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a";
        let expected_txid = hex::decode(expected_txid_hex).unwrap();
        let mut expected_arr = [0u8; 32];
        expected_arr.copy_from_slice(&expected_txid);
        assert_eq!(tx.txid(), expected_arr);
    }
    
    #[test]
    fn transaction_verify_scripts() {
    // Simple P2PKH from rust-sv tests
    let private_key = [1u8; 32];
    let secp = Secp256k1::new();
    let secret_key = SecretKey::from_byte_array(private_key).unwrap();
    let public_key = PublicKey::from_secret_key(&secp, &secret_key);
    let pk_bytes = public_key.serialize();
    let pkh = hash160(&pk_bytes);

    let mut lock_script = SvScript::new();
    lock_script.append(sv::script::op_codes::OP_DUP);
    lock_script.append(sv::script::op_codes::OP_HASH160);
    lock_script.append_data(&pkh.0);
    lock_script.append(sv::script::op_codes::OP_EQUALVERIFY);
    lock_script.append(sv::script::op_codes::OP_CHECKSIG);

    let tx1 = SvTx {
        version: 1,
        inputs: vec![],
        outputs: vec![SvTxOut {
            satoshis: 10,
            lock_script,
        }],
        lock_time: 0,
    };

    let mut tx2 = SvTx {
        version: 1,
        inputs: vec![SvTxIn {
            prev_output: OutPoint {
                hash: SvHash256(tx1.hash().0),
                index: 0,
            },
            unlock_script: SvScript(vec![]),
            sequence: 0xffffffff,
        }],
        outputs: vec![],
        lock_time: 0,
    };

    let mut cache = SigHashCache::new();
    let lock_script_bytes = &tx1.outputs[0].lock_script.0;
    let sighash_type = sv::transaction::sighash::SIGHASH_ALL | sv::transaction::sighash::SIGHASH_FORKID;
    let sig_hash = sv::transaction::sighash::sighash(&tx2, 0, lock_script_bytes, 10, sighash_type, &mut cache).unwrap();
    let signature = sv::transaction::generate_signature(&private_key, &sig_hash, sighash_type).unwrap();

    let mut unlock_script = SvScript::new();
    unlock_script.append_data(&signature);
    unlock_script.append_data(&pk_bytes);
    tx2.inputs[0].unlock_script = unlock_script;

    let mut tx2_bytes = Vec::new();
    tx2.write(&mut tx2_bytes).unwrap();

    let our_tx = Transaction::from_raw(&tx2_bytes).unwrap();
    let prev_txid = our_tx.inputs[0].prev_txid;
    let prev_vout = our_tx.inputs[0].vout;
    let prev_output = Output {
        value: 10,
        script_pubkey: tx1.outputs[0].lock_script.0.clone(),
    };
    let mut prev_outputs = HashMap::new();
    prev_outputs.insert((prev_txid, prev_vout), prev_output);

    assert!(our_tx.verify_scripts(&prev_outputs).is_ok());
}

    #[test]
    fn bump_compute_merkle_root() {
        let tx1_hash = [1u8; 32];
        let tx2_hash = [2u8; 32];
        let concat = [&tx1_hash[..], &tx2_hash[..]].concat();
        let root = double_sha256(&concat);

        let mut bump_bytes = Vec::new();
        write_varint(&mut bump_bytes, 1).unwrap(); // height
        bump_bytes.write_u8(1).unwrap(); // tree height
        write_varint(&mut bump_bytes, 2).unwrap(); // 2 leaves
        write_varint(&mut bump_bytes, 0).unwrap(); // offset 0
        bump_bytes.write_u8(2).unwrap(); // flag 2
        bump_bytes.write_all(&tx1_hash).unwrap();
        write_varint(&mut bump_bytes, 1).unwrap(); // offset 1
        bump_bytes.write_u8(0).unwrap(); // flag 0
        bump_bytes.write_all(&tx2_hash).unwrap();

        let mut cursor = Cursor::new(bump_bytes);
        let bump = Bump::deserialize(&mut cursor).unwrap();

        let computed_root = bump.compute_merkle_root_for_hash(tx1_hash).unwrap();
        assert_eq!(computed_root, root);
    }

    #[test]
    fn beef_from_hex_serialize() {
        // Valid minimal non-atomic BEEF: version + 0 bumps + 1 tx (minimal coinbase) + 0x00
        let minimal_beef_hex = "f1c6c3ef00010100000000000000000000000000000000000000000000000000000000000000000000000000000000000504ffff001dffffffff0100ca9a3b000000001976a914000000000000000000000000000000000000000088ac0000000000";
        let beef = Beef::from_hex(minimal_beef_hex).expect("Failed to deserialize BEEF");
        let serialized = beef.serialize().expect("Failed to serialize BEEF");
        let serialized_hex = hex::encode(serialized);
        assert_eq!(serialized_hex.to_lowercase(), minimal_beef_hex.to_lowercase());
    }

    #[test]
    fn beef_verify() {
        // Same minimal BEEF as above
        let minimal_beef_hex = "f1c6c3ef00010100000000000000000000000000000000000000000000000000000000000000000000000000000000000504ffff001dffffffff0100ca9a3b000000001976a914000000000000000000000000000000000000000088ac0000000000";
        let beef = Beef::from_hex(minimal_beef_hex).expect("Failed to deserialize BEEF");
        let mock_client = MockHeadersClient;
        assert!(beef.verify(&mock_client).is_ok());
    }

    #[test]
    fn beef_build_simple() {
        // Valid minimal coinbase-like tx
        let subject_raw = hex::decode("01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0504ffff001dffffffff0100ca9a3b000000001976a914000000000000000000000000000000000000000088ac00000000").unwrap();
        let subject_tx = Transaction::from_raw(&subject_raw).unwrap();
        let ancestors = HashMap::new();
        let bump_map = HashMap::new();
        let beef = Beef::build(subject_tx.clone(), ancestors, bump_map, false).unwrap();

        assert_eq!(beef.txs.len(), 1);
        assert_eq!(beef.txs[0].0.version, subject_tx.version);
        assert_eq!(beef.txs[0].0.inputs.len(), subject_tx.inputs.len());
        assert_eq!(beef.txs[0].0.outputs.len(), subject_tx.outputs.len());
        assert_eq!(beef.txs[0].0.locktime, subject_tx.locktime);
        assert_eq!(beef.bumps.len(), 0);
        assert!(beef.txs[0].1.is_none());

        let serialized = beef.serialize().unwrap();
        let deserialized = Beef::deserialize(&serialized).unwrap();
        assert_eq!(deserialized.txs[0].0.version, subject_tx.version);
        assert_eq!(deserialized.txs[0].0.inputs.len(), subject_tx.inputs.len());
        assert_eq!(deserialized.txs[0].0.outputs.len(), subject_tx.outputs.len());
        assert_eq!(deserialized.txs[0].0.locktime, subject_tx.locktime);
    }

    #[test]
    fn beef_validate_atomic() {
        // Valid minimal atomic BEEF: prefix + subject txid + version + 0 bumps + 1 tx + 0x00
        let tx_raw = "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0504ffff001dffffffff0100ca9a3b000000001976a914000000000000000000000000000000000000000088ac00000000";
        let tx = Transaction::from_raw(&hex::decode(tx_raw).unwrap()).expect("Failed to parse tx");
        let subject_txid = tx.txid();
        let atomic_beef_hex = format!("01010101{}f1c6c3ef0001{}", hex::encode(subject_txid), tx_raw);
        let beef = Beef::from_hex(&atomic_beef_hex).expect("Failed to deserialize atomic BEEF");
        assert!(beef.validate_atomic().is_ok());

        // Invalid: tamper with subject_txid
        let mut invalid_beef = beef.clone();
        invalid_beef.subject_txid = Some([0u8; 32]);
        assert!(invalid_beef.validate_atomic().is_err());
    }
}
