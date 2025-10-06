//! BSV Transaction structures and parsing.
//! Compatible with `sv` crate for script evaluation.
use crate::errors::{Result, ShiaError};
use crate::utils::double_sha256;
use byteorder::{LittleEndian, ReadBytesExt};
use std::collections::HashMap;
use std::io::{Cursor, Read};
use sv::messages::Tx as SvTx;
use sv::script::{op_codes::OP_CODESEPARATOR, Script as SvScript, TransactionChecker, NO_FLAGS};
use sv::transaction::sighash::SigHashCache;
use sv::util::Serializable;
/// Input for a transaction.
#[derive(Clone, Debug)]
pub struct Input {
    /// Previous TXID (little-endian).
    pub prev_txid: [u8; 32],
    /// Output index.
    pub vout: u32,
    /// ScriptSig (unlock script).
    pub script_sig: Vec<u8>,
    /// Sequence number.
    pub sequence: u32,
}
/// Output for a transaction.
#[derive(Clone, Debug)]
pub struct Output {
    /// Value in satoshis.
    pub value: u64,
    /// ScriptPubkey (lock script).
    pub script_pubkey: Vec<u8>,
}
/// BSV Transaction wrapper: parses raw bytes, computes hashes, verifies scripts.
#[derive(Clone, Debug)]
pub struct Transaction {
    /// Version number.
    pub version: u32,
    /// Inputs.
    pub inputs: Vec<Input>,
    /// Outputs.
    pub outputs: Vec<Output>,
    /// Locktime.
    pub locktime: u32,
    /// Raw serialized bytes.
    pub raw: Vec<u8>,
}
impl Transaction {
    /// Parses a raw transaction from bytes (BSV format).
    /// # Errors
    /// - IO or VarInt errors during deserialization.
    pub fn from_raw(raw: &[u8]) -> Result<Self> {
        let mut local_cursor = Cursor::new(raw);
        let version = local_cursor.read_u32::<LittleEndian>()?;
        let num_inputs = crate::utils::read_varint(&mut local_cursor)? as usize;
        let mut inputs = Vec::with_capacity(num_inputs);
        for _ in 0..num_inputs {
            let mut prev_txid = [0u8; 32];
            local_cursor.read_exact(&mut prev_txid)?;
            prev_txid.reverse(); // To little-endian TXID
            let vout = local_cursor.read_u32::<LittleEndian>()?;
            let script_len = crate::utils::read_varint(&mut local_cursor)? as usize;
            let mut script_sig = vec![0u8; script_len];
            local_cursor.read_exact(&mut script_sig)?;
            let sequence = local_cursor.read_u32::<LittleEndian>()?;
            inputs.push(Input { prev_txid, vout, script_sig, sequence });
        }
        let num_outputs = crate::utils::read_varint(&mut local_cursor)? as usize;
        let mut outputs = Vec::with_capacity(num_outputs);
        for _ in 0..num_outputs {
            let value = local_cursor.read_u64::<LittleEndian>()?;
            let script_len = crate::utils::read_varint(&mut local_cursor)? as usize;
            let mut script_pubkey = vec![0u8; script_len];
            local_cursor.read_exact(&mut script_pubkey)?;
            outputs.push(Output { value, script_pubkey });
        }
        let locktime = local_cursor.read_u32::<LittleEndian>()?;
        let consumed = local_cursor.position() as usize;
        Ok(Self { version, inputs, outputs, locktime, raw: raw[0..consumed].to_vec() })
    }
    /// Computes TXID (double SHA256 of raw, big-endian).
    pub fn txid(&self) -> [u8; 32] {
        double_sha256(&self.raw)
    }
    /// Computes Merkle leaf hash (double SHA256 of raw, big-endian).
    pub fn merkle_hash(&self) -> [u8; 32] {
        double_sha256(&self.raw)
    }
    /// Validates all input scripts against provided previous outputs/UTXOs.
    /// Uses `sv` crate for full BSV script execution (supports P2PKH, multisig, etc.).
    /// Skips coinbase inputs.
    /// # Errors
    /// - [ShiaError::ScriptEval] if any script fails.
    /// - [ShiaError::Verification] if UTXO missing.
    /// # Example
    /// ```
    /// use shia::tx::{Transaction, Output};
    /// use std::collections::HashMap;
    /// use hex;
    ///
    /// // Example coinbase tx (verification skipped for coinbase inputs)
    /// let tx_hex = "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0504ffff001dffffffff0100ca9a3b000000001976a914000000000000000000000000000000000000000088ac00000000";
    /// let tx_raw = hex::decode(tx_hex).unwrap();
    /// let tx = Transaction::from_raw(&tx_raw).unwrap();
    /// let mut prev_outputs = HashMap::new();
    /// let prev_txid = [0u8; 32];
    /// let prev_vout = 0xffffffffu32;
    /// let prev_output = Output {
    ///     value: 1000,
    ///     script_pubkey: vec![],
    /// };
    /// prev_outputs.insert((prev_txid, prev_vout), prev_output);
    /// tx.verify_scripts(&prev_outputs).unwrap();
    /// ```
    pub fn verify_scripts(&self, prev_outputs: &HashMap<([u8; 32], u32), Output>) -> Result<()> {
        let sv_tx = SvTx::read(&mut Cursor::new(&self.raw))
            .map_err(|e| ShiaError::ScriptEval(e.to_string()))?;
        for (idx, input) in self.inputs.iter().enumerate() {
            if input.prev_txid == [0u8; 32] {
                continue; // Skip coinbase
            }
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
            combined_script
                .eval(&mut checker, NO_FLAGS)
                .map_err(|e| ShiaError::ScriptEval(e.to_string()))?;
        }
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;
    use std::collections::HashMap;
    #[test]
    fn test_transaction_from_raw() {
        // Genesis coinbase tx hex
        let raw = hex!("01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4d04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73ffffffff0100f2052a01000000434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000");
        let tx = Transaction::from_raw(&raw).unwrap();
        assert_eq!(tx.version, 1);
        assert_eq!(tx.inputs.len(), 1);
        assert_eq!(tx.inputs[0].prev_txid, [0u8; 32]);
        assert_eq!(tx.inputs[0].vout, 0xffffffff);
        assert_eq!(tx.inputs[0].script_sig.len(), 77);
        assert_eq!(tx.inputs[0].sequence, 0xffffffff);
        assert_eq!(tx.outputs.len(), 1);
        assert_eq!(tx.outputs[0].value, 5_000_000_000u64); // 50 BTC = 5 billion sats
        assert_eq!(tx.outputs[0].script_pubkey.len(), 67);
        assert_eq!(tx.locktime, 0);
        let expected_txid = hex!("3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a");
        assert_eq!(tx.txid(), expected_txid);
    }
    #[test]
    fn transaction_verify_scripts() {
        use secp256k1::{Secp256k1, SecretKey, PublicKey};
        use sv::messages::{OutPoint, TxIn as SvTxIn, TxOut as SvTxOut};
        use sv::script::Script as SvScript;
        use sv::util::{Hash256 as SvHash256, hash160};
        use sv::transaction::sighash::{SIGHASH_ALL, SIGHASH_FORKID};
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
        let sighash_type = SIGHASH_ALL | SIGHASH_FORKID;
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
}
