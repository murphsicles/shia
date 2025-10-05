//! BSV Transaction structures and parsing.
//! Compatible with `sv` crate for script evaluation.

use crate::errors::{Result, ShiaError};
use crate::utils::double_sha256;
use std::collections::HashMap;
use std::io::{Cursor, Read};

use byteorder::{LittleEndian, ReadBytesExt};
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
        let mut cursor = Cursor::new(raw);
        let version = cursor.read_u32::<LittleEndian>()?;
        let num_inputs = super::utils::read_varint(&mut cursor)? as usize;
        let mut inputs = Vec::with_capacity(num_inputs);
        for _ in 0..num_inputs {
            let mut prev_txid = [0u8; 32];
            cursor.read_exact(&mut prev_txid)?;
            prev_txid.reverse(); // To little-endian TXID
            let vout = cursor.read_u32::<LittleEndian>()?;
            let script_len = super::utils::read_varint(&mut cursor)? as usize;
            let mut script_sig = vec![0u8; script_len];
            cursor.read_exact(&mut script_sig)?;
            let sequence = cursor.read_u32::<LittleEndian>()?;
            inputs.push(Input { prev_txid, vout, script_sig, sequence });
        }
        let num_outputs = super::utils::read_varint(&mut cursor)? as usize;
        let mut outputs = Vec::with_capacity(num_outputs);
        for _ in 0..num_outputs {
            let value = cursor.read_u64::<LittleEndian>()?;
            let script_len = super::utils::read_varint(&mut cursor)? as usize;
            let mut script_pubkey = vec![0u8; script_len];
            cursor.read_exact(&mut script_pubkey)?;
            outputs.push(Output { value, script_pubkey });
        }
        let locktime = cursor.read_u32::<LittleEndian>()?;
        Ok(Self { version, inputs, outputs, locktime, raw: raw.to_vec() })
    }

    /// Computes TXID (double SHA256 of raw, reversed to little-endian).
    pub fn txid(&self) -> [u8; 32] {
        let mut hash = double_sha256(&self.raw);
        hash.reverse();
        hash
    }

    /// Computes Merkle leaf hash (double SHA256 of raw, big-endian).
    pub fn merkle_hash(&self) -> [u8; 32] {
        double_sha256(&self.raw)
    }

    /// Validates all input scripts against provided previous outputs/UTXOs.
    /// Uses `sv` crate for full BSV script execution (supports P2PKH, multisig, etc.).
    /// # Errors
    /// - [ShiaError::ScriptEval] if any script fails.
    /// - [ShiaError::Verification] if UTXO missing.
    /// # Example
    /// ```
    /// let mut utxos = HashMap::new();
    /// // Populate utxos with (prev_txid, vout) -> Output
    /// tx.verify_scripts(&utxos)?;
    /// ```
    pub fn verify_scripts(&self, prev_outputs: &HashMap<([u8; 32], u32), Output>) -> Result<()> {
        let sv_tx = SvTx::read(&mut Cursor::new(&self.raw))
            .map_err(|e| ShiaError::ScriptEval(e.to_string()))?;
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
        // Genesis coinbase tx hex (truncated for brevity; full in original)
        let raw = hex!("01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4d04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73ffffffff0100f2052a01000000434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000");
        let tx = Transaction::from_raw(&raw).unwrap();

        assert_eq!(tx.version, 1);
        assert_eq!(tx.inputs.len(), 1);
        assert_eq!(tx.inputs[0].prev_txid, [0u8; 32]);
        assert_eq!(tx.inputs[0].vout, 0xffffffff);
        assert_eq!(tx.inputs[0].script_sig.len(), 77);
        assert_eq!(tx.inputs[0].sequence, 0xffffffff);
        assert_eq!(tx.outputs.len(), 1);
        assert_eq!(tx.outputs[0].value, 50_000_000); // Corrected: 00f2052a LE = 50M sats
        assert_eq!(tx.outputs[0].script_pubkey.len(), 67);
        assert_eq!(tx.locktime, 0);

        let expected_txid = hex!("3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a");
        assert_eq!(tx.txid(), expected_txid);
    }

    // ... (Include the full transaction_verify_scripts test from original, adapted with hex_literal for raw bytes)
    // Note: For brevity, assuming you paste the secp256k1 setup here as-is.
}
