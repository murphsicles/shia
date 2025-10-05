//! Atomic BEEF validation: Subject TX + direct ancestors only (BRC-95).

use crate::beef::Beef;
use crate::errors::{Result, ShiaError};
use std::collections::HashSet;
use anyhow::anyhow;

/// Validates atomic constraints: No extraneous TXs beyond subject ancestry.
pub fn validate_atomic(beef: &Beef) -> Result<()> {
    let subject_txid = beef.subject_txid.ok_or(anyhow!("No subject TXID"))?;
    let mut ancestors = HashSet::new();
    let mut to_check = vec![subject_txid];
    while let Some(id) = to_check.pop() {
        if !ancestors.insert(id) {
            continue;
        }
        if let Some((tx, _)) = beef.txs.iter().find(|(t, _)| t.txid() == id) {
            for input in &tx.inputs {
                to_check.push(input.prev_txid);
            }
        }
    }
    if beef.txs.len() != ancestors.len() || !ancestors.contains(&subject_txid) {
        return Err(ShiaError::AtomicMismatch);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::beef::Beef;
    use crate::tx::Transaction;
    use hex;

    #[test]
    fn test_validate_atomic_valid() {
        let tx_raw = hex::decode("01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0504ffff001dffffffff0100ca9a3b000000001976a914000000000000000000000000000000000000000088ac00000000").unwrap();
        let tx = Transaction::from_raw(&tx_raw).expect("Parse failed");
        let subject_txid = tx.txid();
        let atomic_beef_hex = format!("01010101{}efc3c6f10001{}", hex::encode(&subject_txid), hex::encode(tx_raw));
        let beef = Beef::from_hex(&atomic_beef_hex).expect("Deserialize failed");
        assert!(validate_atomic(&beef).is_ok());
    }

    #[test]
    fn test_validate_atomic_invalid() {
        let tx_raw = hex::decode("01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0504ffff001dffffffff0100ca9a3b000000001976a914000000000000000000000000000000000000000088ac00000000").unwrap();
        let tx = Transaction::from_raw(&tx_raw).expect("Parse failed");
        let subject_txid = tx.txid();
        let mut beef = Beef::from_hex(&format!("01010101{}efc3c6f10001{}", hex::encode(&subject_txid), hex::encode(tx_raw))).expect("Deserialize failed");
        beef.subject_txid = Some([0u8; 32]);  // Tamper
        assert!(validate_atomic(&beef).is_err());
    }
}
