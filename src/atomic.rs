//! Atomic BEEF validation: Subject TX + direct ancestors only (BRC-95).
use crate::beef::Beef;
use crate::errors::{Result, ShiaError};
use std::collections::{HashSet, HashMap};

/// Validates atomic constraints: No extraneous TXs beyond subject ancestry.
pub fn validate_atomic(beef: &Beef) -> Result<()> {
    let subject_txid = beef.subject_txid.ok_or(ShiaError::AtomicMismatch)?;

    // Pre-index transactions by TXID for O(1) lookup
    let tx_map: HashMap<[u8; 32], (&crate::tx::Transaction, &Option<usize>)> = beef.txs.iter()
        .map(|(tx, proof)| (tx.txid(), (tx, proof)))
        .collect();

    // Verify subject transaction exists
    if !tx_map.contains_key(&subject_txid) {
        return Err(ShiaError::AtomicMismatch);
    }

    let mut ancestors = HashSet::new();
    let mut to_check = vec![subject_txid];

    while let Some(id) = to_check.pop() {
        if let Some((tx, _)) = tx_map.get(&id) {
            if !ancestors.insert(*id) {
                continue; // Already processed
            }
            for input in &tx.inputs {
                if input.prev_txid != [0u8; 32] {  // Skip coinbase
                    to_check.push(input.prev_txid);
                }
            }
        }
    }

    // Verify BEEF contains exactly the reached ancestor set
    if beef.txs.len() != ancestors.len() {
        return Err(ShiaError::AtomicMismatch);
    }
    for (tx, _) in &beef.txs {
        if !ancestors.contains(&tx.txid()) {
            return Err(ShiaError::AtomicMismatch);
        }
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
        let tx_raw = hex::decode(
            "01000000010000000000000000000000000000000000000000000000000000000000000000\
             ffffffff0504ffff001dffffffff0100ca9a3b000000001976a914000000000000000000000\
             000000000000000000088ac00000000"
        ).unwrap();

        let tx = Transaction::from_raw(&tx_raw).expect("Parse failed");
        let subject_txid = tx.txid();

        let beef = Beef {
            subject_txid: Some(subject_txid),
            txs: vec![(tx, None)],
            bumps: vec![],
            is_atomic: true,
        };

        assert!(validate_atomic(&beef).is_ok());
    }

    #[test]
    fn test_validate_atomic_invalid_wrong_subject() {
        let tx_raw = hex::decode(
            "01000000010000000000000000000000000000000000000000000000000000000000000000\
             ffffffff0504ffff001dffffffff0100ca9a3b000000001976a914000000000000000000000\
             000000000000000000088ac00000000"
        ).unwrap();

        let tx = Transaction::from_raw(&tx_raw).expect("Parse failed");
        let wrong_txid = [0xff; 32];

        let beef = Beef {
            subject_txid: Some(wrong_txid),
            txs: vec![(tx, None)],
            bumps: vec![],
            is_atomic: true,
        };

        assert!(validate_atomic(&beef).is_err());
    }

    #[test]
    fn test_validate_atomic_invalid_extraneous_tx() {
        let tx1_raw = hex::decode(
            "01000000010000000000000000000000000000000000000000000000000000000000000000\
             ffffffff0504ffff001dffffffff0100ca9a3b000000001976a914000000000000000000000\
             000000000000000000088ac00000000"
        ).unwrap();

        let tx2_raw = hex::decode(
            "01000000010000000000000000000000000000000000000000000000000000000000000000\
             ffffffff0504ffff002dffffffff0100ca9a3b000000001976a914111111111111111111111\
             111111111111111111188ac00000000"
        ).unwrap();

        let tx1 = Transaction::from_raw(&tx1_raw).expect("Parse failed");
        let tx2 = Transaction::from_raw(&tx2_raw).expect("Parse failed");

        let beef = Beef {
            subject_txid: Some(tx1.txid()),
            txs: vec![(tx1, None), (tx2, None)],
            bumps: vec![],
            is_atomic: true,
        };

        assert!(validate_atomic(&beef).is_err());
    }

    #[test]
    fn test_validate_atomic_with_ancestors() {
        let coinbase_raw = hex::decode(
            "01000000010000000000000000000000000000000000000000000000000000000000000000\
             ffffffff0504ffff001dffffffff0100ca9a3b000000001976a914000000000000000000000\
             000000000000000000088ac00000000"
        ).unwrap();

        let tx = Transaction::from_raw(&coinbase_raw).expect("Parse failed");

        let beef = Beef {
            subject_txid: Some(tx.txid()),
            txs: vec![(tx, None)],
            bumps: vec![],
            is_atomic: true,
        };

        assert!(validate_atomic(&beef).is_ok());
    }
}
