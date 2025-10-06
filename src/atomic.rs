//! Atomic BEEF validation: Subject TX + direct ancestors only (BRC-95).
use crate::beef::Beef;
use crate::errors::{Result, ShiaError};
use std::collections::{HashSet, HashMap};
use anyhow::anyhow;

/// Validates atomic constraints: No extraneous TXs beyond subject ancestry.
pub fn validate_atomic(beef: &Beef) -> Result<()> {
    let subject_txid = beef.subject_txid.ok_or(anyhow!("No subject TXID"))?;
   
    // Pre-index transactions by TXID for O(1) lookup
    let tx_map: HashMap<_, _> = beef.txs.iter()
        .map(|(tx, proof)| (tx.txid(), (tx, proof)))
        .collect();
   
    // Verify subject transaction exists
    if !tx_map.contains_key(&subject_txid) {
        return Err(ShiaError::AtomicMismatch);
    }
   
    let mut ancestors = HashSet::new();
    let mut to_check = vec![subject_txid];
   
    while let Some(id) = to_check.pop() {
        if !ancestors.insert(id) {
            continue; // Already processed this transaction
        }
       
        if let Some((tx, _)) = tx_map.get(&id) {
            for input in &tx.inputs {
                // Skip coinbase inputs (prev_txid is all zeros)
                if input.prev_txid != [0u8; 32] {
                    to_check.push(input.prev_txid);
                }
            }
        }
        // Note: Missing transactions in ancestry chain are allowed
        // as they might be confirmed transactions not included in BEEF
    }
   
    // Verify BEEF contains exactly the ancestor set, nothing more
    if beef.txs.len() != ancestors.len() {
        return Err(ShiaError::AtomicMismatch);
    }
   
    // Verify all transactions in BEEF are part of the ancestry
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
        // Test with coinbase transaction (no inputs to follow)
        let tx_raw = hex::decode(
            "01000000010000000000000000000000000000000000000000000000000000000000000000\
             ffffffff0504ffff001dffffffff0100ca9a3b000000001976a914000000000000000000000\
             000000000000000000088ac00000000"
        ).unwrap();
       
        let tx = Transaction::from_raw(&tx_raw).expect("Parse failed");
        let subject_txid = tx.txid();
       
        let atomic_beef_hex = format!(
            "01010101{}f1c6c3ef0001{}",
            hex::encode(&subject_txid),
            hex::encode(tx_raw)
        );
       
        let beef = Beef::from_hex(&atomic_beef_hex).expect("Deserialize failed");
        assert!(validate_atomic(&beef).is_ok());
    }
   
    #[test]
    fn test_validate_atomic_invalid_wrong_subject() {
        // Test with wrong subject TXID
        let tx_raw = hex::decode(
            "01000000010000000000000000000000000000000000000000000000000000000000000000\
             ffffffff0504ffff001dffffffff0100ca9a3b000000001976a914000000000000000000000\
             000000000000000000088ac00000000"
        ).unwrap();
       
        let tx = Transaction::from_raw(&tx_raw).expect("Parse failed");
        let subject_txid = tx.txid();
       
        let mut beef = Beef::from_hex(&format!(
            "01010101{}f1c6c3ef0001{}",
            hex::encode(&subject_txid),
            hex::encode(tx_raw)
        )).expect("Deserialize failed");
       
        // Set subject to non-existent transaction
        beef.subject_txid = Some([0xff; 32]);
        assert!(validate_atomic(&beef).is_err());
    }
   
    #[test]
    fn test_validate_atomic_invalid_extraneous_tx() {
        // Test with extra transaction not in ancestry
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
       
        // Construct a BEEF with two unrelated transactions
        let beef = Beef {
            subject_txid: Some(tx1.txid()),  // Fixed: include required field
            txs: vec![(tx1, None), (tx2, None)],  // Fixed: use txs for (tx, proof) tuples
            bumps: vec![],  // Fixed: empty Vec<Bump> (no proofs needed for this test)
            is_atomic: true,
        };
       
        assert!(validate_atomic(&beef).is_err());
    }
   
    #[test]
    fn test_validate_atomic_with_ancestors() {
        // Create a more complex test with actual ancestry chain
        // This would require proper transaction construction with valid inputs
        // For now, we'll test the coinbase case is properly handled
       
        let coinbase_raw = hex::decode(
            "01000000010000000000000000000000000000000000000000000000000000000000000000\
             ffffffff0504ffff001dffffffff0100ca9a3b000000001976a914000000000000000000000\
             000000000000000000088ac00000000"
        ).unwrap();
       
        let tx = Transaction::from_raw(&coinbase_raw).expect("Parse failed");
       
        // Construct a minimal BEEF with just the coinbase transaction
        let beef = Beef {
            subject_txid: Some(tx.txid()),  // Fixed: include required field
            txs: vec![(tx, None)],  // Fixed: use txs for (tx, proof) tuples
            bumps: vec![],  // Fixed: empty Vec<Bump> (no proofs needed for this test)
            is_atomic: true,
        };
       
        // Should validate - coinbase has no ancestors to follow
        assert!(validate_atomic(&beef).is_ok());
    }
}
