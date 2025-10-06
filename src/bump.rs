//! BSV Universal Merkle Paths (BUMPs) for SPV proofs (BRC-74).
//!
//! BUMPs provide compact, multi-path Merkle proofs for transaction inclusion in BSV blocks.
//! Encoded bottom-up (level 0 = leaves), with flags for efficiency: duplicates mirror the working hash
//! (saving ~32 bytes/level), unique siblings include full hash, leaf tx hashes are client-provided.
//! Supports merging proofs at the same height (union leaves if roots match).
//!
//! ## Structure (Binary Format)
//!
//! - **Block Height**: VarInt (u64, 1-9 bytes): Height of the block.
//! - **Tree Height**: u8 (1 byte): Log2 of leaves (max 64).
//! - **Levels** (bottom-up, tree_height levels):
//!   - **nLeaves**: VarInt (u64, 1-9 bytes): Encoded leaves at this level.
//!   - **Leaves** (for each):
//!     - **Offset**: VarInt (u64, 1-9 bytes): Position in level.
//!     - **Flags**: u8 (1 byte):
//!       - `0`: Unique sibling/branch hash follows (32 bytes).
//!       - `1`: Duplicate—mirror working hash (no bytes).
//!       - `2`: Leaf TX hash (client-provided, 32 bytes).
//!     - **Hash**: [u8; 32] (0 or 32 bytes): If flags 0 or 2.
//!
//! ## Root Computation
//!
//! - Find leaf (flag=2, matching TX hash) in level 0 → get offset.
//! - For each level (0 to tree_height-1):
//!   - Sibling offset = current ^ 1.
//!   - Sibling hash: Mirror working if flag=1; use hash if 0/2.
//!   - Concat: Working left + sibling if even offset; reverse if odd.
//!   - Working = double SHA256(concat); current /= 2.
//! - Final working = Merkle root; verify against block header.
//!
//! ## Examples
//!
//! See `Bump::compute_merkle_root_for_hash` for code.
use crate::errors::{Result, ShiaError};
use crate::utils::{read_varint, write_varint, double_sha256};
use byteorder::{ReadBytesExt, WriteBytesExt};
use std::io::{Read, Write};
use anyhow::anyhow;

/// Leaf node in a BUMP level.
///
/// Represents a position in the Merkle level with optional hash and flag for compactness.
#[derive(Debug, Clone)]
pub struct Leaf {
    /// Position/offset in the level (binary tree index).
    pub offset: u64,
    /// Flags: 0=unique hash (sibling/branch), 1=duplicate (mirror working), 2=leaf TX hash.
    pub flags: u8,
    /// Hash value (None for flag=1; required for 0/2).
    pub hash: Option<[u8; 32]>,
}

/// BUMP structure: Compact Merkle proof for TX inclusion.
///
/// Bottom-up levels (level 0=leaves); supports up to 64-bit trees. Dedups via flags/merging.
#[derive(Debug, Clone)]
pub struct Bump {
    /// Block height containing the TXs.
    pub block_height: u64,
    /// Merkle tree height (log2 of leaves; 0=1 leaf, max 64).
    pub tree_height: u8,
    /// Levels of leaves (bottom-up; len() == tree_height).
    pub levels: Vec<Vec<Leaf>>,
}

impl Bump {
    /// Deserializes from bytes.
    ///
    /// Parses block height, tree height, then levels with leaves/flags/hashes.
    /// Validates flags (0/1/2 only); rejects invalid VarInts/IO.
    ///
    /// # Errors
    /// - `ShiaError::InvalidFlags`: Flag not 0/1/2.
    /// - IO failures (e.g., short reads for hashes).
    /// - VarInt overflows or tree_height > 64.
    pub fn deserialize(reader: &mut impl Read) -> Result<Self> {
        let block_height = read_varint(reader)?;
        let tree_height = reader.read_u8()?;
        if tree_height > 64 {
            return Err(ShiaError::InvalidTreeHeight(tree_height));
        }
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
                    return Err(ShiaError::InvalidFlags(flags));
                };
                leaves.push(Leaf { offset, flags, hash });
            }
            levels.push(leaves);
        }
        Ok(Self { block_height, tree_height, levels })
    }

    /// Serializes to bytes.
    ///
    /// Mirrors deserialize: Height, tree height, levels with offsets/flags/hashes (omitted for flag=1).
    ///
    /// # Errors
    /// - IO failures on write (e.g., VarInt overflow).
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

    /// Computes Merkle root for a given leaf TX hash using the proof path.
    ///
    /// Traverses levels bottom-up: Finds leaf (flag=2 in level 0), computes siblings (offset ^ 1),
    /// mirrors for duplicates (flag=1), concats based on parity (even: working left), double-SHA256s.
    /// Final working hash is the root.
    ///
    /// # Errors
    /// - `ShiaError::LeafNotFound`: No matching flag=2 leaf in level 0.
    /// - `ShiaError::MissingSibling`: Sibling offset not in level.
    /// - `ShiaError::InvalidFlags`: Unexpected flag in sibling.
    /// - Missing hash for non-duplicate leaf.
    ///
    /// # Example
    /// ```
    /// use shia::bump::{Bump, Leaf};
    /// use shia::utils::double_sha256;
    ///
    /// let leaf_hash = [1u8; 32];
    /// let sibling_hash = [2u8; 32];
    /// let expected_root = double_sha256(&[&leaf_hash[..], &sibling_hash[..]].concat());
    ///
    /// let bump = Bump {
    ///     block_height: 1,
    ///     tree_height: 1,
    ///     levels: vec![vec![
    ///         Leaf { offset: 0, flags: 2, hash: Some(leaf_hash) },
    ///         Leaf { offset: 1, flags: 0, hash: Some(sibling_hash) },
    ///     ]],
    /// };
    /// let root = bump.compute_merkle_root_for_hash(leaf_hash).unwrap();
    /// assert_eq!(root, expected_root);
    /// ```
    pub fn compute_merkle_root_for_hash(&self, leaf_hash: [u8; 32]) -> Result<[u8; 32]> {
        if self.levels.is_empty() {
            return Ok(leaf_hash); // Degenerate tree (height=0)
        }
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
                1 => working, // Mirror working hash
                0 | 2 => sibling_leaf.hash.ok_or(anyhow!("Hash missing for non-duplicate"))?,
                _ => return Err(ShiaError::InvalidFlags(sibling_leaf.flags)),
            };
            let concat = if current_offset % 2 == 0 {
                [&working[..], &sibling_hash[..]].concat() // Left: working, right: sibling
            } else {
                [&sibling_hash[..], &working[..]].concat() // Left: sibling, right: working
            };
            working = double_sha256(&concat);
            current_offset /= 2;
        }
        Ok(working)
    }

    /// Merges this BUMP with another at the same height.
    ///
    /// Unions leaves per level if roots match; dedups offsets. Fails if heights/roots differ.
    /// Useful for combining partial proofs from multiple sources.
    ///
    /// # Errors
    /// - Height or root mismatch.
    /// - Overlapping offsets with conflicting hashes/flags.
    pub fn merge(&mut self, other: &Bump) -> Result<()> {
        if self.block_height != other.block_height || self.tree_height != other.tree_height {
            return Err(ShiaError::MergeMismatch("Heights differ"));
        }
        let self_root = self.compute_merkle_root_for_hash([0u8; 32])?; // Dummy leaf for root check
        let other_root = other.compute_merkle_root_for_hash([0u8; 32])?;
        if self_root != other_root {
            return Err(ShiaError::MergeMismatch("Roots differ"));
        }
        for (self_level, other_level) in self.levels.iter_mut().zip(other.levels.iter()) {
            for other_leaf in other_level {
                if let Some(existing) = self_level.iter_mut().find(|l| l.offset == other_leaf.offset) {
                    if existing.flags != other_leaf.flags || existing.hash != other_leaf.hash {
                        return Err(ShiaError::MergeMismatch("Conflicting leaf"));
                    }
                } else {
                    self_level.push(other_leaf.clone());
                }
            }
            self_level.sort_by_key(|l| l.offset); // Maintain order
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    /// Tests root computation for 2-leaf tree (height=1): Leaf at offset 0 (flag=2), sibling at 1 (flag=0).
    #[test]
    fn test_bump_compute_merkle_root() {
        let tx1_hash = [1u8; 32];
        let tx2_hash = [2u8; 32];
        let concat = [&tx1_hash[..], &tx2_hash[..]].concat();
        let root = double_sha256(&concat);
        let mut bump_bytes = Vec::new();
        write_varint(&mut bump_bytes, 1u64).unwrap(); // block height
        bump_bytes.write_u8(1).unwrap(); // tree height
        write_varint(&mut bump_bytes, 2u64).unwrap(); // 2 leaves
        write_varint(&mut bump_bytes, 0u64).unwrap(); // offset 0
        bump_bytes.write_u8(2).unwrap(); // flag 2 (leaf)
        bump_bytes.extend_from_slice(&tx1_hash);
        write_varint(&mut bump_bytes, 1u64).unwrap(); // offset 1
        bump_bytes.write_u8(0).unwrap(); // flag 0 (unique sibling)
        bump_bytes.extend_from_slice(&tx2_hash);
        let mut cursor = Cursor::new(bump_bytes);
        let bump = Bump::deserialize(&mut cursor).unwrap();
        let computed_root = bump.compute_merkle_root_for_hash(tx1_hash).unwrap();
        assert_eq!(computed_root, root);
    }

    /// Tests duplicate flag (flag=1): Mirrors working hash, no sibling hash bytes.
    #[test]
    fn test_bump_duplicate_mirror() {
        let leaf_hash = [1u8; 32];
        let mirrored_concat = [&leaf_hash[..], &leaf_hash[..]].concat();
        let root = double_sha256(&mirrored_concat);
        let mut bump_bytes = Vec::new();
        write_varint(&mut bump_bytes, 1u64).unwrap();
        bump_bytes.write_u8(1).unwrap();
        write_varint(&mut bump_bytes, 1u64).unwrap(); // 1 leaf (duplicate sibling implied)
        write_varint(&mut bump_bytes, 0u64).unwrap(); // offset 0
        bump_bytes.write_u8(2).unwrap(); // flag 2
        bump_bytes.extend_from_slice(&leaf_hash);
        // No sibling leaf—duplicate covers offset 1
        let mut cursor = Cursor::new(bump_bytes);
        let bump = Bump::deserialize(&mut cursor).unwrap();
        let computed_root = bump.compute_merkle_root_for_hash(leaf_hash).unwrap();
        assert_eq!(computed_root, root);
    }

    /// Tests merge: Unions non-conflicting leaves at same height/root.
    #[test]
    fn test_bump_merge() {
        let bump1 = Bump {
            block_height: 1,
            tree_height: 1,
            levels: vec![vec![
                Leaf { offset: 0, flags: 2, hash: Some([1u8; 32]) },
            ]],
        };
        let bump2 = Bump {
            block_height: 1,
            tree_height: 1,
            levels: vec![vec![
                Leaf { offset: 1, flags: 0, hash: Some([2u8; 32]) },
            ]],
        };
        let mut merged = bump1.clone();
        merged.merge(&bump2).unwrap();
        assert_eq!(merged.levels[0].len(), 2);
        assert_eq!(merged.levels[0][0].offset, 0);
        assert_eq!(merged.levels[0][1].offset, 1);
    }

    /// Tests invalid merge: Conflicting leaf.
    #[test]
    fn test_bump_merge_conflict() {
        let bump1 = Bump {
            block_height: 1,
            tree_height: 1,
            levels: vec![vec![
                Leaf { offset: 0, flags: 2, hash: Some([1u8; 32]) },
            ]],
        };
        let bump2 = Bump {
            block_height: 1,
            tree_height: 1,
            levels: vec![vec![
                Leaf { offset: 0, flags: 2, hash: Some([3u8; 32]) }, // Conflict
            ]],
        };
        let mut merged = bump1.clone();
        assert!(merged.merge(&bump2).is_err());
    }
}
