//! BSV Universal Merkle Paths (BUMPs) for SPV proofs (BRC-74).

use crate::errors::{Result, ShiaError};
use crate::utils::{read_varint, write_varint, double_sha256};
use byteorder::{ReadBytesExt, WriteBytesExt};
use std::io::{Read, Write};
use anyhow::anyhow;

/// Leaf node in a BUMP level.
#[derive(Debug, Clone)]
pub struct Leaf {
    /// Position/offset in the level.
    pub offset: u64,
    /// Flags: 0=unique hash, 1=duplicate (mirror), 2=leaf TX hash.
    pub flags: u8,
    /// Hash value (None for flag=1).
    pub hash: Option<[u8; 32]>,
}

/// BUMP structure: Compact Merkle proof for TX inclusion.
#[derive(Debug, Clone)]
pub struct Bump {
    /// Block height.
    pub block_height: u64,
    /// Merkle tree height (log2 of leaves).
    pub tree_height: u8,
    /// Levels of leaves (bottom-up).
    pub levels: Vec<Vec<Leaf>>,
}

impl Bump {
    /// Deserializes from bytes.
    /// # Errors
    /// - Invalid flags or VarInts.
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

    /// Serializes to bytes.
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
    /// Handles duplicates (flag=1) by mirroring the working hash.
    /// # Errors
    /// - [ShiaError::LeafNotFound] if hash not in level 0.
    /// - [ShiaError::MissingSibling] if path incomplete.
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
                1 => working,  // Mirror
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_bump_compute_merkle_root() {
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
}
