//! Utility functions: hashing, VarInt read/write.

use crate::errors::Result;
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use sha2::{Digest, Sha256};
use std::io::{Read, Write};

/// Computes double SHA256 hash, used for TXIDs and Merkle trees.
pub fn double_sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let hash1 = hasher.finalize();
    let mut hasher = Sha256::new();
    hasher.update(hash1);
    hasher.finalize().into()
}

/// Reads a compact VarInt (0-9 bytes) from a reader.
/// Enforces BSV encoding rules (e.g., no underflow).
/// # Errors
/// - [ShiaError::InvalidVarInt] if encoding is invalid.
pub fn read_varint<R: Read>(reader: &mut R) -> Result<u64> {
    let mut b = [0u8; 1];
    reader.read_exact(&mut b)?;
    let n = b[0];
    match n {
        0..=0xfc => Ok(n as u64),
        0xfd => {
            let val = reader.read_u16::<LittleEndian>()? as u64;
            if val < 0xfd {
                return Err(crate::errors::ShiaError::InvalidVarInt);
            }
            Ok(val)
        }
        0xfe => {
            let val = reader.read_u32::<LittleEndian>()? as u64;
            if val < 0x10000 {
                return Err(crate::errors::ShiaError::InvalidVarInt);
            }
            Ok(val)
        }
        0xff => {
            let val = reader.read_u64::<LittleEndian>()?;
            if val < 0x100000000 {
                return Err(crate::errors::ShiaError::InvalidVarInt);
            }
            if val > usize::MAX as u64 {
                return Err(crate::errors::ShiaError::InvalidVarInt);
            }
            Ok(val)
        }
    }
}

/// Writes a compact VarInt to a writer.
pub fn write_varint<W: Write>(writer: &mut W, n: u64) -> Result<()> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_read_varint() {
        // Valid VarInts: 1 (0x01), 253 (0xfd 0xfd 0x00), 65535 (0xfd 0xff 0xff), 4294967296 (0xff 0x00 0x00 0x00 0x00 0x01 0x00 0x00 0x00 0x00)
        let data = vec![
            0x01,
            0xfd, 0xfd, 0x00,
            0xfd, 0xff, 0xff,
            0xff, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00
        ];
        let mut cursor = Cursor::new(data);
        assert_eq!(read_varint(&mut cursor).unwrap(), 1);
        assert_eq!(read_varint(&mut cursor).unwrap(), 253);
        assert_eq!(read_varint(&mut cursor).unwrap(), 65535);
        assert_eq!(read_varint(&mut cursor).unwrap(), 4_294_967_296u64);
    }

    #[test]
    fn test_write_varint() {
        let mut buf = Vec::new();
        write_varint(&mut buf, 1).unwrap();
        write_varint(&mut buf, 253).unwrap();
        write_varint(&mut buf, 65535).unwrap();
        write_varint(&mut buf, 4_294_967_296u64).unwrap();
        let expected = vec![
            0x01,
            0xfd, 0xfd, 0x00,
            0xfd, 0xff, 0xff,
            0xff, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00
        ];
        assert_eq!(buf, expected);
    }
}
