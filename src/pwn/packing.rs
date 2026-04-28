//! Endian-aware packing/unpacking helpers (pwntools-style p8/p16/p32/p64).

use crate::error::{DbgError, DbgResult};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Endian { Little, Big }

pub fn p8(v: u8) -> [u8; 1] { [v] }
pub fn p16(v: u16, e: Endian) -> [u8; 2] { match e { Endian::Little => v.to_le_bytes(), Endian::Big => v.to_be_bytes() } }
pub fn p32(v: u32, e: Endian) -> [u8; 4] { match e { Endian::Little => v.to_le_bytes(), Endian::Big => v.to_be_bytes() } }
pub fn p64(v: u64, e: Endian) -> [u8; 8] { match e { Endian::Little => v.to_le_bytes(), Endian::Big => v.to_be_bytes() } }

pub fn u8_(b: &[u8]) -> DbgResult<u8> { take(b, 1).map(|s| s[0]) }
pub fn u16_(b: &[u8], e: Endian) -> DbgResult<u16> {
    let s = take(b, 2)?;
    Ok(match e { Endian::Little => u16::from_le_bytes([s[0], s[1]]),
                 Endian::Big    => u16::from_be_bytes([s[0], s[1]]) })
}
pub fn u32_(b: &[u8], e: Endian) -> DbgResult<u32> {
    let s = take(b, 4)?;
    let arr = [s[0], s[1], s[2], s[3]];
    Ok(match e { Endian::Little => u32::from_le_bytes(arr), Endian::Big => u32::from_be_bytes(arr) })
}
pub fn u64_(b: &[u8], e: Endian) -> DbgResult<u64> {
    let s = take(b, 8)?;
    let mut arr = [0u8; 8];
    arr.copy_from_slice(&s[..8]);
    Ok(match e { Endian::Little => u64::from_le_bytes(arr), Endian::Big => u64::from_be_bytes(arr) })
}

fn take(b: &[u8], n: usize) -> DbgResult<&[u8]> {
    if b.len() < n {
        Err(DbgError::InvalidArgument(format!("need {n} bytes, got {}", b.len())))
    } else { Ok(&b[..n]) }
}
