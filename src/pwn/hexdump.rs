//! Hexdump formatter (xxd-style).

use std::fmt::Write;

pub fn hexdump(bytes: &[u8], base: u64) -> String {
    let mut out = String::with_capacity(bytes.len() * 4);
    for (i, chunk) in bytes.chunks(16).enumerate() {
        let addr = base + (i * 16) as u64;
        let _ = write!(out, "{:016x}  ", addr);
        for j in 0..16 {
            if j == 8 { let _ = write!(out, " "); }
            if let Some(b) = chunk.get(j) {
                let _ = write!(out, "{:02x} ", b);
            } else {
                let _ = write!(out, "   ");
            }
        }
        let _ = write!(out, " |");
        for &b in chunk {
            let c = if (0x20..=0x7e).contains(&b) { b as char } else { '.' };
            out.push(c);
        }
        out.push_str("|\n");
    }
    out
}
