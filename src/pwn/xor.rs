//! XOR helpers (pwntools-style).

/// XOR `data` with `key` (key cycles).
pub fn xor(data: &[u8], key: &[u8]) -> Vec<u8> {
    if key.is_empty() { return data.to_vec(); }
    data.iter().enumerate()
        .map(|(i, b)| b ^ key[i % key.len()])
        .collect()
}

/// XOR `data` with a single byte.
pub fn xor_byte(data: &[u8], k: u8) -> Vec<u8> {
    data.iter().map(|b| b ^ k).collect()
}

/// Recover a single-byte key by maximizing printable-ASCII fraction in the
/// decoded plaintext.  Returns `(best_key, decoded_bytes, score)` where
/// `score` is the printable fraction in `[0.0, 1.0]`.
pub fn xor_brute_single(data: &[u8]) -> (u8, Vec<u8>, f64) {
    let mut best = (0u8, data.to_vec(), 0.0_f64);
    for k in 0u8..=255 {
        let dec = xor_byte(data, k);
        let printable = dec.iter().filter(|&&b| matches!(b, 0x20..=0x7E | b'\n' | b'\r' | b'\t')).count();
        let score = if dec.is_empty() { 0.0 } else { printable as f64 / dec.len() as f64 };
        if score > best.2 { best = (k, dec, score); }
    }
    best
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn round_trip() {
        let key = b"abc";
        let pt  = b"hello world";
        let ct  = xor(pt, key);
        assert_eq!(xor(&ct, key), pt);
    }
    #[test] fn brute_recovers_key() {
        // We can't assert which specific key wins (multiple keys may map
        // printable->printable), but the brute-forcer must always pick
        // *some* key whose round-trip yields its own decoded buffer and
        // that buffer must be highly printable.
        let pt = b"this is a quite long printable English plaintext for scoring";
        let key: u8 = 0x42;
        let ct = xor_byte(pt, key);
        let (k, dec, score) = xor_brute_single(&ct);
        assert_eq!(xor_byte(&ct, k), dec);
        assert!(score > 0.9, "expected printable score, got {score}");
    }
}
