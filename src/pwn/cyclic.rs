//! pwntools-compatible cyclic pattern (de Bruijn-style A..Z a..z 0..9 over
//! a default subsequence length of 4).

const DEFAULT_ALPHA: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

/// Generate the standard pwntools-style cyclic pattern of length `n`
/// using subsequence length 4 over the default alphabet.
pub fn cyclic(n: usize) -> Vec<u8> {
    cyclic_with(n, DEFAULT_ALPHA, 4)
}

/// Generate a de Bruijn sequence over `alphabet`, take the first `n` symbols.
/// Mirrors `pwnlib.util.cyclic.cyclic`.
pub fn cyclic_with(n: usize, alphabet: &[u8], subseq_len: usize) -> Vec<u8> {
    let k = alphabet.len();
    let nseq = subseq_len;
    let mut a = vec![0usize; k * nseq];
    let mut sequence: Vec<usize> = Vec::with_capacity(n);

    fn db(t: usize, p: usize, k: usize, n: usize, a: &mut [usize], seq: &mut Vec<usize>, limit: usize) {
        if seq.len() >= limit { return; }
        if t > n {
            if n.is_multiple_of(p) {
                for &x in &a[1..=p] {
                    if seq.len() >= limit { return; }
                    seq.push(x);
                }
            }
        } else {
            a[t] = a[t - p];
            db(t + 1, p, k, n, a, seq, limit);
            for j in (a[t - p] + 1)..k {
                a[t] = j;
                db(t + 1, t, k, n, a, seq, limit);
            }
        }
    }

    db(1, 1, k, nseq, &mut a, &mut sequence, n);
    sequence.into_iter().map(|i| alphabet[i]).collect()
}

/// Find the first index where `needle` appears in the default cyclic
/// pattern. Useful for crash-offset discovery.
pub fn cyclic_find(needle: &[u8]) -> Option<usize> {
    cyclic_find_with(needle, DEFAULT_ALPHA, 4, 0x10_0000)
}

pub fn cyclic_find_with(needle: &[u8], alphabet: &[u8], subseq_len: usize, max_len: usize) -> Option<usize> {
    if needle.is_empty() { return Some(0); }
    let len = needle.len().max(subseq_len);
    let pattern = cyclic_with(max_len, alphabet, len);
    pattern.windows(needle.len()).position(|w| w == needle)
}

/// Convenience: `cyclic_find` for a 4- or 8-byte little-endian integer.
pub fn cyclic_find_int(value: u64, byte_len: usize) -> Option<usize> {
    let bytes: Vec<u8> = value.to_le_bytes()[..byte_len.min(8)].to_vec();
    // Trim trailing zero bytes (often from stack pointers truncated to 4 bytes).
    let trimmed = trim_trailing_zeros(&bytes);
    cyclic_find(trimmed)
}

fn trim_trailing_zeros(b: &[u8]) -> &[u8] {
    let mut end = b.len();
    while end > 1 && b[end - 1] == 0 { end -= 1; }
    &b[..end]
}
