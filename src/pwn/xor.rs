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

/// Hamming (bitwise) distance between two equal-length buffers.
pub fn hamming(a: &[u8], b: &[u8]) -> u32 {
    a.iter().zip(b).map(|(x, y)| (x ^ y).count_ones()).sum()
}

/// Score a buffer's resemblance to English text in `[0.0, 1.0]`.
///
/// Combines printable fraction with letter/space frequency, which separates
/// genuine plaintext from merely-printable noise far better than printability
/// alone — the difference that makes repeating-key XOR breaking reliable.
pub fn score_english(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut printable = 0usize;
    let mut freq = 0.0f64;
    for &b in data {
        if matches!(b, 0x20..=0x7E | b'\n' | b'\r' | b'\t') {
            printable += 1;
        } else {
            // Control/binary bytes are a strong signal of wrong key.
            freq -= 4.0;
        }
        let c = b.to_ascii_lowercase();
        freq += match c {
            b' ' => 13.0,
            b'e' => 12.7,
            b't' => 9.0,
            b'a' => 8.2,
            b'o' => 7.5,
            b'i' => 7.0,
            b'n' => 6.7,
            b's' | b'h' | b'r' => 6.0,
            b'd' | b'l' => 4.0,
            other if other.is_ascii_lowercase() => 2.0,
            other if other.is_ascii_digit() => 0.5,
            _ => -0.5,
        };
    }
    let printable_frac = printable as f64 / data.len() as f64;
    let freq_norm = (freq / (data.len() as f64 * 13.0)).clamp(0.0, 1.0);
    0.5 * printable_frac + 0.5 * freq_norm
}

/// Single-byte XOR brute force scored by [`score_english`].
/// Returns `(best_key, decoded, score)`.
pub fn xor_brute_single_english(data: &[u8]) -> (u8, Vec<u8>, f64) {
    let mut best = (0u8, data.to_vec(), f64::MIN);
    for k in 0u8..=255 {
        let dec = xor_byte(data, k);
        let score = score_english(&dec);
        if score > best.2 {
            best = (k, dec, score);
        }
    }
    best
}

/// Rank candidate repeating-XOR key sizes by normalised Hamming distance.
///
/// Classic Vigenère/Kreukel keysize detection: the correct key length
/// minimises the average bit-distance between adjacent key-sized blocks.
/// Returns `(keysize, normalised_distance)` sorted best-first.
pub fn rank_keysizes(data: &[u8], max_keysize: usize) -> Vec<(usize, f64)> {
    let max = max_keysize.min(data.len() / 4).max(1);
    let mut scored = Vec::new();
    for ks in 2..=max {
        // Average distance over as many block pairs as we can afford.
        let blocks = (data.len() / ks).clamp(2, 8);
        if blocks < 2 {
            continue;
        }
        let mut total = 0u32;
        let mut pairs = 0u32;
        for i in 0..blocks - 1 {
            let a = &data[i * ks..(i + 1) * ks];
            let b = &data[(i + 1) * ks..(i + 2) * ks];
            total += hamming(a, b);
            pairs += 1;
        }
        if pairs == 0 {
            continue;
        }
        let norm = total as f64 / pairs as f64 / ks as f64;
        scored.push((ks, norm));
    }
    scored.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal));
    scored
}

/// Break repeating-key XOR for a known key size by solving each key column
/// independently with single-byte brute force.  Returns `(key, plaintext)`.
pub fn break_repeating_xor(data: &[u8], keysize: usize) -> (Vec<u8>, Vec<u8>) {
    if keysize == 0 {
        return (vec![], data.to_vec());
    }
    let mut key = vec![0u8; keysize];
    for (col, k) in key.iter_mut().enumerate() {
        let column: Vec<u8> = data.iter().skip(col).step_by(keysize).copied().collect();
        let (best, _, _) = xor_brute_single_english(&column);
        *k = best;
    }
    let pt = xor(data, &key);
    (key, pt)
}

/// Reduce a key to its smallest repeating unit (e.g. `b"ICEICE"` -> `b"ICE"`).
/// XOR with the reduced key produces identical output.
pub fn minimal_period(key: &[u8]) -> Vec<u8> {
    let n = key.len();
    for d in 1..=n {
        if n.is_multiple_of(d) && (0..n).all(|i| key[i] == key[i % d]) {
            return key[..d].to_vec();
        }
    }
    key.to_vec()
}

/// Fully-automatic repeating-key XOR break: pick the best key size, solve it,
/// and return `(key, plaintext, score)`.  Tries the top few candidate sizes
/// and, on a tie, prefers the shorter key (collapsed to its minimal period).
pub fn break_repeating_xor_auto(data: &[u8], max_keysize: usize) -> Option<(Vec<u8>, Vec<u8>, f64)> {
    if data.len() < 4 {
        return None;
    }
    // Candidates are ordered by ascending normalised Hamming distance, which
    // is a far more reliable key-size signal than the decoded-plaintext score.
    // We therefore walk them best-first and accept the first that decodes to
    // plausible text, only falling back to the best score if none qualifies.
    let candidates = rank_keysizes(data, max_keysize);
    let mut best: Option<(Vec<u8>, Vec<u8>, f64)> = None;
    for (ks, _) in candidates.into_iter().take(6) {
        let (key, pt) = break_repeating_xor(data, ks);
        let key = minimal_period(&key);
        let score = score_english(&pt);
        if score >= 0.55 {
            return Some((key, pt, score));
        }
        if best.as_ref().map(|b| score > b.2).unwrap_or(true) {
            best = Some((key, pt, score));
        }
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
    #[test] fn breaks_repeating_key() {
        let pt = b"When in the Course of human events it becomes necessary for one people \
                   to dissolve the political bands which have connected them with another";
        let key = b"ICE";
        let ct = xor(pt, key);
        let (rec_key, rec_pt, score) = break_repeating_xor_auto(&ct, 16).unwrap();
        assert_eq!(rec_key, key, "recovered key mismatch (score {score})");
        assert_eq!(rec_pt, pt.to_vec());
    }
}
