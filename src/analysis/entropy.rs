//! Shannon-entropy analysis: packer / encryption detection and high-entropy
//! region location.
//!
//! High byte entropy (close to 8 bits/byte) is the classic signal of packed,
//! compressed, or encrypted data.  These helpers compute entropy globally and
//! per-window so the GUI can flag suspicious regions of a binary.

/// Shannon entropy of a byte buffer in bits per byte (0.0 ..= 8.0).
pub fn shannon(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let len = data.len() as f64;
    let mut h = 0.0;
    for &c in &counts {
        if c == 0 {
            continue;
        }
        let p = c as f64 / len;
        h -= p * p.log2();
    }
    h
}

/// Qualitative label for an entropy value.
pub fn classify(entropy: f64) -> &'static str {
    match entropy {
        e if e >= 7.8 => "encrypted/compressed (very high)",
        e if e >= 7.0 => "likely packed/compressed",
        e if e >= 5.5 => "mixed code/data",
        e if e >= 3.5 => "typical code/text",
        _ => "low (sparse/structured)",
    }
}

#[derive(Debug, Clone)]
pub struct Window {
    pub offset: usize,
    pub len: usize,
    pub entropy: f64,
}

/// Sliding-window entropy. Returns one [`Window`] per `window`-sized chunk
/// (the final chunk may be shorter).
pub fn windows(data: &[u8], window: usize) -> Vec<Window> {
    let window = window.max(1);
    data.chunks(window)
        .enumerate()
        .map(|(i, c)| Window {
            offset: i * window,
            len: c.len(),
            entropy: shannon(c),
        })
        .collect()
}

/// Locate contiguous runs of windows whose entropy exceeds `threshold`
/// (bits/byte).  Useful for spotting embedded packed/encrypted blobs.
pub fn high_entropy_regions(data: &[u8], window: usize, threshold: f64) -> Vec<Window> {
    let mut out = Vec::new();
    let mut run: Option<Window> = None;
    for w in windows(data, window) {
        if w.entropy >= threshold {
            match &mut run {
                Some(r) => r.len += w.len,
                None => run = Some(w),
            }
        } else if let Some(r) = run.take() {
            out.push(recompute(data, r));
        }
    }
    if let Some(r) = run.take() {
        out.push(recompute(data, r));
    }
    out
}

fn recompute(data: &[u8], mut w: Window) -> Window {
    let end = (w.offset + w.len).min(data.len());
    w.entropy = shannon(&data[w.offset..end]);
    w.len = end - w.offset;
    w
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entropy_bounds() {
        assert!(shannon(&[]).abs() < 1e-9);
        assert!(shannon(&[0u8; 256]).abs() < 1e-9); // single symbol -> 0
        let all: Vec<u8> = (0..=255).collect();
        assert!((shannon(&all) - 8.0).abs() < 1e-9); // uniform -> 8 bits
    }

    #[test]
    fn classifies_random_high() {
        let all: Vec<u8> = (0..=255).cycle().take(4096).collect();
        assert!(shannon(&all) > 7.9);
        assert_eq!(classify(8.0), "encrypted/compressed (very high)");
    }
}
