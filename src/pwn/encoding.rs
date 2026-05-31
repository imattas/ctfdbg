//! Self-contained encoders/decoders for the codecs that show up constantly in
//! CTF and reversing work: Base64 (standard + URL-safe), Base32, hex, URL
//! percent-encoding, ROT-N / Caesar, and ASCII85.
//!
//! Everything here is dependency-free (no `base64`/`base32` crates) so the
//! decode logic is auditable and the binary stays lean.

// ----------------------------------------------------------------- Base64 ---

const B64_STD: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const B64_URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

fn b64_encode_with(data: &[u8], alpha: &[u8; 64], pad: bool) -> String {
    let mut out = String::with_capacity((data.len() + 2) / 3 * 4);
    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(alpha[(n >> 18 & 0x3f) as usize] as char);
        out.push(alpha[(n >> 12 & 0x3f) as usize] as char);
        if chunk.len() > 1 {
            out.push(alpha[(n >> 6 & 0x3f) as usize] as char);
        } else if pad {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(alpha[(n & 0x3f) as usize] as char);
        } else if pad {
            out.push('=');
        }
    }
    out
}

pub fn base64_encode(data: &[u8]) -> String {
    b64_encode_with(data, B64_STD, true)
}
pub fn base64url_encode(data: &[u8]) -> String {
    b64_encode_with(data, B64_URL, false)
}

/// Decode standard *or* URL-safe Base64 (auto-detected), tolerating missing
/// padding and embedded whitespace.
pub fn base64_decode(s: &str) -> Option<Vec<u8>> {
    let mut rev = [255u8; 256];
    for (i, &c) in B64_STD.iter().enumerate() {
        rev[c as usize] = i as u8;
    }
    rev[b'-' as usize] = 62; // URL-safe
    rev[b'_' as usize] = 63;
    let mut bits = 0u32;
    let mut nbits = 0u32;
    let mut out = Vec::new();
    for &c in s.as_bytes() {
        if c == b'=' || c.is_ascii_whitespace() {
            continue;
        }
        let v = rev[c as usize];
        if v == 255 {
            return None;
        }
        bits = (bits << 6) | v as u32;
        nbits += 6;
        if nbits >= 8 {
            nbits -= 8;
            out.push((bits >> nbits) as u8);
        }
    }
    Some(out)
}

// ----------------------------------------------------------------- Base32 ---

const B32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

pub fn base32_encode(data: &[u8]) -> String {
    let mut out = String::new();
    for chunk in data.chunks(5) {
        let mut buf = [0u8; 5];
        buf[..chunk.len()].copy_from_slice(chunk);
        let n = (buf[0] as u64) << 32
            | (buf[1] as u64) << 24
            | (buf[2] as u64) << 16
            | (buf[3] as u64) << 8
            | buf[4] as u64;
        let chars = (chunk.len() * 8 + 4) / 5;
        for i in 0..8 {
            if i < chars {
                out.push(B32[((n >> (35 - i * 5)) & 0x1f) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

pub fn base32_decode(s: &str) -> Option<Vec<u8>> {
    let mut rev = [255u8; 256];
    for (i, &c) in B32.iter().enumerate() {
        rev[c as usize] = i as u8;
        rev[c.to_ascii_lowercase() as usize] = i as u8;
    }
    let mut bits = 0u64;
    let mut nbits = 0u32;
    let mut out = Vec::new();
    for &c in s.as_bytes() {
        if c == b'=' || c.is_ascii_whitespace() {
            continue;
        }
        let v = rev[c as usize];
        if v == 255 {
            return None;
        }
        bits = (bits << 5) | v as u64;
        nbits += 5;
        if nbits >= 8 {
            nbits -= 8;
            out.push((bits >> nbits) as u8);
        }
    }
    Some(out)
}

// -------------------------------------------------------------------- Hex ---

pub fn hex_encode(data: &[u8]) -> String {
    data.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn hex_decode(s: &str) -> Option<Vec<u8>> {
    let cleaned: String = s
        .chars()
        .filter(|c| !c.is_whitespace() && *c != ':' && *c != ',')
        .collect();
    let cleaned = cleaned.strip_prefix("0x").unwrap_or(&cleaned);
    if cleaned.len() % 2 != 0 {
        return None;
    }
    hex::decode(cleaned).ok()
}

// ------------------------------------------------------------- URL-encode ---

pub fn url_decode(s: &str) -> Option<Vec<u8>> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'%' if i + 2 < b.len() => {
                let h = (b[i + 1] as char).to_digit(16)?;
                let l = (b[i + 2] as char).to_digit(16)?;
                out.push((h * 16 + l) as u8);
                i += 3;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    Some(out)
}

pub fn url_encode(data: &[u8]) -> String {
    let mut out = String::new();
    for &b in data {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

// ----------------------------------------------------------- ROT-N / Caesar -

/// Rotate ASCII letters by `n` (Caesar cipher). ROT13 is `n == 13`.
pub fn rot_n(data: &[u8], n: u8) -> Vec<u8> {
    let n = n % 26;
    data.iter()
        .map(|&b| match b {
            b'a'..=b'z' => b'a' + (b - b'a' + n) % 26,
            b'A'..=b'Z' => b'A' + (b - b'A' + n) % 26,
            other => other,
        })
        .collect()
}

/// All 26 Caesar rotations, as `(shift, decoded)` pairs.
pub fn rot_all(data: &[u8]) -> Vec<(u8, Vec<u8>)> {
    (0..26).map(|n| (n, rot_n(data, n))).collect()
}

// ----------------------------------------------------------------- ASCII85 --

pub fn ascii85_decode(s: &str) -> Option<Vec<u8>> {
    let s = s.trim().trim_start_matches("<~").trim_end_matches("~>");
    let mut out = Vec::new();
    let mut group = [0u8; 5];
    let mut n = 0usize;
    for c in s.chars() {
        if c.is_whitespace() {
            continue;
        }
        if c == 'z' && n == 0 {
            out.extend_from_slice(&[0, 0, 0, 0]);
            continue;
        }
        if !('!'..='u').contains(&c) {
            return None;
        }
        group[n] = c as u8 - b'!';
        n += 1;
        if n == 5 {
            let mut val = 0u32;
            for &g in &group {
                val = val.checked_mul(85)?.checked_add(g as u32)?;
            }
            out.extend_from_slice(&val.to_be_bytes());
            n = 0;
        }
    }
    if n > 0 {
        for g in group.iter_mut().skip(n) {
            *g = 84;
        }
        let mut val = 0u32;
        for &g in &group {
            val = val.checked_mul(85)?.checked_add(g as u32)?;
        }
        let bytes = val.to_be_bytes();
        out.extend_from_slice(&bytes[..n - 1]);
    }
    Some(out)
}

// ------------------------------------------------------------ auto-decode ---

/// A single decode step that the auto-decoder applied.
#[derive(Debug, Clone)]
pub struct DecodeStep {
    pub codec: &'static str,
    pub output: Vec<u8>,
}

fn looks_textual(data: &[u8]) -> bool {
    !data.is_empty()
        && data
            .iter()
            .filter(|&&b| matches!(b, 0x20..=0x7E | b'\n' | b'\r' | b'\t'))
            .count() as f64
            / data.len() as f64
            > 0.85
}

/// Greedily peel encoding layers off `data`, trying each codec and keeping the
/// first that yields plausible output, until nothing else applies or we hit
/// `max_depth`.  Returns the chain of steps (empty if nothing decoded).
///
/// This is the "just decode it" button: feed it `SFRDe1JFQ0...`-style blobs and
/// it walks Base64 → hex → Base32 → ASCII85 layers automatically.
pub fn auto_decode(data: &[u8], max_depth: usize) -> Vec<DecodeStep> {
    let mut steps = Vec::new();
    let mut cur = data.to_vec();
    for _ in 0..max_depth {
        // Compute the chosen decode in an inner scope so the borrows of `cur`
        // (via the lossy string / closures) are released before we reassign it.
        let chosen: Option<DecodeStep> = {
        let s = String::from_utf8_lossy(&cur);
        let trimmed = s.trim();

        // Each attempt must (a) succeed, (b) materially change the data, and
        // (c) not just produce garbage shorter than a couple of bytes.
        let attempts: [(&'static str, Box<dyn Fn() -> Option<Vec<u8>>>); 6] = [
            ("base64", Box::new(|| {
                if trimmed.len() >= 4 && trimmed.bytes().all(|b| {
                    b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'-' | b'_' | b'=')
                }) { base64_decode(trimmed) } else { None }
            })),
            ("hex", Box::new(|| {
                if trimmed.len() >= 4 && trimmed.len() % 2 == 0
                    && trimmed.bytes().all(|b| b.is_ascii_hexdigit()) {
                    hex_decode(trimmed)
                } else { None }
            })),
            ("base32", Box::new(|| {
                if trimmed.len() >= 8 && trimmed.bytes().all(|b| {
                    matches!(b, b'A'..=b'Z' | b'a'..=b'z' | b'2'..=b'7' | b'=')
                }) { base32_decode(trimmed) } else { None }
            })),
            ("url", Box::new(|| {
                if trimmed.contains('%') { url_decode(trimmed) } else { None }
            })),
            ("ascii85", Box::new(|| {
                if trimmed.starts_with("<~") { ascii85_decode(trimmed) } else { None }
            })),
            ("rot13", Box::new(|| {
                // Only meaningful if it changes the text and improves letters.
                let r = rot_n(trimmed.as_bytes(), 13);
                if r != trimmed.as_bytes() { Some(r) } else { None }
            })),
        ];

        let mut found = None;
        for (codec, f) in attempts {
            if codec == "rot13" {
                // ROT13 never shortens, so only try it as a last resort when
                // the data is already printable and nothing else fired.
                continue;
            }
            if let Some(decoded) = f() {
                if decoded.as_slice() != cur.as_slice() && decoded.len() >= 2 && looks_textual(&decoded) {
                    found = Some(DecodeStep { codec, output: decoded });
                    break;
                }
            }
        }
        found
        };

        match chosen {
            Some(step) => {
                cur = step.output.clone();
                steps.push(step);
            }
            None => break,
        }
    }
    steps
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_round_trip() {
        for s in ["", "f", "fo", "foo", "foob", "fooba", "foobar"] {
            let e = base64_encode(s.as_bytes());
            assert_eq!(base64_decode(&e).unwrap(), s.as_bytes(), "b64 {s:?}");
        }
        assert_eq!(base64_decode("aGVsbG8=").unwrap(), b"hello");
    }

    #[test]
    fn base64url_decodes() {
        let raw = &[0xfb, 0xff, 0xbf];
        let u = base64url_encode(raw);
        assert!(!u.contains('+') && !u.contains('/'));
        assert_eq!(base64_decode(&u).unwrap(), raw);
    }

    #[test]
    fn base32_round_trip() {
        for s in ["", "f", "fo", "foo", "foob", "fooba", "foobar"] {
            let e = base32_encode(s.as_bytes());
            assert_eq!(base32_decode(&e).unwrap(), s.as_bytes(), "b32 {s:?}");
        }
    }

    #[test]
    fn rot13_is_involutive() {
        let s = b"Hello, World!";
        assert_eq!(rot_n(&rot_n(s, 13), 13), s);
    }

    #[test]
    fn url_round_trip() {
        let raw = b"a b&c=/?";
        let e = url_encode(raw);
        assert_eq!(url_decode(&e).unwrap(), raw);
    }

    #[test]
    fn auto_decode_peels_layers() {
        // hex(base64("secret flag here"))
        let inner = base64_encode(b"secret flag here");
        let outer = hex_encode(inner.as_bytes());
        let steps = auto_decode(outer.as_bytes(), 6);
        assert!(steps.len() >= 2, "expected >=2 layers, got {}", steps.len());
        assert_eq!(steps.last().unwrap().output, b"secret flag here");
    }
}
