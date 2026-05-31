//! Crypto-constant and hash recognition.
//!
//! Reversing crypto routines is far easier once you know *which* primitive
//! you're looking at.  This module scans a buffer for well-known magic
//! constants (AES tables, SHA/MD5 initialisation vectors and round constants,
//! and so on) and identifies hash *strings* by length/charset — the two
//! questions that come up first in any crypto reversing or CTF task.

/// A signature: a named constant fingerprint to scan for.
struct Sig {
    name: &'static str,
    /// Bytes to search for (little- or big-endian agnostic: we search raw).
    needle: &'static [u8],
}

/// A hit from [`scan_constants`].
#[derive(Debug, Clone)]
pub struct ConstHit {
    pub name: &'static str,
    pub offset: usize,
}

// The first bytes of the AES forward S-box (Rijndael) — an unmistakable
// fingerprint present in essentially every software AES implementation.
const AES_SBOX_HEAD: &[u8] = &[
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
];
// AES inverse S-box head.
const AES_INV_SBOX_HEAD: &[u8] = &[
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
];
// SHA-256 initial hash values H0 (big-endian word stream).
const SHA256_H: &[u8] = &[
    0x6a, 0x09, 0xe6, 0x67, 0xbb, 0x67, 0xae, 0x85, 0x3c, 0x6e, 0xf3, 0x72, 0xa5, 0x4f, 0xf5, 0x3a,
];
// SHA-256 first round constants K0..K1 (big-endian).
const SHA256_K: &[u8] = &[
    0x42, 0x8a, 0x2f, 0x98, 0x71, 0x37, 0x44, 0x91,
];
// MD5 first sine-table constant T[1] = 0xd76aa478 (little-endian in code).
const MD5_T1_LE: &[u8] = &[0x78, 0xa4, 0x6a, 0xd7];
// MD5 / SHA-1 A init = 0x67452301 (little-endian).
const MD_A_INIT_LE: &[u8] = &[0x01, 0x23, 0x45, 0x67];
// SHA-1 round constant K0 = 0x5a827999 (big-endian).
const SHA1_K0_BE: &[u8] = &[0x5a, 0x82, 0x79, 0x99];
// CRC32 (IEEE) reversed polynomial table entry 0x100 = 0xedb88320 (LE).
const CRC32_POLY_LE: &[u8] = &[0x20, 0x83, 0xb8, 0xed];
// zlib/deflate header bytes commonly embedded.
const ZLIB_HDR: &[u8] = &[0x78, 0x9c];
// Base64 standard alphabet (presence hints at custom decoders).
const B64_ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

const SIGS: &[Sig] = &[
    Sig { name: "AES forward S-box", needle: AES_SBOX_HEAD },
    Sig { name: "AES inverse S-box", needle: AES_INV_SBOX_HEAD },
    Sig { name: "SHA-256 init (H)", needle: SHA256_H },
    Sig { name: "SHA-256 round const (K)", needle: SHA256_K },
    Sig { name: "MD5 sine table T[1]", needle: MD5_T1_LE },
    Sig { name: "MD5/SHA-1 A init (0x67452301)", needle: MD_A_INIT_LE },
    Sig { name: "SHA-1 round const K0", needle: SHA1_K0_BE },
    Sig { name: "CRC32 IEEE polynomial", needle: CRC32_POLY_LE },
    Sig { name: "zlib/deflate header", needle: ZLIB_HDR },
    Sig { name: "Base64 standard alphabet", needle: B64_ALPHABET },
];

/// Scan `data` for known crypto / encoding constants.
pub fn scan_constants(data: &[u8]) -> Vec<ConstHit> {
    let mut hits = Vec::new();
    for sig in SIGS {
        if sig.needle.len() < 2 || sig.needle.len() > data.len() {
            continue;
        }
        // Naive substring search — fine for the small buffers we scan.
        for off in 0..=data.len() - sig.needle.len() {
            if &data[off..off + sig.needle.len()] == sig.needle {
                hits.push(ConstHit { name: sig.name, offset: off });
                break; // one hit per signature is enough to flag it
            }
        }
    }
    hits
}

/// Identify the likely hash algorithm(s) a hex/Base64 string could represent,
/// based on its length and character set.
pub fn identify_hash(s: &str) -> Vec<&'static str> {
    let t = s.trim();
    let mut out = Vec::new();
    let is_hex = !t.is_empty() && t.bytes().all(|b| b.is_ascii_hexdigit());
    if is_hex {
        match t.len() {
            32 => out.push("MD5 / MD4 / NTLM (128-bit hex)"),
            40 => out.push("SHA-1 (160-bit hex)"),
            56 => out.push("SHA-224"),
            64 => out.push("SHA-256 (256-bit hex)"),
            96 => out.push("SHA-384"),
            128 => out.push("SHA-512 / Whirlpool"),
            8 => out.push("CRC32 / Adler-32 (32-bit hex)"),
            16 => out.push("CRC64 / 64-bit hash"),
            _ => {}
        }
    }
    // bcrypt / common prefixed formats.
    if t.starts_with("$2a$") || t.starts_with("$2b$") || t.starts_with("$2y$") {
        out.push("bcrypt");
    }
    if t.starts_with("$1$") {
        out.push("md5crypt");
    }
    if t.starts_with("$5$") {
        out.push("sha256crypt");
    }
    if t.starts_with("$6$") {
        out.push("sha512crypt");
    }
    if t.starts_with("$argon2") {
        out.push("Argon2");
    }
    if out.is_empty() {
        out.push("unknown (no length/format match)");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_aes_sbox() {
        let mut buf = vec![0u8; 32];
        buf.extend_from_slice(AES_SBOX_HEAD);
        let hits = scan_constants(&buf);
        assert!(hits.iter().any(|h| h.name.contains("AES forward")));
        assert_eq!(hits.iter().find(|h| h.name.contains("AES forward")).unwrap().offset, 32);
    }

    #[test]
    fn identifies_hash_lengths() {
        assert!(identify_hash(&"a".repeat(32))[0].contains("MD5"));
        assert!(identify_hash(&"a".repeat(64))[0].contains("SHA-256"));
        assert!(identify_hash("$2b$12$abc")[0].contains("bcrypt"));
    }
}
