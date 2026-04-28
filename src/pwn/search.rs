/// Linear byte search (substring).
pub fn search(haystack: &[u8], needle: &[u8]) -> Vec<usize> {
    if needle.is_empty() || needle.len() > haystack.len() { return vec![]; }
    let mut out = Vec::new();
    let mut i = 0;
    while i + needle.len() <= haystack.len() {
        if &haystack[i..i + needle.len()] == needle {
            out.push(i);
            i += 1;
        } else {
            i += 1;
        }
    }
    out
}

pub fn search_string(haystack: &[u8], needle: &str) -> Vec<usize> {
    search(haystack, needle.as_bytes())
}

/// Search little-endian pointer-sized values.
pub fn search_le_u64(haystack: &[u8], value: u64) -> Vec<usize> {
    search(haystack, &value.to_le_bytes())
}
