//! Indicator / flag extraction.
//!
//! Pulls the artefacts you grep a binary or memory dump for first: CTF flags,
//! URLs, IPv4 addresses, e-mail addresses, and long Base64 blobs.  Implemented
//! with hand-written scanners (no `regex` dependency) over the printable
//! strings in a buffer.

#[derive(Debug, Clone, Default)]
pub struct Iocs {
    pub flags: Vec<String>,
    pub urls: Vec<String>,
    pub ipv4: Vec<String>,
    pub emails: Vec<String>,
    pub base64_blobs: Vec<String>,
}

impl Iocs {
    pub fn is_empty(&self) -> bool {
        self.flags.is_empty()
            && self.urls.is_empty()
            && self.ipv4.is_empty()
            && self.emails.is_empty()
            && self.base64_blobs.is_empty()
    }
    pub fn total(&self) -> usize {
        self.flags.len()
            + self.urls.len()
            + self.ipv4.len()
            + self.emails.len()
            + self.base64_blobs.len()
    }
}

/// Common flag prefixes recognised by [`extract`] when no custom format is set.
pub const DEFAULT_FLAG_PREFIXES: &[&str] = &[
    "flag", "ctf", "key", "FLAG", "CTF", "KEY", "HTB", "picoCTF", "pico", "DUCTF", "uiuctf",
];

/// Extract indicators from a byte buffer.  If `flag_format` is given (e.g.
/// `"picoCTF"`), only `format{...}` is matched; otherwise the default prefix
/// list is used and any `word{...}` is also captured heuristically.
pub fn extract(data: &[u8], flag_format: Option<&str>) -> Iocs {
    let strings = printable_strings(data, 4);
    let mut iocs = Iocs::default();
    for s in &strings {
        find_flags(s, flag_format, &mut iocs.flags);
        find_urls(s, &mut iocs.urls);
        find_ipv4(s, &mut iocs.ipv4);
        find_emails(s, &mut iocs.emails);
        find_b64(s, &mut iocs.base64_blobs);
    }
    dedup(&mut iocs.flags);
    dedup(&mut iocs.urls);
    dedup(&mut iocs.ipv4);
    dedup(&mut iocs.emails);
    dedup(&mut iocs.base64_blobs);
    iocs
}

fn dedup(v: &mut Vec<String>) {
    v.sort();
    v.dedup();
}

/// Extract NUL/non-printable-delimited ASCII strings of at least `min` chars.
pub fn printable_strings(data: &[u8], min: usize) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    for &b in data {
        if matches!(b, 0x20..=0x7E) {
            cur.push(b as char);
        } else {
            if cur.len() >= min {
                out.push(std::mem::take(&mut cur));
            } else {
                cur.clear();
            }
        }
    }
    if cur.len() >= min {
        out.push(cur);
    }
    out
}

fn find_flags(s: &str, fmt: Option<&str>, out: &mut Vec<String>) {
    let bytes = s.as_bytes();
    let mut i = 0;
    while let Some(rel) = s[i..].find('{') {
        let open = i + rel;
        // Walk back to the start of the identifier preceding '{'.
        let mut start = open;
        while start > 0 {
            let c = bytes[start - 1];
            if c.is_ascii_alphanumeric() || c == b'_' {
                start -= 1;
            } else {
                break;
            }
        }
        if let Some(close_rel) = s[open..].find('}') {
            let close = open + close_rel;
            let prefix = &s[start..open];
            let matches = match fmt {
                Some(f) => prefix.eq_ignore_ascii_case(f),
                None => {
                    !prefix.is_empty()
                        && DEFAULT_FLAG_PREFIXES
                            .iter()
                            .any(|p| prefix.eq_ignore_ascii_case(p))
                }
            };
            if matches && close > open {
                out.push(s[start..=close].to_string());
            }
            i = close + 1;
        } else {
            break;
        }
    }
}

fn find_urls(s: &str, out: &mut Vec<String>) {
    for scheme in ["https://", "http://", "ftp://", "ws://", "wss://"] {
        let mut from = 0;
        while let Some(rel) = s[from..].find(scheme) {
            let start = from + rel;
            let end = s[start..]
                .find(|c: char| c.is_whitespace() || c == '"' || c == '\'' || c == '<' || c == '>')
                .map(|e| start + e)
                .unwrap_or(s.len());
            if end - start > scheme.len() {
                out.push(s[start..end].to_string());
            }
            from = end.max(start + 1);
        }
    }
}

fn find_ipv4(s: &str, out: &mut Vec<String>) {
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i].is_ascii_digit() {
            let start = i;
            while i < bytes.len() && (bytes[i].is_ascii_digit() || bytes[i] == b'.') {
                i += 1;
            }
            let cand = &s[start..i];
            if is_ipv4(cand) {
                out.push(cand.to_string());
            }
        } else {
            i += 1;
        }
    }
}

fn is_ipv4(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    parts.len() == 4
        && parts.iter().all(|p| {
            !p.is_empty() && p.len() <= 3 && p.parse::<u16>().map(|n| n <= 255).unwrap_or(false)
        })
}

fn find_emails(s: &str, out: &mut Vec<String>) {
    let bytes = s.as_bytes();
    for (i, &c) in bytes.iter().enumerate() {
        if c != b'@' {
            continue;
        }
        // local part
        let mut start = i;
        while start > 0 && is_local(bytes[start - 1]) {
            start -= 1;
        }
        // domain part
        let mut end = i + 1;
        while end < bytes.len() && is_domain(bytes[end]) {
            end += 1;
        }
        let local = &s[start..i];
        let domain = &s[i + 1..end];
        if !local.is_empty() && domain.contains('.') && !domain.starts_with('.') {
            out.push(format!("{local}@{domain}"));
        }
    }
}

fn is_local(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'%' | b'+' | b'-')
}
fn is_domain(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-')
}

fn find_b64(s: &str, out: &mut Vec<String>) {
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if is_b64(bytes[i]) {
            let start = i;
            while i < bytes.len() && is_b64(bytes[i]) {
                i += 1;
            }
            // require a reasonable length and a 4-char alignment to avoid noise
            if i - start >= 20 && (i - start) % 4 == 0 {
                out.push(s[start..i].to_string());
            }
        } else {
            i += 1;
        }
    }
}

fn is_b64(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_flag() {
        let data = b"junk\x00flag{th15_is_4_t3st}\x00more";
        let i = extract(data, None);
        assert_eq!(i.flags, vec!["flag{th15_is_4_t3st}".to_string()]);
    }

    #[test]
    fn extracts_url_ip_email() {
        let data = b"connect https://evil.example.com/x to 192.168.1.42 admin@example.org";
        let i = extract(data, None);
        assert!(i.urls.iter().any(|u| u.contains("evil.example.com")));
        assert!(i.ipv4.contains(&"192.168.1.42".to_string()));
        assert!(i.emails.contains(&"admin@example.org".to_string()));
    }

    #[test]
    fn custom_flag_format() {
        let data = b"picoCTF{abc} flag{xyz}";
        let i = extract(data, Some("picoCTF"));
        assert_eq!(i.flags, vec!["picoCTF{abc}".to_string()]);
    }

    #[test]
    fn rejects_bad_ipv4() {
        let data = b"version 1.2.3.4567 and 999.1.1.1";
        let i = extract(data, None);
        assert!(i.ipv4.is_empty());
    }
}
