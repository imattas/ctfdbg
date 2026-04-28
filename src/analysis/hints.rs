//! Heuristic "hint" detection used by the Register and Stack panels.

use crate::debugger::modules::DebugModule;

pub enum Hint {
    Pointer(u64),
    AsciiString(String),
    Utf16String(String),
    ModuleOffset(String),
    Unknown,
}

pub fn classify_pointer(value: u64, modules: &[DebugModule], read_mem: impl Fn(u64, usize) -> Option<Vec<u8>>) -> Hint {
    if value == 0 { return Hint::Unknown; }
    if let Some(m) = modules.iter().find(|m| m.contains(value)) {
        return Hint::ModuleOffset(format!("{}+0x{:x}", m.name, value - m.base));
    }
    if let Some(bytes) = read_mem(value, 64) {
        if let Some(s) = ascii_string(&bytes) { return Hint::AsciiString(s); }
        if let Some(s) = utf16_string(&bytes) { return Hint::Utf16String(s); }
        return Hint::Pointer(value);
    }
    Hint::Unknown
}

pub fn ascii_string(bytes: &[u8]) -> Option<String> {
    let mut out = String::new();
    for &b in bytes.iter().take(64) {
        if b == 0 {
            return if out.len() >= 4 { Some(out) } else { None };
        }
        if !(0x20..=0x7e).contains(&b) { return None; }
        out.push(b as char);
    }
    if out.len() >= 4 { Some(out) } else { None }
}

pub fn utf16_string(bytes: &[u8]) -> Option<String> {
    if bytes.len() < 8 { return None; }
    let mut out = String::new();
    for chunk in bytes.chunks_exact(2).take(64) {
        let v = u16::from_le_bytes([chunk[0], chunk[1]]);
        if v == 0 { return if out.len() >= 4 { Some(out) } else { None }; }
        if !(0x20..=0x7e).contains(&v) { return None; }
        out.push(v as u8 as char);
    }
    if out.len() >= 4 { Some(out) } else { None }
}
