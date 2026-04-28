//! Auto-analysis: derive higher-level facts from a freshly-loaded binary
//! without running it.  Cheap, deterministic, and safe to run on the GUI
//! thread for typical CTF binary sizes (≤ a few MiB).
//!
//! Currently produces:
//!   * function candidates (entry, exports, prologue scan)
//!   * printable strings (≥ min_len ASCII / UTF-16LE)
//!   * security mitigation summary (already in `BinaryInfo.security`)
//!   * a few high-signal hints (NX off, ASLR off, format-string sinks, etc.)
//!
//! It deliberately avoids any binary rewriting or symbol guessing that
//! could mislead the user; everything here is a *candidate*.

use std::collections::BTreeSet;

use crate::target::binary::BinaryInfo;

#[derive(Debug, Clone, Default)]
pub struct AnalyzedFunction {
    pub address: u64,
    pub name: String,
    pub source: FunctionSource,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FunctionSource {
    #[default] Entry,
    Symbol,
    Export,
    PrologueScan,
}

#[derive(Debug, Clone, Default)]
pub struct AnalyzedString {
    pub address: u64,
    pub bytes: Vec<u8>,
    pub utf16: bool,
}

impl AnalyzedString {
    pub fn as_string_lossy(&self) -> String {
        if self.utf16 {
            let codepoints: Vec<u16> = self.bytes
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect();
            String::from_utf16_lossy(&codepoints)
        } else {
            String::from_utf8_lossy(&self.bytes).into_owned()
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct AutoAnalysis {
    pub functions: Vec<AnalyzedFunction>,
    pub strings: Vec<AnalyzedString>,
    pub hints: Vec<String>,
    pub instruction_count_estimate: usize,
}

/// Run all enabled passes and return the result.  `bytes` is the raw
/// file content (already parsed by `BinaryInfo`); we still need it for
/// linear scans.
pub fn analyze(info: &BinaryInfo, bytes: &[u8]) -> AutoAnalysis {
    let mut out = AutoAnalysis::default();

    out.functions = function_candidates(info, bytes);
    out.strings   = scan_strings(info, bytes, 5);
    out.hints     = mitigation_hints(info, &out);
    out.instruction_count_estimate = estimate_insn_count(info, bytes);

    out
}

/// Best-effort function discovery.
///
/// Sources (deduplicated by address, ordered):
///   1. Entry point.
///   2. Symbols flagged `is_function`.
///   3. Exports (for libraries / DLLs).
///   4. x86/x64 prologue pattern scan over executable sections:
///         55 8B EC                ; push ebp / mov ebp, esp   (i386)
///         55 48 89 E5             ; push rbp / mov rbp, rsp   (x86_64)
///         48 83 EC ??             ; sub rsp, imm8             (x86_64 leaf)
fn function_candidates(info: &BinaryInfo, bytes: &[u8]) -> Vec<AnalyzedFunction> {
    let mut seen: BTreeSet<u64> = BTreeSet::new();
    let mut out: Vec<AnalyzedFunction> = Vec::new();

    let mut push = |addr: u64, name: String, src: FunctionSource,
                    seen: &mut BTreeSet<u64>, out: &mut Vec<AnalyzedFunction>| {
        if addr == 0 { return; }
        if seen.insert(addr) {
            out.push(AnalyzedFunction { address: addr, name, source: src });
        }
    };

    if info.entry_point != 0 {
        push(info.entry_point, "entry".into(), FunctionSource::Entry, &mut seen, &mut out);
    }
    for s in &info.symbols {
        if s.is_function && s.address != 0 {
            push(s.address, s.name.clone(), FunctionSource::Symbol, &mut seen, &mut out);
        }
    }
    for e in &info.exports {
        if e.address != 0 {
            push(e.address, e.name.clone(), FunctionSource::Export, &mut seen, &mut out);
        }
    }

    // Prologue scan over executable sections.
    for sec in &info.sections {
        if !sec.executable { continue; }
        let start = sec.file_offset as usize;
        let end = (sec.file_offset + sec.file_size) as usize;
        if end > bytes.len() || start >= end { continue; }
        let slice = &bytes[start..end];
        for (i, win) in slice.windows(4).enumerate() {
            let va = sec.virtual_address + i as u64;
            // x86_64: 55 48 89 e5 (push rbp; mov rbp, rsp)
            if win == [0x55, 0x48, 0x89, 0xE5] {
                push(va, format!("sub_{va:x}"), FunctionSource::PrologueScan, &mut seen, &mut out);
            }
            // i386: 55 89 e5 ?? (push ebp; mov ebp, esp; ...)
            if win[..3] == [0x55, 0x89, 0xE5] || win[..3] == [0x55, 0x8B, 0xEC] {
                push(va, format!("sub_{va:x}"), FunctionSource::PrologueScan, &mut seen, &mut out);
            }
        }
        // x86_64 leaf: 48 83 EC ?? (sub rsp, imm8)  — only if not already seen.
        for (i, win) in slice.windows(4).enumerate() {
            if win[..3] == [0x48, 0x83, 0xEC] {
                let va = sec.virtual_address + i as u64;
                if !seen.contains(&va) {
                    push(va, format!("sub_{va:x}"), FunctionSource::PrologueScan, &mut seen, &mut out);
                }
            }
        }
    }
    out.sort_by_key(|f| f.address);
    out
}

/// Find printable ASCII and UTF-16LE strings of length >= `min_len`.
pub fn scan_strings(info: &BinaryInfo, bytes: &[u8], min_len: usize) -> Vec<AnalyzedString> {
    let mut out: Vec<AnalyzedString> = Vec::new();

    // Helper: scan one byte slice for ASCII strings and 16-bit-aligned UTF-16LE.
    let scan_section = |sec_va: u64, slice: &[u8], out: &mut Vec<AnalyzedString>| {
        // ASCII
        let mut i = 0;
        while i < slice.len() {
            let mut j = i;
            while j < slice.len() && is_print_ascii(slice[j]) { j += 1; }
            if j - i >= min_len {
                out.push(AnalyzedString {
                    address: sec_va + i as u64,
                    bytes: slice[i..j].to_vec(),
                    utf16: false,
                });
            }
            i = j + 1;
        }
        // UTF-16LE (very rough): every other byte must be 0 and the low byte printable
        let mut i = 0;
        while i + 2 <= slice.len() {
            let mut j = i;
            let mut count = 0;
            while j + 2 <= slice.len()
                && slice[j + 1] == 0
                && is_print_ascii(slice[j])
            {
                j += 2;
                count += 1;
            }
            if count >= min_len {
                out.push(AnalyzedString {
                    address: sec_va + i as u64,
                    bytes: slice[i..j].to_vec(),
                    utf16: true,
                });
                i = j + 2;
            } else {
                i += 2;
            }
        }
    };

    let mut had_section = false;
    for sec in &info.sections {
        let start = sec.file_offset as usize;
        let end = (sec.file_offset + sec.file_size) as usize;
        if end > bytes.len() || start >= end { continue; }
        had_section = true;
        scan_section(sec.virtual_address, &bytes[start..end], &mut out);
    }
    if !had_section {
        // Fallback: scan entire raw file.
        scan_section(info.loaded_image_base, bytes, &mut out);
    }

    // Cap to a reasonable amount so the GUI doesn't choke on huge binaries.
    out.sort_by_key(|s| s.address);
    out.truncate(20_000);
    out
}

fn is_print_ascii(b: u8) -> bool {
    matches!(b, 0x09 | 0x0A | 0x0D | 0x20..=0x7E)
}

fn mitigation_hints(info: &BinaryInfo, anal: &AutoAnalysis) -> Vec<String> {
    let mut hints = Vec::new();
    let s = &info.security;

    if !s.aslr            { hints.push("[!] ASLR disabled — fixed image base, easy to ROP.".into()); }
    if !s.dep_nx          { hints.push("[!] NX/DEP disabled — stack/heap may be executable; shellcode is viable.".into()); }
    if !s.cfg             { hints.push("[~] Control-Flow Guard not present — indirect-call hijacks are unmitigated.".into()); }
    if !s.gs_cookie_hint  { hints.push("[~] No /GS stack-cookie marker found — classic stack overflows likely.".into()); }
    if  s.high_entropy_va { hints.push("[i] High-entropy VA (64-bit ASLR).".into()); }
    if  s.authenticode_signed_hint { hints.push("[i] Binary appears Authenticode-signed.".into()); }

    // Format-string sinks: scan imports for printf-family.
    let fs_sinks = ["printf","fprintf","sprintf","snprintf","vprintf","vfprintf","vsprintf","wprintf"];
    let imported: Vec<&str> = info.imports.iter()
        .map(|i| i.name.as_str())
        .filter(|n| fs_sinks.contains(&n.trim_start_matches('_')))
        .collect();
    if !imported.is_empty() {
        hints.push(format!("[i] Format-string sinks imported: {}", imported.join(", ")));
    }

    // Dangerous libc imports.
    let dangerous = ["gets","strcpy","strcat","sprintf","scanf","system"];
    let imp_dangerous: Vec<&str> = info.imports.iter()
        .map(|i| i.name.as_str())
        .filter(|n| dangerous.contains(&n.trim_start_matches('_')))
        .collect();
    if !imp_dangerous.is_empty() {
        hints.push(format!("[!] Dangerous imports: {}", imp_dangerous.join(", ")));
    }

    if anal.functions.is_empty() {
        hints.push("[?] No functions discovered — try changing architecture or providing symbols.".into());
    } else {
        hints.push(format!("[+] Discovered {} candidate function(s).", anal.functions.len()));
    }
    hints.push(format!("[+] Found {} string(s) (min 5 chars).", anal.strings.len()));
    hints
}

fn estimate_insn_count(info: &BinaryInfo, bytes: &[u8]) -> usize {
    // Average x86/x64 instruction length ~ 3.5 bytes.
    let exec_bytes: u64 = info.sections.iter()
        .filter(|s| s.executable)
        .map(|s| s.file_size.min((bytes.len() as u64).saturating_sub(s.file_offset)))
        .sum();
    (exec_bytes as f64 / 3.5) as usize
}
