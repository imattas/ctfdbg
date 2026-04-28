//! Bundled default plugins.
//!
//! Each plugin is a small, dependency-free wrapper over an existing
//! analysis or `pwn::*` helper.  They're registered automatically by
//! [`crate::plugins::default_plugins`].

use crate::gui::state::AppState;
use crate::plugins::{Plugin, PluginCategory, PluginMeta, PluginOutput};

// ---------------------------------------------------------------- Analysis --

pub struct AutoAnalyzePlugin;
impl Plugin for AutoAnalyzePlugin {
    fn meta(&self) -> PluginMeta {
        PluginMeta {
            id: "auto-analyze",
            name: "Auto Analyze",
            description: "Re-run automatic analysis (functions, strings, hints) on the loaded binary.",
            category: PluginCategory::Analysis,
        }
    }
    fn run(&self, state: &AppState, _arg: Option<&str>) -> PluginOutput {
        let mut out = PluginOutput::default();
        match (state.binary.as_ref(), state.binary_bytes.as_ref()) {
            (Some(info), Some(bytes)) => {
                let a = crate::analysis::auto::analyze(info, bytes);
                out = out.line(format!("[auto] {} functions, {} strings", a.functions.len(), a.strings.len()));
                for h in &a.hints { out = out.line(format!("[auto] {h}")); }
            }
            _ => out = out.line("[!] no binary loaded"),
        }
        out
    }
}

pub struct ChecksecPlugin;
impl Plugin for ChecksecPlugin {
    fn meta(&self) -> PluginMeta {
        PluginMeta {
            id: "checksec",
            name: "Checksec",
            description: "Show binary mitigation summary (ASLR, NX, CFG, /GS, signed).",
            category: PluginCategory::Analysis,
        }
    }
    fn run(&self, state: &AppState, _arg: Option<&str>) -> PluginOutput {
        let mut out = PluginOutput::default();
        let Some(info) = state.binary.as_ref() else {
            return out.line("[!] no binary loaded");
        };
        let s = &info.security;
        let yn = |b: bool| if b { "yes" } else { "no" };
        out = out.line(format!("ASLR:           {}", yn(s.aslr)));
        out = out.line(format!("NX/DEP:         {}", yn(s.dep_nx)));
        out = out.line(format!("CFG:            {}", yn(s.cfg)));
        out = out.line(format!("SafeSEH:        {}", yn(s.safe_seh)));
        out = out.line(format!("HighEntropyVA:  {}", yn(s.high_entropy_va)));
        out = out.line(format!("/GS cookie:     {}", yn(s.gs_cookie_hint)));
        out = out.line(format!("Authenticode:   {}", yn(s.authenticode_signed_hint)));
        out
    }
}

pub struct RopScanPlugin;
impl Plugin for RopScanPlugin {
    fn meta(&self) -> PluginMeta {
        PluginMeta {
            id: "rop-scan",
            name: "ROP Gadget Scan",
            description: "Find short ROP gadgets in executable sections of the loaded binary.",
            category: PluginCategory::Analysis,
        }
    }
    fn run(&self, state: &AppState, arg: Option<&str>) -> PluginOutput {
        let mut out = PluginOutput::default();
        let limit: usize = arg.and_then(|a| a.parse().ok()).unwrap_or(50);
        let Some(info) = state.binary.as_ref() else {
            return out.line("[!] no binary loaded");
        };
        let Some(bytes) = state.binary_bytes.as_ref() else {
            return out.line("[!] no binary bytes");
        };
        // Pick the first executable section.
        let Some(sec) = info.sections.iter().find(|s| s.executable) else {
            return out.line("[!] no executable section");
        };
        let start = sec.file_offset as usize;
        let end = (sec.file_offset + sec.file_size) as usize;
        if end > bytes.len() {
            return out.line("[!] section out of file range");
        }
        match crate::analysis::rop::find_gadgets(&bytes[start..end], sec.virtual_address, info.architecture) {
            Ok(gadgets) => {
                out = out.line(format!("Found {} gadget(s); showing up to {}:", gadgets.len(), limit));
                for g in gadgets.iter().take(limit) {
                    out = out.line(format!("0x{:016x}: {}", g.address, g.instructions.join(" ; ")));
                }
            }
            Err(e) => out = out.line(format!("[!] {e}")),
        }
        out
    }
}

pub struct DisasmPlugin;
impl Plugin for DisasmPlugin {
    fn meta(&self) -> PluginMeta {
        PluginMeta {
            id: "disasm",
            name: "Disassemble Memory",
            description: "Disassemble bytes at given address. Arg: 'addr' or 'addr count' (decimal/hex).",
            category: PluginCategory::Analysis,
        }
    }
    fn run(&self, state: &AppState, arg: Option<&str>) -> PluginOutput {
        let mut out = PluginOutput::default();
        let arg = arg.unwrap_or("");
        let mut parts = arg.split_whitespace();
        let addr_str = parts.next().unwrap_or("");
        let count: usize = parts.next().and_then(|s| parse_num_usize(s)).unwrap_or(16);
        let Some(addr) = parse_num(addr_str) else {
            return out.line("[!] usage: disasm <addr> [insn-count]");
        };
        let arch = state.binary.as_ref()
            .map(|b| b.architecture)
            .unwrap_or(crate::target::arch::Architecture::X86_64);
        // Try the loaded image first; otherwise pull the current memory window.
        let bytes_opt: Option<Vec<u8>> = state.binary_bytes.as_ref().and_then(|file_bytes| {
            let info = state.binary.as_ref()?;
            let sec = info.sections.iter().find(|s|
                s.executable
                && addr >= s.virtual_address
                && addr < s.virtual_address + s.virtual_size
            )?;
            let off = (addr - sec.virtual_address) + sec.file_offset;
            let off = off as usize;
            let end = (off + count * 16).min(file_bytes.len());
            Some(file_bytes[off..end].to_vec())
        });
        let bytes = match bytes_opt {
            Some(b) => b,
            None => state.memory_bytes.clone(),
        };
        match crate::pwn::asm::disasm_all(arch, addr, &bytes) {
            Ok(insns) => {
                for i in insns.iter().take(count) {
                    out = out.line(format!(
                        "0x{:016x}: {:<24} {} {}",
                        i.address,
                        i.bytes.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(" "),
                        i.mnemonic, i.operands,
                    ));
                }
            }
            Err(e) => out = out.line(format!("[!] {e}")),
        }
        out
    }
}

// --------------------------------------------------------------------- Pwn --

pub struct CyclicPlugin;
impl Plugin for CyclicPlugin {
    fn meta(&self) -> PluginMeta {
        PluginMeta {
            id: "cyclic",
            name: "Cyclic Pattern",
            description: "Generate de Bruijn cyclic pattern. Arg: length (default 100).",
            category: PluginCategory::Pwn,
        }
    }
    fn run(&self, _state: &AppState, arg: Option<&str>) -> PluginOutput {
        let n: usize = arg.and_then(parse_num_usize).unwrap_or(100);
        let pat = crate::pwn::cyclic::cyclic(n);
        PluginOutput::default().line(String::from_utf8_lossy(&pat).into_owned())
    }
}

pub struct CyclicFindPlugin;
impl Plugin for CyclicFindPlugin {
    fn meta(&self) -> PluginMeta {
        PluginMeta {
            id: "cyclic-find",
            name: "Cyclic Find",
            description: "Find offset of a 4/8-byte value inside the default cyclic pattern. Arg: hex value or ASCII.",
            category: PluginCategory::Pwn,
        }
    }
    fn run(&self, _state: &AppState, arg: Option<&str>) -> PluginOutput {
        let arg = arg.unwrap_or("").trim();
        if arg.is_empty() { return PluginOutput::default().line("[!] usage: cyclic-find <hex|ascii>"); }
        // Try hex first (with optional 0x prefix).
        let needle: Vec<u8> = if let Some(stripped) = arg.strip_prefix("0x").or_else(|| arg.strip_prefix("0X")) {
            match hex::decode(stripped) {
                Ok(v) => v.into_iter().rev().collect(), // little-endian text
                Err(_) => arg.as_bytes().to_vec(),
            }
        } else {
            arg.as_bytes().to_vec()
        };
        match crate::pwn::cyclic::cyclic_find(&needle) {
            Some(off) => PluginOutput::default().line(format!("offset = {off}")),
            None => PluginOutput::default().line("[!] not found in default cyclic pattern"),
        }
    }
}

pub struct HexdumpPlugin;
impl Plugin for HexdumpPlugin {
    fn meta(&self) -> PluginMeta {
        PluginMeta {
            id: "hexdump",
            name: "Hexdump Memory Window",
            description: "Pretty-print the current memory view as a hex/ASCII table.",
            category: PluginCategory::Pwn,
        }
    }
    fn run(&self, state: &AppState, _arg: Option<&str>) -> PluginOutput {
        if state.memory_bytes.is_empty() {
            return PluginOutput::default().line("[!] memory window empty (read some memory first)");
        }
        let dump = crate::pwn::hexdump::hexdump(&state.memory_bytes, state.memory_view_address);
        let mut out = PluginOutput::default();
        for line in dump.lines() { out = out.line(line.to_string()); }
        out
    }
}

pub struct FmtStringProbePlugin;
impl Plugin for FmtStringProbePlugin {
    fn meta(&self) -> PluginMeta {
        PluginMeta {
            id: "fmtstr-probe",
            name: "Format-String Probe",
            description: "Build an `AAAA %p %p ...` probe string. Arg: number of %p slots (default 20).",
            category: PluginCategory::Pwn,
        }
    }
    fn run(&self, state: &AppState, arg: Option<&str>) -> PluginOutput {
        let count: usize = arg.and_then(parse_num_usize).unwrap_or(20);
        let bits: u8 = match state.binary.as_ref().map(|b| b.architecture) {
            Some(crate::target::arch::Architecture::X86_64) => 64,
            Some(crate::target::arch::Architecture::AArch64) => 64,
            _ => 32,
        };
        PluginOutput::default()
            .line(format!("// {bits}-bit probe; send to target, then run fmtstr-find on the response"))
            .line(crate::pwn::fmtstr::build_probe(bits, count))
    }
}

pub struct XorBrutePlugin;
impl Plugin for XorBrutePlugin {
    fn meta(&self) -> PluginMeta {
        PluginMeta {
            id: "xor-brute",
            name: "Single-byte XOR Brute",
            description: "Brute single-byte XOR over the current memory window; reports best key.",
            category: PluginCategory::Pwn,
        }
    }
    fn run(&self, state: &AppState, _arg: Option<&str>) -> PluginOutput {
        if state.memory_bytes.is_empty() {
            return PluginOutput::default().line("[!] memory window empty");
        }
        let (k, dec, score) = crate::pwn::xor::xor_brute_single(&state.memory_bytes);
        let preview: String = dec.iter().take(80)
            .map(|&b| if b.is_ascii_graphic() || b == b' ' { b as char } else { '.' })
            .collect();
        PluginOutput::default()
            .line(format!("best key = 0x{k:02x}  printable score = {:.2}%", score * 100.0))
            .line(format!("preview: {preview}"))
    }
}

pub struct ShellcodeListPlugin;
impl Plugin for ShellcodeListPlugin {
    fn meta(&self) -> PluginMeta {
        PluginMeta {
            id: "shellcode-list",
            name: "List Shellcode Templates",
            description: "List built-in educational shellcode payloads (CTF/lab use only).",
            category: PluginCategory::Pwn,
        }
    }
    fn run(&self, _state: &AppState, _arg: Option<&str>) -> PluginOutput {
        let mut out = PluginOutput::default();
        for sc in crate::pwn::shellcode::ALL {
            let hex: String = sc.bytes.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join("");
            out = out.line(format!("{:<22} [{} / {}] {} ({} bytes)", sc.name, sc.arch, sc.os, sc.description, sc.bytes.len()));
            out = out.line(format!("  bytes: {hex}"));
        }
        out
    }
}

// ----------------------------------------------------------------- helpers --

fn parse_num(s: &str) -> Option<u64> {
    let s = s.trim();
    if let Some(rest) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(rest, 16).ok()
    } else {
        s.parse::<u64>().ok().or_else(|| u64::from_str_radix(s, 16).ok())
    }
}
fn parse_num_usize(s: &str) -> Option<usize> {
    parse_num(s).map(|v| v as usize)
}
