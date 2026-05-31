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
            Some(arch) if arch.is_64bit() => 64,
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

// ----------------------------------------------------- Architecture / Rev --

pub struct ArchListPlugin;
impl Plugin for ArchListPlugin {
    fn meta(&self) -> PluginMeta {
        PluginMeta {
            id: "arch-list",
            name: "List Architectures (BFD)",
            description: "List the binutils/BFD architecture set ctfdbg recognises. Arg: optional name filter.",
            category: PluginCategory::Rev,
        }
    }
    fn run(&self, _state: &AppState, arg: Option<&str>) -> PluginOutput {
        use crate::target::bfd;
        let filter = arg.unwrap_or("").trim().to_ascii_lowercase();
        let mut out = PluginOutput::default();
        out = out.line(format!(
            "{} architecture families described, {} with a live disassembler:",
            bfd::count(),
            bfd::disassemblable_count()
        ));
        for a in bfd::ARCHS {
            if !filter.is_empty()
                && !a.name.to_ascii_lowercase().contains(&filter)
                && !a.printable.to_ascii_lowercase().contains(&filter)
            {
                continue;
            }
            out = out.line(format!(
                "{:<16} {:<30} {:>2}/{:>2} bit {:<7} {}",
                a.name,
                a.printable,
                a.bits_per_word,
                a.bits_per_address,
                a.byte_order.name(),
                if a.has_disassembler() { "[disasm]" } else { "[descriptor]" },
            ));
        }
        out
    }
}

pub struct ArchInfoPlugin;
impl Plugin for ArchInfoPlugin {
    fn meta(&self) -> PluginMeta {
        PluginMeta {
            id: "arch-info",
            name: "Architecture Info",
            description: "Describe a BFD architecture by name/alias. Arg: e.g. 'mips64el', 'ppc64', 'sparc:v9'.",
            category: PluginCategory::Rev,
        }
    }
    fn run(&self, _state: &AppState, arg: Option<&str>) -> PluginOutput {
        use crate::target::bfd;
        let Some(name) = arg.map(str::trim).filter(|s| !s.is_empty()) else {
            return PluginOutput::default().line("[!] usage: arch-info <name|alias>");
        };
        let Some(a) = bfd::lookup(name) else {
            return PluginOutput::default().line(format!("[!] unknown architecture: {name}"));
        };
        let mut out = PluginOutput::default();
        out = out.line(format!("name:        {}", a.name));
        out = out.line(format!("printable:   {}", a.printable));
        if !a.aliases.is_empty() {
            out = out.line(format!("aliases:     {}", a.aliases.join(", ")));
        }
        out = out.line(format!("word size:   {} bits", a.bits_per_word));
        out = out.line(format!("addr size:   {} bits ({} bytes)", a.bits_per_address, a.pointer_size()));
        out = out.line(format!("byte order:  {}", a.byte_order.name()));
        out = out.line(format!("ELF machine: {}", a.elf_machine.map(|m| format!("{m} (0x{m:x})")).unwrap_or_else(|| "n/a".into())));
        out = out.line(format!("disassembler:{}", if a.has_disassembler() { " capstone (live)" } else { " none in this build (descriptor only)" }));
        out
    }
}

pub struct DisasmArchPlugin;
impl Plugin for DisasmArchPlugin {
    fn meta(&self) -> PluginMeta {
        PluginMeta {
            id: "disasm-arch",
            name: "Disassemble (any architecture)",
            description: "Disassemble the current memory window for a named arch. Arg: '<arch> [le|be] [count]'.",
            category: PluginCategory::Rev,
        }
    }
    fn run(&self, state: &AppState, arg: Option<&str>) -> PluginOutput {
        use crate::target::arch::Endian;
        let mut out = PluginOutput::default();
        let arg = arg.unwrap_or("").trim();
        let mut parts = arg.split_whitespace();
        let Some(name) = parts.next() else {
            return out.line("[!] usage: disasm-arch <arch> [le|be] [count]");
        };
        let mut endian = Endian::Auto;
        let mut count = 16usize;
        for p in parts {
            match p.to_ascii_lowercase().as_str() {
                "le" | "little" => endian = Endian::Little,
                "be" | "big" => endian = Endian::Big,
                other => if let Some(n) = parse_num_usize(other) { count = n; },
            }
        }
        if state.memory_bytes.is_empty() {
            return out.line("[!] memory window empty (read some memory first)");
        }
        match crate::pwn::asm::disasm_named(name, endian, state.memory_view_address, &state.memory_bytes) {
            Ok(insns) => {
                if insns.is_empty() {
                    out = out.line("[!] no instructions decoded");
                }
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

pub struct EntropyPlugin;
impl Plugin for EntropyPlugin {
    fn meta(&self) -> PluginMeta {
        PluginMeta {
            id: "entropy",
            name: "Entropy / Packer Scan",
            description: "Shannon entropy of the loaded binary (per section) and current memory window.",
            category: PluginCategory::Analysis,
        }
    }
    fn run(&self, state: &AppState, _arg: Option<&str>) -> PluginOutput {
        use crate::analysis::entropy;
        let mut out = PluginOutput::default();
        if let (Some(info), Some(bytes)) = (state.binary.as_ref(), state.binary_bytes.as_ref()) {
            let whole = entropy::shannon(bytes);
            out = out.line(format!("file entropy: {:.3} bits/byte  ({})", whole, entropy::classify(whole)));
            for s in &info.sections {
                let start = s.file_offset as usize;
                let end = (s.file_offset + s.file_size) as usize;
                if start < end && end <= bytes.len() && s.file_size > 0 {
                    let e = entropy::shannon(&bytes[start..end]);
                    out = out.line(format!("  {:<16} {:.3}  {}", s.name, e, entropy::classify(e)));
                }
            }
            // Flag suspicious high-entropy regions.
            for r in entropy::high_entropy_regions(bytes, 256, 7.2).into_iter().take(8) {
                out = out.line(format!("  [!] high-entropy region @ 0x{:x} ({} bytes, {:.2})", r.offset, r.len, r.entropy));
            }
        }
        if !state.memory_bytes.is_empty() {
            let e = entropy::shannon(&state.memory_bytes);
            out = out.line(format!("memory window entropy: {:.3}  ({})", e, entropy::classify(e)));
        }
        if out.lines.is_empty() {
            out = out.line("[!] no binary or memory loaded");
        }
        out
    }
}

pub struct IocScanPlugin;
impl Plugin for IocScanPlugin {
    fn meta(&self) -> PluginMeta {
        PluginMeta {
            id: "iocs",
            name: "Extract Flags / IoCs",
            description: "Scan the binary (or memory) for flags, URLs, IPv4, e-mails, Base64. Arg: optional flag format e.g. 'picoCTF'.",
            category: PluginCategory::Rev,
        }
    }
    fn run(&self, state: &AppState, arg: Option<&str>) -> PluginOutput {
        use crate::analysis::iocs;
        let fmt = arg.map(str::trim).filter(|s| !s.is_empty());
        let bytes: &[u8] = state.binary_bytes.as_deref()
            .filter(|b| !b.is_empty())
            .unwrap_or(&state.memory_bytes);
        if bytes.is_empty() {
            return PluginOutput::default().line("[!] no binary or memory loaded");
        }
        let found = iocs::extract(bytes, fmt);
        let mut out = PluginOutput::default();
        if found.is_empty() {
            return out.line("[*] no indicators found");
        }
        let section = |out: PluginOutput, title: &str, items: &[String]| {
            if items.is_empty() { return out; }
            let mut o = out.line(format!("--- {} ({}) ---", title, items.len()));
            for it in items.iter().take(50) { o = o.line(it.clone()); }
            o
        };
        out = section(out, "flags", &found.flags);
        out = section(out, "urls", &found.urls);
        out = section(out, "ipv4", &found.ipv4);
        out = section(out, "emails", &found.emails);
        out = section(out, "base64 blobs", &found.base64_blobs);
        out
    }
}

// --------------------------------------------------------------- Crypto ---

pub struct CryptoIdPlugin;
impl Plugin for CryptoIdPlugin {
    fn meta(&self) -> PluginMeta {
        PluginMeta {
            id: "crypto-id",
            name: "Identify Crypto Constants",
            description: "Scan the binary (or memory) for AES/SHA/MD5/CRC32 constants and known tables.",
            category: PluginCategory::Crypto,
        }
    }
    fn run(&self, state: &AppState, _arg: Option<&str>) -> PluginOutput {
        use crate::analysis::crypto;
        let bytes: &[u8] = state.binary_bytes.as_deref()
            .filter(|b| !b.is_empty())
            .unwrap_or(&state.memory_bytes);
        if bytes.is_empty() {
            return PluginOutput::default().line("[!] no binary or memory loaded");
        }
        let hits = crypto::scan_constants(bytes);
        let mut out = PluginOutput::default();
        if hits.is_empty() {
            return out.line("[*] no known crypto constants found");
        }
        for h in hits {
            out = out.line(format!("0x{:08x}  {}", h.offset, h.name));
        }
        out
    }
}

pub struct HashIdPlugin;
impl Plugin for HashIdPlugin {
    fn meta(&self) -> PluginMeta {
        PluginMeta {
            id: "hash-id",
            name: "Identify Hash",
            description: "Guess the hash algorithm of a digest string by length/format. Arg: the hash.",
            category: PluginCategory::Crypto,
        }
    }
    fn run(&self, _state: &AppState, arg: Option<&str>) -> PluginOutput {
        use crate::analysis::crypto;
        let Some(h) = arg.map(str::trim).filter(|s| !s.is_empty()) else {
            return PluginOutput::default().line("[!] usage: hash-id <digest>");
        };
        let mut out = PluginOutput::default().line(format!("candidates for {} ({} chars):", h, h.len()));
        for c in crypto::identify_hash(h) {
            out = out.line(format!("  - {c}"));
        }
        out
    }
}

// ----------------------------------------------------------- Deobfuscation -

pub struct DeobfuscatePlugin;
impl Plugin for DeobfuscatePlugin {
    fn meta(&self) -> PluginMeta {
        PluginMeta {
            id: "deobf",
            name: "Deobfuscate Expression (MBA)",
            description: "Simplify a mixed boolean-arithmetic expression. Arg: e.g. '(x ^ y) + 2*(x & y)'.",
            category: PluginCategory::Deobfuscation,
        }
    }
    fn run(&self, _state: &AppState, arg: Option<&str>) -> PluginOutput {
        use crate::analysis::deobfuscate;
        let Some(expr) = arg.map(str::trim).filter(|s| !s.is_empty()) else {
            return PluginOutput::default()
                .line("[!] usage: deobf <expr>   (vars a-z, ops + - * & | ^ ~ << >>)");
        };
        match deobfuscate::deobfuscate(expr) {
            Ok(d) => {
                let mut out = PluginOutput::default();
                out = out.line(format!("input:      {}", d.original));
                out = out.line(format!("simplified: {}", d.simplified));
                if let Some(s) = d.synthesized {
                    out = out.line(format!("synthesized: {s}"));
                    out = out.line("  (equivalent over 400+ sampled inputs across the 64-bit ring)");
                }
                if let Some(c) = d.constant_value {
                    out = out.line(format!("value:      {c} (0x{c:x})"));
                }
                if !d.variables.is_empty() {
                    out = out.line(format!("variables:  {}", d.variables.join(", ")));
                }
                out
            }
            Err(e) => PluginOutput::default().line(format!("[!] parse error: {e}")),
        }
    }
}

pub struct DecodePlugin;
impl Plugin for DecodePlugin {
    fn meta(&self) -> PluginMeta {
        PluginMeta {
            id: "decode",
            name: "Auto-Decode",
            description: "Peel Base64/hex/Base32/ASCII85/URL layers off a string (or the memory window).",
            category: PluginCategory::Deobfuscation,
        }
    }
    fn run(&self, state: &AppState, arg: Option<&str>) -> PluginOutput {
        use crate::pwn::encoding;
        let owned;
        let data: &[u8] = match arg.map(str::trim).filter(|s| !s.is_empty()) {
            Some(s) => { owned = s.as_bytes().to_vec(); &owned }
            None => &state.memory_bytes,
        };
        if data.is_empty() {
            return PluginOutput::default().line("[!] usage: decode <string>  (or read memory first)");
        }
        let steps = encoding::auto_decode(data, 8);
        let mut out = PluginOutput::default();
        if steps.is_empty() {
            return out.line("[*] no decoding layer applied (input not a recognised encoding)");
        }
        for (i, s) in steps.iter().enumerate() {
            let preview = String::from_utf8_lossy(&s.output);
            let preview: String = preview.chars().take(120).collect();
            out = out.line(format!("[{}] {:<8} -> {}", i + 1, s.codec, preview));
        }
        out
    }
}

pub struct XorKeyPlugin;
impl Plugin for XorKeyPlugin {
    fn meta(&self) -> PluginMeta {
        PluginMeta {
            id: "xor-key",
            name: "Break Repeating-Key XOR",
            description: "Recover a repeating XOR key over the current memory window. Arg: max key size (default 40).",
            category: PluginCategory::Deobfuscation,
        }
    }
    fn run(&self, state: &AppState, arg: Option<&str>) -> PluginOutput {
        use crate::pwn::xor;
        if state.memory_bytes.is_empty() {
            return PluginOutput::default().line("[!] memory window empty (read some memory first)");
        }
        let max_ks = arg.and_then(parse_num_usize).unwrap_or(40);
        match xor::break_repeating_xor_auto(&state.memory_bytes, max_ks) {
            Some((key, pt, score)) => {
                let key_hex: String = key.iter().map(|b| format!("{b:02x}")).collect();
                let key_ascii: String = key.iter()
                    .map(|&b| if b.is_ascii_graphic() { b as char } else { '.' }).collect();
                let preview: String = pt.iter().take(120)
                    .map(|&b| if b.is_ascii_graphic() || b == b' ' { b as char } else { '.' }).collect();
                PluginOutput::default()
                    .line(format!("key ({} bytes): {} | \"{}\"  english-score={:.3}", key.len(), key_hex, key_ascii, score))
                    .line(format!("plaintext: {preview}"))
            }
            None => PluginOutput::default().line("[!] could not recover a key (buffer too small)"),
        }
    }
}

// ---------------------------------------------------------- Pwn (gadgets) --

pub struct GadgetPlugin;
impl Plugin for GadgetPlugin {
    fn meta(&self) -> PluginMeta {
        PluginMeta {
            id: "gadget",
            name: "Gadget Search",
            description: "Find x86/x64 ROP gadgets matching a query in the first exec section. Arg: e.g. 'pop rdi'.",
            category: PluginCategory::Pwn,
        }
    }
    fn run(&self, state: &AppState, arg: Option<&str>) -> PluginOutput {
        let query = arg.unwrap_or("").trim();
        let mut out = PluginOutput::default();
        let (Some(info), Some(bytes)) = (state.binary.as_ref(), state.binary_bytes.as_ref()) else {
            return out.line("[!] no binary loaded");
        };
        let Some(sec) = info.sections.iter().find(|s| s.executable) else {
            return out.line("[!] no executable section");
        };
        let start = sec.file_offset as usize;
        let end = (sec.file_offset + sec.file_size) as usize;
        if end > bytes.len() {
            return out.line("[!] section out of file range");
        }
        match crate::pwn::gadget::find(&bytes[start..end], sec.virtual_address, info.architecture, query) {
            Ok(gadgets) => {
                out = out.line(format!("{} gadget(s){}:", gadgets.len(),
                    if query.is_empty() { String::new() } else { format!(" matching '{query}'") }));
                for g in gadgets.iter().take(80) {
                    out = out.line(format!("0x{:016x}: {}", g.address, g.text));
                }
            }
            Err(e) => out = out.line(format!("[!] {e}")),
        }
        out
    }
}

pub struct SyscallSitesPlugin;
impl Plugin for SyscallSitesPlugin {
    fn meta(&self) -> PluginMeta {
        PluginMeta {
            id: "syscall-sites",
            name: "Find Syscall Sites",
            description: "Locate syscall / int 0x80 / sysenter instructions in the first exec section.",
            category: PluginCategory::Pwn,
        }
    }
    fn run(&self, state: &AppState, _arg: Option<&str>) -> PluginOutput {
        let mut out = PluginOutput::default();
        let (Some(info), Some(bytes)) = (state.binary.as_ref(), state.binary_bytes.as_ref()) else {
            return out.line("[!] no binary loaded");
        };
        let Some(sec) = info.sections.iter().find(|s| s.executable) else {
            return out.line("[!] no executable section");
        };
        let start = sec.file_offset as usize;
        let end = (sec.file_offset + sec.file_size) as usize;
        if end > bytes.len() {
            return out.line("[!] section out of file range");
        }
        let sites = crate::pwn::gadget::syscall_sites(&bytes[start..end], sec.virtual_address);
        out = out.line(format!("{} syscall site(s):", sites.len()));
        for s in sites.iter().take(100) {
            out = out.line(format!("0x{:016x}: {}", s.address, s.kind));
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
