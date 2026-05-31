//! ROP / JOP gadget search for x86 and x86-64.
//!
//! Extends the basic `analysis::rop` scanner with: free-text gadget queries
//! ("find me `pop rdi ; ret`"), classification of `pop <reg> ; ret` gadgets,
//! and location of raw syscall sites (`syscall`, `int 0x80`, `sysenter`).
//!
//! The search is a linear backwards scan from every `ret` byte — the standard
//! technique for small CTF binaries — decoding 1..=MAX_BACK preceding bytes
//! and keeping sequences that decode cleanly and end in a return.

use crate::analysis::disasm::Disassembler;
use crate::error::DbgResult;
use crate::target::arch::Architecture;

#[derive(Debug, Clone)]
pub struct Gadget {
    pub address: u64,
    pub text: String,
    pub instructions: Vec<String>,
}

const MAX_BACK: usize = 12;
const MAX_INSNS: usize = 6;

fn is_ret(mnemonic: &str) -> bool {
    matches!(mnemonic, "ret" | "retq" | "retf" | "retn")
}

/// Find x86/x86-64 ROP gadgets ending in `ret`.  `query`, when non-empty, is a
/// case-insensitive substring filter applied to the rendered gadget text
/// (e.g. `"pop rdi"`).
pub fn find(bytes: &[u8], base: u64, arch: Architecture, query: &str) -> DbgResult<Vec<Gadget>> {
    let dis = Disassembler::new(arch)?;
    let q = query.trim().to_ascii_lowercase();
    let mut out: Vec<Gadget> = Vec::new();

    for (i, &b) in bytes.iter().enumerate() {
        if b != 0xC3 && b != 0xC2 {
            continue;
        }
        for back in 1..=MAX_BACK {
            if i + 1 < back {
                continue;
            }
            let start = i + 1 - back;
            let slice = &bytes[start..=i];
            let address = base + start as u64;
            let Ok(insns) = dis.disassemble(slice, address, MAX_INSNS + 1) else {
                continue;
            };
            let consumed: usize = insns.iter().map(|x| x.bytes.len()).sum();
            let ends_in_ret = insns.last().map(|x| is_ret(&x.mnemonic)).unwrap_or(false);
            if insns.is_empty() || consumed != back || !ends_in_ret {
                continue;
            }
            let parts: Vec<String> = insns
                .iter()
                .map(|x| {
                    if x.op_str.is_empty() {
                        x.mnemonic.clone()
                    } else {
                        format!("{} {}", x.mnemonic, x.op_str)
                    }
                })
                .collect();
            let text = parts.join(" ; ");
            if !q.is_empty() && !text.to_ascii_lowercase().contains(&q) {
                continue;
            }
            out.push(Gadget { address, text, instructions: parts });
        }
    }
    out.sort_by(|a, b| a.text.len().cmp(&b.text.len()).then(a.address.cmp(&b.address)));
    out.dedup_by(|a, b| a.address == b.address && a.text == b.text);
    Ok(out)
}

/// Convenience: find `pop <reg> ; ret` gadgets, returning `(address, register)`.
pub fn pop_reg_gadgets(bytes: &[u8], base: u64, arch: Architecture) -> DbgResult<Vec<(u64, String)>> {
    let gadgets = find(bytes, base, arch, "")?;
    let mut out = Vec::new();
    for g in gadgets {
        if g.instructions.len() == 2 && g.instructions[0].starts_with("pop ") && is_ret_text(&g.instructions[1]) {
            let reg = g.instructions[0][4..].trim().to_string();
            out.push((g.address, reg));
        }
    }
    out.sort();
    out.dedup();
    Ok(out)
}

fn is_ret_text(s: &str) -> bool {
    is_ret(s.split_whitespace().next().unwrap_or(""))
}

#[derive(Debug, Clone)]
pub struct SyscallSite {
    pub address: u64,
    pub kind: &'static str,
}

/// Locate raw syscall instructions by opcode: `syscall` (0F 05),
/// `int 0x80` (CD 80) and `sysenter` (0F 34).
pub fn syscall_sites(bytes: &[u8], base: u64) -> Vec<SyscallSite> {
    let mut out = Vec::new();
    let mut i = 0;
    while i + 1 < bytes.len() {
        let kind = match (bytes[i], bytes[i + 1]) {
            (0x0F, 0x05) => Some("syscall"),
            (0x0F, 0x34) => Some("sysenter"),
            (0xCD, 0x80) => Some("int 0x80"),
            _ => None,
        };
        if let Some(k) = kind {
            out.push(SyscallSite { address: base + i as u64, kind: k });
        }
        i += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_pop_rdi_ret() {
        // 5f c3 = pop rdi ; ret
        let bytes = [0x90, 0x5f, 0xc3];
        let g = find(&bytes, 0x1000, Architecture::X86_64, "pop rdi").unwrap();
        assert!(g.iter().any(|x| x.text.contains("pop rdi") && x.text.contains("ret")));
        let pops = pop_reg_gadgets(&bytes, 0x1000, Architecture::X86_64).unwrap();
        assert!(pops.iter().any(|(_, r)| r == "rdi"));
    }

    #[test]
    fn finds_syscall() {
        let bytes = [0x0f, 0x05, 0x00, 0xcd, 0x80];
        let s = syscall_sites(&bytes, 0x400000);
        assert!(s.iter().any(|x| x.kind == "syscall" && x.address == 0x400000));
        assert!(s.iter().any(|x| x.kind == "int 0x80"));
    }
}
