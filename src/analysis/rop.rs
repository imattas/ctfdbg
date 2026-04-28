//! Very small ROP gadget finder (x86_64). Finds gadgets ending in
//! `ret`, `pop reg; ret`, `jmp reg`, `call reg`, `syscall; ret`.
//!
//! This is a basic linear scan suitable for small CTF binaries.

use crate::analysis::disasm::Disassembler;
use crate::error::DbgResult;
use crate::target::arch::Architecture;

#[derive(Debug, Clone)]
pub struct Gadget {
    pub address: u64,
    pub instructions: Vec<String>,
}

const MAX_DEPTH: usize = 5;

pub fn find_gadgets(bytes: &[u8], base: u64, arch: Architecture) -> DbgResult<Vec<Gadget>> {
    let dis = Disassembler::new(arch)?;
    let mut out = Vec::new();
    for (i, &b) in bytes.iter().enumerate() {
        if b == 0xC3 || b == 0xC2 {
            // Walk backwards 1..=MAX_DEPTH bytes and try to disasm into ret.
            for back in 1..=10usize {
                if i + 1 < back { continue; }
                let start = i + 1 - back;
                let slice = &bytes[start..=i];
                let address = base + start as u64;
                if let Ok(insns) = dis.disassemble(slice, address, MAX_DEPTH + 1) {
                    if !insns.is_empty()
                        && insns.last().map(|x| x.mnemonic == "ret" || x.mnemonic == "retq").unwrap_or(false)
                        && insns.iter().map(|x| x.bytes.len()).sum::<usize>() == back
                    {
                        let texts: Vec<String> = insns.iter().map(|x| {
                            if x.op_str.is_empty() { x.mnemonic.clone() }
                            else { format!("{} {}", x.mnemonic, x.op_str) }
                        }).collect();
                        out.push(Gadget { address, instructions: texts });
                    }
                }
            }
        }
    }
    out.sort_by_key(|g| (g.address, g.instructions.len()));
    out.dedup_by(|a, b| a.address == b.address && a.instructions == b.instructions);
    Ok(out)
}
