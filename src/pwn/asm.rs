//! One-shot disassembly helper using capstone.  No `asm` (assembly) is
//! offered because we deliberately avoid pulling in `keystone-engine`
//! (a separate native dependency).
//!
//! Use [`disasm_one`] / [`disasm_all`] from the GUI / commands /
//! plugins to render arbitrary buffers.

use capstone::prelude::*;

use crate::error::{DbgError, DbgResult};
use crate::target::arch::Architecture;

#[derive(Debug, Clone)]
pub struct DisasmInsn {
    pub address: u64,
    pub bytes:   Vec<u8>,
    pub mnemonic: String,
    pub operands: String,
}

fn build(arch: Architecture) -> DbgResult<Capstone> {
    let cs = match arch {
        Architecture::X86_64 => Capstone::new().x86().mode(arch::x86::ArchMode::Mode64).syntax(arch::x86::ArchSyntax::Intel).detail(true).build(),
        Architecture::X86    => Capstone::new().x86().mode(arch::x86::ArchMode::Mode32).syntax(arch::x86::ArchSyntax::Intel).detail(true).build(),
        Architecture::AArch64 => Capstone::new().arm64().mode(arch::arm64::ArchMode::Arm).detail(true).build(),
        Architecture::Arm    => Capstone::new().arm().mode(arch::arm::ArchMode::Arm).detail(true).build(),
        Architecture::Riscv64 => Capstone::new().x86().mode(arch::x86::ArchMode::Mode64).syntax(arch::x86::ArchSyntax::Intel).detail(true).build(),
        Architecture::Auto   => Capstone::new().x86().mode(arch::x86::ArchMode::Mode64).syntax(arch::x86::ArchSyntax::Intel).detail(true).build(),
    };
    cs.map_err(|e| DbgError::Capstone(format!("capstone init: {e}")))
}

pub fn disasm_all(arch: Architecture, base: u64, bytes: &[u8]) -> DbgResult<Vec<DisasmInsn>> {
    let cs = build(arch)?;
    let insns = cs.disasm_all(bytes, base)
        .map_err(|e| DbgError::Capstone(format!("disasm: {e}")))?;
    Ok(insns.iter().map(|i| DisasmInsn {
        address: i.address(),
        bytes:   i.bytes().to_vec(),
        mnemonic: i.mnemonic().unwrap_or("").to_string(),
        operands: i.op_str().unwrap_or("").to_string(),
    }).collect())
}

pub fn disasm_one(arch: Architecture, base: u64, bytes: &[u8]) -> DbgResult<Option<DisasmInsn>> {
    Ok(disasm_all(arch, base, bytes)?.into_iter().next())
}

/// Render a sequence as a multi-line string, mimicking `pwntools.disasm`.
pub fn pretty(insns: &[DisasmInsn]) -> String {
    use std::fmt::Write as _;
    let mut s = String::new();
    for i in insns {
        let bytes_hex: String = i.bytes.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(" ");
        let _ = writeln!(s, "{:>16x}: {:<24} {} {}", i.address, bytes_hex, i.mnemonic, i.operands);
    }
    s
}
