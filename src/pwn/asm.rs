//! One-shot disassembly helpers for the GUI / commands / plugins.
//!
//! This is a thin convenience layer over [`crate::analysis::disasm`], which
//! does the real multi-architecture work.  No assembler (`asm`) is offered:
//! we deliberately avoid pulling in `keystone-engine` (a separate native
//! dependency).

use crate::analysis::disasm::Disassembler;
use crate::error::DbgResult;
use crate::target::arch::{Architecture, Endian};

#[derive(Debug, Clone)]
pub struct DisasmInsn {
    pub address: u64,
    pub bytes: Vec<u8>,
    pub mnemonic: String,
    pub operands: String,
}

impl From<crate::analysis::disasm::DisasmInsn> for DisasmInsn {
    fn from(i: crate::analysis::disasm::DisasmInsn) -> Self {
        Self {
            address: i.address,
            bytes: i.bytes,
            mnemonic: i.mnemonic,
            operands: i.op_str,
        }
    }
}

pub fn disasm_all(arch: Architecture, base: u64, bytes: &[u8]) -> DbgResult<Vec<DisasmInsn>> {
    let dis = Disassembler::new(arch)?;
    Ok(dis.disassemble_all(bytes, base)?.into_iter().map(Into::into).collect())
}

pub fn disasm_one(arch: Architecture, base: u64, bytes: &[u8]) -> DbgResult<Option<DisasmInsn>> {
    Ok(disasm_all(arch, base, bytes)?.into_iter().next())
}

/// Disassemble for any BFD architecture by name (e.g. `"mips64el"`, `"ppc64"`,
/// `"sparc:v9"`), honouring an explicit endianness override.
pub fn disasm_named(name: &str, endian: Endian, base: u64, bytes: &[u8]) -> DbgResult<Vec<DisasmInsn>> {
    let dis = Disassembler::for_named(name, endian)?;
    Ok(dis.disassemble_all(bytes, base)?.into_iter().map(Into::into).collect())
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
