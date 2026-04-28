//! Capstone-backed disassembler.

use crate::error::{DbgError, DbgResult};
use crate::target::arch::Architecture;
use capstone::prelude::*;

pub struct DisasmInsn {
    pub address: u64,
    pub bytes: Vec<u8>,
    pub mnemonic: String,
    pub op_str: String,
}

pub struct Disassembler {
    cs: Capstone,
    arch: Architecture,
}

impl Disassembler {
    pub fn new(arch: Architecture) -> DbgResult<Self> {
        let cs = match arch {
            Architecture::X86_64 | Architecture::Auto => Capstone::new()
                .x86().mode(arch::x86::ArchMode::Mode64).syntax(arch::x86::ArchSyntax::Intel)
                .detail(true).build()?,
            Architecture::X86 => Capstone::new()
                .x86().mode(arch::x86::ArchMode::Mode32).syntax(arch::x86::ArchSyntax::Intel)
                .detail(true).build()?,
            Architecture::Arm => Capstone::new()
                .arm().mode(arch::arm::ArchMode::Arm).detail(true).build()?,
            Architecture::AArch64 => Capstone::new()
                .arm64().mode(arch::arm64::ArchMode::Arm).detail(true).build()?,
            Architecture::Riscv64 => Capstone::new()
                .riscv().mode(arch::riscv::ArchMode::RiscV64).detail(true).build()?,
        };
        Ok(Self { cs, arch })
    }

    pub fn arch(&self) -> Architecture { self.arch }

    pub fn disassemble(&self, bytes: &[u8], address: u64, max: usize) -> DbgResult<Vec<DisasmInsn>> {
        let insns = self.cs.disasm_count(bytes, address, max)
            .map_err(DbgError::from)?;
        let mut out = Vec::with_capacity(insns.len());
        for i in insns.iter() {
            out.push(DisasmInsn {
                address: i.address(),
                bytes: i.bytes().to_vec(),
                mnemonic: i.mnemonic().unwrap_or("").to_string(),
                op_str: i.op_str().unwrap_or("").to_string(),
            });
        }
        Ok(out)
    }

    pub fn disassemble_one(&self, bytes: &[u8], address: u64) -> DbgResult<Option<DisasmInsn>> {
        Ok(self.disassemble(bytes, address, 1)?.into_iter().next())
    }
}
