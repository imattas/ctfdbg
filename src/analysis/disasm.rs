//! Multi-architecture capstone-backed disassembler.
//!
//! The engine is driven by a [`CsTarget`] (family + mode + endianness) taken
//! from the BFD architecture registry ([`crate::target::bfd`]).  Every
//! capstone family available in this build — x86, ARM/Thumb, AArch64, MIPS,
//! PowerPC, SPARC, SystemZ, m68k, m680x, XCore, TMS320C64x, EVM and RISC-V —
//! is reachable, in both byte orders where the family supports it.
//!
//! [`Disassembler::new`] keeps the original `Architecture`-based entry point
//! for the live debugger; [`Disassembler::for_target`] exposes the full set.

use capstone::prelude::*;
use capstone::Endian as CsEndian;

use crate::error::{DbgError, DbgResult};
use crate::target::arch::{Architecture, Endian};
use crate::target::bfd::{self, CsFamily, CsMode, CsTarget};

#[derive(Debug, Clone)]
pub struct DisasmInsn {
    pub address: u64,
    pub bytes: Vec<u8>,
    pub mnemonic: String,
    pub op_str: String,
}

pub struct Disassembler {
    cs: Capstone,
    arch: Architecture,
    target: CsTarget,
}

impl Disassembler {
    /// Build a disassembler for one of the live-debugger architectures.
    ///
    /// `Architecture::Auto` (and any architecture without a capstone backend)
    /// falls back to x86-64 so existing call sites keep working.
    pub fn new(arch: Architecture) -> DbgResult<Self> {
        let target = bfd::for_architecture(arch)
            .and_then(|a| a.cs)
            .unwrap_or(CsTarget { family: CsFamily::X86, mode: CsMode::X86_64, big_endian: false });
        Self::for_target(target).map(|mut d| {
            d.arch = arch;
            d
        })
    }

    /// Build a disassembler for an arbitrary capstone target.
    pub fn for_target(target: CsTarget) -> DbgResult<Self> {
        let cs = build_capstone(target)?;
        Ok(Self { cs, arch: Architecture::Auto, target })
    }

    /// Build from a BFD architecture name (e.g. `"mipsel"`, `"ppc64"`).
    ///
    /// Returns `Unsupported` when the named architecture is recognised but has
    /// no live decoder, so callers can report that distinctly from "unknown".
    pub fn for_named(name: &str, endian: Endian) -> DbgResult<Self> {
        let info = bfd::lookup(name)
            .ok_or_else(|| DbgError::InvalidArgument(format!("unknown architecture: {name}")))?;
        let target = info.cs_target(endian).ok_or_else(|| {
            DbgError::Unsupported(format!(
                "{} ({}): descriptor known but no live disassembler in this build",
                info.name, info.printable
            ))
        })?;
        Self::for_target(target)
    }

    pub fn arch(&self) -> Architecture {
        self.arch
    }

    pub fn target(&self) -> CsTarget {
        self.target
    }

    pub fn disassemble(&self, bytes: &[u8], address: u64, max: usize) -> DbgResult<Vec<DisasmInsn>> {
        let insns = self
            .cs
            .disasm_count(bytes, address, max)
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

    pub fn disassemble_all(&self, bytes: &[u8], address: u64) -> DbgResult<Vec<DisasmInsn>> {
        let insns = self.cs.disasm_all(bytes, address).map_err(DbgError::from)?;
        Ok(insns
            .iter()
            .map(|i| DisasmInsn {
                address: i.address(),
                bytes: i.bytes().to_vec(),
                mnemonic: i.mnemonic().unwrap_or("").to_string(),
                op_str: i.op_str().unwrap_or("").to_string(),
            })
            .collect())
    }

    pub fn disassemble_one(&self, bytes: &[u8], address: u64) -> DbgResult<Option<DisasmInsn>> {
        Ok(self.disassemble(bytes, address, 1)?.into_iter().next())
    }
}

/// Translate a [`CsTarget`] into a configured `Capstone` instance.
fn build_capstone(t: CsTarget) -> DbgResult<Capstone> {
    use capstone::arch;
    let endian = if t.big_endian { CsEndian::Big } else { CsEndian::Little };

    let res = match (t.family, t.mode) {
        // ---- x86 (fixed little-endian) ----
        (CsFamily::X86, CsMode::X86_16) => Capstone::new()
            .x86().mode(arch::x86::ArchMode::Mode16).syntax(arch::x86::ArchSyntax::Intel).detail(true).build(),
        (CsFamily::X86, CsMode::X86_32) => Capstone::new()
            .x86().mode(arch::x86::ArchMode::Mode32).syntax(arch::x86::ArchSyntax::Intel).detail(true).build(),
        (CsFamily::X86, _) => Capstone::new()
            .x86().mode(arch::x86::ArchMode::Mode64).syntax(arch::x86::ArchSyntax::Intel).detail(true).build(),
        // ---- ARM / Thumb (bi-endian) ----
        (CsFamily::Arm, CsMode::ArmThumb) => Capstone::new()
            .arm().mode(arch::arm::ArchMode::Thumb).endian(endian).detail(true).build(),
        (CsFamily::Arm, _) => Capstone::new()
            .arm().mode(arch::arm::ArchMode::Arm).endian(endian).detail(true).build(),
        // ---- AArch64 (bi-endian) ----
        (CsFamily::Arm64, _) => Capstone::new()
            .arm64().mode(arch::arm64::ArchMode::Arm).endian(endian).detail(true).build(),
        // ---- MIPS (bi-endian) ----
        (CsFamily::Mips, CsMode::Mips64) => Capstone::new()
            .mips().mode(arch::mips::ArchMode::Mips64).endian(endian).detail(true).build(),
        (CsFamily::Mips, CsMode::Mips32R6) => Capstone::new()
            .mips().mode(arch::mips::ArchMode::Mips32R6).endian(endian).detail(true).build(),
        (CsFamily::Mips, _) => Capstone::new()
            .mips().mode(arch::mips::ArchMode::Mips32).endian(endian).detail(true).build(),
        // ---- PowerPC (bi-endian) ----
        (CsFamily::Ppc, CsMode::Ppc64) => Capstone::new()
            .ppc().mode(arch::ppc::ArchMode::Mode64).endian(endian).detail(true).build(),
        (CsFamily::Ppc, _) => Capstone::new()
            .ppc().mode(arch::ppc::ArchMode::Mode32).endian(endian).detail(true).build(),
        // ---- SPARC (big-endian only) ----
        (CsFamily::Sparc, CsMode::SparcV9) => Capstone::new()
            .sparc().mode(arch::sparc::ArchMode::V9).detail(true).build(),
        (CsFamily::Sparc, _) => Capstone::new()
            .sparc().mode(arch::sparc::ArchMode::Default).detail(true).build(),
        // ---- SystemZ / s390x ----
        (CsFamily::SysZ, _) => Capstone::new()
            .sysz().mode(arch::sysz::ArchMode::Default).detail(true).build(),
        // ---- m68k ----
        (CsFamily::M68k, CsMode::M68k040) => Capstone::new()
            .m68k().mode(arch::m68k::ArchMode::M68k040).detail(true).build(),
        (CsFamily::M68k, _) => Capstone::new()
            .m68k().mode(arch::m68k::ArchMode::M68k000).detail(true).build(),
        // ---- m680x ----
        (CsFamily::M680x, _) => Capstone::new()
            .m680x().mode(arch::m680x::ArchMode::M680x6809).detail(true).build(),
        // ---- XCore ----
        (CsFamily::Xcore, _) => Capstone::new()
            .xcore().mode(arch::xcore::ArchMode::Default).detail(true).build(),
        // ---- TMS320C64x ----
        (CsFamily::Tms320c64x, _) => Capstone::new()
            .tms320c64x().mode(arch::tms320c64x::ArchMode::Default).detail(true).build(),
        // ---- EVM ----
        (CsFamily::Evm, _) => Capstone::new()
            .evm().mode(arch::evm::ArchMode::Default).detail(true).build(),
        // ---- RISC-V (bi-endian) ----
        (CsFamily::RiscV, CsMode::RiscV32) => Capstone::new()
            .riscv().mode(arch::riscv::ArchMode::RiscV32).endian(endian).detail(true).build(),
        (CsFamily::RiscV, _) => Capstone::new()
            .riscv().mode(arch::riscv::ArchMode::RiscV64).endian(endian).detail(true).build(),
    };
    res.map_err(|e| DbgError::Capstone(format!("capstone init ({:?}/{:?}): {e}", t.family, t.mode)))
}
