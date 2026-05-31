//! BFD-style architecture registry — a Rust port of the architecture
//! descriptors that binutils/BFD keeps in `bfd/archures.c`.
//!
//! BFD describes every target it understands with a `bfd_arch_info_type`
//! record: a printable name, the number of bits in a word / address / byte,
//! the default byte order, the ELF `e_machine` number, and a chain of
//! "machine" variants.  This module ports that table into a compile-time
//! [`ArchInfo`] array so ctfdbg can *recognise and describe* the full
//! binutils architecture set — roughly 80 families — even for targets it
//! cannot yet execute.
//!
//! Where a live disassembler exists (capstone backs 13 of these families),
//! the entry carries a [`CsTarget`] so [`crate::analysis::disasm`] can wire
//! up an actual decoder with the right mode and endianness.  For the rest,
//! the descriptor is still useful: format detection, word/pointer sizing,
//! endianness, and honest "descriptor known, no live decoder" reporting.
//!
//! This is intentionally faithful to BFD's data rather than to its C: the
//! opcode tables themselves (millions of lines under `opcodes/`) are not
//! ported; capstone (itself derived from LLVM) provides decoding.

use crate::target::arch::{Architecture, Endian};

/// Default byte order of an architecture, mirroring BFD's `enum bfd_endian`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ByteOrder {
    Big,
    Little,
    /// Architecture is byte-order agnostic (e.g. pure 8-bit cores).
    Endianless,
}

impl ByteOrder {
    pub fn to_endian(self) -> Endian {
        match self {
            ByteOrder::Big => Endian::Big,
            ByteOrder::Little | ByteOrder::Endianless => Endian::Little,
        }
    }
    pub fn name(self) -> &'static str {
        match self {
            ByteOrder::Big => "big",
            ByteOrder::Little => "little",
            ByteOrder::Endianless => "endianless",
        }
    }
}

/// capstone architecture family available in this build (capstone 0.12).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CsFamily {
    X86,
    Arm,
    Arm64,
    Mips,
    Ppc,
    Sparc,
    SysZ,
    M68k,
    M680x,
    Xcore,
    Tms320c64x,
    Evm,
    RiscV,
}

/// Concrete capstone decode mode (family + width + variant) used to build a
/// `Capstone` instance.  Endianness is supplied separately by [`CsTarget`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CsMode {
    X86_16,
    X86_32,
    X86_64,
    ArmArm,
    ArmThumb,
    Arm64,
    Mips32,
    Mips64,
    Mips32R6,
    Ppc32,
    Ppc64,
    SparcDefault,
    SparcV9,
    SysZ,
    M68k000,
    M68k040,
    M680x6809,
    Xcore,
    Tms320c64x,
    Evm,
    RiscV32,
    RiscV64,
}

/// A fully-specified live-disassembly target: family, mode, endianness.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CsTarget {
    pub family: CsFamily,
    pub mode: CsMode,
    pub big_endian: bool,
}

impl CsTarget {
    const fn le(family: CsFamily, mode: CsMode) -> Self {
        Self { family, mode, big_endian: false }
    }
    const fn be(family: CsFamily, mode: CsMode) -> Self {
        Self { family, mode, big_endian: true }
    }
    /// Return a copy with the endianness overridden (used when a file's
    /// header disagrees with the architecture default — e.g. MIPSEL).
    pub fn with_endian(mut self, endian: Endian) -> Self {
        match endian {
            Endian::Big => self.big_endian = true,
            Endian::Little => self.big_endian = false,
            Endian::Auto => {}
        }
        self
    }
}

/// One BFD architecture-family descriptor.
///
/// Mirrors the salient fields of `bfd_arch_info_type` plus the ELF machine
/// number and (optionally) a capstone backend.
#[derive(Debug, Clone, Copy)]
pub struct ArchInfo {
    /// Canonical BFD name, e.g. `"powerpc:common64"` is shortened here to the
    /// family head `"powerpc"`; full mach names live in [`Self::aliases`].
    pub name: &'static str,
    /// Human-facing printable name (BFD's `printable_name`).
    pub printable: &'static str,
    /// Common aliases / mach names accepted by [`lookup`].
    pub aliases: &'static [&'static str],
    pub bits_per_word: u16,
    pub bits_per_address: u16,
    pub bits_per_byte: u8,
    pub byte_order: ByteOrder,
    /// ELF `e_machine` value, when this family has an ELF binding.
    pub elf_machine: Option<u16>,
    /// Live disassembler backend, when one is available.
    pub cs: Option<CsTarget>,
    /// Closest variant of the small [`Architecture`] enum used by the live
    /// debugger UI / register model.
    pub arch: Architecture,
}

impl ArchInfo {
    pub fn pointer_size(&self) -> usize {
        (self.bits_per_address / 8) as usize
    }
    pub fn has_disassembler(&self) -> bool {
        self.cs.is_some()
    }
    /// Live-disassembly target with the file's endianness applied if the
    /// architecture supports both byte orders.
    pub fn cs_target(&self, endian: Endian) -> Option<CsTarget> {
        self.cs.map(|t| t.with_endian(endian))
    }
}

// ELF e_machine constants (subset of the values in <elf.h>).  Kept local so
// we do not depend on goblin exposing every one of them.
mod em {
    pub const M32: u16 = 1;
    pub const SPARC: u16 = 2;
    pub const I386: u16 = 3;
    pub const M68K: u16 = 4;
    pub const M88K: u16 = 5;
    pub const I860: u16 = 7;
    pub const MIPS: u16 = 8;
    pub const MIPS_RS3_LE: u16 = 10;
    pub const PARISC: u16 = 15;
    pub const SPARC32PLUS: u16 = 18;
    pub const PPC: u16 = 20;
    pub const PPC64: u16 = 21;
    pub const S390: u16 = 22;
    pub const SPU: u16 = 23;
    pub const ARM: u16 = 40;
    pub const SH: u16 = 42;
    pub const SPARCV9: u16 = 43;
    pub const TRICORE: u16 = 44;
    pub const ARC: u16 = 45;
    pub const H8_300: u16 = 46;
    pub const IA_64: u16 = 50;
    pub const X86_64: u16 = 62;
    pub const PDP11: u16 = 65;
    pub const VAX: u16 = 75;
    pub const CRIS: u16 = 76;
    pub const MMIX: u16 = 80;
    pub const AVR: u16 = 83;
    pub const FR30: u16 = 84;
    pub const D10V: u16 = 85;
    pub const D30V: u16 = 86;
    pub const V850: u16 = 87;
    pub const M32R: u16 = 88;
    pub const MN10300: u16 = 89;
    pub const MN10200: u16 = 90;
    pub const PJ: u16 = 91;
    pub const OPENRISC: u16 = 92;
    pub const XTENSA: u16 = 94;
    pub const NS32K: u16 = 97;
    pub const IP2K: u16 = 101;
    pub const MSP430: u16 = 105;
    pub const BLACKFIN: u16 = 106;
    pub const ALTERA_NIOS2: u16 = 113;
    pub const XGATE: u16 = 115;
    pub const M32C: u16 = 120;
    pub const SCORE7: u16 = 135;
    pub const LATTICEMICO32: u16 = 138;
    pub const TI_C6000: u16 = 140;
    pub const NDS32: u16 = 167;
    pub const RX: u16 = 173;
    pub const METAG: u16 = 174;
    pub const CR16: u16 = 177;
    pub const AARCH64: u16 = 183;
    pub const TILEPRO: u16 = 188;
    pub const MICROBLAZE: u16 = 189;
    pub const TILEGX: u16 = 191;
    pub const RL78: u16 = 197;
    pub const XCORE: u16 = 203;
    pub const FT32: u16 = 222;
    pub const MOXIE: u16 = 223;
    pub const RISCV: u16 = 243;
    pub const BPF: u16 = 247;
    pub const CSKY: u16 = 252;
    pub const LOONGARCH: u16 = 258;
    pub const Z80: u16 = 220;
    pub const VISIUM: u16 = 221;
    pub const FRV: u16 = 0x5441;
    pub const IQ2000: u16 = 0xFEBA;
    pub const M68HC11: u16 = 0x6811;
    pub const ALPHA: u16 = 0x9026;
}

// Convenience constructors keep the big table readable.
const fn cs_le(f: CsFamily, m: CsMode) -> Option<CsTarget> {
    Some(CsTarget::le(f, m))
}
const fn cs_be(f: CsFamily, m: CsMode) -> Option<CsTarget> {
    Some(CsTarget::be(f, m))
}

use Architecture as A;
use ByteOrder::{Big, Little};
use CsFamily as F;
use CsMode as M;

/// The architecture table — a port of BFD's family descriptors.
///
/// Entries are ordered roughly as in `bfd/archures.c`.  Capstone-backed
/// families carry a [`CsTarget`]; the remainder are descriptor-only.
pub static ARCHS: &[ArchInfo] = &[
    // ------------------------------------------------------------- x86 ----
    ArchInfo { name: "i386", printable: "Intel 386", aliases: &["x86", "i486", "i686", "ia32"],
        bits_per_word: 32, bits_per_address: 32, bits_per_byte: 8, byte_order: Little,
        elf_machine: Some(em::I386), cs: cs_le(F::X86, M::X86_32), arch: A::X86 },
    ArchInfo { name: "i386:x86-64", printable: "AMD x86-64", aliases: &["x86_64", "x64", "amd64"],
        bits_per_word: 64, bits_per_address: 64, bits_per_byte: 8, byte_order: Little,
        elf_machine: Some(em::X86_64), cs: cs_le(F::X86, M::X86_64), arch: A::X86_64 },
    ArchInfo { name: "i8086", printable: "Intel 8086 (16-bit)", aliases: &["8086", "i286", "real-mode"],
        bits_per_word: 16, bits_per_address: 16, bits_per_byte: 8, byte_order: Little,
        elf_machine: None, cs: cs_le(F::X86, M::X86_16), arch: A::X86 },
    // ------------------------------------------------------------- ARM ----
    ArchInfo { name: "arm", printable: "ARM (AArch32)", aliases: &["armv7", "armle", "arm32"],
        bits_per_word: 32, bits_per_address: 32, bits_per_byte: 8, byte_order: Little,
        elf_machine: Some(em::ARM), cs: cs_le(F::Arm, M::ArmArm), arch: A::Arm },
    ArchInfo { name: "armeb", printable: "ARM (big-endian)", aliases: &["armbe", "armv7eb"],
        bits_per_word: 32, bits_per_address: 32, bits_per_byte: 8, byte_order: Big,
        elf_machine: Some(em::ARM), cs: cs_be(F::Arm, M::ArmArm), arch: A::Arm },
    ArchInfo { name: "thumb", printable: "ARM Thumb", aliases: &["armthumb", "thumb2"],
        bits_per_word: 32, bits_per_address: 32, bits_per_byte: 8, byte_order: Little,
        elf_machine: Some(em::ARM), cs: cs_le(F::Arm, M::ArmThumb), arch: A::Thumb },
    ArchInfo { name: "aarch64", printable: "AArch64 (ARM64)", aliases: &["arm64", "armv8"],
        bits_per_word: 64, bits_per_address: 64, bits_per_byte: 8, byte_order: Little,
        elf_machine: Some(em::AARCH64), cs: cs_le(F::Arm64, M::Arm64), arch: A::AArch64 },
    ArchInfo { name: "aarch64_be", printable: "AArch64 (big-endian)", aliases: &["arm64be", "arm64_be"],
        bits_per_word: 64, bits_per_address: 64, bits_per_byte: 8, byte_order: Big,
        elf_machine: Some(em::AARCH64), cs: cs_be(F::Arm64, M::Arm64), arch: A::AArch64 },
    // ------------------------------------------------------------ MIPS ----
    ArchInfo { name: "mips", printable: "MIPS (big-endian)", aliases: &["mips32", "mipseb"],
        bits_per_word: 32, bits_per_address: 32, bits_per_byte: 8, byte_order: Big,
        elf_machine: Some(em::MIPS), cs: cs_be(F::Mips, M::Mips32), arch: A::Mips },
    ArchInfo { name: "mipsel", printable: "MIPS (little-endian)", aliases: &["mipsle", "mips32el"],
        bits_per_word: 32, bits_per_address: 32, bits_per_byte: 8, byte_order: Little,
        elf_machine: Some(em::MIPS_RS3_LE), cs: cs_le(F::Mips, M::Mips32), arch: A::Mips },
    ArchInfo { name: "mips64", printable: "MIPS64 (big-endian)", aliases: &["mips3", "mips4"],
        bits_per_word: 64, bits_per_address: 64, bits_per_byte: 8, byte_order: Big,
        elf_machine: Some(em::MIPS), cs: cs_be(F::Mips, M::Mips64), arch: A::Mips64 },
    ArchInfo { name: "mips64el", printable: "MIPS64 (little-endian)", aliases: &["mips64le"],
        bits_per_word: 64, bits_per_address: 64, bits_per_byte: 8, byte_order: Little,
        elf_machine: Some(em::MIPS), cs: cs_le(F::Mips, M::Mips64), arch: A::Mips64 },
    ArchInfo { name: "mips:isa32r6", printable: "MIPS32 Release 6", aliases: &["mips32r6"],
        bits_per_word: 32, bits_per_address: 32, bits_per_byte: 8, byte_order: Big,
        elf_machine: Some(em::MIPS), cs: cs_be(F::Mips, M::Mips32R6), arch: A::Mips },
    // ----------------------------------------------------------- PowerPC --
    ArchInfo { name: "powerpc", printable: "PowerPC (32-bit)", aliases: &["ppc", "ppc32"],
        bits_per_word: 32, bits_per_address: 32, bits_per_byte: 8, byte_order: Big,
        elf_machine: Some(em::PPC), cs: cs_be(F::Ppc, M::Ppc32), arch: A::PowerPc },
    ArchInfo { name: "powerpc:common64", printable: "PowerPC (64-bit)", aliases: &["ppc64"],
        bits_per_word: 64, bits_per_address: 64, bits_per_byte: 8, byte_order: Big,
        elf_machine: Some(em::PPC64), cs: cs_be(F::Ppc, M::Ppc64), arch: A::PowerPc64 },
    ArchInfo { name: "powerpcle", printable: "PowerPC (64-bit LE)", aliases: &["ppc64le", "ppcle"],
        bits_per_word: 64, bits_per_address: 64, bits_per_byte: 8, byte_order: Little,
        elf_machine: Some(em::PPC64), cs: cs_le(F::Ppc, M::Ppc64), arch: A::PowerPc64 },
    // ------------------------------------------------------------ SPARC ---
    ArchInfo { name: "sparc", printable: "SPARC (32-bit)", aliases: &["sparc32"],
        bits_per_word: 32, bits_per_address: 32, bits_per_byte: 8, byte_order: Big,
        elf_machine: Some(em::SPARC), cs: cs_be(F::Sparc, M::SparcDefault), arch: A::Sparc },
    ArchInfo { name: "sparc:v9", printable: "SPARC V9 (64-bit)", aliases: &["sparc64", "sparcv9"],
        bits_per_word: 64, bits_per_address: 64, bits_per_byte: 8, byte_order: Big,
        elf_machine: Some(em::SPARCV9), cs: cs_be(F::Sparc, M::SparcV9), arch: A::Sparc64 },
    ArchInfo { name: "sparc:sparclite", printable: "SPARClite", aliases: &["sparclite"],
        bits_per_word: 32, bits_per_address: 32, bits_per_byte: 8, byte_order: Big,
        elf_machine: Some(em::SPARC32PLUS), cs: cs_be(F::Sparc, M::SparcDefault), arch: A::Sparc },
    // ---------------------------------------------------------- SystemZ ---
    ArchInfo { name: "s390:64-bit", printable: "IBM S/390 (z/Architecture)", aliases: &["s390x", "systemz", "sysz"],
        bits_per_word: 64, bits_per_address: 64, bits_per_byte: 8, byte_order: Big,
        elf_machine: Some(em::S390), cs: cs_be(F::SysZ, M::SysZ), arch: A::SystemZ },
    ArchInfo { name: "s390:31-bit", printable: "IBM S/390 (31-bit)", aliases: &["s390"],
        bits_per_word: 32, bits_per_address: 32, bits_per_byte: 8, byte_order: Big,
        elf_machine: Some(em::S390), cs: cs_be(F::SysZ, M::SysZ), arch: A::SystemZ },
    // ----------------------------------------------------------- m68k -----
    ArchInfo { name: "m68k", printable: "Motorola 68000", aliases: &["68000", "m68000"],
        bits_per_word: 32, bits_per_address: 32, bits_per_byte: 8, byte_order: Big,
        elf_machine: Some(em::M68K), cs: cs_be(F::M68k, M::M68k000), arch: A::M68k },
    ArchInfo { name: "m68k:68040", printable: "Motorola 68040", aliases: &["68040", "m68040"],
        bits_per_word: 32, bits_per_address: 32, bits_per_byte: 8, byte_order: Big,
        elf_machine: Some(em::M68K), cs: cs_be(F::M68k, M::M68k040), arch: A::M68k },
    ArchInfo { name: "m68hc11", printable: "Motorola 68HC11", aliases: &["68hc11"],
        bits_per_word: 16, bits_per_address: 16, bits_per_byte: 8, byte_order: Big,
        elf_machine: Some(em::M68HC11), cs: cs_be(F::M680x, M::M680x6809), arch: A::Unsupported },
    ArchInfo { name: "m6809", printable: "Motorola 6809", aliases: &["6809", "m680x"],
        bits_per_word: 16, bits_per_address: 16, bits_per_byte: 8, byte_order: Big,
        elf_machine: None, cs: cs_be(F::M680x, M::M680x6809), arch: A::Unsupported },
    // ----------------------------------------------------------- RISC-V ---
    ArchInfo { name: "riscv", printable: "RISC-V (64-bit)", aliases: &["riscv64", "rv64"],
        bits_per_word: 64, bits_per_address: 64, bits_per_byte: 8, byte_order: Little,
        elf_machine: Some(em::RISCV), cs: cs_le(F::RiscV, M::RiscV64), arch: A::Riscv64 },
    ArchInfo { name: "riscv:rv32", printable: "RISC-V (32-bit)", aliases: &["riscv32", "rv32"],
        bits_per_word: 32, bits_per_address: 32, bits_per_byte: 8, byte_order: Little,
        elf_machine: Some(em::RISCV), cs: cs_le(F::RiscV, M::RiscV32), arch: A::Riscv32 },
    // ------------------------------------------------------------ XCore ---
    ArchInfo { name: "xcore", printable: "XMOS XCore", aliases: &["xc"],
        bits_per_word: 32, bits_per_address: 32, bits_per_byte: 8, byte_order: Big,
        elf_machine: Some(em::XCORE), cs: cs_be(F::Xcore, M::Xcore), arch: A::Unsupported },
    // -------------------------------------------------------- TMS320C64x --
    ArchInfo { name: "tic6x", printable: "TI TMS320C64x DSP", aliases: &["tms320c64x", "c6x", "c64x"],
        bits_per_word: 32, bits_per_address: 32, bits_per_byte: 8, byte_order: Little,
        elf_machine: Some(em::TI_C6000), cs: cs_le(F::Tms320c64x, M::Tms320c64x), arch: A::Unsupported },
    // ------------------------------------------------------------- EVM ----
    ArchInfo { name: "evm", printable: "Ethereum VM bytecode", aliases: &["ethereum"],
        bits_per_word: 256, bits_per_address: 256, bits_per_byte: 8, byte_order: Big,
        elf_machine: None, cs: cs_be(F::Evm, M::Evm), arch: A::Unsupported },
    // ==================================================================
    // Descriptor-only families: recognised and described, decoded by BFD
    // upstream but without a capstone backend in this build.
    // ==================================================================
    ArchInfo { name: "alpha", printable: "DEC Alpha", aliases: &["alpha-ev6"],
        bits_per_word: 64, bits_per_address: 64, bits_per_byte: 8, byte_order: Little,
        elf_machine: Some(em::ALPHA), cs: None, arch: A::Unsupported },
    ArchInfo { name: "hppa", printable: "HP PA-RISC", aliases: &["parisc", "hppa2.0"],
        bits_per_word: 32, bits_per_address: 32, bits_per_byte: 8, byte_order: Big,
        elf_machine: Some(em::PARISC), cs: None, arch: A::Unsupported },
    ArchInfo { name: "ia64", printable: "Intel IA-64 (Itanium)", aliases: &["itanium", "ia-64"],
        bits_per_word: 64, bits_per_address: 64, bits_per_byte: 8, byte_order: Little,
        elf_machine: Some(em::IA_64), cs: None, arch: A::Unsupported },
    ArchInfo { name: "sh", printable: "Renesas / Hitachi SuperH", aliases: &["sh4", "superh"],
        bits_per_word: 32, bits_per_address: 32, bits_per_byte: 8, byte_order: Little,
        elf_machine: Some(em::SH), cs: None, arch: A::SuperH },
    ArchInfo { name: "arc", printable: "Synopsys ARC", aliases: &["arcompact", "arcv2"],
        bits_per_word: 32, bits_per_address: 32, bits_per_byte: 8, byte_order: Little,
        elf_machine: Some(em::ARC), cs: None, arch: A::Unsupported },
    ArchInfo { name: "avr", printable: "Atmel AVR", aliases: &["atmega", "attiny"],
        bits_per_word: 16, bits_per_address: 16, bits_per_byte: 8, byte_order: Little,
        elf_machine: Some(em::AVR), cs: None, arch: A::Unsupported },
    ArchInfo { name: "msp430", printable: "TI MSP430", aliases: &["msp"],
        bits_per_word: 16, bits_per_address: 16, bits_per_byte: 8, byte_order: Little,
        elf_machine: Some(em::MSP430), cs: None, arch: A::Unsupported },
    ArchInfo { name: "xtensa", printable: "Tensilica Xtensa", aliases: &["lx6", "lx106"],
        bits_per_word: 32, bits_per_address: 32, bits_per_byte: 8, byte_order: Little,
        elf_machine: Some(em::XTENSA), cs: None, arch: A::Unsupported },
    ArchInfo { name: "microblaze", printable: "Xilinx MicroBlaze", aliases: &["mb"],
        bits_per_word: 32, bits_per_address: 32, bits_per_byte: 8, byte_order: Big,
        elf_machine: Some(em::MICROBLAZE), cs: None, arch: A::Unsupported },
    ArchInfo { name: "nios2", printable: "Altera Nios II", aliases: &["nios"],
        bits_per_word: 32, bits_per_address: 32, bits_per_byte: 8, byte_order: Little,
        elf_machine: Some(em::ALTERA_NIOS2), cs: None, arch: A::Unsupported },
    ArchInfo { name: "or1k", printable: "OpenRISC 1000", aliases: &["openrisc", "or1200"],
        bits_per_word: 32, bits_per_address: 32, bits_per_byte: 8, byte_order: Big,
        elf_machine: Some(em::OPENRISC), cs: None, arch: A::Unsupported },
    ArchInfo { name: "loongarch", printable: "LoongArch", aliases: &["la64", "loongarch64"],
        bits_per_word: 64, bits_per_address: 64, bits_per_byte: 8, byte_order: Little,
        elf_machine: Some(em::LOONGARCH), cs: None, arch: A::Unsupported },
    ArchInfo { name: "csky", printable: "C-SKY", aliases: &["mcore"],
        bits_per_word: 32, bits_per_address: 32, bits_per_byte: 8, byte_order: Little,
        elf_machine: Some(em::CSKY), cs: None, arch: A::Unsupported },
    ArchInfo { name: "bpf", printable: "Linux eBPF", aliases: &["ebpf"],
        bits_per_word: 64, bits_per_address: 64, bits_per_byte: 8, byte_order: Little,
        elf_machine: Some(em::BPF), cs: None, arch: A::Unsupported },
    ArchInfo { name: "nds32", printable: "Andes NDS32", aliases: &["andes"],
        bits_per_word: 32, bits_per_address: 32, bits_per_byte: 8, byte_order: Little,
        elf_machine: Some(em::NDS32), cs: None, arch: A::Unsupported },
    ArchInfo { name: "rx", printable: "Renesas RX", aliases: &[],
        bits_per_word: 32, bits_per_address: 32, bits_per_byte: 8, byte_order: Little,
        elf_machine: Some(em::RX), cs: None, arch: A::Unsupported },
    ArchInfo { name: "rl78", printable: "Renesas RL78", aliases: &[],
        bits_per_word: 16, bits_per_address: 16, bits_per_byte: 8, byte_order: Little,
        elf_machine: Some(em::RL78), cs: None, arch: A::Unsupported },
    ArchInfo { name: "v850", printable: "Renesas V850", aliases: &["v850e"],
        bits_per_word: 32, bits_per_address: 32, bits_per_byte: 8, byte_order: Little,
        elf_machine: Some(em::V850), cs: None, arch: A::Unsupported },
    ArchInfo { name: "m32r", printable: "Renesas M32R", aliases: &[],
        bits_per_word: 32, bits_per_address: 32, bits_per_byte: 8, byte_order: Big,
        elf_machine: Some(em::M32R), cs: None, arch: A::Unsupported },
    ArchInfo { name: "m32c", printable: "Renesas M32C", aliases: &["m16c"],
        bits_per_word: 32, bits_per_address: 24, bits_per_byte: 8, byte_order: Little,
        elf_machine: Some(em::M32C), cs: None, arch: A::Unsupported },
    ArchInfo { name: "h8300", printable: "Renesas H8/300", aliases: &["h8"],
        bits_per_word: 16, bits_per_address: 16, bits_per_byte: 8, byte_order: Big,
        elf_machine: Some(em::H8_300), cs: None, arch: A::Unsupported },
    ArchInfo { name: "cris", printable: "Axis CRIS", aliases: &["crisv32"],
        bits_per_word: 32, bits_per_address: 32, bits_per_byte: 8, byte_order: Little,
        elf_machine: Some(em::CRIS), cs: None, arch: A::Unsupported },
    ArchInfo { name: "mmix", printable: "Donald Knuth's MMIX", aliases: &[],
        bits_per_word: 64, bits_per_address: 64, bits_per_byte: 8, byte_order: Big,
        elf_machine: Some(em::MMIX), cs: None, arch: A::Unsupported },
    ArchInfo { name: "frv", printable: "Fujitsu FR-V", aliases: &["fr500"],
        bits_per_word: 32, bits_per_address: 32, bits_per_byte: 8, byte_order: Big,
        elf_machine: Some(em::FRV), cs: None, arch: A::Unsupported },
    ArchInfo { name: "fr30", printable: "Fujitsu FR30", aliases: &[],
        bits_per_word: 32, bits_per_address: 32, bits_per_byte: 8, byte_order: Big,
        elf_machine: Some(em::FR30), cs: None, arch: A::Unsupported },
    ArchInfo { name: "vax", printable: "DEC VAX", aliases: &[],
        bits_per_word: 32, bits_per_address: 32, bits_per_byte: 8, byte_order: Little,
        elf_machine: Some(em::VAX), cs: None, arch: A::Unsupported },
    ArchInfo { name: "pdp11", printable: "DEC PDP-11", aliases: &[],
        bits_per_word: 16, bits_per_address: 16, bits_per_byte: 8, byte_order: Little,
        elf_machine: Some(em::PDP11), cs: None, arch: A::Unsupported },
    ArchInfo { name: "ns32k", printable: "National Semiconductor 32000", aliases: &["32k"],
        bits_per_word: 32, bits_per_address: 32, bits_per_byte: 8, byte_order: Little,
        elf_machine: Some(em::NS32K), cs: None, arch: A::Unsupported },
    ArchInfo { name: "i860", printable: "Intel i860", aliases: &[],
        bits_per_word: 32, bits_per_address: 32, bits_per_byte: 8, byte_order: Big,
        elf_machine: Some(em::I860), cs: None, arch: A::Unsupported },
    ArchInfo { name: "i960", printable: "Intel i960", aliases: &["960"],
        bits_per_word: 32, bits_per_address: 32, bits_per_byte: 8, byte_order: Little,
        elf_machine: None, cs: None, arch: A::Unsupported },
    ArchInfo { name: "m88k", printable: "Motorola 88000", aliases: &["88k"],
        bits_per_word: 32, bits_per_address: 32, bits_per_byte: 8, byte_order: Big,
        elf_machine: Some(em::M88K), cs: None, arch: A::Unsupported },
    ArchInfo { name: "tilegx", printable: "Tilera TILE-Gx", aliases: &["tile-gx"],
        bits_per_word: 64, bits_per_address: 64, bits_per_byte: 8, byte_order: Little,
        elf_machine: Some(em::TILEGX), cs: None, arch: A::Unsupported },
    ArchInfo { name: "tilepro", printable: "Tilera TILEPro", aliases: &[],
        bits_per_word: 32, bits_per_address: 32, bits_per_byte: 8, byte_order: Little,
        elf_machine: Some(em::TILEPRO), cs: None, arch: A::Unsupported },
    ArchInfo { name: "spu", printable: "Cell Broadband Engine SPU", aliases: &[],
        bits_per_word: 32, bits_per_address: 32, bits_per_byte: 8, byte_order: Big,
        elf_machine: Some(em::SPU), cs: None, arch: A::Unsupported },
    ArchInfo { name: "blackfin", printable: "Analog Devices Blackfin", aliases: &["bfin"],
        bits_per_word: 32, bits_per_address: 32, bits_per_byte: 8, byte_order: Little,
        elf_machine: Some(em::BLACKFIN), cs: None, arch: A::Unsupported },
    ArchInfo { name: "tic30", printable: "TI TMS320C30 DSP", aliases: &["c30"],
        bits_per_word: 32, bits_per_address: 32, bits_per_byte: 8, byte_order: Big,
        elf_machine: None, cs: None, arch: A::Unsupported },
    ArchInfo { name: "tic54x", printable: "TI TMS320C54x DSP", aliases: &["c54x"],
        bits_per_word: 16, bits_per_address: 16, bits_per_byte: 8, byte_order: Little,
        elf_machine: None, cs: None, arch: A::Unsupported },
    ArchInfo { name: "z80", printable: "Zilog Z80", aliases: &["z180", "gbz80"],
        bits_per_word: 8, bits_per_address: 16, bits_per_byte: 8, byte_order: Little,
        elf_machine: Some(em::Z80), cs: None, arch: A::Unsupported },
    ArchInfo { name: "z8k", printable: "Zilog Z8000", aliases: &["z8000"],
        bits_per_word: 16, bits_per_address: 16, bits_per_byte: 8, byte_order: Big,
        elf_machine: None, cs: None, arch: A::Unsupported },
    ArchInfo { name: "moxie", printable: "Moxie", aliases: &[],
        bits_per_word: 32, bits_per_address: 32, bits_per_byte: 8, byte_order: Big,
        elf_machine: Some(em::MOXIE), cs: None, arch: A::Unsupported },
    ArchInfo { name: "ft32", printable: "FTDI FT32", aliases: &[],
        bits_per_word: 32, bits_per_address: 32, bits_per_byte: 8, byte_order: Little,
        elf_machine: Some(em::FT32), cs: None, arch: A::Unsupported },
    ArchInfo { name: "lm32", printable: "Lattice Mico32", aliases: &["mico32"],
        bits_per_word: 32, bits_per_address: 32, bits_per_byte: 8, byte_order: Big,
        elf_machine: Some(em::LATTICEMICO32), cs: None, arch: A::Unsupported },
    ArchInfo { name: "metag", printable: "Imagination META", aliases: &[],
        bits_per_word: 32, bits_per_address: 32, bits_per_byte: 8, byte_order: Little,
        elf_machine: Some(em::METAG), cs: None, arch: A::Unsupported },
    ArchInfo { name: "cr16", printable: "National Semiconductor CR16", aliases: &[],
        bits_per_word: 16, bits_per_address: 32, bits_per_byte: 8, byte_order: Little,
        elf_machine: Some(em::CR16), cs: None, arch: A::Unsupported },
    ArchInfo { name: "visium", printable: "CDS VISIUMcore", aliases: &[],
        bits_per_word: 32, bits_per_address: 32, bits_per_byte: 8, byte_order: Big,
        elf_machine: Some(em::VISIUM), cs: None, arch: A::Unsupported },
    ArchInfo { name: "iq2000", printable: "Vitesse IQ2000", aliases: &[],
        bits_per_word: 32, bits_per_address: 32, bits_per_byte: 8, byte_order: Big,
        elf_machine: Some(em::IQ2000), cs: None, arch: A::Unsupported },
    ArchInfo { name: "ip2k", printable: "Ubicom IP2000", aliases: &["ip2022"],
        bits_per_word: 16, bits_per_address: 16, bits_per_byte: 8, byte_order: Big,
        elf_machine: Some(em::IP2K), cs: None, arch: A::Unsupported },
    ArchInfo { name: "mn10300", printable: "Matsushita MN10300", aliases: &["am33"],
        bits_per_word: 32, bits_per_address: 32, bits_per_byte: 8, byte_order: Little,
        elf_machine: Some(em::MN10300), cs: None, arch: A::Unsupported },
    ArchInfo { name: "mn10200", printable: "Matsushita MN10200", aliases: &[],
        bits_per_word: 32, bits_per_address: 32, bits_per_byte: 8, byte_order: Little,
        elf_machine: Some(em::MN10200), cs: None, arch: A::Unsupported },
    ArchInfo { name: "d10v", printable: "Mitsubishi D10V", aliases: &[],
        bits_per_word: 16, bits_per_address: 16, bits_per_byte: 8, byte_order: Big,
        elf_machine: Some(em::D10V), cs: None, arch: A::Unsupported },
    ArchInfo { name: "d30v", printable: "Mitsubishi D30V", aliases: &[],
        bits_per_word: 32, bits_per_address: 32, bits_per_byte: 8, byte_order: Big,
        elf_machine: Some(em::D30V), cs: None, arch: A::Unsupported },
    ArchInfo { name: "pj", printable: "picoJava", aliases: &["picojava"],
        bits_per_word: 32, bits_per_address: 32, bits_per_byte: 8, byte_order: Big,
        elf_machine: Some(em::PJ), cs: None, arch: A::Unsupported },
    ArchInfo { name: "score", printable: "Sunplus S+core", aliases: &["score7"],
        bits_per_word: 32, bits_per_address: 32, bits_per_byte: 8, byte_order: Big,
        elf_machine: Some(em::SCORE7), cs: None, arch: A::Unsupported },
    ArchInfo { name: "xgate", printable: "Freescale XGATE", aliases: &[],
        bits_per_word: 16, bits_per_address: 16, bits_per_byte: 8, byte_order: Big,
        elf_machine: Some(em::XGATE), cs: None, arch: A::Unsupported },
    ArchInfo { name: "tricore", printable: "Infineon TriCore", aliases: &[],
        bits_per_word: 32, bits_per_address: 32, bits_per_byte: 8, byte_order: Little,
        elf_machine: Some(em::TRICORE), cs: None, arch: A::Unsupported },
    ArchInfo { name: "m32", printable: "AT&T WE32000", aliases: &["we32k"],
        bits_per_word: 32, bits_per_address: 32, bits_per_byte: 8, byte_order: Big,
        elf_machine: Some(em::M32), cs: None, arch: A::Unsupported },
    ArchInfo { name: "wasm32", printable: "WebAssembly (32-bit)", aliases: &["wasm"],
        bits_per_word: 32, bits_per_address: 32, bits_per_byte: 8, byte_order: Little,
        elf_machine: None, cs: None, arch: A::Unsupported },
];

/// Total number of architecture families described.
pub fn count() -> usize {
    ARCHS.len()
}

/// Number of families with a working live disassembler.
pub fn disassemblable_count() -> usize {
    ARCHS.iter().filter(|a| a.has_disassembler()).count()
}

/// Look up a descriptor by canonical name or any alias (case-insensitive).
pub fn lookup(name: &str) -> Option<&'static ArchInfo> {
    let n = name.trim().to_ascii_lowercase();
    ARCHS.iter().find(|a| {
        a.name.eq_ignore_ascii_case(&n)
            || a.printable.eq_ignore_ascii_case(&n)
            || a.aliases.iter().any(|x| x.eq_ignore_ascii_case(&n))
    })
}

/// Map an ELF `e_machine` value to the best descriptor, refining the byte
/// order with the file's actual endianness when the family is bi-endian.
pub fn from_elf_machine(machine: u16, big_endian: bool) -> Option<&'static ArchInfo> {
    let want = if big_endian { ByteOrder::Big } else { ByteOrder::Little };
    let mut fallback = None;
    for a in ARCHS {
        if a.elf_machine == Some(machine) {
            if a.byte_order == want || a.byte_order == ByteOrder::Endianless {
                return Some(a);
            }
            fallback.get_or_insert(a);
        }
    }
    fallback
}

/// Find the descriptor that best matches a small [`Architecture`] enum value.
pub fn for_architecture(arch: Architecture) -> Option<&'static ArchInfo> {
    ARCHS.iter().find(|a| a.arch == arch && a.cs.is_some())
}
