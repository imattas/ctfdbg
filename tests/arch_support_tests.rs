//! Integration coverage for the BFD architecture registry and the
//! multi-architecture disassembler.

use ctfdbg::analysis::disasm::Disassembler;
use ctfdbg::target::arch::{Architecture, Endian};
use ctfdbg::target::bfd;

#[test]
fn registry_describes_many_architectures() {
    // We claim to recognise the binutils/BFD family set.
    assert!(bfd::count() >= 60, "only {} arches described", bfd::count());
    // A solid subset must have live disassembly.
    assert!(bfd::disassemblable_count() >= 13);
}

#[test]
fn lookup_by_name_and_alias() {
    assert_eq!(bfd::lookup("amd64").unwrap().arch, Architecture::X86_64);
    assert_eq!(bfd::lookup("x86_64").unwrap().arch, Architecture::X86_64);
    assert_eq!(bfd::lookup("mips64el").unwrap().byte_order, bfd::ByteOrder::Little);
    assert_eq!(bfd::lookup("sparc:v9").unwrap().bits_per_address, 64);
    assert!(bfd::lookup("definitely-not-an-arch").is_none());
}

#[test]
fn elf_machine_mapping_refines_endianness() {
    // EM_MIPS = 8; big- vs little-endian should map to distinct descriptors.
    let be = bfd::from_elf_machine(8, true).unwrap();
    let le = bfd::from_elf_machine(8, false).unwrap();
    assert_eq!(be.byte_order, bfd::ByteOrder::Big);
    assert_eq!(le.byte_order, bfd::ByteOrder::Little);
}

#[test]
fn disassembles_aarch64() {
    // ret  -> c0 03 5f d6 (little-endian)
    let dis = Disassembler::new(Architecture::AArch64).unwrap();
    let insns = dis.disassemble_all(&[0xc0, 0x03, 0x5f, 0xd6], 0x1000).unwrap();
    assert_eq!(insns.len(), 1);
    assert_eq!(insns[0].mnemonic, "ret");
}

#[test]
fn disassembles_mips_big_endian() {
    // jr $ra ; nop  (MIPS, big-endian): 03 e0 00 08 , 00 00 00 00
    let insns = ctfdbg::pwn::asm::disasm_named(
        "mips",
        Endian::Big,
        0x400000,
        &[0x03, 0xe0, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00],
    )
    .unwrap();
    assert!(insns.iter().any(|i| i.mnemonic.contains("jr")));
}

#[test]
fn descriptor_only_arch_reports_clearly() {
    // SuperH is described but has no capstone backend in this build.
    let msg = match Disassembler::for_named("sh", Endian::Little) {
        Ok(_) => panic!("expected SuperH to have no live disassembler"),
        Err(e) => format!("{e}"),
    };
    assert!(msg.contains("no live disassembler") || msg.contains("descriptor"));
}
