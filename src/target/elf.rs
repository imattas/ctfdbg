//! ELF parser via goblin (secondary format).

use crate::error::DbgResult;
use crate::target::arch::{Architecture, Endian};
use crate::target::binary::*;
use crate::target::format::FileFormat;
use crate::target::platform::Platform;
use goblin::elf::Elf;

pub fn parse_elf(bytes: &[u8], path: Option<std::path::PathBuf>) -> DbgResult<BinaryInfo> {
    let elf = Elf::parse(bytes)?;

    // Resolve via the full BFD architecture table (covers ~80 machines and
    // refines byte order), falling back to the legacy short list.
    let arch = crate::target::bfd::from_elf_machine(elf.header.e_machine, !elf.little_endian)
        .map(|a| a.arch)
        .filter(|a| !matches!(a, Architecture::Unsupported))
        .unwrap_or_else(|| match elf.header.e_machine {
            goblin::elf::header::EM_386 => Architecture::X86,
            goblin::elf::header::EM_X86_64 => Architecture::X86_64,
            goblin::elf::header::EM_ARM => Architecture::Arm,
            goblin::elf::header::EM_AARCH64 => Architecture::AArch64,
            goblin::elf::header::EM_RISCV => Architecture::Riscv64,
            _ => Architecture::Auto,
        });

    let sections = elf
        .section_headers
        .iter()
        .map(|sh| {
            let name = elf
                .shdr_strtab
                .get_at(sh.sh_name)
                .unwrap_or("")
                .to_string();
            let exec = sh.sh_flags & u64::from(goblin::elf::section_header::SHF_EXECINSTR) != 0;
            let write = sh.sh_flags & u64::from(goblin::elf::section_header::SHF_WRITE) != 0;
            let alloc = sh.sh_flags & u64::from(goblin::elf::section_header::SHF_ALLOC) != 0;
            let mut flags = String::new();
            if alloc { flags.push('R'); }
            if write { flags.push('W'); }
            if exec { flags.push('X'); }
            Section {
                name,
                virtual_address: sh.sh_addr,
                virtual_size: sh.sh_size,
                file_offset: sh.sh_offset,
                file_size: sh.sh_size,
                flags_text: flags,
                readable: alloc,
                writable: write,
                executable: exec,
            }
        })
        .collect();

    let mut symbols: Vec<Symbol> = vec![];
    for sym in elf.syms.iter() {
        if let Some(name) = elf.strtab.get_at(sym.st_name) {
            if name.is_empty() {
                continue;
            }
            symbols.push(Symbol {
                name: name.to_string(),
                address: sym.st_value,
                size: sym.st_size,
                is_function: sym.is_function(),
                is_imported: sym.st_shndx == 0,
                is_exported: sym.st_bind() == goblin::elf::sym::STB_GLOBAL,
            });
        }
    }

    Ok(BinaryInfo {
        path,
        format: FileFormat::Elf,
        architecture: arch,
        platform: Platform::Linux,
        endianness: if elf.little_endian { Endian::Little } else { Endian::Big },
        entry_point: elf.entry,
        preferred_image_base: 0,
        loaded_image_base: 0,
        sections,
        symbols,
        imports: vec![],
        exports: vec![],
        relocations: vec![],
        security: SecurityFeatures {
            dep_nx: !elf.program_headers.iter().any(|ph| {
                ph.p_type == goblin::elf::program_header::PT_GNU_STACK
                    && ph.p_flags & 1 != 0 // PF_X
            }),
            ..Default::default()
        },
        raw_size: bytes.len() as u64,
    })
}
