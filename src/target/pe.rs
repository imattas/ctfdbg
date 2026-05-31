//! PE/COFF parser using goblin.

use crate::error::DbgResult;
use crate::target::arch::{Architecture, Endian};
use crate::target::binary::*;
use crate::target::format::FileFormat;
use crate::target::platform::Platform;
use goblin::pe::PE;

pub fn parse_pe(bytes: &[u8], path: Option<std::path::PathBuf>) -> DbgResult<BinaryInfo> {
    let pe = PE::parse(bytes)?;
    let arch = if pe.is_64 { Architecture::X86_64 } else { Architecture::X86 };
    let oh = pe.header.optional_header;

    let preferred_base = oh.map(|h| h.windows_fields.image_base).unwrap_or(0);
    let entry = pe.entry as u64;
    let dll_chars = oh.map(|h| h.windows_fields.dll_characteristics).unwrap_or(0);

    // DLL characteristics flags
    const IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA: u16 = 0x0020;
    const IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE: u16 = 0x0040;
    const IMAGE_DLLCHARACTERISTICS_NX_COMPAT: u16 = 0x0100;
    const IMAGE_DLLCHARACTERISTICS_NO_SEH: u16 = 0x0400;
    const IMAGE_DLLCHARACTERISTICS_GUARD_CF: u16 = 0x4000;

    let security = SecurityFeatures {
        aslr: dll_chars & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE != 0,
        dep_nx: dll_chars & IMAGE_DLLCHARACTERISTICS_NX_COMPAT != 0,
        cfg: dll_chars & IMAGE_DLLCHARACTERISTICS_GUARD_CF != 0,
        safe_seh: dll_chars & IMAGE_DLLCHARACTERISTICS_NO_SEH == 0,
        high_entropy_va: dll_chars & IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA != 0,
        gs_cookie_hint: false,
        authenticode_signed_hint: pe.header.coff_header.pointer_to_symbol_table != 0,
    };

    let sections = pe
        .sections
        .iter()
        .map(|s| {
            let name = String::from_utf8_lossy(&s.name)
                .trim_end_matches('\0')
                .to_string();
            let chars = s.characteristics;
            let read = chars & 0x4000_0000 != 0;
            let write = chars & 0x8000_0000 != 0;
            let exec = chars & 0x2000_0000 != 0;
            let mut flags = String::new();
            if read { flags.push('R'); }
            if write { flags.push('W'); }
            if exec { flags.push('X'); }
            Section {
                name,
                virtual_address: preferred_base.saturating_add(s.virtual_address as u64),
                virtual_size: s.virtual_size as u64,
                file_offset: s.pointer_to_raw_data as u64,
                file_size: s.size_of_raw_data as u64,
                flags_text: flags,
                readable: read,
                writable: write,
                executable: exec,
            }
        })
        .collect();

    let imports = pe
        .imports
        .iter()
        .map(|imp| ImportEntry {
            library: imp.dll.to_string(),
            name: imp.name.to_string(),
            address: preferred_base.saturating_add(imp.rva as u64),
            ordinal: if imp.ordinal != 0 { Some(imp.ordinal) } else { None },
        })
        .collect();

    let exports = pe
        .exports
        .iter()
        .map(|exp| ExportEntry {
            name: exp.name.unwrap_or("").to_string(),
            address: exp.rva as u64 + preferred_base,
            ordinal: 0,
            forwarded_to: exp.reexport.as_ref().map(|r| format!("{:?}", r)),
        })
        .collect();

    // Symbols: PE exports, with imports appended below.
    let mut symbols: Vec<Symbol> = pe
        .exports
        .iter()
        .map(|exp| Symbol {
            name: exp.name.unwrap_or("<unnamed>").to_string(),
            address: exp.rva as u64 + preferred_base,
            size: exp.size as u64,
            is_function: true,
            is_imported: false,
            is_exported: true,
        })
        .collect();

    for imp in &pe.imports {
        symbols.push(Symbol {
            name: format!("{}!{}", imp.dll, imp.name),
            address: preferred_base.saturating_add(imp.rva as u64),
            size: 0,
            is_function: true,
            is_imported: true,
            is_exported: false,
        });
    }

    Ok(BinaryInfo {
        path,
        format: FileFormat::Pe,
        architecture: arch,
        platform: Platform::Windows,
        endianness: Endian::Little,
        entry_point: entry + preferred_base,
        preferred_image_base: preferred_base,
        loaded_image_base: preferred_base,
        sections,
        symbols,
        imports,
        exports,
        relocations: vec![],
        security,
        raw_size: bytes.len() as u64,
    })
}
