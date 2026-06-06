//! Mach-O parser via goblin (very minimal).

use crate::error::DbgResult;
use crate::target::arch::{Architecture, Endian};
use crate::target::binary::*;
use crate::target::format::FileFormat;
use crate::target::platform::Platform;
use goblin::mach::Mach;

pub fn parse_macho(bytes: &[u8], path: Option<std::path::PathBuf>) -> DbgResult<BinaryInfo> {
    let mach = Mach::parse(bytes)?;
    let macho = match mach {
        Mach::Binary(b) => b,
        Mach::Fat(_) => {
            return Ok(BinaryInfo {
                path,
                format: FileFormat::MachO,
                platform: Platform::MacOs,
                raw_size: bytes.len() as u64,
                ..Default::default()
            });
        }
    };

    // Detect architecture from the Mach-O cputype.
    use goblin::mach::constants::cputype::*;
    let arch = match macho.header.cputype {
        CPU_TYPE_X86_64 => Architecture::X86_64,
        CPU_TYPE_X86 => Architecture::X86,
        CPU_TYPE_ARM64 | CPU_TYPE_ARM64_32 => Architecture::AArch64,
        CPU_TYPE_ARM => Architecture::Arm,
        CPU_TYPE_POWERPC64 => Architecture::PowerPc64,
        CPU_TYPE_POWERPC => Architecture::PowerPc,
        _ => if macho.is_64 { Architecture::X86_64 } else { Architecture::X86 },
    };

    Ok(BinaryInfo {
        path,
        format: FileFormat::MachO,
        architecture: arch,
        platform: Platform::MacOs,
        endianness: Endian::Little,
        entry_point: macho.entry,
        preferred_image_base: 0,
        loaded_image_base: 0,
        sections: vec![],
        symbols: vec![],
        imports: vec![],
        exports: vec![],
        relocations: vec![],
        security: SecurityFeatures::default(),
        raw_size: bytes.len() as u64,
    })
}
