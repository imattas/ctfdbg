//! Raw shellcode "format" - no headers, just bytes.

use crate::error::DbgResult;
use crate::target::arch::{Architecture, Endian};
use crate::target::binary::*;
use crate::target::format::FileFormat;
use crate::target::platform::Platform;

pub fn parse_raw(
    bytes: &[u8],
    arch: Architecture,
    base: u64,
    path: Option<std::path::PathBuf>,
) -> DbgResult<BinaryInfo> {
    Ok(BinaryInfo {
        path,
        format: FileFormat::Raw,
        architecture: if matches!(arch, Architecture::Auto) { Architecture::X86_64 } else { arch },
        platform: Platform::Unknown,
        endianness: Endian::Little,
        entry_point: base,
        preferred_image_base: base,
        loaded_image_base: base,
        sections: vec![Section {
            name: ".raw".into(),
            virtual_address: base,
            virtual_size: bytes.len() as u64,
            file_offset: 0,
            file_size: bytes.len() as u64,
            flags_text: "RWX".into(),
            readable: true,
            writable: true,
            executable: true,
        }],
        symbols: vec![],
        imports: vec![],
        exports: vec![],
        relocations: vec![],
        security: SecurityFeatures::default(),
        raw_size: bytes.len() as u64,
    })
}
