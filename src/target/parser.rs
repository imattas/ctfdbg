//! Format detection + dispatch parser.

use crate::error::{DbgError, DbgResult};
use crate::target::arch::Architecture;
use crate::target::binary::BinaryInfo;
use crate::target::format::FileFormat;
use std::path::Path;

pub fn detect_format(bytes: &[u8]) -> FileFormat {
    if bytes.len() >= 2 && &bytes[..2] == b"MZ" {
        FileFormat::Pe
    } else if bytes.len() >= 4 && &bytes[..4] == b"\x7fELF" {
        FileFormat::Elf
    } else if bytes.len() >= 4
        && (bytes[..4] == [0xCF, 0xFA, 0xED, 0xFE]
            || bytes[..4] == [0xCE, 0xFA, 0xED, 0xFE]
            || bytes[..4] == [0xFE, 0xED, 0xFA, 0xCE]
            || bytes[..4] == [0xFE, 0xED, 0xFA, 0xCF]
            || bytes[..4] == [0xCA, 0xFE, 0xBA, 0xBE])
    {
        FileFormat::MachO
    } else {
        FileFormat::Unknown
    }
}

/// Parse a binary file from disk, autodetecting its format if needed.
pub fn parse_file(
    path: &Path,
    requested_format: FileFormat,
    arch_hint: Architecture,
    base_hint: Option<u64>,
) -> DbgResult<BinaryInfo> {
    let bytes = std::fs::read(path)?;
    parse_bytes(&bytes, Some(path.to_path_buf()), requested_format, arch_hint, base_hint)
}

pub fn parse_bytes(
    bytes: &[u8],
    path: Option<std::path::PathBuf>,
    requested_format: FileFormat,
    arch_hint: Architecture,
    base_hint: Option<u64>,
) -> DbgResult<BinaryInfo> {
    let format = match requested_format {
        FileFormat::Auto | FileFormat::Unknown => detect_format(bytes),
        f => f,
    };

    match format {
        FileFormat::Pe => crate::target::pe::parse_pe(bytes, path),
        FileFormat::Elf => crate::target::elf::parse_elf(bytes, path),
        FileFormat::MachO => crate::target::macho::parse_macho(bytes, path),
        FileFormat::Raw => crate::target::raw::parse_raw(bytes, arch_hint, base_hint.unwrap_or(0), path),
        FileFormat::Auto | FileFormat::Unknown => Err(DbgError::Unsupported(
            "Could not auto-detect binary format. Pass --format raw|pe|elf|macho.".into(),
        )),
    }
}
