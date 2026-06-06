//! Unified binary model used by the GUI and analysis modules.

use crate::target::arch::{Architecture, Endian};
use crate::target::format::FileFormat;
use crate::target::platform::Platform;

#[derive(Debug, Clone, Default)]
pub struct Section {
    pub name: String,
    pub virtual_address: u64,
    pub virtual_size: u64,
    pub file_offset: u64,
    pub file_size: u64,
    pub flags_text: String,
    pub readable: bool,
    pub writable: bool,
    pub executable: bool,
}

impl Section {
    /// In-memory span of the section. Uses the larger of the virtual and file
    /// sizes so file-less tails (e.g. `.bss`) are still covered.
    pub fn virtual_span(&self) -> u64 {
        self.virtual_size.max(self.file_size)
    }

    /// Whether `addr` falls within this section's mapped range.
    pub fn contains(&self, addr: u64) -> bool {
        let span = self.virtual_span();
        span != 0 && addr >= self.virtual_address && addr < self.virtual_address + span
    }
}

#[derive(Debug, Clone, Default)]
pub struct Symbol {
    pub name: String,
    pub address: u64,
    pub size: u64,
    pub is_function: bool,
    pub is_imported: bool,
    pub is_exported: bool,
}

#[derive(Debug, Clone, Default)]
pub struct ImportEntry {
    pub library: String,
    pub name: String,
    pub address: u64,
    pub ordinal: Option<u16>,
}

#[derive(Debug, Clone, Default)]
pub struct ExportEntry {
    pub name: String,
    pub address: u64,
    pub ordinal: u16,
    pub forwarded_to: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct RelocationEntry {
    pub address: u64,
    pub kind: String,
}

#[derive(Debug, Clone, Default)]
pub struct SecurityFeatures {
    pub aslr: bool,
    pub dep_nx: bool,
    pub cfg: bool,
    pub safe_seh: bool,
    pub high_entropy_va: bool,
    pub gs_cookie_hint: bool,
    pub authenticode_signed_hint: bool,
}

#[derive(Debug, Clone)]
pub struct BinaryInfo {
    pub path: Option<std::path::PathBuf>,
    pub format: FileFormat,
    pub architecture: Architecture,
    pub platform: Platform,
    pub endianness: Endian,
    pub entry_point: u64,
    pub preferred_image_base: u64,
    pub loaded_image_base: u64,
    pub sections: Vec<Section>,
    pub symbols: Vec<Symbol>,
    pub imports: Vec<ImportEntry>,
    pub exports: Vec<ExportEntry>,
    pub relocations: Vec<RelocationEntry>,
    pub security: SecurityFeatures,
    pub raw_size: u64,
}

impl BinaryInfo {
    /// The section whose mapped range contains `addr`, if any.
    pub fn section_containing(&self, addr: u64) -> Option<&Section> {
        self.sections.iter().find(|s| s.contains(addr))
    }

    /// Resolve a symbol or export *name* to its address.
    pub fn address_of_name(&self, name: &str) -> Option<u64> {
        self.symbols
            .iter()
            .find(|s| s.name == name)
            .map(|s| s.address)
            .or_else(|| self.exports.iter().find(|e| e.name == name).map(|e| e.address))
    }
}

impl Default for BinaryInfo {
    fn default() -> Self {
        Self {
            path: None,
            format: FileFormat::Unknown,
            architecture: Architecture::Auto,
            platform: Platform::Unknown,
            endianness: Endian::Little,
            entry_point: 0,
            preferred_image_base: 0,
            loaded_image_base: 0,
            sections: vec![],
            symbols: vec![],
            imports: vec![],
            exports: vec![],
            relocations: vec![],
            security: SecurityFeatures::default(),
            raw_size: 0,
        }
    }
}
