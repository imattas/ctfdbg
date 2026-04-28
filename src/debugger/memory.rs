//! Memory region helpers.

#[derive(Debug, Clone)]
pub struct MemoryRegion {
    pub base: u64,
    pub size: u64,
    pub readable: bool,
    pub writable: bool,
    pub executable: bool,
    pub label: String,
}
