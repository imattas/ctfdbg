#[derive(Debug, Clone, Default)]
pub struct DebugModule {
    pub name: String,
    pub path: String,
    pub base: u64,
    pub size: u64,
    pub is_main: bool,
}

impl DebugModule {
    pub fn end(&self) -> u64 { self.base.saturating_add(self.size) }
    pub fn contains(&self, address: u64) -> bool {
        address >= self.base && address < self.end()
    }
}
