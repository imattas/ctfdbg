#[derive(Debug, Clone, Default)]
pub struct DebugThread {
    pub thread_id: u32,
    pub start_address: u64,
    pub teb_address: u64,
    pub suspended: bool,
    pub name: Option<String>,
}
