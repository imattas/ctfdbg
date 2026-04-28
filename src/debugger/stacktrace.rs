#[derive(Debug, Clone, Default)]
pub struct StackFrame {
    pub frame_index: u32,
    pub thread_id: u32,
    pub pc: u64,
    pub sp: u64,
    pub fp: u64,
    pub function: Option<String>,
    pub module: Option<String>,
}
