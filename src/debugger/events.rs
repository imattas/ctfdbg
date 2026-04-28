//! Events sent from backend to GUI.

#[derive(Debug, Clone)]
pub enum DebuggerEvent {
    Launched { pid: u32 },
    Attached { pid: u32 },
    Running,
    Stopped { reason: String, thread_id: u32, address: u64 },
    BreakpointHit { id: u64, thread_id: u32, address: u64 },
    SingleStep { thread_id: u32, address: u64 },
    Exception { code: u32, message: String, thread_id: u32, address: u64, first_chance: bool },
    ThreadCreated { thread_id: u32, start_address: u64 },
    ThreadExited { thread_id: u32, exit_code: u32 },
    ModuleLoaded { name: String, base: u64, size: u64 },
    ModuleUnloaded { base: u64 },
    OutputDebugString { message: String },
    ProcessExited { exit_code: i32 },
    Error { message: String },
}

impl DebuggerEvent {
    pub fn short_label(&self) -> String {
        match self {
            Self::Launched { pid } => format!("Launched (pid {pid})"),
            Self::Attached { pid } => format!("Attached (pid {pid})"),
            Self::Running => "Running".into(),
            Self::Stopped { reason, .. } => format!("Stopped ({reason})"),
            Self::BreakpointHit { id, .. } => format!("Breakpoint hit #{id}"),
            Self::SingleStep { .. } => "Single step".into(),
            Self::Exception { code, .. } => format!("Exception 0x{code:08x}"),
            Self::ThreadCreated { thread_id, .. } => format!("Thread {thread_id} created"),
            Self::ThreadExited { thread_id, .. } => format!("Thread {thread_id} exited"),
            Self::ModuleLoaded { name, .. } => format!("Module loaded: {name}"),
            Self::ModuleUnloaded { base } => format!("Module unloaded @ 0x{base:x}"),
            Self::OutputDebugString { message } => format!("OutputDebugString: {message}"),
            Self::ProcessExited { exit_code } => format!("Exited (code {exit_code})"),
            Self::Error { message } => format!("Error: {message}"),
        }
    }
}
