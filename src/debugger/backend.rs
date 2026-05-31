//! Backend trait + a fallback Unsupported impl.

use crate::debugger::breakpoint::{BreakpointId, BreakpointInfo, BreakpointKind};
use crate::debugger::events::DebuggerEvent;
use crate::debugger::modules::DebugModule;
use crate::debugger::registers::RegisterFile;
use crate::debugger::stacktrace::StackFrame;
use crate::debugger::state::TargetState;
use crate::debugger::threads::DebugThread;
use crate::error::{DbgError, DbgResult};
use std::path::PathBuf;

/// What to launch / attach to.
#[derive(Debug, Clone, Default)]
pub struct DebugTarget {
    pub executable: Option<PathBuf>,
    pub arguments: String,
    pub working_directory: Option<PathBuf>,
    pub environment: Vec<(String, String)>,
    pub launch_in_external_terminal: bool,
    pub break_on_entry: bool,
    pub break_on_tls_callbacks: bool,
}

/// Cross-platform debugger backend trait.
///
/// Implementors run on a worker thread and own the OS-level handles.
pub trait DebugBackend {
    fn name(&self) -> &'static str;

    fn state(&self) -> TargetState;
    fn pid(&self) -> Option<u32>;

    fn launch(&mut self, target: &DebugTarget) -> DbgResult<()>;
    fn attach(&mut self, pid: u32) -> DbgResult<()>;
    fn detach(&mut self) -> DbgResult<()>;
    fn kill(&mut self) -> DbgResult<()>;

    fn continue_exec(&mut self) -> DbgResult<DebuggerEvent>;
    fn pause(&mut self) -> DbgResult<DebuggerEvent>;
    fn single_step(&mut self) -> DbgResult<DebuggerEvent>;
    fn step_over(&mut self) -> DbgResult<DebuggerEvent>;
    fn step_return(&mut self) -> DbgResult<DebuggerEvent>;
    fn run_to_address(&mut self, address: u64) -> DbgResult<DebuggerEvent>;

    fn read_registers(&self, thread_id: Option<u32>) -> DbgResult<RegisterFile>;
    fn write_register(&mut self, thread_id: Option<u32>, register: &str, value: u64) -> DbgResult<()>;
    fn set_instruction_pointer(&mut self, thread_id: Option<u32>, address: u64) -> DbgResult<()>;

    fn read_memory(&self, address: u64, size: usize) -> DbgResult<Vec<u8>>;
    fn write_memory(&mut self, address: u64, data: &[u8]) -> DbgResult<()>;

    fn set_breakpoint(&mut self, address: u64) -> DbgResult<BreakpointId>;

    /// Set a hardware breakpoint / watchpoint using the CPU debug registers.
    ///
    /// Backends with debug-register support (x86 via DR0–DR7) override this to
    /// trap on execute / read / write / access. The default implementation can
    /// only emulate an *execute* breakpoint (with a software breakpoint); data
    /// watchpoints are rejected rather than silently planting an `int3` byte
    /// into the watched data, which would corrupt the debuggee.
    fn set_hardware_breakpoint(
        &mut self,
        address: u64,
        kind: BreakpointKind,
        _size: u8,
    ) -> DbgResult<BreakpointId> {
        match kind {
            BreakpointKind::HardwareExecute | BreakpointKind::Software => self.set_breakpoint(address),
            BreakpointKind::HardwareRead | BreakpointKind::HardwareWrite | BreakpointKind::HardwareAccess => {
                Err(DbgError::Unsupported(
                    "data watchpoints require hardware debug registers, which this backend does not program".into(),
                ))
            }
        }
    }

    fn remove_breakpoint(&mut self, id: BreakpointId) -> DbgResult<()>;
    fn enable_breakpoint(&mut self, id: BreakpointId, enabled: bool) -> DbgResult<()>;
    fn set_breakpoint_condition(&mut self, id: BreakpointId, condition: Option<String>) -> DbgResult<()>;
    fn list_breakpoints(&self) -> Vec<BreakpointInfo>;

    fn list_threads(&self) -> DbgResult<Vec<DebugThread>>;
    fn list_modules(&self) -> DbgResult<Vec<DebugModule>>;
    fn stack_trace(&self, thread_id: u32) -> DbgResult<Vec<StackFrame>>;
}

/// Used on platforms with no debugger implementation, or for misconfigured selections.
pub struct UnsupportedBackend {
    reason: String,
}

impl UnsupportedBackend {
    pub fn new(reason: impl Into<String>) -> Self {
        Self { reason: reason.into() }
    }
    fn err<T>(&self) -> DbgResult<T> {
        Err(DbgError::Unsupported(self.reason.clone()))
    }
}

impl DebugBackend for UnsupportedBackend {
    fn name(&self) -> &'static str { "unsupported" }
    fn state(&self) -> TargetState { TargetState::Error }
    fn pid(&self) -> Option<u32> { None }

    fn launch(&mut self, _t: &DebugTarget) -> DbgResult<()> { self.err() }
    fn attach(&mut self, _pid: u32) -> DbgResult<()> { self.err() }
    fn detach(&mut self) -> DbgResult<()> { self.err() }
    fn kill(&mut self) -> DbgResult<()> { self.err() }

    fn continue_exec(&mut self) -> DbgResult<DebuggerEvent> { self.err() }
    fn pause(&mut self) -> DbgResult<DebuggerEvent> { self.err() }
    fn single_step(&mut self) -> DbgResult<DebuggerEvent> { self.err() }
    fn step_over(&mut self) -> DbgResult<DebuggerEvent> { self.err() }
    fn step_return(&mut self) -> DbgResult<DebuggerEvent> { self.err() }
    fn run_to_address(&mut self, _a: u64) -> DbgResult<DebuggerEvent> { self.err() }

    fn read_registers(&self, _t: Option<u32>) -> DbgResult<RegisterFile> { self.err() }
    fn write_register(&mut self, _t: Option<u32>, _r: &str, _v: u64) -> DbgResult<()> { self.err() }
    fn set_instruction_pointer(&mut self, _t: Option<u32>, _a: u64) -> DbgResult<()> { self.err() }

    fn read_memory(&self, _a: u64, _s: usize) -> DbgResult<Vec<u8>> { self.err() }
    fn write_memory(&mut self, _a: u64, _d: &[u8]) -> DbgResult<()> { self.err() }

    fn set_breakpoint(&mut self, _a: u64) -> DbgResult<BreakpointId> { self.err() }
    fn remove_breakpoint(&mut self, _id: BreakpointId) -> DbgResult<()> { self.err() }
    fn enable_breakpoint(&mut self, _id: BreakpointId, _e: bool) -> DbgResult<()> { self.err() }
    fn set_breakpoint_condition(&mut self, _id: BreakpointId, _c: Option<String>) -> DbgResult<()> { self.err() }
    fn list_breakpoints(&self) -> Vec<BreakpointInfo> { vec![] }

    fn list_threads(&self) -> DbgResult<Vec<DebugThread>> { Ok(vec![]) }
    fn list_modules(&self) -> DbgResult<Vec<DebugModule>> { Ok(vec![]) }
    fn stack_trace(&self, _t: u32) -> DbgResult<Vec<StackFrame>> { Ok(vec![]) }
}
