//! Stub Linux ptrace backend. Full ptrace implementation is left as
//! a TODO; this returns clear "unsupported" errors so the GUI keeps
//! working on Linux hosts without the real backend.

use crate::debugger::backend::{DebugBackend, DebugTarget};
use crate::debugger::breakpoint::{BreakpointId, BreakpointInfo};
use crate::debugger::events::DebuggerEvent;
use crate::debugger::modules::DebugModule;
use crate::debugger::registers::RegisterFile;
use crate::debugger::stacktrace::StackFrame;
use crate::debugger::state::TargetState;
use crate::debugger::threads::DebugThread;
use crate::error::{DbgError, DbgResult};

pub struct LinuxPtraceBackend { state: TargetState }

impl LinuxPtraceBackend {
    pub fn new() -> Self { Self { state: TargetState::NotStarted } }
    fn err<T>(&self, what: &str) -> DbgResult<T> {
        Err(DbgError::Unsupported(format!("Linux ptrace backend: {what} not yet implemented")))
    }
}

impl DebugBackend for LinuxPtraceBackend {
    fn name(&self) -> &'static str { "Linux ptrace (stub)" }
    fn state(&self) -> TargetState { self.state }
    fn pid(&self) -> Option<u32> { None }

    fn launch(&mut self, _t: &DebugTarget) -> DbgResult<()> { self.err("launch") }
    fn attach(&mut self, _pid: u32) -> DbgResult<()> { self.err("attach") }
    fn detach(&mut self) -> DbgResult<()> { Ok(()) }
    fn kill(&mut self) -> DbgResult<()> { Ok(()) }

    fn continue_exec(&mut self) -> DbgResult<DebuggerEvent> { self.err("continue") }
    fn pause(&mut self) -> DbgResult<DebuggerEvent> { self.err("pause") }
    fn single_step(&mut self) -> DbgResult<DebuggerEvent> { self.err("single_step") }
    fn step_over(&mut self) -> DbgResult<DebuggerEvent> { self.err("step_over") }
    fn step_return(&mut self) -> DbgResult<DebuggerEvent> { self.err("step_return") }
    fn run_to_address(&mut self, _a: u64) -> DbgResult<DebuggerEvent> { self.err("run_to_address") }

    fn read_registers(&self, _t: Option<u32>) -> DbgResult<RegisterFile> { self.err("registers") }
    fn write_register(&mut self, _t: Option<u32>, _r: &str, _v: u64) -> DbgResult<()> { self.err("write_register") }
    fn set_instruction_pointer(&mut self, _t: Option<u32>, _a: u64) -> DbgResult<()> { self.err("set_ip") }

    fn read_memory(&self, _a: u64, _s: usize) -> DbgResult<Vec<u8>> { self.err("read_memory") }
    fn write_memory(&mut self, _a: u64, _d: &[u8]) -> DbgResult<()> { self.err("write_memory") }

    fn set_breakpoint(&mut self, _a: u64) -> DbgResult<BreakpointId> { self.err("set_breakpoint") }
    fn remove_breakpoint(&mut self, _id: BreakpointId) -> DbgResult<()> { Ok(()) }
    fn enable_breakpoint(&mut self, _id: BreakpointId, _e: bool) -> DbgResult<()> { Ok(()) }
    fn set_breakpoint_condition(&mut self, _id: BreakpointId, _c: Option<String>) -> DbgResult<()> { Ok(()) }
    fn list_breakpoints(&self) -> Vec<BreakpointInfo> { vec![] }

    fn list_threads(&self) -> DbgResult<Vec<DebugThread>> { Ok(vec![]) }
    fn list_modules(&self) -> DbgResult<Vec<DebugModule>> { Ok(vec![]) }
    fn stack_trace(&self, _t: u32) -> DbgResult<Vec<StackFrame>> { Ok(vec![]) }
}
