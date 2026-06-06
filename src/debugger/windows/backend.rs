//! Windows debugger backend (primary, fully working at the level needed
//! for launch / attach / continue / step / breakpoint / read-write).
//!
//! Higher-level orchestration (worker thread, channels) lives in the GUI
//! layer; this module just owns the OS handles and implements the
//! `DebugBackend` trait.

use crate::debugger::backend::{DebugBackend, DebugTarget};
use crate::debugger::breakpoint::{BreakpointId, BreakpointInfo, BreakpointKind};
use crate::debugger::events::DebuggerEvent;
use crate::debugger::modules::DebugModule;
use crate::debugger::registers::RegisterFile;
use crate::debugger::stacktrace::StackFrame;
use crate::debugger::state::TargetState;
use crate::debugger::threads::DebugThread;
use crate::error::{DbgError, DbgResult};

use std::collections::HashMap;
use std::ffi::c_void;
use std::os::windows::ffi::OsStrExt;

use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE, BOOL};
use windows::Win32::System::Diagnostics::Debug::{
    ContinueDebugEvent, DebugActiveProcess, DebugBreakProcess, FlushInstructionCache,
    ReadProcessMemory, WaitForDebugEvent, WriteProcessMemory, DEBUG_EVENT,
};
use windows::Win32::System::Threading::{
    CreateProcessW, OpenProcess, TerminateProcess, DEBUG_ONLY_THIS_PROCESS, DEBUG_PROCESS,
    PROCESS_ALL_ACCESS, PROCESS_INFORMATION, STARTUPINFOW,
};

use super::context;
use super::debug_loop::*;
use super::process as proc_mod;

/// A pending re-insert after a software breakpoint hit.
#[derive(Debug, Clone, Copy)]
struct PendingReinsert {
    bp_id: BreakpointId,
    address: u64,
    thread_id: u32,
}

pub struct WindowsDebugBackend {
    state: TargetState,
    pid: Option<u32>,
    process_handle: HANDLE,
    main_thread_handle: HANDLE,
    saw_initial_event: bool,

    breakpoints: HashMap<BreakpointId, BreakpointInfo>,
    bp_by_addr: HashMap<u64, BreakpointId>,
    next_bp_id: u64,

    threads: Vec<DebugThread>,
    modules: Vec<DebugModule>,

    last_stop_thread: u32,
    last_stop_addr: u64,
    pending_reinsert: Option<PendingReinsert>,

    /// True after we issued a continue and have not yet returned the next stop.
    awaiting_event: bool,
    /// pid / tid of the last reported event, needed for ContinueDebugEvent.
    last_event_pid: u32,
    last_event_tid: u32,
}

// SAFETY: The Win32 HANDLEs stored in this struct are owned exclusively by
// whichever thread holds the backend. We always run the backend on a single
// dedicated worker thread (see `gui::state::spawn_worker`), so concurrent
// access from multiple threads cannot occur and the !Send raw pointer in
// HANDLE is safe to move across the spawn boundary.
unsafe impl Send for WindowsDebugBackend {}

impl WindowsDebugBackend {
    pub fn new() -> Self {
        Self {
            state: TargetState::NotStarted,
            pid: None,
            process_handle: INVALID_HANDLE_VALUE,
            main_thread_handle: INVALID_HANDLE_VALUE,
            saw_initial_event: false,
            breakpoints: HashMap::new(),
            bp_by_addr: HashMap::new(),
            next_bp_id: 1,
            threads: vec![],
            modules: vec![],
            last_stop_thread: 0,
            last_stop_addr: 0,
            pending_reinsert: None,
            awaiting_event: false,
            last_event_pid: 0,
            last_event_tid: 0,
        }
    }

    fn close_process_handles(&mut self) {
        // SAFETY: handles owned by us. Safe to close on cleanup paths.
        unsafe {
            if !self.process_handle.is_invalid() && self.process_handle != INVALID_HANDLE_VALUE {
                let _ = CloseHandle(self.process_handle);
            }
            if !self.main_thread_handle.is_invalid() && self.main_thread_handle != INVALID_HANDLE_VALUE {
                let _ = CloseHandle(self.main_thread_handle);
            }
        }
        self.process_handle = INVALID_HANDLE_VALUE;
        self.main_thread_handle = INVALID_HANDLE_VALUE;
    }

    fn require_running(&self) -> DbgResult<()> {
        if matches!(self.state, TargetState::NotStarted | TargetState::Exited | TargetState::Error) {
            return Err(DbgError::NotRunning);
        }
        Ok(())
    }

    fn alloc_bp_id(&mut self) -> BreakpointId {
        let id = BreakpointId(self.next_bp_id);
        self.next_bp_id += 1;
        id
    }

    fn read_byte(&self, address: u64) -> DbgResult<u8> {
        let v = self.read_memory(address, 1)?;
        v.first().copied().ok_or_else(|| DbgError::Memory {
            address,
            message: "short read (0 bytes)".into(),
        })
    }

    fn write_byte(&self, address: u64, byte: u8) -> DbgResult<()> {
        // SAFETY: WriteProcessMemory with valid handle and small buffer.
        unsafe {
            let mut written = 0usize;
            WriteProcessMemory(
                self.process_handle,
                address as *const c_void,
                &byte as *const u8 as *const c_void,
                1,
                Some(&mut written),
            )?;
            // Flush the instruction cache so the int3 takes effect immediately.
            let _ = FlushInstructionCache(self.process_handle, Some(address as *const c_void), 1);
        }
        Ok(())
    }

    /// Wait for a single debug event with the given timeout in ms.
    fn wait_one(&mut self, timeout_ms: u32) -> DbgResult<Option<DEBUG_EVENT>> {
        let mut event = DEBUG_EVENT::default();
        // SAFETY: WaitForDebugEvent fills the event struct. We pass a valid &mut.
        unsafe {
            match WaitForDebugEvent(&mut event, timeout_ms) {
                Ok(()) => Ok(Some(event)),
                Err(e) => {
                    // Timeout -> ERROR_SEM_TIMEOUT (0x79) returns Err in newer windows crate
                    if e.code().0 as u32 == 0x8007_0079 || e.code().0 as u32 == 0x0000_0079 {
                        Ok(None)
                    } else {
                        Err(DbgError::Windows(e.to_string()))
                    }
                }
            }
        }
    }

    fn continue_event(&mut self, status: windows::Win32::Foundation::NTSTATUS) -> DbgResult<()> {
        if self.last_event_pid == 0 { return Ok(()); }
        // SAFETY: pid/tid from last event.
        unsafe {
            ContinueDebugEvent(self.last_event_pid, self.last_event_tid, status)?;
        }
        self.last_event_pid = 0;
        self.last_event_tid = 0;
        Ok(())
    }

    /// Process a single debug event into a high-level DebuggerEvent (or
    /// `None` if it was a bookkeeping event we silently continued).
    fn process_event(&mut self, event: DEBUG_EVENT) -> DbgResult<Option<DebuggerEvent>> {
        self.last_event_pid = event.dwProcessId;
        self.last_event_tid = event.dwThreadId;
        let code = event.dwDebugEventCode;

        if code == CREATE_PROCESS_DEBUG_EVENT_C {
            // SAFETY: union access matches event code.
            let info = unsafe { event.u.CreateProcessInfo };
            self.saw_initial_event = true;
            if self.process_handle.is_invalid() || self.process_handle == INVALID_HANDLE_VALUE {
                self.process_handle = info.hProcess;
            }
            if self.main_thread_handle.is_invalid() || self.main_thread_handle == INVALID_HANDLE_VALUE {
                self.main_thread_handle = info.hThread;
            }
            self.threads.push(DebugThread {
                thread_id: event.dwThreadId,
                start_address: info.lpStartAddress.map(|p| p as usize as u64).unwrap_or(0),
                ..Default::default()
            });
            // Refresh module list (best-effort).
            if let Ok(mods) = proc_mod::list_process_modules(event.dwProcessId) {
                self.modules = mods;
            }
            // Close the file handle the OS hands us; we do not need it.
            // SAFETY: handle ownership is transferred to us per MSDN.
            unsafe { let _ = CloseHandle(info.hFile); }
            self.continue_event(DBG_CONTINUE)?;
            Ok(Some(DebuggerEvent::Launched { pid: event.dwProcessId }))
        } else if code == EXIT_PROCESS_DEBUG_EVENT_C {
            // SAFETY: union access matches event code.
            let info = unsafe { event.u.ExitProcess };
            self.state = TargetState::Exited;
            self.continue_event(DBG_CONTINUE)?;
            Ok(Some(DebuggerEvent::ProcessExited { exit_code: info.dwExitCode as i32 }))
        } else if code == CREATE_THREAD_DEBUG_EVENT_C {
            // SAFETY: union access matches event code.
            let info = unsafe { event.u.CreateThread };
            self.threads.push(DebugThread {
                thread_id: event.dwThreadId,
                start_address: info.lpStartAddress.map(|p| p as usize as u64).unwrap_or(0),
                ..Default::default()
            });
            self.continue_event(DBG_CONTINUE)?;
            Ok(Some(DebuggerEvent::ThreadCreated {
                thread_id: event.dwThreadId,
                start_address: info.lpStartAddress.map(|p| p as usize as u64).unwrap_or(0),
            }))
        } else if code == EXIT_THREAD_DEBUG_EVENT_C {
            // SAFETY: union access matches event code.
            let info = unsafe { event.u.ExitThread };
            let exit_code = info.dwExitCode;
            self.threads.retain(|t| t.thread_id != event.dwThreadId);
            self.continue_event(DBG_CONTINUE)?;
            Ok(Some(DebuggerEvent::ThreadExited { thread_id: event.dwThreadId, exit_code }))
        } else if code == LOAD_DLL_DEBUG_EVENT_C {
            // SAFETY: union access matches event code.
            let info = unsafe { event.u.LoadDll };
            let base = info.lpBaseOfDll as usize as u64;
            // Best-effort name.
            let name = format!("module@0x{base:x}");
            // SAFETY: we close the handed-out file handle.
            unsafe { let _ = CloseHandle(info.hFile); }
            self.continue_event(DBG_CONTINUE)?;
            // Refresh module list.
            if let Some(pid) = self.pid {
                if let Ok(mods) = proc_mod::list_process_modules(pid) {
                    self.modules = mods;
                }
            }
            Ok(Some(DebuggerEvent::ModuleLoaded { name, base, size: 0 }))
        } else if code == UNLOAD_DLL_DEBUG_EVENT_C {
            // SAFETY: union access matches event code.
            let info = unsafe { event.u.UnloadDll };
            let base = info.lpBaseOfDll as usize as u64;
            self.continue_event(DBG_CONTINUE)?;
            Ok(Some(DebuggerEvent::ModuleUnloaded { base }))
        } else if code == OUTPUT_DEBUG_STRING_EVENT_C {
            // SAFETY: union access matches event code.
            let info = unsafe { event.u.DebugString };
            let addr = info.lpDebugStringData.0 as u64;
            let len = info.nDebugStringLength as usize;
            let bytes = self.read_memory(addr, len).unwrap_or_default();
            let msg = if info.fUnicode != 0 {
                let utf16: Vec<u16> = bytes.chunks_exact(2)
                    .map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
                String::from_utf16_lossy(&utf16).trim_end_matches('\0').to_string()
            } else {
                String::from_utf8_lossy(&bytes).trim_end_matches('\0').to_string()
            };
            self.continue_event(DBG_CONTINUE)?;
            Ok(Some(DebuggerEvent::OutputDebugString { message: msg }))
        } else if code == EXCEPTION_DEBUG_EVENT_C {
            // SAFETY: union access matches event code.
            let info = unsafe { event.u.Exception };
            let code = info.ExceptionRecord.ExceptionCode.0;
            let addr = info.ExceptionRecord.ExceptionAddress as usize as u64;
            let first_chance = info.dwFirstChance != 0;
            self.last_stop_thread = event.dwThreadId;
            self.last_stop_addr = addr;
            self.state = TargetState::Stopped;

            match code {
                EXC_BREAKPOINT => {
                    if let Some(&bp_id) = self.bp_by_addr.get(&addr) {
                        // Restore the original byte and decrement RIP for the
                        // single step that re-runs the original instruction.
                        if let Some(bp) = self.breakpoints.get(&bp_id) {
                            if let Some(orig) = bp.original_byte {
                                let _ = self.write_byte(addr, orig);
                            }
                        }
                        #[cfg(target_arch = "x86_64")]
                        {
                            if let Ok(mut ctx) = context::read_context_x64(event.dwThreadId) {
                                ctx.Rip = addr;
                                // Set TF so that, when we continue, we get a SINGLE_STEP
                                // exception after re-executing the restored instruction.
                                ctx.EFlags |= 0x100;
                                let _ = context::write_context_x64(event.dwThreadId, &ctx);
                            }
                        }
                        if let Some(bp) = self.breakpoints.get_mut(&bp_id) {
                            bp.hit_count += 1;
                        }
                        self.pending_reinsert = Some(PendingReinsert {
                            bp_id, address: addr, thread_id: event.dwThreadId,
                        });
                        Ok(Some(DebuggerEvent::BreakpointHit {
                            id: bp_id.0, thread_id: event.dwThreadId, address: addr,
                        }))
                    } else {
                        // Initial loader breakpoint or unknown int3.
                        Ok(Some(DebuggerEvent::Stopped {
                            reason: "Breakpoint".into(),
                            thread_id: event.dwThreadId,
                            address: addr,
                        }))
                    }
                }
                EXC_SINGLE_STEP => {
                    Ok(Some(DebuggerEvent::SingleStep {
                        thread_id: event.dwThreadId, address: addr,
                    }))
                }
                EXC_ACCESS_VIOLATION => Ok(Some(DebuggerEvent::Exception {
                    code: code as u32, message: "Access violation".into(),
                    thread_id: event.dwThreadId, address: addr, first_chance,
                })),
                EXC_ILLEGAL_INSTRUCTION => Ok(Some(DebuggerEvent::Exception {
                    code: code as u32, message: "Illegal instruction".into(),
                    thread_id: event.dwThreadId, address: addr, first_chance,
                })),
                EXC_INT_DIVIDE_BY_ZERO => Ok(Some(DebuggerEvent::Exception {
                    code: code as u32, message: "Divide by zero".into(),
                    thread_id: event.dwThreadId, address: addr, first_chance,
                })),
                _ => Ok(Some(DebuggerEvent::Exception {
                    code: code as u32, message: format!("Exception 0x{:08x}", code as u32),
                    thread_id: event.dwThreadId, address: addr, first_chance,
                })),
            }
        } else {
            self.continue_event(DBG_CONTINUE)?;
            Ok(None)
        }
    }

    /// Pump events until we have one to surface to the user.
    fn run_until_user_event(&mut self) -> DbgResult<DebuggerEvent> {
        loop {
            let ev = self.wait_one(u32::MAX)?;
            let Some(ev) = ev else { continue; };
            if let Some(out) = self.process_event(ev)? {
                return Ok(out);
            }
        }
    }

    fn handle_pending_reinsert(&mut self) -> DbgResult<()> {
        let Some(pi) = self.pending_reinsert.take() else { return Ok(()); };
        // Continue from breakpoint hit (TF already set, byte restored).
        self.continue_event(DBG_CONTINUE)?;
        // Wait for the SINGLE_STEP exception.
        loop {
            let Some(ev) = self.wait_one(u32::MAX)? else { continue; };
            self.last_event_pid = ev.dwProcessId;
            self.last_event_tid = ev.dwThreadId;
            let code = ev.dwDebugEventCode;
            if code == EXCEPTION_DEBUG_EVENT_C {
                // SAFETY: union access matches event code.
                let info = unsafe { ev.u.Exception };
                if info.ExceptionRecord.ExceptionCode.0 == EXC_SINGLE_STEP
                    && ev.dwThreadId == pi.thread_id
                {
                    // Re-insert the breakpoint.
                    let _ = self.write_byte(pi.address, 0xCC);
                    // Clear TF so we don't keep stepping.
                    #[cfg(target_arch = "x86_64")]
                    {
                        if let Ok(mut ctx) = context::read_context_x64(pi.thread_id) {
                            ctx.EFlags &= !0x100;
                            let _ = context::write_context_x64(pi.thread_id, &ctx);
                        }
                    }
                    self.continue_event(DBG_CONTINUE)?;
                    return Ok(());
                }
            }
            // Anything else: continue and keep waiting.
            self.continue_event(DBG_CONTINUE)?;
        }
    }
}

impl Drop for WindowsDebugBackend {
    fn drop(&mut self) { self.close_process_handles(); }
}

impl DebugBackend for WindowsDebugBackend {
    fn name(&self) -> &'static str { "Windows Debug API" }
    fn state(&self) -> TargetState { self.state }
    fn pid(&self) -> Option<u32> { self.pid }

    fn launch(&mut self, target: &DebugTarget) -> DbgResult<()> {
        let exe = target.executable.as_ref()
            .ok_or_else(|| DbgError::InvalidArgument("no executable specified".into()))?;
        // Build a quoted, mutable command line. CreateProcessW requires PWSTR (mutable).
        let mut cmdline_str = format!("\"{}\"", exe.display());
        if !target.arguments.is_empty() {
            cmdline_str.push(' ');
            cmdline_str.push_str(&target.arguments);
        }
        let mut cmdline: Vec<u16> = std::ffi::OsString::from(&cmdline_str).encode_wide().collect();
        cmdline.push(0);

        let cwd_w: Option<Vec<u16>> = target.working_directory.as_ref().map(|p| {
            let mut v: Vec<u16> = p.as_os_str().encode_wide().collect();
            v.push(0); v
        });
        let cwd_pcwstr = match &cwd_w {
            Some(v) => PCWSTR(v.as_ptr()),
            None => PCWSTR::null(),
        };

        let mut si = STARTUPINFOW { cb: std::mem::size_of::<STARTUPINFOW>() as u32, ..Default::default() };
        let mut pi = PROCESS_INFORMATION::default();
        let flags = DEBUG_PROCESS | DEBUG_ONLY_THIS_PROCESS;

        // SAFETY: pointers reference owned buffers that remain valid through the call.
        unsafe {
            CreateProcessW(
                PCWSTR::null(),
                PWSTR(cmdline.as_mut_ptr()),
                None,
                None,
                BOOL(0),
                flags,
                None,
                cwd_pcwstr,
                &si,
                &mut pi,
            )?;
        }

        self.pid = Some(pi.dwProcessId);
        self.process_handle = pi.hProcess;
        self.main_thread_handle = pi.hThread;
        self.state = TargetState::Running;
        self.saw_initial_event = false;

        // Pump events until the first user-visible event (typically Launched
        // from CREATE_PROCESS_DEBUG_EVENT, then loader BP).
        let _ = self.run_until_user_event()?;
        if !target.break_on_entry {
            // Continue past the initial loader breakpoint.
            self.continue_event(DBG_CONTINUE)?;
            self.state = TargetState::Running;
        } else {
            self.state = TargetState::Stopped;
        }
        Ok(())
    }

    fn attach(&mut self, pid: u32) -> DbgResult<()> {
        // SAFETY: standard Win32 API.
        unsafe { DebugActiveProcess(pid)?; }
        let h = unsafe { OpenProcess(PROCESS_ALL_ACCESS, false, pid)? };
        self.process_handle = h;
        self.pid = Some(pid);
        self.state = TargetState::Stopped;
        // Pump initial events.
        let _ = self.run_until_user_event()?;
        Ok(())
    }

    fn detach(&mut self) -> DbgResult<()> {
        if let Some(pid) = self.pid {
            // SAFETY: standard Win32 API.
            unsafe {
                use windows::Win32::System::Diagnostics::Debug::DebugActiveProcessStop;
                let _ = DebugActiveProcessStop(pid);
            }
        }
        self.close_process_handles();
        self.state = TargetState::NotStarted;
        self.pid = None;
        Ok(())
    }

    fn kill(&mut self) -> DbgResult<()> {
        if !self.process_handle.is_invalid() {
            // SAFETY: handle valid.
            unsafe { let _ = TerminateProcess(self.process_handle, 1); }
        }
        // Drain remaining events until ExitProcess.
        for _ in 0..32 {
            if let Ok(Some(ev)) = self.wait_one(100) {
                let _ = self.process_event(ev);
                if matches!(self.state, TargetState::Exited) { break; }
            } else { break; }
        }
        self.close_process_handles();
        self.state = TargetState::Exited;
        Ok(())
    }

    fn continue_exec(&mut self) -> DbgResult<DebuggerEvent> {
        self.require_running()?;
        if self.pending_reinsert.is_some() {
            self.handle_pending_reinsert()?;
        } else {
            self.continue_event(DBG_CONTINUE)?;
        }
        self.state = TargetState::Running;
        let ev = self.run_until_user_event()?;
        Ok(ev)
    }

    fn pause(&mut self) -> DbgResult<DebuggerEvent> {
        self.require_running()?;
        if !self.process_handle.is_invalid() {
            // SAFETY: process handle valid.
            unsafe { DebugBreakProcess(self.process_handle)?; }
        }
        // Wait for the synthetic breakpoint exception.
        let ev = self.run_until_user_event()?;
        Ok(ev)
    }

    fn single_step(&mut self) -> DbgResult<DebuggerEvent> {
        self.require_running()?;
        let tid = self.last_stop_thread;
        // Set TF on the active thread.
        #[cfg(target_arch = "x86_64")]
        {
            if let Ok(mut ctx) = context::read_context_x64(tid) {
                ctx.EFlags |= 0x100;
                context::write_context_x64(tid, &ctx)?;
            }
        }
        if self.pending_reinsert.is_some() {
            self.handle_pending_reinsert()?;
        } else {
            self.continue_event(DBG_CONTINUE)?;
        }
        let ev = self.run_until_user_event()?;
        // Clear TF.
        #[cfg(target_arch = "x86_64")]
        {
            if let Ok(mut ctx) = context::read_context_x64(tid) {
                ctx.EFlags &= !0x100;
                let _ = context::write_context_x64(tid, &ctx);
            }
        }
        Ok(ev)
    }

    fn step_over(&mut self) -> DbgResult<DebuggerEvent> {
        // Conservative: same as single_step. A future improvement would
        // place a temp BP at the next instruction when at a CALL.
        self.single_step()
    }

    fn step_return(&mut self) -> DbgResult<DebuggerEvent> {
        // Read return address from [rsp] then run-to-address.
        let regs = self.read_registers(None)?;
        let sp = regs.sp().ok_or_else(|| DbgError::Register("missing sp".into()))?;
        let bytes = self.read_memory(sp, 8)?;
        if bytes.len() < 8 {
            return Err(DbgError::Memory {
                address: sp,
                message: "short read of return address".into(),
            });
        }
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&bytes[..8]);
        let ret_addr = u64::from_le_bytes(buf);
        self.run_to_address(ret_addr)
    }

    fn run_to_address(&mut self, address: u64) -> DbgResult<DebuggerEvent> {
        // Place a temporary software breakpoint, continue, then remove it.
        let id = self.set_breakpoint(address)?;
        let ev = self.continue_exec()?;
        let _ = self.remove_breakpoint(id);
        Ok(ev)
    }

    fn read_registers(&self, thread_id: Option<u32>) -> DbgResult<RegisterFile> {
        let tid = thread_id.unwrap_or(self.last_stop_thread);
        if tid == 0 { return Err(DbgError::Register("no active thread".into())); }
        #[cfg(target_arch = "x86_64")]
        {
            let ctx = context::read_context_x64(tid)?;
            Ok(context::context_to_register_file(&ctx, tid))
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            Err(DbgError::Unsupported("non-x86_64 host".into()))
        }
    }

    fn write_register(&mut self, thread_id: Option<u32>, register: &str, value: u64) -> DbgResult<()> {
        let tid = thread_id.unwrap_or(self.last_stop_thread);
        if tid == 0 { return Err(DbgError::Register("no active thread".into())); }
        #[cfg(target_arch = "x86_64")]
        {
            let mut ctx = context::read_context_x64(tid)?;
            context::apply_register_to_context(&mut ctx, register, value)?;
            context::write_context_x64(tid, &ctx)?;
            Ok(())
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            let _ = (register, value);
            Err(DbgError::Unsupported("non-x86_64 host".into()))
        }
    }

    fn set_instruction_pointer(&mut self, thread_id: Option<u32>, address: u64) -> DbgResult<()> {
        self.write_register(thread_id, "rip", address)
    }

    fn read_memory(&self, address: u64, size: usize) -> DbgResult<Vec<u8>> {
        let mut buf = vec![0u8; size];
        let mut read = 0usize;
        // SAFETY: process handle is valid; buffer is owned and large enough.
        unsafe {
            ReadProcessMemory(
                self.process_handle,
                address as *const c_void,
                buf.as_mut_ptr() as *mut c_void,
                size,
                Some(&mut read),
            ).map_err(|e| DbgError::Memory { address, message: e.to_string() })?;
        }
        buf.truncate(read);
        Ok(buf)
    }

    fn write_memory(&mut self, address: u64, data: &[u8]) -> DbgResult<()> {
        let mut written = 0usize;
        // SAFETY: process handle valid; data borrowed.
        unsafe {
            WriteProcessMemory(
                self.process_handle,
                address as *const c_void,
                data.as_ptr() as *const c_void,
                data.len(),
                Some(&mut written),
            ).map_err(|e| DbgError::Memory { address, message: e.to_string() })?;
            let _ = FlushInstructionCache(self.process_handle, Some(address as *const c_void), data.len());
        }
        Ok(())
    }

    fn set_breakpoint(&mut self, address: u64) -> DbgResult<BreakpointId> {
        if let Some(&id) = self.bp_by_addr.get(&address) {
            return Ok(id);
        }
        let original = self.read_byte(address)?;
        self.write_byte(address, 0xCC)?;
        let id = self.alloc_bp_id();
        let module_label = self.modules
            .iter()
            .find(|m| m.contains(address))
            .map(|m| format!("{}+0x{:x}", m.name, address - m.base))
            .unwrap_or_else(|| format!("0x{:x}", address));
        let mut bp = BreakpointInfo::new_software(id, address, module_label);
        bp.original_byte = Some(original);
        self.breakpoints.insert(id, bp);
        self.bp_by_addr.insert(address, id);
        Ok(id)
    }

    fn remove_breakpoint(&mut self, id: BreakpointId) -> DbgResult<()> {
        if let Some(bp) = self.breakpoints.remove(&id) {
            if bp.enabled {
                if let Some(orig) = bp.original_byte {
                    let _ = self.write_byte(bp.address, orig);
                }
            }
            self.bp_by_addr.remove(&bp.address);
        }
        Ok(())
    }

    fn enable_breakpoint(&mut self, id: BreakpointId, enabled: bool) -> DbgResult<()> {
        let Some(bp) = self.breakpoints.get_mut(&id) else { return Err(DbgError::Breakpoint("unknown id".into())); };
        if bp.enabled == enabled { return Ok(()); }
        bp.enabled = enabled;
        let addr = bp.address;
        let orig = bp.original_byte;
        if enabled {
            if orig.is_none() {
                let b = self.read_byte(addr)?;
                if let Some(b2) = self.breakpoints.get_mut(&id) { b2.original_byte = Some(b); }
            }
            self.write_byte(addr, 0xCC)?;
        } else if let Some(o) = orig {
            self.write_byte(addr, o)?;
        }
        Ok(())
    }

    fn set_breakpoint_condition(&mut self, id: BreakpointId, condition: Option<String>) -> DbgResult<()> {
        let bp = self.breakpoints.get_mut(&id)
            .ok_or_else(|| DbgError::Breakpoint("unknown id".into()))?;
        bp.condition = condition;
        Ok(())
    }

    fn list_breakpoints(&self) -> Vec<BreakpointInfo> {
        let mut v: Vec<_> = self.breakpoints.values().cloned().collect();
        v.sort_by_key(|b| b.id.0);
        v
    }

    fn list_threads(&self) -> DbgResult<Vec<DebugThread>> {
        if let Some(pid) = self.pid {
            proc_mod::list_process_threads(pid)
        } else {
            Ok(vec![])
        }
    }

    fn list_modules(&self) -> DbgResult<Vec<DebugModule>> {
        if let Some(pid) = self.pid {
            if let Ok(mods) = proc_mod::list_process_modules(pid) {
                return Ok(mods);
            }
        }
        Ok(self.modules.clone())
    }

    fn stack_trace(&self, thread_id: u32) -> DbgResult<Vec<StackFrame>> {
        let thread_id = if thread_id != 0 { thread_id } else { self.last_stop_thread };
        let regs = self.read_registers(Some(thread_id))?;
        let pc = regs.pc().unwrap_or(0);
        let sp = regs.sp().unwrap_or(0);
        let fp = regs.fp().unwrap_or(0);
        let ptr_size = if regs.architecture.is_64bit() { 8 } else { 4 };
        // Frame-pointer unwind through the saved RBP/EBP chain.
        let unwound = crate::analysis::stack::frame_pointer_unwind(pc, fp, ptr_size, 64, |addr| {
            self.read_memory(addr, ptr_size).ok().and_then(|b| {
                if b.len() < ptr_size {
                    None
                } else {
                    let mut buf = [0u8; 8];
                    buf[..ptr_size].copy_from_slice(&b[..ptr_size]);
                    Some(u64::from_le_bytes(buf))
                }
            })
        });
        let module_of = |addr: u64| self.modules.iter().find(|m| m.contains(addr)).map(|m| m.name.clone());
        let frames = unwound
            .iter()
            .enumerate()
            .map(|(i, f)| StackFrame {
                frame_index: i as u32,
                thread_id,
                pc: f.pc,
                sp: if i == 0 { sp } else { f.fp },
                fp: f.fp,
                function: None,
                module: module_of(f.pc),
            })
            .collect();
        Ok(frames)
    }
}

// Used by GUI to populate the Attach dialog.
pub fn list_system_processes() -> DbgResult<Vec<proc_mod::SystemProcess>> {
    proc_mod::list_system_processes()
}
