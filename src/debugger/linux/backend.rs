//! Real Linux `ptrace` debugger backend.
//!
//! Implements launch / attach, software breakpoints (`int3` on x86, `BRK` on
//! AArch64), single-step, instruction-aware step-over, step-return,
//! run-to-address, register and memory read/write, `/proc`-based module and
//! thread enumeration, and a frame-pointer stack unwind.
//!
//! Register marshalling and the breakpoint encoding are architecture-specific;
//! the [`arch`] submodule provides one implementation per supported target
//! (x86-64, x86, AArch64).  The surrounding control-flow logic is shared.

use std::collections::HashMap;

use libc::pid_t;

use crate::debugger::backend::{DebugBackend, DebugTarget};
use crate::debugger::breakpoint::{BreakpointId, BreakpointInfo, BreakpointKind};
use crate::debugger::events::DebuggerEvent;
use crate::debugger::modules::DebugModule;
use crate::debugger::registers::RegisterFile;
use crate::debugger::stacktrace::StackFrame;
use crate::debugger::state::TargetState;
use crate::debugger::threads::DebugThread;
use crate::error::{DbgError, DbgResult};

use super::ptrace::{self, WaitOutcome};

pub struct LinuxPtraceBackend {
    state: TargetState,
    pid: Option<pid_t>,
    breakpoints: HashMap<BreakpointId, BreakpointInfo>,
    bp_by_addr: HashMap<u64, BreakpointId>,
    /// Original instruction bytes saved under each breakpoint.
    orig: HashMap<u64, Vec<u8>>,
    next_bp_id: u64,
    last_stop_tid: u32,
    last_stop_addr: u64,
    /// Address of a breakpoint we must step over and re-arm before resuming.
    pending_reinsert: Option<u64>,
    /// Signal to deliver to the tracee on the next resume (0 = none).
    pending_signal: i32,
    modules: Vec<DebugModule>,
    /// True when we attached to an existing process (vs. launched it). Attached
    /// targets are detached, not killed, when the backend is dropped.
    attached: bool,
    /// Hardware debug-register slots (x86 DR0–DR3): (breakpoint id, address).
    #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
    hw_slots: [Option<(BreakpointId, u64)>; 4],
    /// Set the x86 resume flag on the next continue so a hardware execute
    /// breakpoint at the current PC does not immediately re-trigger.
    #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
    hw_resume_rf: bool,
}

impl LinuxPtraceBackend {
    pub fn new() -> Self {
        Self {
            state: TargetState::NotStarted,
            pid: None,
            breakpoints: HashMap::new(),
            bp_by_addr: HashMap::new(),
            orig: HashMap::new(),
            next_bp_id: 1,
            last_stop_tid: 0,
            last_stop_addr: 0,
            pending_reinsert: None,
            pending_signal: 0,
            modules: vec![],
            attached: false,
            #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
            hw_slots: [None; 4],
            #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
            hw_resume_rf: false,
        }
    }

    fn require_running(&self) -> DbgResult<pid_t> {
        match self.pid {
            Some(p) if !matches!(self.state, TargetState::Exited | TargetState::NotStarted) => Ok(p),
            _ => Err(DbgError::NotRunning),
        }
    }

    fn alloc_bp_id(&mut self) -> BreakpointId {
        let id = BreakpointId(self.next_bp_id);
        self.next_bp_id += 1;
        id
    }

    /// Mark the process as exited and clear transient state.
    fn mark_exited(&mut self) {
        self.state = TargetState::Exited;
        self.pending_reinsert = None;
        self.pending_signal = 0;
    }

    /// Interpret a `waitpid` result into a high-level event, handling the
    /// register/byte fix-up when we land on one of our breakpoints.
    fn interpret(&mut self, status: i32, was_step: bool) -> DbgResult<DebuggerEvent> {
        let pid = self.pid.ok_or(DbgError::NotRunning)?;
        match ptrace::decode_status(status) {
            WaitOutcome::Exited(code) => {
                self.mark_exited();
                Ok(DebuggerEvent::ProcessExited { exit_code: code })
            }
            WaitOutcome::Signalled(sig) => {
                self.mark_exited();
                Ok(DebuggerEvent::ProcessExited { exit_code: -sig })
            }
            WaitOutcome::Stopped(sig) if sig == libc::SIGTRAP => {
                let mut regs = ptrace::get_regs(pid)?;
                let pc = arch::pc(&regs);
                let cand = arch::trap_bp_addr(pc);
                self.state = TargetState::Stopped;
                self.last_stop_tid = pid as u32;
                if let Some(&id) = self.bp_by_addr.get(&cand) {
                    // Rewind to the breakpoint address and restore the
                    // original instruction so it can be re-executed.
                    arch::set_pc(&mut regs, cand);
                    ptrace::set_regs(pid, &regs)?;
                    if let Some(orig) = self.orig.get(&cand) {
                        ptrace::write_mem(pid, cand, orig)?;
                    }
                    self.pending_reinsert = Some(cand);
                    self.last_stop_addr = cand;
                    if let Some(bp) = self.breakpoints.get_mut(&id) {
                        bp.hit_count += 1;
                    }
                    Ok(DebuggerEvent::BreakpointHit { id: id.0, thread_id: pid as u32, address: cand })
                } else {
                    // A hardware debug register may have fired instead.
                    #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
                    if let Some(ev) = self.check_hw_hit(pid, pc) {
                        return Ok(ev);
                    }
                    self.last_stop_addr = pc;
                    if was_step {
                        Ok(DebuggerEvent::SingleStep { thread_id: pid as u32, address: pc })
                    } else {
                        Ok(DebuggerEvent::Stopped { reason: "trap".into(), thread_id: pid as u32, address: pc })
                    }
                }
            }
            WaitOutcome::Stopped(sig) if sig == libc::SIGSTOP => {
                // A stop (typically debugger-induced via `pause()`). Do NOT
                // record it as pending: re-delivering SIGSTOP on the next
                // resume would immediately stop the target again.
                let pc = ptrace::get_regs(pid).map(|r| arch::pc(&r)).unwrap_or(0);
                self.state = TargetState::Stopped;
                self.last_stop_tid = pid as u32;
                self.last_stop_addr = pc;
                self.pending_signal = 0;
                Ok(DebuggerEvent::Stopped { reason: "paused".into(), thread_id: pid as u32, address: pc })
            }
            WaitOutcome::Stopped(sig) => {
                // A real signal (SIGSEGV, SIGILL, ...). Remember it so it is
                // delivered to the tracee when the user resumes.
                let pc = ptrace::get_regs(pid).map(|r| arch::pc(&r)).unwrap_or(0);
                self.state = TargetState::Stopped;
                self.last_stop_tid = pid as u32;
                self.last_stop_addr = pc;
                self.pending_signal = sig;
                Ok(DebuggerEvent::Exception {
                    code: sig as u32,
                    message: ptrace::signal_name(sig).into(),
                    thread_id: pid as u32,
                    address: pc,
                    first_chance: true,
                })
            }
            WaitOutcome::Other => Ok(DebuggerEvent::Stopped {
                reason: "unknown stop".into(),
                thread_id: pid as u32,
                address: 0,
            }),
        }
    }

    /// Shared resume path for continue (`step == false`) and single-step.
    fn resume(&mut self, step: bool) -> DbgResult<DebuggerEvent> {
        let pid = self.require_running()?;
        let sig = std::mem::take(&mut self.pending_signal);

        // After a hardware execute breakpoint, set the x86 resume flag so we
        // do not immediately re-trap on the same instruction.
        #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
        if std::mem::take(&mut self.hw_resume_rf) {
            if let Ok(mut regs) = ptrace::get_regs(pid) {
                arch::set_resume_flag(&mut regs);
                let _ = ptrace::set_regs(pid, &regs);
            }
        }

        // If we are sitting on a breakpoint whose original instruction we
        // restored, step over it and re-arm the breakpoint first.
        if let Some(addr) = self.pending_reinsert.take() {
            ptrace::single_step(pid, sig)?;
            let status = ptrace::wait(pid)?;
            match ptrace::decode_status(status) {
                WaitOutcome::Exited(code) => {
                    self.mark_exited();
                    return Ok(DebuggerEvent::ProcessExited { exit_code: code });
                }
                WaitOutcome::Signalled(s) => {
                    self.mark_exited();
                    return Ok(DebuggerEvent::ProcessExited { exit_code: -s });
                }
                _ => {}
            }
            // Re-arm the breakpoint now the original instruction has executed.
            ptrace::write_mem(pid, addr, arch::BP_BYTES)?;
            // If single-stepping the restored instruction itself raised a real
            // signal (SIGSEGV/SIGILL/...), surface that fault rather than
            // masking it by re-arming and continuing.
            if let WaitOutcome::Stopped(s) = ptrace::decode_status(status) {
                if s != libc::SIGTRAP {
                    return self.interpret(status, step);
                }
            }
            if step {
                // The step-over instruction is exactly the user's single step.
                let regs = ptrace::get_regs(pid)?;
                let pc = arch::pc(&regs);
                self.last_stop_addr = pc;
                self.state = TargetState::Stopped;
                return Ok(DebuggerEvent::SingleStep { thread_id: pid as u32, address: pc });
            }
            // Otherwise fall through to a normal continue (signal consumed).
            ptrace::cont(pid, 0)?;
            self.state = TargetState::Running;
            let status = ptrace::wait(pid)?;
            return self.interpret(status, false);
        }

        if step {
            ptrace::single_step(pid, sig)?;
        } else {
            ptrace::cont(pid, sig)?;
        }
        self.state = TargetState::Running;
        let status = ptrace::wait(pid)?;
        self.interpret(status, step)
    }

    fn refresh_modules(&mut self) {
        if let Some(pid) = self.pid {
            if let Ok(m) = read_proc_maps(pid) {
                self.modules = m;
            }
        }
    }

    /// Program an x86 debug register (DR0–DR3 + DR7) for a hardware breakpoint.
    #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
    fn set_hw_x86(&mut self, address: u64, kind: BreakpointKind, size: u8) -> DbgResult<BreakpointId> {
        let pid = self.require_running()?;
        let slot = self
            .hw_slots
            .iter()
            .position(|s| s.is_none())
            .ok_or_else(|| DbgError::Breakpoint("all 4 hardware debug-register slots are in use".into()))?;
        // x86 DR7 RW encodings: 00=execute, 01=write, 11=read/write access.
        // There is no read-only mode, so a "read" watchpoint is programmed as
        // read/write access and reported as such (see `effective_kind`) rather
        // than falsely promising read-only behaviour.
        let (rw, len, effective_kind) = match kind {
            BreakpointKind::HardwareExecute => (0b00u64, 0b00u64, kind),
            BreakpointKind::HardwareWrite => (0b01, len_bits(size), kind),
            BreakpointKind::HardwareRead | BreakpointKind::HardwareAccess => {
                (0b11, len_bits(size), BreakpointKind::HardwareAccess)
            }
            BreakpointKind::Software => return self.set_breakpoint(address),
        };
        ptrace::poke_user(pid, ptrace::debugreg_offset(slot), address)?;
        let mut dr7 = ptrace::peek_user(pid, ptrace::debugreg_offset(7))?;
        dr7 |= 1u64 << (slot * 2); // local enable
        dr7 &= !(0b1111u64 << (16 + slot * 4)); // clear this slot's RW+LEN
        dr7 |= (rw << (16 + slot * 4)) | (len << (18 + slot * 4));
        ptrace::poke_user(pid, ptrace::debugreg_offset(7), dr7)?;

        let id = self.alloc_bp_id();
        let label = self
            .modules
            .iter()
            .find(|m| m.contains(address))
            .map(|m| format!("{}+0x{:x}", m.name, address - m.base))
            .unwrap_or_else(|| format!("0x{address:x}"));
        let mut bp = BreakpointInfo::new_software(id, address, label);
        bp.kind = effective_kind;
        bp.size = size;
        self.breakpoints.insert(id, bp);
        self.hw_slots[slot] = Some((id, address));
        Ok(id)
    }

    /// If a hardware debug register fired (DR6), map it to a breakpoint event.
    #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
    fn check_hw_hit(&mut self, pid: pid_t, _pc: u64) -> Option<DebuggerEvent> {
        let dr6 = ptrace::peek_user(pid, ptrace::debugreg_offset(6)).unwrap_or(0);
        if dr6 & 0xf == 0 {
            return None;
        }
        let slot = (dr6 & 0xf).trailing_zeros() as usize;
        let _ = ptrace::poke_user(pid, ptrace::debugreg_offset(6), 0); // clear status
        if let Some((id, addr)) = self.hw_slots.get(slot).copied().flatten() {
            self.hw_resume_rf = true;
            self.last_stop_addr = addr;
            if let Some(bp) = self.breakpoints.get_mut(&id) {
                bp.hit_count += 1;
            }
            return Some(DebuggerEvent::BreakpointHit { id: id.0, thread_id: pid as u32, address: addr });
        }
        None
    }
}

/// Split a command-line argument string into argv with shell-like quoting.
///
/// Handles single quotes, double quotes, and backslash escapes; whitespace
/// outside quotes separates arguments. Empty quoted strings (`''`) yield an
/// empty argument. This matches how the CLI presents the `--args` field.
fn split_args(s: &str) -> Vec<String> {
    let mut args = Vec::new();
    let mut cur = String::new();
    let mut has_token = false;
    let mut in_single = false;
    let mut in_double = false;
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\\' if !in_single => {
                if let Some(n) = chars.next() {
                    cur.push(n);
                    has_token = true;
                }
            }
            '\'' if !in_double => {
                in_single = !in_single;
                has_token = true;
            }
            '"' if !in_single => {
                in_double = !in_double;
                has_token = true;
            }
            c if c.is_whitespace() && !in_single && !in_double => {
                if has_token {
                    args.push(std::mem::take(&mut cur));
                    has_token = false;
                }
            }
            c => {
                cur.push(c);
                has_token = true;
            }
        }
    }
    if has_token {
        args.push(cur);
    }
    args
}

/// x86 DR7 length encoding for a watchpoint size in bytes.
#[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
fn len_bits(size: u8) -> u64 {
    match size {
        1 => 0b00,
        2 => 0b01,
        8 => 0b10,
        _ => 0b11, // 4 bytes
    }
}

impl Default for LinuxPtraceBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for LinuxPtraceBackend {
    fn drop(&mut self) {
        let Some(pid) = self.pid else { return };
        if matches!(self.state, TargetState::Exited | TargetState::NotStarted) {
            return;
        }
        if self.attached {
            // Leave a process we attached to running: restore any patched
            // breakpoints and detach instead of killing it.
            for (addr, orig) in self.orig.drain() {
                let _ = ptrace::write_mem(pid, addr, &orig);
            }
            let _ = ptrace::detach(pid, 0);
        } else {
            // We launched this child: tear it down.
            ptrace::send_signal(pid, libc::SIGKILL);
            let _ = ptrace::wait(pid);
        }
    }
}

impl DebugBackend for LinuxPtraceBackend {
    fn name(&self) -> &'static str {
        "Linux ptrace"
    }
    fn state(&self) -> TargetState {
        self.state
    }
    fn pid(&self) -> Option<u32> {
        self.pid.map(|p| p as u32)
    }

    fn launch(&mut self, target: &DebugTarget) -> DbgResult<()> {
        let exe = target
            .executable
            .as_ref()
            .ok_or_else(|| DbgError::InvalidArgument("no executable specified".into()))?;
        let exe_str = exe.to_string_lossy().into_owned();
        // Parse the argument string with shell-like quoting (matching how the
        // CLI / Windows backend treat it) so quoted arguments stay intact.
        let args = split_args(&target.arguments);
        let cwd = target.working_directory.as_ref().map(|p| p.to_string_lossy().into_owned());

        let pid = ptrace::fork_exec(&exe_str, &args, cwd.as_deref())?;
        self.pid = Some(pid);
        self.attached = false;

        // Wait for the initial stop right after execve.
        let status = ptrace::wait(pid)?;
        match ptrace::decode_status(status) {
            WaitOutcome::Exited(_) | WaitOutcome::Signalled(_) => {
                self.mark_exited();
                return Err(DbgError::Other("target exited before the initial stop".into()));
            }
            _ => {}
        }
        // Kill the tracee if the debugger dies.
        let _ = ptrace::set_options(pid, libc::PTRACE_O_EXITKILL);
        self.state = TargetState::Stopped;
        self.last_stop_tid = pid as u32;
        if let Ok(regs) = ptrace::get_regs(pid) {
            self.last_stop_addr = arch::pc(&regs);
        }
        self.refresh_modules();

        // Honour `break_on_entry`: when it is not requested, resume past the
        // initial exec stop so the target runs (matching the Windows backend),
        // rather than forcing the user to continue manually every session.
        if !target.break_on_entry {
            ptrace::cont(pid, 0)?;
            self.state = TargetState::Running;
        }
        Ok(())
    }

    fn attach(&mut self, pid: u32) -> DbgResult<()> {
        let pid = pid as pid_t;
        ptrace::attach(pid)?;
        let status = ptrace::wait(pid)?;
        if let WaitOutcome::Exited(_) | WaitOutcome::Signalled(_) = ptrace::decode_status(status) {
            return Err(DbgError::Other("process exited during attach".into()));
        }
        // Note: we deliberately do NOT set PTRACE_O_EXITKILL here — an attached
        // process must outlive the debugger (see Drop, which detaches it).
        self.pid = Some(pid);
        self.attached = true;
        self.state = TargetState::Stopped;
        self.last_stop_tid = pid as u32;
        if let Ok(regs) = ptrace::get_regs(pid) {
            self.last_stop_addr = arch::pc(&regs);
        }
        self.refresh_modules();
        Ok(())
    }

    fn detach(&mut self) -> DbgResult<()> {
        if let Some(pid) = self.pid {
            // Restore every patched breakpoint before letting the process go.
            for (addr, orig) in self.orig.drain() {
                let _ = ptrace::write_mem(pid, addr, &orig);
            }
            let _ = ptrace::detach(pid, 0);
        }
        self.state = TargetState::NotStarted;
        self.pid = None;
        self.breakpoints.clear();
        self.bp_by_addr.clear();
        Ok(())
    }

    fn kill(&mut self) -> DbgResult<()> {
        if let Some(pid) = self.pid {
            ptrace::send_signal(pid, libc::SIGKILL);
            let _ = ptrace::wait(pid);
        }
        self.mark_exited();
        Ok(())
    }

    fn continue_exec(&mut self) -> DbgResult<DebuggerEvent> {
        self.resume(false)
    }

    fn pause(&mut self) -> DbgResult<DebuggerEvent> {
        let pid = self.require_running()?;
        // If the tracee is already stopped, sending SIGSTOP and then blocking
        // in waitpid would hang forever (a stopped tracee reports no new wait
        // status until resumed). Just report the current stop instead.
        if self.state != TargetState::Running {
            return Ok(DebuggerEvent::Stopped {
                reason: "already stopped".into(),
                thread_id: self.last_stop_tid,
                address: self.last_stop_addr,
            });
        }
        // Stop the running tracee; it will report a SIGSTOP group-stop.
        ptrace::send_signal(pid, libc::SIGSTOP);
        let status = ptrace::wait(pid)?;
        self.interpret(status, false)
    }

    fn single_step(&mut self) -> DbgResult<DebuggerEvent> {
        self.resume(true)
    }

    fn step_over(&mut self) -> DbgResult<DebuggerEvent> {
        let pid = self.require_running()?;
        let regs = ptrace::get_regs(pid)?;
        let pc = arch::pc(&regs);
        // Decode the instruction at PC; only `call` needs a temp breakpoint.
        if let Ok(bytes) = ptrace::read_mem(pid, pc, 16) {
            if let Ok(Some(insn)) = crate::pwn::asm::disasm_one(arch::ARCH, pc, &bytes) {
                if insn.mnemonic.starts_with("call") || insn.mnemonic == "bl" || insn.mnemonic == "blr" || insn.mnemonic == "blx" {
                    let next = pc + insn.bytes.len() as u64;
                    return self.run_to_address(next);
                }
            }
        }
        self.single_step()
    }

    fn step_return(&mut self) -> DbgResult<DebuggerEvent> {
        let pid = self.require_running()?;
        let regs = ptrace::get_regs(pid)?;
        let ret = arch::return_address(pid, &regs)?;
        self.run_to_address(ret)
    }

    fn run_to_address(&mut self, address: u64) -> DbgResult<DebuggerEvent> {
        let already = self.bp_by_addr.contains_key(&address);
        let id = if already { None } else { Some(self.set_breakpoint(address)?) };
        let ev = self.continue_exec()?;
        if let Some(id) = id {
            let _ = self.remove_breakpoint(id);
        }
        Ok(ev)
    }

    fn read_registers(&self, thread_id: Option<u32>) -> DbgResult<RegisterFile> {
        let pid = thread_id.map(|t| t as pid_t).or(self.pid).ok_or(DbgError::NotRunning)?;
        let regs = ptrace::get_regs(pid)?;
        Ok(arch::to_register_file(&regs, pid as u32))
    }

    fn write_register(&mut self, thread_id: Option<u32>, register: &str, value: u64) -> DbgResult<()> {
        let pid = thread_id.map(|t| t as pid_t).or(self.pid).ok_or(DbgError::NotRunning)?;
        let mut regs = ptrace::get_regs(pid)?;
        if !arch::apply_register(&mut regs, register, value) {
            return Err(DbgError::Register(format!("unknown register: {register}")));
        }
        ptrace::set_regs(pid, &regs)
    }

    fn set_instruction_pointer(&mut self, thread_id: Option<u32>, address: u64) -> DbgResult<()> {
        self.write_register(thread_id, arch::PC_NAME, address)
    }

    fn read_memory(&self, address: u64, size: usize) -> DbgResult<Vec<u8>> {
        let pid = self.pid.ok_or(DbgError::NotRunning)?;
        let mut data = ptrace::read_mem(pid, address, size)?;
        // Hide any breakpoint bytes from the user's view of memory.
        for (addr, orig) in &self.orig {
            for (i, &b) in orig.iter().enumerate() {
                let a = addr + i as u64;
                if a >= address && a < address + data.len() as u64 {
                    data[(a - address) as usize] = b;
                }
            }
        }
        Ok(data)
    }

    fn write_memory(&mut self, address: u64, data: &[u8]) -> DbgResult<()> {
        let pid = self.pid.ok_or(DbgError::NotRunning)?;
        ptrace::write_mem(pid, address, data)?;

        // If the write overlaps an armed software breakpoint, the user's bytes
        // just clobbered our int3. Update the saved original bytes to the new
        // values (so read_memory shows the patch and removal restores it) and
        // re-insert the breakpoint opcode so it stays armed.
        let end = address + data.len() as u64;
        let overlapping: Vec<u64> = self
            .orig
            .keys()
            .copied()
            .filter(|bp_addr| {
                let bp_end = bp_addr + arch::BP_BYTES.len() as u64;
                *bp_addr < end && bp_end > address
            })
            .collect();
        for bp_addr in overlapping {
            if let Some(orig) = self.orig.get_mut(&bp_addr) {
                for (i, b) in orig.iter_mut().enumerate() {
                    let a = bp_addr + i as u64;
                    if a >= address && a < end {
                        *b = data[(a - address) as usize];
                    }
                }
            }
            let _ = ptrace::write_mem(pid, bp_addr, arch::BP_BYTES);
        }
        Ok(())
    }

    fn set_breakpoint(&mut self, address: u64) -> DbgResult<BreakpointId> {
        if let Some(&id) = self.bp_by_addr.get(&address) {
            return Ok(id);
        }
        let pid = self.require_running()?;
        let original = ptrace::read_mem(pid, address, arch::BP_BYTES.len())?;
        if original.len() < arch::BP_BYTES.len() {
            return Err(DbgError::Memory { address, message: "unreadable code at breakpoint".into() });
        }
        ptrace::write_mem(pid, address, arch::BP_BYTES)?;
        let id = self.alloc_bp_id();
        let label = self
            .modules
            .iter()
            .find(|m| m.contains(address))
            .map(|m| format!("{}+0x{:x}", m.name, address - m.base))
            .unwrap_or_else(|| format!("0x{address:x}"));
        let mut bp = BreakpointInfo::new_software(id, address, label);
        bp.original_byte = original.first().copied();
        self.breakpoints.insert(id, bp);
        self.bp_by_addr.insert(address, id);
        self.orig.insert(address, original);
        Ok(id)
    }

    fn set_hardware_breakpoint(&mut self, address: u64, kind: BreakpointKind, size: u8) -> DbgResult<BreakpointId> {
        #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
        {
            self.set_hw_x86(address, kind, size)
        }
        #[cfg(not(any(target_arch = "x86_64", target_arch = "x86")))]
        {
            // No debug-register marshalling on this arch yet. An execute
            // hardware breakpoint behaves identically to a software one, but a
            // data watchpoint must NOT plant a breakpoint instruction into the
            // watched data (that would corrupt the tracee and never trap).
            let _ = size;
            match kind {
                BreakpointKind::HardwareExecute | BreakpointKind::Software => self.set_breakpoint(address),
                BreakpointKind::HardwareRead | BreakpointKind::HardwareWrite | BreakpointKind::HardwareAccess => {
                    Err(DbgError::Unsupported(
                        "data watchpoints require hardware debug registers, not yet programmed on this architecture".into(),
                    ))
                }
            }
        }
    }

    fn remove_breakpoint(&mut self, id: BreakpointId) -> DbgResult<()> {
        if let Some(bp) = self.breakpoints.remove(&id) {
            // Only drop the address map if it still points at *this* breakpoint
            // (a hardware breakpoint may share an address with a software one).
            if self.bp_by_addr.get(&bp.address) == Some(&id) {
                self.bp_by_addr.remove(&bp.address);
            }
            #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
            if let Some(slot) = self.hw_slots.iter().position(|s| matches!(s, Some((sid, _)) if *sid == id)) {
                if let Some(pid) = self.pid {
                    if let Ok(mut dr7) = ptrace::peek_user(pid, ptrace::debugreg_offset(7)) {
                        dr7 &= !(1u64 << (slot * 2));
                        let _ = ptrace::poke_user(pid, ptrace::debugreg_offset(7), dr7);
                    }
                }
                self.hw_slots[slot] = None;
            }
            // Software-breakpoint teardown (int3 byte restore) must only run for
            // software breakpoints — a hardware breakpoint may share an address
            // with a software one whose saved bytes/reinsert must be preserved.
            if bp.kind == BreakpointKind::Software {
                if let (Some(pid), Some(orig)) = (self.pid, self.orig.remove(&bp.address)) {
                    if bp.enabled {
                        let _ = ptrace::write_mem(pid, bp.address, &orig);
                    }
                }
                if self.pending_reinsert == Some(bp.address) {
                    self.pending_reinsert = None;
                }
            }
        }
        Ok(())
    }

    fn enable_breakpoint(&mut self, id: BreakpointId, enabled: bool) -> DbgResult<()> {
        let (address, was) = {
            let bp = self.breakpoints.get(&id).ok_or_else(|| DbgError::Breakpoint("unknown id".into()))?;
            (bp.address, bp.enabled)
        };
        if was == enabled {
            return Ok(());
        }
        let pid = self.require_running()?;

        // Hardware breakpoints live in a debug-register slot; toggle DR7's
        // enable bit rather than patching the (data) address with an int3.
        #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
        if let Some(slot) = self.hw_slots.iter().position(|s| matches!(s, Some((sid, _)) if *sid == id)) {
            let mut dr7 = ptrace::peek_user(pid, ptrace::debugreg_offset(7))?;
            if enabled {
                dr7 |= 1u64 << (slot * 2);
            } else {
                dr7 &= !(1u64 << (slot * 2));
            }
            ptrace::poke_user(pid, ptrace::debugreg_offset(7), dr7)?;
            if let Some(bp) = self.breakpoints.get_mut(&id) {
                bp.enabled = enabled;
            }
            return Ok(());
        }

        // Software breakpoint: patch / restore the instruction byte(s).
        if enabled {
            let original = ptrace::read_mem(pid, address, arch::BP_BYTES.len())?;
            ptrace::write_mem(pid, address, arch::BP_BYTES)?;
            self.orig.insert(address, original);
        } else {
            if let Some(orig) = self.orig.remove(&address) {
                ptrace::write_mem(pid, address, &orig)?;
            }
            // If we are stopped on this breakpoint, drop the pending re-arm so
            // the next resume does not re-install an int3 for a now-disabled
            // breakpoint (which would leave an int3 with no saved original).
            if self.pending_reinsert == Some(address) {
                self.pending_reinsert = None;
            }
        }
        if let Some(bp) = self.breakpoints.get_mut(&id) {
            bp.enabled = enabled;
        }
        Ok(())
    }

    fn set_breakpoint_condition(&mut self, id: BreakpointId, condition: Option<String>) -> DbgResult<()> {
        let bp = self.breakpoints.get_mut(&id).ok_or_else(|| DbgError::Breakpoint("unknown id".into()))?;
        bp.condition = condition;
        Ok(())
    }

    fn list_breakpoints(&self) -> Vec<BreakpointInfo> {
        let mut v: Vec<_> = self.breakpoints.values().cloned().collect();
        v.sort_by_key(|b| b.id.0);
        v
    }

    fn list_threads(&self) -> DbgResult<Vec<DebugThread>> {
        let Some(pid) = self.pid else { return Ok(vec![]) };
        let mut threads = Vec::new();
        if let Ok(entries) = std::fs::read_dir(format!("/proc/{pid}/task")) {
            for e in entries.flatten() {
                if let Some(tid) = e.file_name().to_str().and_then(|s| s.parse::<u32>().ok()) {
                    threads.push(DebugThread { thread_id: tid, ..Default::default() });
                }
            }
        }
        if threads.is_empty() {
            threads.push(DebugThread { thread_id: pid as u32, ..Default::default() });
        }
        threads.sort_by_key(|t| t.thread_id);
        Ok(threads)
    }

    fn list_modules(&self) -> DbgResult<Vec<DebugModule>> {
        if let Some(pid) = self.pid {
            if let Ok(m) = read_proc_maps(pid) {
                return Ok(m);
            }
        }
        Ok(self.modules.clone())
    }

    fn stack_trace(&self, thread_id: u32) -> DbgResult<Vec<StackFrame>> {
        let pid = if thread_id != 0 { thread_id as pid_t } else { self.pid.ok_or(DbgError::NotRunning)? };
        let regs = ptrace::get_regs(pid)?;
        let mut frames = Vec::new();
        let mut pc = arch::pc(&regs);
        let mut fp = arch::fp(&regs);
        let sp = arch::sp(&regs);
        let module_of = |addr: u64| self.modules.iter().find(|m| m.contains(addr)).map(|m| m.name.clone());
        frames.push(StackFrame { frame_index: 0, thread_id, pc, sp, fp, function: None, module: module_of(pc) });
        // Frame-pointer unwind: [fp] = saved fp, [fp + ptr] = return address.
        let ptr = arch::PTR_SIZE as u64;
        for i in 1..32u32 {
            if fp == 0 {
                break;
            }
            let Ok(saved) = ptrace::read_mem(pid, fp, arch::PTR_SIZE) else { break };
            let Ok(ret_b) = ptrace::read_mem(pid, fp + ptr, arch::PTR_SIZE) else { break };
            if saved.len() < arch::PTR_SIZE || ret_b.len() < arch::PTR_SIZE {
                break;
            }
            let new_fp = read_ptr(&saved);
            let ret = read_ptr(&ret_b);
            if ret == 0 || new_fp <= fp {
                break;
            }
            frames.push(StackFrame { frame_index: i, thread_id, pc: ret, sp: fp, fp: new_fp, function: None, module: module_of(ret) });
            pc = ret;
            fp = new_fp;
            let _ = pc;
        }
        Ok(frames)
    }
}

fn read_ptr(bytes: &[u8]) -> u64 {
    let mut buf = [0u8; 8];
    let n = bytes.len().min(8);
    buf[..n].copy_from_slice(&bytes[..n]);
    u64::from_le_bytes(buf)
}

/// Parse `/proc/<pid>/maps` into one [`DebugModule`] per backing file.
fn read_proc_maps(pid: pid_t) -> DbgResult<Vec<DebugModule>> {
    let text = std::fs::read_to_string(format!("/proc/{pid}/maps"))
        .map_err(|e| DbgError::Other(e.to_string()))?;
    // Aggregate the address range of each distinct path.
    let mut by_path: HashMap<String, (u64, u64)> = HashMap::new();
    let mut order: Vec<String> = Vec::new();
    for line in text.lines() {
        // Format: start-end perms offset dev inode    pathname
        let mut parts = line.splitn(6, ' ').filter(|s| !s.is_empty());
        let range = parts.next().unwrap_or("");
        let _perms = parts.next();
        let _off = parts.next();
        let _dev = parts.next();
        let _inode = parts.next();
        let path = parts.next().unwrap_or("").trim();
        if path.is_empty() || path.starts_with('[') {
            continue;
        }
        let Some((s, e)) = range.split_once('-') else { continue };
        let (Ok(start), Ok(end)) = (u64::from_str_radix(s, 16), u64::from_str_radix(e, 16)) else { continue };
        let entry = by_path.entry(path.to_string()).or_insert_with(|| {
            order.push(path.to_string());
            (start, end)
        });
        entry.0 = entry.0.min(start);
        entry.1 = entry.1.max(end);
    }
    let mut mods = Vec::new();
    for (i, path) in order.iter().enumerate() {
        let (base, end) = by_path[path];
        let name = path.rsplit('/').next().unwrap_or(path).to_string();
        mods.push(DebugModule {
            name,
            path: path.clone(),
            base,
            size: end.saturating_sub(base),
            is_main: i == 0,
        });
    }
    Ok(mods)
}

// ============================================================ arch-specific ==

#[cfg(target_arch = "x86_64")]
mod arch {
    use super::*;
    use crate::target::arch::Architecture;

    pub const BP_BYTES: &[u8] = &[0xCC];
    pub const PTR_SIZE: usize = 8;
    pub const ARCH: Architecture = Architecture::X86_64;
    pub const PC_NAME: &str = "rip";

    pub fn pc(r: &libc::user_regs_struct) -> u64 { r.rip }
    pub fn sp(r: &libc::user_regs_struct) -> u64 { r.rsp }
    pub fn fp(r: &libc::user_regs_struct) -> u64 { r.rbp }
    pub fn set_pc(r: &mut libc::user_regs_struct, v: u64) { r.rip = v; }
    /// On x86 `int3` advances RIP one byte past the breakpoint.
    pub fn trap_bp_addr(pc: u64) -> u64 { pc.wrapping_sub(1) }
    /// Set EFLAGS.RF so the next instruction does not re-trigger an exec bp.
    pub fn set_resume_flag(r: &mut libc::user_regs_struct) { r.eflags |= 0x1_0000; }

    pub fn return_address(pid: libc::pid_t, r: &libc::user_regs_struct) -> DbgResult<u64> {
        let b = ptrace::read_mem(pid, r.rsp, 8)?;
        Ok(read_ptr(&b))
    }

    pub fn to_register_file(r: &libc::user_regs_struct, tid: u32) -> RegisterFile {
        let mut rf = RegisterFile::new(Architecture::X86_64, tid);
        rf.set("rax", r.rax); rf.set("rbx", r.rbx); rf.set("rcx", r.rcx); rf.set("rdx", r.rdx);
        rf.set("rsi", r.rsi); rf.set("rdi", r.rdi); rf.set("rbp", r.rbp); rf.set("rsp", r.rsp);
        rf.set("r8", r.r8); rf.set("r9", r.r9); rf.set("r10", r.r10); rf.set("r11", r.r11);
        rf.set("r12", r.r12); rf.set("r13", r.r13); rf.set("r14", r.r14); rf.set("r15", r.r15);
        rf.set("rip", r.rip); rf.set("rflags", r.eflags);
        rf
    }

    pub fn apply_register(r: &mut libc::user_regs_struct, name: &str, v: u64) -> bool {
        match name.to_ascii_lowercase().as_str() {
            "rax" => r.rax = v, "rbx" => r.rbx = v, "rcx" => r.rcx = v, "rdx" => r.rdx = v,
            "rsi" => r.rsi = v, "rdi" => r.rdi = v, "rbp" | "fp" => r.rbp = v,
            "rsp" | "sp" => r.rsp = v, "r8" => r.r8 = v, "r9" => r.r9 = v, "r10" => r.r10 = v,
            "r11" => r.r11 = v, "r12" => r.r12 = v, "r13" => r.r13 = v, "r14" => r.r14 = v,
            "r15" => r.r15 = v, "rip" | "pc" => r.rip = v, "rflags" | "eflags" => r.eflags = v,
            _ => return false,
        }
        true
    }
}

#[cfg(target_arch = "x86")]
mod arch {
    use super::*;
    use crate::target::arch::Architecture;

    pub const BP_BYTES: &[u8] = &[0xCC];
    pub const PTR_SIZE: usize = 4;
    pub const ARCH: Architecture = Architecture::X86;
    pub const PC_NAME: &str = "eip";

    pub fn pc(r: &libc::user_regs_struct) -> u64 { r.eip as u64 }
    pub fn sp(r: &libc::user_regs_struct) -> u64 { r.esp as u64 }
    pub fn fp(r: &libc::user_regs_struct) -> u64 { r.ebp as u64 }
    pub fn set_pc(r: &mut libc::user_regs_struct, v: u64) { r.eip = v as _; }
    pub fn trap_bp_addr(pc: u64) -> u64 { pc.wrapping_sub(1) }
    pub fn set_resume_flag(r: &mut libc::user_regs_struct) { r.eflags |= 0x1_0000; }

    pub fn return_address(pid: libc::pid_t, r: &libc::user_regs_struct) -> DbgResult<u64> {
        let b = ptrace::read_mem(pid, r.esp as u64, 4)?;
        Ok(read_ptr(&b))
    }

    pub fn to_register_file(r: &libc::user_regs_struct, tid: u32) -> RegisterFile {
        let mut rf = RegisterFile::new(Architecture::X86, tid);
        rf.set("eax", r.eax as u64); rf.set("ebx", r.ebx as u64); rf.set("ecx", r.ecx as u64);
        rf.set("edx", r.edx as u64); rf.set("esi", r.esi as u64); rf.set("edi", r.edi as u64);
        rf.set("ebp", r.ebp as u64); rf.set("esp", r.esp as u64); rf.set("eip", r.eip as u64);
        rf.set("eflags", r.eflags as u64);
        rf
    }

    pub fn apply_register(r: &mut libc::user_regs_struct, name: &str, v: u64) -> bool {
        match name.to_ascii_lowercase().as_str() {
            "eax" => r.eax = v as _, "ebx" => r.ebx = v as _, "ecx" => r.ecx = v as _,
            "edx" => r.edx = v as _, "esi" => r.esi = v as _, "edi" => r.edi = v as _,
            "ebp" | "fp" => r.ebp = v as _, "esp" | "sp" => r.esp = v as _,
            "eip" | "pc" => r.eip = v as _, "eflags" => r.eflags = v as _,
            _ => return false,
        }
        true
    }
}

#[cfg(target_arch = "aarch64")]
mod arch {
    use super::*;
    use crate::target::arch::Architecture;

    /// AArch64 `BRK #0` (0xD4200000), little-endian.
    pub const BP_BYTES: &[u8] = &[0x00, 0x00, 0x20, 0xD4];
    pub const PTR_SIZE: usize = 8;
    pub const ARCH: Architecture = Architecture::AArch64;
    pub const PC_NAME: &str = "pc";

    pub fn pc(r: &libc::user_regs_struct) -> u64 { r.pc }
    pub fn sp(r: &libc::user_regs_struct) -> u64 { r.sp }
    pub fn fp(r: &libc::user_regs_struct) -> u64 { r.regs[29] }
    pub fn set_pc(r: &mut libc::user_regs_struct, v: u64) { r.pc = v; }
    /// AArch64 leaves PC at the `BRK` instruction.
    pub fn trap_bp_addr(pc: u64) -> u64 { pc }

    pub fn return_address(_pid: libc::pid_t, r: &libc::user_regs_struct) -> DbgResult<u64> {
        Ok(r.regs[30]) // x30 / LR
    }

    pub fn to_register_file(r: &libc::user_regs_struct, tid: u32) -> RegisterFile {
        let mut rf = RegisterFile::new(Architecture::AArch64, tid);
        for i in 0..31 {
            rf.set(&format!("x{i}"), r.regs[i]);
        }
        rf.set("fp", r.regs[29]);
        rf.set("lr", r.regs[30]);
        rf.set("sp", r.sp);
        rf.set("pc", r.pc);
        rf.set("pstate", r.pstate);
        rf
    }

    pub fn apply_register(r: &mut libc::user_regs_struct, name: &str, v: u64) -> bool {
        let n = name.to_ascii_lowercase();
        match n.as_str() {
            "sp" => r.sp = v,
            "pc" => r.pc = v,
            "fp" => r.regs[29] = v,
            "lr" => r.regs[30] = v,
            "pstate" => r.pstate = v,
            _ => {
                if let Some(idx) = n.strip_prefix('x').and_then(|s| s.parse::<usize>().ok()) {
                    if idx < 31 {
                        r.regs[idx] = v;
                        return true;
                    }
                }
                return false;
            }
        }
        true
    }
}

#[cfg(test)]
mod arg_tests {
    use super::split_args;

    #[test]
    fn plain_and_quoted_arguments() {
        assert_eq!(split_args(""), Vec::<String>::new());
        assert_eq!(split_args("   "), Vec::<String>::new());
        assert_eq!(split_args("a b c"), vec!["a", "b", "c"]);
        assert_eq!(split_args("\"hello world\" --flag"), vec!["hello world", "--flag"]);
        assert_eq!(split_args("'single quoted' x"), vec!["single quoted", "x"]);
        assert_eq!(split_args(r#"a\ b"#), vec!["a b"]);
        assert_eq!(split_args("''"), vec![""]);
        assert_eq!(split_args(r#"--path="/a b/c" -n"#), vec!["--path=/a b/c", "-n"]);
    }
}
