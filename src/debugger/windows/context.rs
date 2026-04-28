//! Thread context helpers for the Windows backend.
//!
//! Currently implements x86_64 (the primary supported host).
//! Other architectures return `Unsupported`.

use crate::debugger::registers::RegisterFile;
use crate::error::{DbgError, DbgResult};
use crate::target::arch::Architecture;

use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::Diagnostics::Debug::{
    GetThreadContext, SetThreadContext, CONTEXT, CONTEXT_FLAGS,
};
use windows::Win32::System::Threading::{OpenThread, THREAD_ACCESS_RIGHTS, THREAD_GET_CONTEXT, THREAD_SET_CONTEXT, THREAD_QUERY_INFORMATION, THREAD_SUSPEND_RESUME};

const CONTEXT_AMD64: u32 = 0x0010_0000;
const CONTEXT_CONTROL: u32 = CONTEXT_AMD64 | 0x1;
const CONTEXT_INTEGER: u32 = CONTEXT_AMD64 | 0x2;
const CONTEXT_SEGMENTS: u32 = CONTEXT_AMD64 | 0x4;
const CONTEXT_FLOATING_POINT: u32 = CONTEXT_AMD64 | 0x8;
const CONTEXT_DEBUG_REGISTERS: u32 = CONTEXT_AMD64 | 0x10;
pub const CONTEXT_ALL_X64: u32 =
    CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS | CONTEXT_FLOATING_POINT | CONTEXT_DEBUG_REGISTERS;

struct ThreadHandle(HANDLE);
impl Drop for ThreadHandle {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            // SAFETY: handle owned exclusively by us.
            unsafe { let _ = CloseHandle(self.0); }
        }
    }
}

fn open_thread(tid: u32, rights: THREAD_ACCESS_RIGHTS) -> DbgResult<ThreadHandle> {
    // SAFETY: OpenThread is a standard Win32 API.
    unsafe { OpenThread(rights, false, tid) }
        .map(ThreadHandle)
        .map_err(DbgError::from)
}

#[cfg(target_arch = "x86_64")]
pub fn read_context_x64(tid: u32) -> DbgResult<CONTEXT> {
    let h = open_thread(tid, THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION)?;
    let mut ctx = CONTEXT::default();
    ctx.ContextFlags = CONTEXT_FLAGS(CONTEXT_ALL_X64);
    // SAFETY: thread handle is valid and CONTEXT struct is appropriately aligned.
    unsafe { GetThreadContext(h.0, &mut ctx)?; }
    Ok(ctx)
}

#[cfg(target_arch = "x86_64")]
pub fn write_context_x64(tid: u32, ctx: &CONTEXT) -> DbgResult<()> {
    let h = open_thread(tid, THREAD_SET_CONTEXT | THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME)?;
    // SAFETY: handle valid; CONTEXT pointer non-null and aligned.
    unsafe { SetThreadContext(h.0, ctx)?; }
    Ok(())
}

#[cfg(target_arch = "x86_64")]
pub fn context_to_register_file(ctx: &CONTEXT, tid: u32) -> RegisterFile {
    let mut rf = RegisterFile::new(Architecture::X86_64, tid);
    rf.set("rax", ctx.Rax);
    rf.set("rbx", ctx.Rbx);
    rf.set("rcx", ctx.Rcx);
    rf.set("rdx", ctx.Rdx);
    rf.set("rsi", ctx.Rsi);
    rf.set("rdi", ctx.Rdi);
    rf.set("rbp", ctx.Rbp);
    rf.set("rsp", ctx.Rsp);
    rf.set("r8",  ctx.R8);
    rf.set("r9",  ctx.R9);
    rf.set("r10", ctx.R10);
    rf.set("r11", ctx.R11);
    rf.set("r12", ctx.R12);
    rf.set("r13", ctx.R13);
    rf.set("r14", ctx.R14);
    rf.set("r15", ctx.R15);
    rf.set("rip", ctx.Rip);
    rf.set("rflags", ctx.EFlags as u64);
    rf
}

#[cfg(target_arch = "x86_64")]
pub fn apply_register_to_context(ctx: &mut CONTEXT, name: &str, value: u64) -> DbgResult<()> {
    match name.to_ascii_lowercase().as_str() {
        "rax" => ctx.Rax = value,
        "rbx" => ctx.Rbx = value,
        "rcx" => ctx.Rcx = value,
        "rdx" => ctx.Rdx = value,
        "rsi" => ctx.Rsi = value,
        "rdi" => ctx.Rdi = value,
        "rbp" => ctx.Rbp = value,
        "rsp" => ctx.Rsp = value,
        "r8"  => ctx.R8  = value,
        "r9"  => ctx.R9  = value,
        "r10" => ctx.R10 = value,
        "r11" => ctx.R11 = value,
        "r12" => ctx.R12 = value,
        "r13" => ctx.R13 = value,
        "r14" => ctx.R14 = value,
        "r15" => ctx.R15 = value,
        "rip" => ctx.Rip = value,
        "rflags" | "eflags" => ctx.EFlags = value as u32,
        other => return Err(DbgError::Register(format!("unknown x64 register: {other}"))),
    }
    Ok(())
}

#[cfg(not(target_arch = "x86_64"))]
pub fn read_context_x64(_tid: u32) -> DbgResult<()> {
    Err(DbgError::Unsupported("non-x86_64 host not supported by Windows backend".into()))
}
