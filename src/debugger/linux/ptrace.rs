//! Thin, safe-ish wrappers over the `ptrace(2)` syscalls used by the Linux
//! x86-64 debugger backend, plus `/proc`-based memory access and process
//! introspection.
//!
//! This module is only compiled for `linux + x86_64` (see `linux/mod.rs`); the
//! register marshalling and the `int3` breakpoint encoding are x86-64 specific.

use std::ffi::{c_void, CString};
use std::fs::File;
use std::io;
use std::os::unix::fs::FileExt;

use libc::{c_long, pid_t, user_regs_struct};

use crate::error::{DbgError, DbgResult};

/// The x86 software-breakpoint opcode (`int3`).
pub const BP_OPCODE: u8 = 0xCC;

fn errno() -> i32 {
    // SAFETY: __errno_location always returns a valid pointer.
    unsafe { *libc::__errno_location() }
}
fn clear_errno() {
    // SAFETY: as above.
    unsafe { *libc::__errno_location() = 0 }
}
fn os_err(ctx: &str) -> DbgError {
    DbgError::Other(format!("{ctx}: {}", io::Error::from_raw_os_error(errno())))
}

fn raw(request: u32, pid: pid_t, addr: *mut c_void, data: *mut c_void) -> c_long {
    // SAFETY: ptrace is variadic; we pass the documented argument shapes.
    unsafe { libc::ptrace(request as _, pid, addr, data) }
}

/// `PTRACE_TRACEME` — called in the child before `exec`.
pub fn trace_me() -> DbgResult<()> {
    if raw(libc::PTRACE_TRACEME, 0, std::ptr::null_mut(), std::ptr::null_mut()) == -1 {
        return Err(os_err("PTRACE_TRACEME"));
    }
    Ok(())
}

pub fn set_options(pid: pid_t, options: i32) -> DbgResult<()> {
    if raw(libc::PTRACE_SETOPTIONS, pid, std::ptr::null_mut(), options as *mut c_void) == -1 {
        return Err(os_err("PTRACE_SETOPTIONS"));
    }
    Ok(())
}

pub fn attach(pid: pid_t) -> DbgResult<()> {
    if raw(libc::PTRACE_ATTACH, pid, std::ptr::null_mut(), std::ptr::null_mut()) == -1 {
        return Err(os_err("PTRACE_ATTACH"));
    }
    Ok(())
}

pub fn detach(pid: pid_t, sig: i32) -> DbgResult<()> {
    if raw(libc::PTRACE_DETACH, pid, std::ptr::null_mut(), sig as *mut c_void) == -1 {
        return Err(os_err("PTRACE_DETACH"));
    }
    Ok(())
}

/// Continue the tracee, delivering `sig` (0 = none).
pub fn cont(pid: pid_t, sig: i32) -> DbgResult<()> {
    if raw(libc::PTRACE_CONT, pid, std::ptr::null_mut(), sig as *mut c_void) == -1 {
        return Err(os_err("PTRACE_CONT"));
    }
    Ok(())
}

/// Execute a single instruction, delivering `sig` (0 = none).
pub fn single_step(pid: pid_t, sig: i32) -> DbgResult<()> {
    if raw(libc::PTRACE_SINGLESTEP, pid, std::ptr::null_mut(), sig as *mut c_void) == -1 {
        return Err(os_err("PTRACE_SINGLESTEP"));
    }
    Ok(())
}

/// `NT_PRSTATUS` regset selector for `PTRACE_GET/SETREGSET`.
const NT_PRSTATUS: usize = 1;

// We use the regset API (`PTRACE_GETREGSET` / `PTRACE_SETREGSET`) rather than
// `PTRACE_GETREGS`, because the latter does not exist on AArch64. The regset
// API is uniform across x86-64, x86 and AArch64.

pub fn get_regs(pid: pid_t) -> DbgResult<user_regs_struct> {
    // SAFETY: zeroed user_regs_struct is a valid POD initial value.
    let mut regs: user_regs_struct = unsafe { std::mem::zeroed() };
    let mut iov = libc::iovec {
        iov_base: &mut regs as *mut _ as *mut c_void,
        iov_len: std::mem::size_of::<user_regs_struct>(),
    };
    if raw(libc::PTRACE_GETREGSET, pid, NT_PRSTATUS as *mut c_void, &mut iov as *mut _ as *mut c_void) == -1 {
        return Err(os_err("PTRACE_GETREGSET"));
    }
    Ok(regs)
}

pub fn set_regs(pid: pid_t, regs: &user_regs_struct) -> DbgResult<()> {
    let mut iov = libc::iovec {
        iov_base: regs as *const _ as *mut c_void,
        iov_len: std::mem::size_of::<user_regs_struct>(),
    };
    if raw(libc::PTRACE_SETREGSET, pid, NT_PRSTATUS as *mut c_void, &mut iov as *mut _ as *mut c_void) == -1 {
        return Err(os_err("PTRACE_SETREGSET"));
    }
    Ok(())
}

/// Read one machine word at `addr` (`PTRACE_PEEKTEXT`).
fn peek(pid: pid_t, addr: u64) -> DbgResult<i64> {
    clear_errno();
    let v = raw(libc::PTRACE_PEEKTEXT, pid, addr as *mut c_void, std::ptr::null_mut());
    if v == -1 && errno() != 0 {
        return Err(DbgError::Memory { address: addr, message: io::Error::from_raw_os_error(errno()).to_string() });
    }
    Ok(v as i64)
}

/// Write one machine word at `addr` (`PTRACE_POKETEXT`).
fn poke(pid: pid_t, addr: u64, word: i64) -> DbgResult<()> {
    if raw(libc::PTRACE_POKETEXT, pid, addr as *mut c_void, word as usize as *mut c_void) == -1 {
        return Err(DbgError::Memory { address: addr, message: io::Error::from_raw_os_error(errno()).to_string() });
    }
    Ok(())
}

const WORD: usize = std::mem::size_of::<c_long>();

/// Read `size` bytes from the tracee via `/proc/<pid>/mem` (fast, arbitrary
/// length). Returns however many bytes were readable.
pub fn read_mem(pid: pid_t, addr: u64, size: usize) -> DbgResult<Vec<u8>> {
    let f = File::open(format!("/proc/{pid}/mem"))
        .map_err(|e| DbgError::Memory { address: addr, message: e.to_string() })?;
    let mut buf = vec![0u8; size];
    match f.read_at(&mut buf, addr) {
        Ok(n) => {
            buf.truncate(n);
            Ok(buf)
        }
        Err(e) => Err(DbgError::Memory { address: addr, message: e.to_string() }),
    }
}

/// Write `data` into the tracee using word-aligned `PTRACE_POKETEXT`, which
/// bypasses page protections (needed to patch `int3` into r-x code pages).
pub fn write_mem(pid: pid_t, addr: u64, data: &[u8]) -> DbgResult<()> {
    if data.is_empty() {
        return Ok(());
    }
    let start = addr - (addr % WORD as u64);
    let end = addr + data.len() as u64;
    let mut cur = start;
    while cur < end {
        let mut word = peek(pid, cur)?.to_ne_bytes();
        for (i, b) in word.iter_mut().enumerate() {
            let byte_addr = cur + i as u64;
            if byte_addr >= addr && byte_addr < end {
                *b = data[(byte_addr - addr) as usize];
            }
        }
        poke(pid, cur, i64::from_ne_bytes(word))?;
        cur += WORD as u64;
    }
    Ok(())
}

/// Spawn `path` with `args`, set it up as a ptrace tracee, and return its pid.
/// The child runs `PTRACE_TRACEME` then `execvp`; the caller waits for the
/// initial `execve` stop.
pub fn fork_exec(path: &str, args: &[String], cwd: Option<&str>) -> DbgResult<pid_t> {
    let c_path = CString::new(path).map_err(|_| DbgError::InvalidArgument("path has NUL".into()))?;
    let mut argv_owned: Vec<CString> = Vec::with_capacity(args.len() + 1);
    argv_owned.push(c_path.clone());
    for a in args {
        argv_owned.push(CString::new(a.as_str()).map_err(|_| DbgError::InvalidArgument("arg has NUL".into()))?);
    }
    let mut argv_ptrs: Vec<*const libc::c_char> = argv_owned.iter().map(|c| c.as_ptr()).collect();
    argv_ptrs.push(std::ptr::null());
    let c_cwd = match cwd {
        Some(d) => Some(CString::new(d).map_err(|_| DbgError::InvalidArgument("cwd has NUL".into()))?),
        None => None,
    };

    // SAFETY: fork in a process that immediately execs in the child; between
    // fork and exec we only call async-signal-safe syscalls and use pointers
    // into buffers allocated before the fork.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(os_err("fork"));
    }
    if pid == 0 {
        // Child.
        unsafe {
            let _ = libc::ptrace(libc::PTRACE_TRACEME as _, 0, std::ptr::null_mut::<c_void>(), std::ptr::null_mut::<c_void>());
            // Make addresses reproducible across runs for easier debugging.
            let _ = libc::personality(libc::ADDR_NO_RANDOMIZE as libc::c_ulong);
            if let Some(d) = &c_cwd {
                let _ = libc::chdir(d.as_ptr());
            }
            libc::execvp(c_path.as_ptr(), argv_ptrs.as_ptr());
            // exec failed.
            libc::_exit(127);
        }
    }
    Ok(pid)
}

/// `waitpid` wrapper returning the raw status word.
pub fn wait(pid: pid_t) -> DbgResult<i32> {
    let mut status: i32 = 0;
    // SAFETY: status is a valid out-pointer.
    let r = unsafe { libc::waitpid(pid, &mut status, 0) };
    if r == -1 {
        return Err(os_err("waitpid"));
    }
    Ok(status)
}

/// Decoded `waitpid` status.
pub enum WaitOutcome {
    Exited(i32),
    Signalled(i32),
    Stopped(i32),
    Other,
}

pub fn decode_status(status: i32) -> WaitOutcome {
    // The W* helpers are pure bit inspection of the status word.
    if libc::WIFEXITED(status) {
        WaitOutcome::Exited(libc::WEXITSTATUS(status))
    } else if libc::WIFSIGNALED(status) {
        WaitOutcome::Signalled(libc::WTERMSIG(status))
    } else if libc::WIFSTOPPED(status) {
        WaitOutcome::Stopped(libc::WSTOPSIG(status))
    } else {
        WaitOutcome::Other
    }
}

/// Human-readable name for a signal number.
pub fn signal_name(sig: i32) -> &'static str {
    match sig {
        libc::SIGSEGV => "SIGSEGV (segmentation fault)",
        libc::SIGILL => "SIGILL (illegal instruction)",
        libc::SIGFPE => "SIGFPE (arithmetic exception)",
        libc::SIGBUS => "SIGBUS (bus error)",
        libc::SIGABRT => "SIGABRT (abort)",
        libc::SIGTRAP => "SIGTRAP (trap)",
        libc::SIGINT => "SIGINT (interrupt)",
        libc::SIGTERM => "SIGTERM",
        libc::SIGKILL => "SIGKILL",
        libc::SIGSTOP => "SIGSTOP",
        _ => "signal",
    }
}

/// Send a signal to a process.
pub fn send_signal(pid: pid_t, sig: i32) {
    // SAFETY: kill with a pid we own.
    unsafe { libc::kill(pid, sig); }
}

// ---- x86 debug-register access (hardware breakpoints / watchpoints) --------

/// Byte offset of debug register `n` within the `struct user` USER area.
#[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
pub fn debugreg_offset(n: usize) -> usize {
    std::mem::offset_of!(libc::user, u_debugreg) + n * std::mem::size_of::<usize>()
}

/// Read debug register `n` (`PTRACE_PEEKUSER`).
#[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
pub fn peek_user(pid: pid_t, offset: usize) -> DbgResult<u64> {
    clear_errno();
    let v = raw(libc::PTRACE_PEEKUSER, pid, offset as *mut c_void, std::ptr::null_mut());
    if v == -1 && errno() != 0 {
        return Err(os_err("PTRACE_PEEKUSER"));
    }
    Ok(v as u64)
}

/// Write debug register `n` (`PTRACE_POKEUSER`).
#[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
pub fn poke_user(pid: pid_t, offset: usize, data: u64) -> DbgResult<()> {
    if raw(libc::PTRACE_POKEUSER, pid, offset as *mut c_void, data as usize as *mut c_void) == -1 {
        return Err(os_err("PTRACE_POKEUSER"));
    }
    Ok(())
}
