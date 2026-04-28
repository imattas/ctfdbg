//! Toolhelp32-based process / module / thread enumeration helpers.

use crate::debugger::modules::DebugModule;
use crate::debugger::threads::DebugThread;
use crate::error::DbgResult;

use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Module32FirstW, Module32NextW, Process32FirstW, Process32NextW,
    Thread32First, Thread32Next, MODULEENTRY32W, PROCESSENTRY32W, TH32CS_SNAPMODULE,
    TH32CS_SNAPMODULE32, TH32CS_SNAPPROCESS, TH32CS_SNAPTHREAD, THREADENTRY32,
};

/// Snapshot wrapper that closes its handle on drop.
struct Snapshot(HANDLE);
impl Drop for Snapshot {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            // SAFETY: handle owned by us and not closed elsewhere.
            unsafe { let _ = CloseHandle(self.0); }
        }
    }
}

#[derive(Debug, Clone)]
pub struct SystemProcess {
    pub pid: u32,
    pub name: String,
}

pub fn list_system_processes() -> DbgResult<Vec<SystemProcess>> {
    let mut out = Vec::new();
    // SAFETY: Win32 toolhelp APIs called with valid args; handles are wrapped.
    unsafe {
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)?;
        let snap = Snapshot(snap);
        let mut entry = PROCESSENTRY32W {
            dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };
        if Process32FirstW(snap.0, &mut entry).is_ok() {
            loop {
                let len = entry.szExeFile.iter().position(|&c| c == 0).unwrap_or(entry.szExeFile.len());
                let name = String::from_utf16_lossy(&entry.szExeFile[..len]);
                out.push(SystemProcess { pid: entry.th32ProcessID, name });
                if Process32NextW(snap.0, &mut entry).is_err() { break; }
            }
        }
    }
    out.sort_by_key(|p| p.pid);
    Ok(out)
}

pub fn list_process_modules(pid: u32) -> DbgResult<Vec<DebugModule>> {
    let mut out = Vec::new();
    // SAFETY: Win32 toolhelp APIs called with valid args.
    unsafe {
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid)?;
        let snap = Snapshot(snap);
        let mut entry = MODULEENTRY32W {
            dwSize: std::mem::size_of::<MODULEENTRY32W>() as u32,
            ..Default::default()
        };
        if Module32FirstW(snap.0, &mut entry).is_ok() {
            let mut first = true;
            loop {
                let nlen = entry.szModule.iter().position(|&c| c == 0).unwrap_or(entry.szModule.len());
                let plen = entry.szExePath.iter().position(|&c| c == 0).unwrap_or(entry.szExePath.len());
                out.push(DebugModule {
                    name: String::from_utf16_lossy(&entry.szModule[..nlen]),
                    path: String::from_utf16_lossy(&entry.szExePath[..plen]),
                    base: entry.modBaseAddr as u64,
                    size: entry.modBaseSize as u64,
                    is_main: first,
                });
                first = false;
                if Module32NextW(snap.0, &mut entry).is_err() { break; }
            }
        }
    }
    Ok(out)
}

pub fn list_process_threads(pid: u32) -> DbgResult<Vec<DebugThread>> {
    let mut out = Vec::new();
    // SAFETY: Win32 toolhelp APIs.
    unsafe {
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)?;
        let snap = Snapshot(snap);
        let mut entry = THREADENTRY32 {
            dwSize: std::mem::size_of::<THREADENTRY32>() as u32,
            ..Default::default()
        };
        if Thread32First(snap.0, &mut entry).is_ok() {
            loop {
                if entry.th32OwnerProcessID == pid {
                    out.push(DebugThread {
                        thread_id: entry.th32ThreadID,
                        start_address: 0,
                        teb_address: 0,
                        suspended: false,
                        name: None,
                    });
                }
                if Thread32Next(snap.0, &mut entry).is_err() { break; }
            }
        }
    }
    Ok(out)
}
