pub mod backend;
pub mod breakpoint;
pub mod events;
pub mod expressions;
pub mod memory;
pub mod modules;
pub mod registers;
pub mod stacktrace;
pub mod state;
pub mod threads;

#[cfg(windows)]
pub mod windows;

#[cfg(unix)]
pub mod linux;

use crate::config::{BackendKind, DebugConfig};
use crate::error::DbgResult;

/// Construct a backend appropriate for the current platform / config.
pub fn make_backend(cfg: &DebugConfig) -> DbgResult<Box<dyn backend::DebugBackend + Send>> {
    match cfg.backend {
        BackendKind::WindowsDebugApi => make_windows(),
        BackendKind::LinuxPtrace => make_linux(),
        BackendKind::Auto => {
            if cfg!(windows) {
                make_windows()
            } else if cfg!(unix) {
                make_linux()
            } else {
                Ok(Box::new(backend::UnsupportedBackend::new(
                    "platform unsupported by debugger backend",
                )))
            }
        }
    }
}

#[cfg(windows)]
fn make_windows() -> DbgResult<Box<dyn backend::DebugBackend + Send>> {
    Ok(Box::new(windows::backend::WindowsDebugBackend::new()))
}

#[cfg(not(windows))]
fn make_windows() -> DbgResult<Box<dyn backend::DebugBackend + Send>> {
    Ok(Box::new(backend::UnsupportedBackend::new(
        "Windows debug backend is only available on Windows",
    )))
}

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "x86", target_arch = "aarch64")
))]
fn make_linux() -> DbgResult<Box<dyn backend::DebugBackend + Send>> {
    Ok(Box::new(linux::backend::LinuxPtraceBackend::new()))
}

#[cfg(all(
    unix,
    not(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "x86", target_arch = "aarch64")
    ))
))]
fn make_linux() -> DbgResult<Box<dyn backend::DebugBackend + Send>> {
    Ok(Box::new(backend::UnsupportedBackend::new(
        "live ptrace debugging is implemented for Linux x86-64 / x86 / AArch64; \
         this platform/architecture is not yet supported",
    )))
}

#[cfg(not(unix))]
fn make_linux() -> DbgResult<Box<dyn backend::DebugBackend + Send>> {
    Ok(Box::new(backend::UnsupportedBackend::new(
        "Linux ptrace backend is only available on Unix",
    )))
}
