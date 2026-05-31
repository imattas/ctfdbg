//! Linux ptrace backend.
//!
//! The real backend is implemented for the architectures whose register
//! marshalling and breakpoint encoding we support (x86-64, x86, AArch64).
//! Other Linux architectures fall back to the `Unsupported` backend via
//! `debugger::make_backend`.

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "x86", target_arch = "aarch64")
))]
pub mod backend;

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "x86", target_arch = "aarch64")
))]
pub mod ptrace;
