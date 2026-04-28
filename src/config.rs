//! Runtime configuration derived from CLI / GUI settings.

use crate::cli::Cli;
use crate::target::arch::{Architecture, Endian};
use crate::target::format::FileFormat;
use crate::target::platform::Platform;
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendKind {
    Auto,
    WindowsDebugApi,
    LinuxPtrace,
}

impl BackendKind {
    pub fn parse(s: &str) -> Self {
        match s.to_ascii_lowercase().as_str() {
            "windows-debug-api" | "windows" | "winapi" => Self::WindowsDebugApi,
            "linux-ptrace" | "linux" | "ptrace" => Self::LinuxPtrace,
            _ => Self::Auto,
        }
    }
}

#[derive(Debug, Clone)]
pub struct DebugConfig {
    pub target: Option<PathBuf>,
    pub args: Option<String>,
    pub pid: Option<u32>,
    pub script: Option<PathBuf>,
    pub arch: Architecture,
    pub format: FileFormat,
    pub platform: Platform,
    pub base_address: Option<u64>,
    pub endian: Endian,
    pub backend: BackendKind,
    pub break_entry: bool,
    pub working_directory: Option<PathBuf>,
}

fn parse_hex(s: &str) -> Option<u64> {
    let s = s.trim().trim_start_matches("0x").trim_start_matches("0X");
    u64::from_str_radix(s, 16).ok()
}

impl DebugConfig {
    pub fn from_cli(cli: &Cli) -> Self {
        Self {
            target: cli.target.clone(),
            args: cli.args.clone(),
            pid: cli.pid,
            script: cli.script.clone(),
            arch: Architecture::parse(&cli.arch),
            format: FileFormat::parse(&cli.format),
            platform: Platform::parse(&cli.platform),
            base_address: cli.base_address.as_deref().and_then(parse_hex),
            endian: Endian::parse(&cli.endian),
            backend: BackendKind::parse(&cli.backend),
            break_entry: cli.break_entry,
            working_directory: cli.working_directory.clone(),
        }
    }

    pub fn empty() -> Self {
        Self {
            target: None,
            args: None,
            pid: None,
            script: None,
            arch: Architecture::Auto,
            format: FileFormat::Auto,
            platform: Platform::Auto,
            base_address: None,
            endian: Endian::Auto,
            backend: BackendKind::Auto,
            break_entry: false,
            working_directory: None,
        }
    }
}
