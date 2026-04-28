//! Command line parsing.

use clap::Parser;
use std::path::PathBuf;

#[derive(Parser, Debug, Clone)]
#[command(
    name = "ctfdbg",
    version,
    about = "Windows-first graphical debugger for legal CTF / RE / authorized exploit-dev",
    long_about = None,
)]
pub struct Cli {
    /// Target executable to load (optional; can be opened from GUI)
    pub target: Option<PathBuf>,

    /// Quoted command-line arguments to pass to the target
    #[arg(long, value_name = "ARGS")]
    pub args: Option<String>,

    /// Attach to an existing PID
    #[arg(long)]
    pub pid: Option<u32>,

    /// Run a debugger-console script file at startup
    #[arg(long, value_name = "FILE")]
    pub script: Option<PathBuf>,

    /// Architecture override
    #[arg(long, default_value = "auto")]
    pub arch: String,

    /// File format override
    #[arg(long, default_value = "auto")]
    pub format: String,

    /// Platform override
    #[arg(long, default_value = "auto")]
    pub platform: String,

    /// Override loaded image base address (hex with optional 0x)
    #[arg(long, value_name = "HEX")]
    pub base_address: Option<String>,

    /// Endianness override
    #[arg(long, default_value = "auto")]
    pub endian: String,

    /// Backend selection
    #[arg(long, default_value = "auto")]
    pub backend: String,

    /// Break on entry point of target
    #[arg(long, default_value_t = false)]
    pub break_entry: bool,

    /// Working directory for launched target
    #[arg(long, value_name = "PATH")]
    pub working_directory: Option<PathBuf>,

    /// Logging level
    #[arg(long, default_value = "info")]
    pub log_level: String,

    /// Run without GUI (script/commands only)
    #[arg(long, default_value_t = false)]
    pub headless: bool,
}
