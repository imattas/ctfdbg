//! Headless command executor (used by --headless / --script mode).

use crate::commands::parser::parse_line;
use crate::config::DebugConfig;
use std::path::Path;

pub fn run_headless(_cfg: DebugConfig, script: Option<&Path>) -> anyhow::Result<()> {
    if let Some(path) = script {
        let text = std::fs::read_to_string(path)?;
        for (i, line) in text.lines().enumerate() {
            match parse_line(line) {
                Ok(Some(cmd)) => println!("[{}] parsed: {:?}", i + 1, cmd),
                Ok(None) => {}
                Err(e) => eprintln!("[{}] error: {}", i + 1, e),
            }
        }
    } else {
        println!("ctfdbg headless mode. Use --script <file> to run a command file.");
    }
    Ok(())
}
