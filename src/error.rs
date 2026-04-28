//! Unified error type.

use thiserror::Error;

pub type DbgResult<T> = std::result::Result<T, DbgError>;

#[derive(Debug, Error)]
pub enum DbgError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Goblin parse error: {0}")]
    Goblin(String),

    #[error("Capstone error: {0}")]
    Capstone(String),

    #[error("Unsupported feature: {0}")]
    Unsupported(String),

    #[error("Invalid argument: {0}")]
    InvalidArgument(String),

    #[error("Backend not initialized")]
    NotInitialized,

    #[error("Process not running")]
    NotRunning,

    #[error("Process is running, must be stopped")]
    NotStopped,

    #[error("Memory error at 0x{address:x}: {message}")]
    Memory { address: u64, message: String },

    #[error("Register error: {0}")]
    Register(String),

    #[error("Breakpoint error: {0}")]
    Breakpoint(String),

    #[error("Expression error: {0}")]
    Expression(String),

    #[error("Command error: {0}")]
    Command(String),

    #[error("Windows error: {0}")]
    Windows(String),

    #[error("{0}")]
    Other(String),
}

impl From<goblin::error::Error> for DbgError {
    fn from(e: goblin::error::Error) -> Self {
        DbgError::Goblin(e.to_string())
    }
}

impl From<capstone::Error> for DbgError {
    fn from(e: capstone::Error) -> Self {
        DbgError::Capstone(e.to_string())
    }
}

impl From<anyhow::Error> for DbgError {
    fn from(e: anyhow::Error) -> Self {
        DbgError::Other(e.to_string())
    }
}

#[cfg(windows)]
impl From<windows::core::Error> for DbgError {
    fn from(e: windows::core::Error) -> Self {
        DbgError::Windows(e.to_string())
    }
}
