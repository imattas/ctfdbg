//! ctfdbg library root.
//!
//! Exposes modules used both by the binary and the integration tests.

pub mod analysis;
pub mod cli;
pub mod commands;
pub mod config;
pub mod debugger;
pub mod error;
pub mod gui;
pub mod plugins;
pub mod pwn;
pub mod target;

pub use error::{DbgError, DbgResult};
