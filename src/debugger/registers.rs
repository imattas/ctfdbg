//! Cross-architecture register file abstraction.

use crate::target::arch::Architecture;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Default)]
pub struct RegisterFile {
    pub architecture: Architecture,
    pub thread_id: u32,
    pub values: BTreeMap<String, u64>,
}

impl RegisterFile {
    pub fn new(architecture: Architecture, thread_id: u32) -> Self {
        Self { architecture, thread_id, values: BTreeMap::new() }
    }

    pub fn get(&self, name: &str) -> Option<u64> {
        self.values.get(name).copied()
            .or_else(|| self.values.get(&name.to_ascii_lowercase()).copied())
    }

    pub fn set(&mut self, name: &str, value: u64) {
        self.values.insert(name.to_ascii_lowercase(), value);
    }

    pub fn pc(&self) -> Option<u64> {
        match self.architecture {
            Architecture::X86_64 | Architecture::Auto => self.get("rip"),
            Architecture::X86 => self.get("eip"),
            // Every other supported architecture names its program counter "pc".
            _ => self.get("pc"),
        }
    }

    pub fn sp(&self) -> Option<u64> {
        match self.architecture {
            Architecture::X86_64 | Architecture::Auto => self.get("rsp"),
            Architecture::X86 => self.get("esp"),
            _ => self.get("sp"),
        }
    }

    pub fn fp(&self) -> Option<u64> {
        match self.architecture {
            Architecture::X86_64 | Architecture::Auto => self.get("rbp"),
            Architecture::X86 => self.get("ebp"),
            _ => self.get("fp"),
        }
    }
}
