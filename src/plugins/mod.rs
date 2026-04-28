//! Built-in plugin system for ctfdbg.
//!
//! A plugin is just a Rust value implementing [`Plugin`].  Plugins receive
//! a mutable [`PluginContext`] containing the loaded `BinaryInfo` plus a
//! shared command sink, and return zero or more strings to be appended to
//! the debugger console.
//!
//! Plugins are deliberately *side-effect-light*: they read state and emit
//! text or `DebugCommand`s.  They do not own UI or background threads.
//!
//! The default plugin set is registered in [`default_plugins`] and shipped
//! with the binary — no installation step required.

use std::collections::BTreeMap;

use crate::gui::actions::Action;
use crate::gui::state::AppState;

pub mod builtins;

/// Anything a plugin can do as part of `run()`.
#[derive(Debug, Clone, Default)]
pub struct PluginOutput {
    /// Lines appended to the debugger console.
    pub lines: Vec<String>,
    /// GUI actions to dispatch.
    pub actions: Vec<Action>,
}

impl PluginOutput {
    pub fn line(mut self, s: impl Into<String>) -> Self { self.lines.push(s.into()); self }
    pub fn action(mut self, a: Action) -> Self { self.actions.push(a); self }
}

/// Read-only metadata for a plugin.  Stable across invocations.
#[derive(Debug, Clone)]
pub struct PluginMeta {
    pub id: &'static str,
    pub name: &'static str,
    pub description: &'static str,
    pub category: PluginCategory,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum PluginCategory {
    Analysis,
    Pwn,
    Utility,
}

impl PluginCategory {
    pub fn label(self) -> &'static str {
        match self {
            PluginCategory::Analysis => "Analysis",
            PluginCategory::Pwn      => "Pwn",
            PluginCategory::Utility  => "Utility",
        }
    }
}

pub trait Plugin: Send + Sync {
    fn meta(&self) -> PluginMeta;
    /// Run the plugin against the current debugger state.  `arg` is an
    /// optional free-form parameter (e.g. an address typed into the
    /// console) that the plugin may interpret.
    fn run(&self, state: &AppState, arg: Option<&str>) -> PluginOutput;
}

/// Central registry of all plugins available to the GUI / console.
pub struct PluginRegistry {
    plugins: BTreeMap<&'static str, Box<dyn Plugin>>,
}

impl PluginRegistry {
    pub fn new() -> Self { Self { plugins: BTreeMap::new() } }

    pub fn register<P: Plugin + 'static>(&mut self, p: P) {
        let id = p.meta().id;
        self.plugins.insert(id, Box::new(p));
    }

    pub fn get(&self, id: &str) -> Option<&dyn Plugin> {
        self.plugins.get(id).map(|b| b.as_ref())
    }

    pub fn list(&self) -> Vec<PluginMeta> {
        self.plugins.values().map(|p| p.meta()).collect()
    }

    pub fn list_by_category(&self, cat: PluginCategory) -> Vec<PluginMeta> {
        self.plugins.values().map(|p| p.meta()).filter(|m| m.category == cat).collect()
    }
}

impl Default for PluginRegistry {
    fn default() -> Self { Self::new() }
}

/// Build a registry pre-populated with all built-in plugins.
pub fn default_plugins() -> PluginRegistry {
    let mut r = PluginRegistry::new();
    r.register(builtins::AutoAnalyzePlugin);
    r.register(builtins::ChecksecPlugin);
    r.register(builtins::CyclicPlugin);
    r.register(builtins::CyclicFindPlugin);
    r.register(builtins::HexdumpPlugin);
    r.register(builtins::RopScanPlugin);
    r.register(builtins::FmtStringProbePlugin);
    r.register(builtins::XorBrutePlugin);
    r.register(builtins::ShellcodeListPlugin);
    r.register(builtins::DisasmPlugin);
    r
}
