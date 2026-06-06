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
    Crypto,
    Deobfuscation,
    Rev,
    Utility,
}

impl PluginCategory {
    pub fn label(self) -> &'static str {
        match self {
            PluginCategory::Analysis      => "Analysis",
            PluginCategory::Pwn           => "Pwn",
            PluginCategory::Crypto        => "Crypto",
            PluginCategory::Deobfuscation => "Deobfuscation",
            PluginCategory::Rev           => "Reverse Engineering",
            PluginCategory::Utility       => "Utility",
        }
    }

    /// All categories in display order.
    pub const ALL: &'static [PluginCategory] = &[
        PluginCategory::Analysis,
        PluginCategory::Rev,
        PluginCategory::Crypto,
        PluginCategory::Deobfuscation,
        PluginCategory::Pwn,
        PluginCategory::Utility,
    ];
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
    // Architecture / reverse-engineering
    r.register(builtins::ArchListPlugin);
    r.register(builtins::ArchInfoPlugin);
    r.register(builtins::DisasmArchPlugin);
    r.register(builtins::EntropyPlugin);
    r.register(builtins::IocScanPlugin);
    // Crypto
    r.register(builtins::CryptoIdPlugin);
    r.register(builtins::HashIdPlugin);
    // Deobfuscation
    r.register(builtins::DeobfuscatePlugin);
    r.register(builtins::DecodePlugin);
    r.register(builtins::XorKeyPlugin);
    // Pwn
    r.register(builtins::GadgetPlugin);
    r.register(builtins::SyscallSitesPlugin);
    r.register(builtins::RevShellPlugin);
    r.register(builtins::RopChainPlugin);
    r.register(builtins::NopSledPlugin);
    r.register(builtins::XorEncodePlugin);
    // Reverse engineering
    r.register(builtins::SyscallPlugin);
    r.register(builtins::SyscallTablePlugin);
    r.register(builtins::XrefPlugin);
    r.register(builtins::CfgPlugin);
    r.register(builtins::CallGraphPlugin);
    // Crypto / Utility
    r.register(builtins::JwtPlugin);
    r.register(builtins::BaseConvertPlugin);
    r.register(builtins::CidrPlugin);
    r
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::DebugConfig;
    use crate::gui::state::{AppState, BackendUpdate, DebugCommand};
    use crossbeam_channel::unbounded;

    fn empty_state() -> AppState {
        let (ctx, _crx) = unbounded::<DebugCommand>();
        let (_utx, urx) = unbounded::<BackendUpdate>();
        AppState::new(DebugConfig::empty(), ctx, urx)
    }

    fn run(reg: &PluginRegistry, st: &AppState, id: &str, arg: Option<&str>) -> Vec<String> {
        reg.get(id)
            .unwrap_or_else(|| panic!("missing plugin {id}"))
            .run(st, arg)
            .lines
    }

    #[test]
    fn registry_metadata_is_well_formed() {
        let reg = default_plugins();
        let metas = reg.list();
        assert!(metas.len() >= 20, "only {} plugins registered", metas.len());

        // Ids must be unique.
        let n = metas.len();
        let mut ids: Vec<&str> = metas.iter().map(|m| m.id).collect();
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), n, "duplicate plugin ids present");

        // Every plugin needs a name and description.
        for m in &metas {
            assert!(!m.name.is_empty(), "{} has empty name", m.id);
            assert!(!m.description.is_empty(), "{} has empty description", m.id);
        }

        // The new tools must all be registered.
        for id in [
            "deobf", "decode", "xor-key", "arch-list", "arch-info", "disasm-arch",
            "crypto-id", "hash-id", "entropy", "iocs", "gadget", "syscall-sites",
        ] {
            assert!(reg.get(id).is_some(), "expected plugin '{id}' to be registered");
        }
    }

    #[test]
    fn stateless_plugins_produce_output() {
        let reg = default_plugins();
        let st = empty_state();

        let out = run(&reg, &st, "deobf", Some("(x ^ y) + 2 * (x & y)"));
        assert!(
            out.iter().any(|l| l.contains("x + y")),
            "deobf did not reduce MBA: {out:?}"
        );

        let out = run(&reg, &st, "hash-id", Some(&"a".repeat(64)));
        assert!(out.iter().any(|l| l.contains("SHA-256")), "{out:?}");

        let out = run(&reg, &st, "arch-list", Some("mips"));
        assert!(out.iter().any(|l| l.to_lowercase().contains("mips")), "{out:?}");

        let out = run(&reg, &st, "arch-info", Some("ppc64"));
        assert!(out.iter().any(|l| l.contains("PowerPC")), "{out:?}");

        let out = run(&reg, &st, "decode", Some("aGVsbG8="));
        assert!(out.iter().any(|l| l.contains("hello")), "{out:?}");
    }

    #[test]
    fn data_driven_plugins_produce_output() {
        let reg = default_plugins();
        let mut st = empty_state();

        // A buffer carrying a flag and the AES forward S-box head.
        let mut data = b"noise\x00flag{plugin_works}\x00".to_vec();
        data.extend_from_slice(&[
            0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7,
            0xab, 0x76,
        ]);
        st.binary_bytes = Some(data);

        let out = run(&reg, &st, "iocs", None);
        assert!(out.iter().any(|l| l.contains("flag{plugin_works}")), "{out:?}");

        let out = run(&reg, &st, "crypto-id", None);
        assert!(out.iter().any(|l| l.contains("AES")), "{out:?}");

        let out = run(&reg, &st, "entropy", None);
        assert!(!out.is_empty());
    }
}
