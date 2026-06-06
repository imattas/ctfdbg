//! Cross-reference recovery: which instructions branch to / call a given
//! address (code xrefs), recovered by a linear disassembly sweep.

use crate::analysis::flow::{branch_target, classify, FlowKind};
use crate::error::DbgResult;
use crate::pwn::asm;
use crate::target::arch::Architecture;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XrefKind {
    Call,
    Jump,
    CondJump,
}

#[derive(Debug, Clone)]
pub struct Xref {
    /// Address of the referencing instruction.
    pub from: u64,
    /// Address being referenced.
    pub to: u64,
    pub kind: XrefKind,
    /// Rendered referencing instruction (e.g. `call 0x401000`).
    pub text: String,
}

/// Disassemble `bytes` (loaded at `base`) and collect every static code
/// reference (call / jump / conditional branch with a resolved target).
pub fn find_all(bytes: &[u8], base: u64, arch: Architecture) -> DbgResult<Vec<Xref>> {
    let insns = asm::disasm_all(arch, base, bytes)?;
    let mut out = Vec::new();
    for insn in &insns {
        let kind = match classify(&insn.mnemonic) {
            FlowKind::Call => XrefKind::Call,
            FlowKind::Jump => XrefKind::Jump,
            FlowKind::CondJump => XrefKind::CondJump,
            _ => continue,
        };
        if let Some(to) = branch_target(insn) {
            let text = if insn.operands.is_empty() {
                insn.mnemonic.clone()
            } else {
                format!("{} {}", insn.mnemonic, insn.operands)
            };
            out.push(Xref { from: insn.address, to, kind, text });
        }
    }
    Ok(out)
}

/// References pointing at exactly `target`.
pub fn to_address(all: &[Xref], target: u64) -> Vec<&Xref> {
    all.iter().filter(|x| x.to == target).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_call_and_jump_targets() {
        // x86-64: at 0x1000: `call 0x1009` (e8 04 00 00 00) then `jmp 0x1000`?
        // Build simple machine code:
        //   e8 00 00 00 00   call rip+0 -> target 0x1005
        //   eb fe            jmp $ (0x1005 -> 0x1005)
        let bytes = [0xe8, 0x00, 0x00, 0x00, 0x00, 0xeb, 0xfe];
        let xs = find_all(&bytes, 0x1000, Architecture::X86_64).unwrap();
        // call at 0x1000 targets 0x1005; jmp at 0x1005 targets itself (0x1005).
        assert!(xs.iter().any(|x| x.from == 0x1000 && x.to == 0x1005 && x.kind == XrefKind::Call));
        let to_1005 = to_address(&xs, 0x1005);
        assert!(!to_1005.is_empty());
    }
}
