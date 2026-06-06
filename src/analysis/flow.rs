//! Control-flow classification of disassembled instructions, plus the
//! gutter-arrow layout used by the disassembly view (IDA/Ghidra-style arrows
//! that show where branches jump).

use crate::pwn::asm::DisasmInsn;

/// What a single instruction does to control flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowKind {
    /// Falls through to the next instruction (normal instruction).
    Sequential,
    /// Unconditional jump (`jmp`, ARM `b`, MIPS `j`, ...).
    Jump,
    /// Conditional jump (`je`, `jne`, `b.eq`, `cbz`, `beq`, ...).
    CondJump,
    /// Call / branch-and-link (`call`, `bl`, `jal`, ...).
    Call,
    /// Return (`ret`, ARM `ret`, ...).
    Return,
    /// Indirect/other terminator we can't resolve statically.
    Indirect,
}

impl FlowKind {
    /// Whether this instruction ends a basic block (no fall-through, or a
    /// conditional split). Calls do **not** end a block.
    pub fn ends_block(self) -> bool {
        matches!(self, FlowKind::Jump | FlowKind::CondJump | FlowKind::Return | FlowKind::Indirect)
    }
    /// Whether control can fall through to the next instruction.
    pub fn falls_through(self) -> bool {
        matches!(self, FlowKind::Sequential | FlowKind::CondJump | FlowKind::Call)
    }
}

/// Classify a mnemonic into a [`FlowKind`].
pub fn classify(mnemonic: &str) -> FlowKind {
    let m = mnemonic.trim().to_ascii_lowercase();
    if m.is_empty() {
        return FlowKind::Sequential;
    }
    // Returns.
    if m == "ret" || m == "retn" || m == "retf" || m == "retq" || m == "iret" || m == "iretd"
        || m == "iretq" || m == "eret" || m == "ret.n"
    {
        return FlowKind::Return;
    }
    // Calls / branch-and-link.
    if m == "call" || m.starts_with("call") || m == "bl" || m == "blx" || m == "blr"
        || m == "jal" || m == "jalr" || m == "bctrl" || m == "callq"
    {
        return FlowKind::Call;
    }
    // Unconditional jumps.
    if m == "jmp" || m == "jmpq" || m == "b" || m == "bx" || m == "br" || m == "j" || m == "bctr" {
        return FlowKind::Jump;
    }
    // Conditional branches.
    if (m.starts_with('j') && m != "jmp" && m != "jmpq")
        || m.starts_with("b.")
        || m.starts_with("cb")  // cbz/cbnz
        || m.starts_with("tb")  // tbz/tbnz
        || matches!(m.as_str(), "beq" | "bne" | "blez" | "bgtz" | "bltz" | "bgez"
            | "bgt" | "blt" | "bge" | "ble" | "bnez" | "beqz" | "loop" | "loopne" | "loope" | "jcxz" | "jecxz")
    {
        return FlowKind::CondJump;
    }
    FlowKind::Sequential
}

/// Parse a statically-known branch/call target address from an instruction's
/// operands. Returns `None` for indirect targets (registers, memory).
pub fn branch_target(insn: &DisasmInsn) -> Option<u64> {
    let kind = classify(&insn.mnemonic);
    if !matches!(kind, FlowKind::Jump | FlowKind::CondJump | FlowKind::Call) {
        return None;
    }
    // Memory / register-indirect branches (`jmp qword ptr [rip+0x..]`,
    // `call [rax]`) have no statically-known target — any hex inside the
    // brackets is a displacement, not the destination.
    if insn.operands.contains('[') {
        return None;
    }
    // Find the first token that looks like an absolute hex address. capstone
    // resolves relative branches to absolute targets in the operand string.
    for raw in insn.operands.split(|c: char| c == ',' || c.is_whitespace()) {
        let tok = raw.trim().trim_start_matches('#').trim_start_matches('$');
        let hex = tok.strip_prefix("0x").or_else(|| tok.strip_prefix("0X"));
        if let Some(h) = hex {
            if !h.is_empty() && h.bytes().all(|b| b.is_ascii_hexdigit()) {
                if let Ok(v) = u64::from_str_radix(h, 16) {
                    return Some(v);
                }
            }
        }
    }
    None
}

/// A branch arrow to draw in the disassembly gutter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Arrow {
    pub from: u64,
    pub to: u64,
    pub kind: FlowKind,
    /// Whether the target is above (`true`) the source in address order.
    pub up: bool,
    /// Horizontal lane (0 = innermost) so nested/overlapping arrows don't merge.
    pub lane: usize,
}

/// Compute the gutter arrows for a window of instructions, only for branches
/// whose target is also visible in the window. Returns the arrows (with lane
/// assignments) and the total number of lanes used.
pub fn compute_arrows(insns: &[DisasmInsn]) -> (Vec<Arrow>, usize) {
    use std::collections::HashSet;
    let visible: HashSet<u64> = insns.iter().map(|i| i.address).collect();
    let mut arrows: Vec<Arrow> = Vec::new();
    for insn in insns {
        let kind = classify(&insn.mnemonic);
        if !matches!(kind, FlowKind::Jump | FlowKind::CondJump) {
            continue; // only draw jump arrows, not calls/returns
        }
        if let Some(to) = branch_target(insn) {
            if visible.contains(&to) && to != insn.address {
                arrows.push(Arrow { from: insn.address, to, kind, up: to < insn.address, lane: 0 });
            }
        }
    }
    let lanes = assign_lanes(&mut arrows);
    (arrows, lanes)
}

/// Greedily assign non-overlapping lanes to arrows (shorter spans get inner
/// lanes), returning the number of lanes used.
fn assign_lanes(arrows: &mut [Arrow]) -> usize {
    // Sort by span so tightly-nested arrows take inner lanes.
    let mut order: Vec<usize> = (0..arrows.len()).collect();
    order.sort_by_key(|&i| {
        let a = &arrows[i];
        (a.from.max(a.to)).saturating_sub(a.from.min(a.to))
    });
    // lane_ends[lane] = set of occupied [lo,hi] ranges on that lane.
    let mut lanes: Vec<Vec<(u64, u64)>> = Vec::new();
    for &i in &order {
        let (lo, hi) = (arrows[i].from.min(arrows[i].to), arrows[i].from.max(arrows[i].to));
        let mut placed = false;
        for (lane_idx, ranges) in lanes.iter_mut().enumerate() {
            if ranges.iter().all(|&(rlo, rhi)| hi < rlo || lo > rhi) {
                ranges.push((lo, hi));
                arrows[i].lane = lane_idx;
                placed = true;
                break;
            }
        }
        if !placed {
            arrows[i].lane = lanes.len();
            lanes.push(vec![(lo, hi)]);
        }
    }
    lanes.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn insn(addr: u64, mn: &str, ops: &str) -> DisasmInsn {
        DisasmInsn { address: addr, bytes: vec![0], mnemonic: mn.into(), operands: ops.into() }
    }

    #[test]
    fn classifies() {
        assert_eq!(classify("jmp"), FlowKind::Jump);
        assert_eq!(classify("je"), FlowKind::CondJump);
        assert_eq!(classify("b.eq"), FlowKind::CondJump);
        assert_eq!(classify("call"), FlowKind::Call);
        assert_eq!(classify("bl"), FlowKind::Call);
        assert_eq!(classify("ret"), FlowKind::Return);
        assert_eq!(classify("mov"), FlowKind::Sequential);
        assert_eq!(classify("b"), FlowKind::Jump);
        assert_eq!(classify("beq"), FlowKind::CondJump);
    }

    #[test]
    fn parses_targets() {
        assert_eq!(branch_target(&insn(0x1000, "je", "0x1020")), Some(0x1020));
        assert_eq!(branch_target(&insn(0x1000, "call", "0x4000")), Some(0x4000));
        assert_eq!(branch_target(&insn(0x1000, "jmp", "rax")), None);
        assert_eq!(branch_target(&insn(0x1000, "mov", "rax, 0x10")), None); // not a branch
        assert_eq!(branch_target(&insn(0x1000, "b", "#0x2000")), Some(0x2000));
        // Memory-indirect branch: displacement is not a target.
        assert_eq!(branch_target(&insn(0x1000, "jmp", "qword ptr [rip + 0x2f1a]")), None);
        assert_eq!(branch_target(&insn(0x1000, "call", "qword ptr [rax + 0x10]")), None);
    }

    #[test]
    fn arrows_only_to_visible_targets() {
        let insns = vec![
            insn(0x10, "je", "0x20"),
            insn(0x14, "mov", "rax, rbx"),
            insn(0x18, "jmp", "0x10"),   // back edge
            insn(0x20, "ret", ""),
            insn(0x24, "jmp", "0x9999"), // off-window: no arrow
        ];
        let (arrows, lanes) = compute_arrows(&insns);
        assert_eq!(arrows.len(), 2);
        assert!(arrows.iter().any(|a| a.from == 0x10 && a.to == 0x20 && !a.up));
        assert!(arrows.iter().any(|a| a.from == 0x18 && a.to == 0x10 && a.up));
        assert!(lanes >= 1);
    }
}
