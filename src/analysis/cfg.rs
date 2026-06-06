//! Control-flow graph construction: split a run of disassembled instructions
//! into basic blocks and recover the edges between them (the data behind a
//! Graph view).

use crate::analysis::flow::{branch_target, classify, FlowKind};
use crate::pwn::asm::DisasmInsn;
use std::collections::{BTreeMap, BTreeSet};

/// An edge kind between basic blocks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EdgeKind {
    /// Fall-through to the next block (e.g. the not-taken side of a branch).
    Fallthrough,
    /// Taken branch / jump target.
    Branch,
}

#[derive(Debug, Clone)]
pub struct BasicBlock {
    pub start: u64,
    /// Address just past the last instruction.
    pub end: u64,
    pub insns: Vec<DisasmInsn>,
    /// Successor block start addresses with the edge kind.
    pub succ: Vec<(u64, EdgeKind)>,
}

#[derive(Debug, Clone)]
pub struct Cfg {
    pub entry: u64,
    pub blocks: Vec<BasicBlock>,
}

impl Cfg {
    pub fn block_at(&self, addr: u64) -> Option<&BasicBlock> {
        self.blocks.iter().find(|b| b.start == addr)
    }
}

/// Extract the instructions of the function starting at `start` from an
/// address-ordered instruction stream.
///
/// Unlike "stop at the first `ret`", this follows forward branch targets: a
/// terminator only ends the function once we've passed every forward branch
/// destination seen so far, so functions with early returns keep their later
/// blocks (and the edges into them). Bounded by `cap` instructions.
pub fn function_slice(insns: &[DisasmInsn], start: u64, cap: usize) -> Vec<DisasmInsn> {
    let mut out = Vec::new();
    let mut furthest = start;
    for ins in insns.iter().filter(|i| i.address >= start) {
        let kind = classify(&ins.mnemonic);
        if let Some(t) = branch_target(ins) {
            if t > furthest {
                furthest = t;
            }
        }
        let addr = ins.address;
        out.push(ins.clone());
        if out.len() >= cap {
            break;
        }
        // A terminator (return / unconditional / indirect) only ends the
        // function once we're past all pending forward branch targets.
        if matches!(kind, FlowKind::Return | FlowKind::Jump | FlowKind::Indirect) && addr >= furthest {
            break;
        }
    }
    out
}

/// Build a CFG from address-ordered instructions (e.g. one function's body).
pub fn build_cfg(insns: &[DisasmInsn]) -> Cfg {
    if insns.is_empty() {
        return Cfg { entry: 0, blocks: vec![] };
    }
    let entry = insns[0].address;
    let addrs: BTreeSet<u64> = insns.iter().map(|i| i.address).collect();
    let by_addr: BTreeMap<u64, usize> = insns.iter().enumerate().map(|(i, x)| (x.address, i)).collect();

    // 1. Collect block leaders.
    let mut leaders: BTreeSet<u64> = BTreeSet::new();
    leaders.insert(entry);
    for (i, insn) in insns.iter().enumerate() {
        let kind = classify(&insn.mnemonic);
        let next = insns.get(i + 1).map(|n| n.address);
        match kind {
            FlowKind::Jump | FlowKind::CondJump => {
                if let Some(t) = branch_target(insn) {
                    if addrs.contains(&t) {
                        leaders.insert(t);
                    }
                }
                // Instruction after a branch starts a new block.
                if let Some(n) = next {
                    leaders.insert(n);
                }
            }
            FlowKind::Return | FlowKind::Indirect => {
                if let Some(n) = next {
                    leaders.insert(n);
                }
            }
            _ => {}
        }
    }

    // 2. Build blocks between consecutive leaders.
    let leader_vec: Vec<u64> = leaders.into_iter().collect();
    let mut blocks = Vec::new();
    for (li, &start) in leader_vec.iter().enumerate() {
        let next_leader = leader_vec.get(li + 1).copied();
        let start_idx = by_addr[&start];
        let mut block_insns = Vec::new();
        let mut idx = start_idx;
        while idx < insns.len() {
            let a = insns[idx].address;
            if let Some(nl) = next_leader {
                if a >= nl {
                    break;
                }
            }
            block_insns.push(insns[idx].clone());
            idx += 1;
        }
        if block_insns.is_empty() {
            continue;
        }
        let end = block_insns.last().map(|i| i.address + i.bytes.len() as u64).unwrap_or(start);
        let last = block_insns.last().unwrap();
        let kind = classify(&last.mnemonic);
        let mut succ = Vec::new();
        match kind {
            FlowKind::Jump => {
                if let Some(t) = branch_target(last) {
                    if addrs.contains(&t) {
                        succ.push((t, EdgeKind::Branch));
                    }
                }
            }
            FlowKind::CondJump => {
                if let Some(t) = branch_target(last) {
                    if addrs.contains(&t) {
                        succ.push((t, EdgeKind::Branch));
                    }
                }
                // Fall-through to the next block.
                if let Some(nl) = next_leader {
                    succ.push((nl, EdgeKind::Fallthrough));
                }
            }
            FlowKind::Return | FlowKind::Indirect => {} // no successors
            _ => {
                // Sequential / call: falls through.
                if let Some(nl) = next_leader {
                    succ.push((nl, EdgeKind::Fallthrough));
                }
            }
        }
        blocks.push(BasicBlock { start, end, insns: block_insns, succ });
    }

    Cfg { entry, blocks }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn insn(addr: u64, len: usize, mn: &str, ops: &str) -> DisasmInsn {
        DisasmInsn { address: addr, bytes: vec![0u8; len], mnemonic: mn.into(), operands: ops.into() }
    }

    #[test]
    fn splits_on_conditional_branch() {
        // 0: cmp ; 4: je 0x10 ; 8: mov ; c: jmp 0x14 ; 10: mov ; 14: ret
        let insns = vec![
            insn(0x0, 4, "cmp", "eax, 1"),
            insn(0x4, 2, "je", "0x10"),
            insn(0x8, 2, "mov", "eax, 0"),
            insn(0xc, 2, "jmp", "0x14"),
            insn(0x10, 2, "mov", "eax, 1"),
            insn(0x14, 1, "ret", ""),
        ];
        let cfg = build_cfg(&insns);
        assert_eq!(cfg.entry, 0x0);
        // Leaders: 0 (entry), 0x10 (je target), 0x8 (after je), 0x14 (jmp target + after jmp)
        let starts: Vec<u64> = cfg.blocks.iter().map(|b| b.start).collect();
        assert!(starts.contains(&0x0) && starts.contains(&0x8) && starts.contains(&0x10) && starts.contains(&0x14));

        let entry_blk = cfg.block_at(0x0).unwrap();
        // entry ends in `je` -> branch to 0x10 + fallthrough to 0x8
        assert!(entry_blk.succ.iter().any(|&(t, k)| t == 0x10 && k == EdgeKind::Branch));
        assert!(entry_blk.succ.iter().any(|&(t, k)| t == 0x8 && k == EdgeKind::Fallthrough));

        // block at 0x8 ends in `jmp 0x14` -> single branch edge, no fallthrough
        let b8 = cfg.block_at(0x8).unwrap();
        assert_eq!(b8.succ, vec![(0x14, EdgeKind::Branch)]);

        // ret block has no successors
        assert!(cfg.block_at(0x14).unwrap().succ.is_empty());
    }

    #[test]
    fn function_slice_follows_forward_branch_past_early_ret() {
        // 0: je 0x10 ; 4: ret (early) ; 10: mov ; 14: ret
        let insns = vec![
            insn(0x0, 2, "je", "0x10"),
            insn(0x4, 1, "ret", ""),
            insn(0x10, 2, "mov", "eax, 1"),
            insn(0x14, 1, "ret", ""),
        ];
        let slice = super::function_slice(&insns, 0x0, 1024);
        // Must include the 0x10 block reached only via the forward branch,
        // not stop at the early ret at 0x4.
        assert!(slice.iter().any(|i| i.address == 0x10));
        assert!(slice.iter().any(|i| i.address == 0x14));
    }
}
