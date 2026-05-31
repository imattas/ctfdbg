//! Lightweight, architecture-agnostic syntax highlighting for disassembly.
//!
//! Mnemonics are coloured by instruction class (control flow / data movement /
//! arithmetic / stack), and operand strings are tokenised into registers,
//! immediates, memory-size keywords and punctuation.  The heuristics cover the
//! capstone output for every architecture ctfdbg disassembles; unknown tokens
//! fall back to sensible defaults rather than mis-colouring.

use egui::text::{LayoutJob, TextFormat};
use egui::{Color32, FontId};

use crate::gui::theme::color;

/// Colour for a mnemonic based on its instruction class.
pub fn mnemonic_color(mnemonic: &str) -> Color32 {
    let m = mnemonic.trim().to_ascii_lowercase();
    if m.is_empty() {
        return color::MN_DEFAULT;
    }
    if m == "nop" || m.starts_with("nop") {
        return color::MUTED;
    }
    if is_flow(&m) {
        return color::MN_FLOW;
    }
    if is_stack(&m) {
        return color::MN_STACK;
    }
    if is_data(&m) {
        return color::MN_DATA;
    }
    if is_arith(&m) {
        return color::MN_ARITH;
    }
    color::MN_DEFAULT
}

fn is_flow(m: &str) -> bool {
    // x86: call/ret/jmp/jcc/loop/iret/int/syscall/sysenter/hlt
    // arm/aarch64: b/bl/bx/blx/br/blr/cbz/cbnz/tbz/ret/b.<cc>
    // mips/riscv/ppc: j/jal/jr/jalr/beq/bne/blez/bgtz/bc/bctr/blr
    matches!(
        m,
        "call" | "ret" | "retn" | "retf" | "retq" | "iret" | "iretd" | "iretq"
            | "syscall" | "sysenter" | "sysret" | "hlt" | "leave"
            | "b" | "bl" | "bx" | "blx" | "br" | "blr" | "eret"
            | "j" | "jal" | "jr" | "jalr" | "jalx"
            | "bctr" | "bctrl" | "bdnz" | "bctrl+"
    ) || m.starts_with('j') // jmp, je, jne, jz, jnz, jg, jle, ...
        || m.starts_with("call")
        || m.starts_with("ret")
        || m.starts_with("int")
        || m.starts_with("loop")
        || m.starts_with("b.") // aarch64 conditional branch (b.eq, b.ne, ...)
        || m.starts_with("cb") // cbz/cbnz
        || m.starts_with("tb") // tbz/tbnz
        || matches!(m, "beq" | "bne" | "blez" | "bgtz" | "bltz" | "bgez" | "bgt" | "blt" | "bge" | "ble")
}

fn is_stack(m: &str) -> bool {
    m.starts_with("push")
        || m.starts_with("pop")
        || matches!(m, "enter" | "pusha" | "popa" | "pushf" | "popf" | "pushfq" | "popfq")
        || matches!(m, "stp" | "ldp") // aarch64 store/load pair (stack-frame heavy)
}

fn is_data(m: &str) -> bool {
    m.starts_with("mov")
        || matches!(
            m,
            "lea" | "xchg" | "cmpxchg" | "bswap" | "cbw" | "cwde" | "cdqe" | "cwd" | "cdq" | "cqo"
                | "movzx" | "movsx" | "movsxd" | "movabs"
                | "ldr" | "ldrb" | "ldrh" | "ldrsw" | "ldur" | "str" | "strb" | "strh" | "stur"
                | "ld" | "lw" | "lh" | "lb" | "lbu" | "lhu" | "ld.w" | "sd" | "sw" | "sh" | "sb"
                | "li" | "la" | "lui" | "auipc" | "mfhi" | "mflo" | "mtc" | "mfc"
                | "adrp" | "adr"
        )
}

fn is_arith(m: &str) -> bool {
    matches!(
        m,
        "add" | "adc" | "sub" | "sbb" | "mul" | "imul" | "div" | "idiv" | "inc" | "dec" | "neg"
            | "and" | "or" | "xor" | "not" | "shl" | "shr" | "sal" | "sar" | "rol" | "ror"
            | "rcl" | "rcr" | "cmp" | "test" | "bt" | "bts" | "btr" | "btc"
            | "adds" | "subs" | "muls" | "ands" | "orr" | "orrs" | "eor" | "eors" | "bic"
            | "lsl" | "lsr" | "asr" | "mvn" | "mneg" | "madd" | "msub" | "umull" | "smull"
            | "addi" | "addiu" | "addu" | "subu" | "slt" | "slti" | "sltu" | "andi" | "ori"
            | "xori" | "sll" | "srl" | "sra" | "mulw" | "divw" | "remw" | "addw" | "subw"
            | "fadd" | "fsub" | "fmul" | "fdiv"
    )
}

/// Token classes recognised in an operand string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TokKind {
    Register,
    Immediate,
    MemKeyword,
    Punct,
    Space,
}

fn classify_ident(ident: &str) -> TokKind {
    let l = ident.to_ascii_lowercase();
    // x86 memory-size and segment keywords.
    if matches!(
        l.as_str(),
        "byte" | "word" | "dword" | "qword" | "tbyte" | "fword" | "xmmword" | "ymmword"
            | "zmmword" | "ptr" | "short" | "near" | "far" | "offset"
    ) {
        return TokKind::MemKeyword;
    }
    // A bare hex word with no 0x prefix (capstone sometimes emits these for
    // branch targets) reads as a number if it is all hex digits and long-ish.
    if ident.len() >= 4 && ident.bytes().all(|b| b.is_ascii_hexdigit()) {
        return TokKind::Immediate;
    }
    TokKind::Register
}

/// Build a coloured [`LayoutJob`] for an operand string at the given font size.
pub fn operand_job(op_str: &str, font_size: f32) -> LayoutJob {
    let font = FontId::monospace(font_size);
    let mut job = LayoutJob::default();
    let bytes = op_str.as_bytes();
    let mut i = 0;

    let mut push = |job: &mut LayoutJob, text: &str, kind: TokKind| {
        let c = match kind {
            TokKind::Register => color::REGISTER,
            TokKind::Immediate => color::IMMEDIATE,
            TokKind::MemKeyword => color::MEM_KW,
            TokKind::Punct => color::PUNCT,
            TokKind::Space => color::TEXT,
        };
        job.append(text, 0.0, TextFormat { font_id: font.clone(), color: c, ..Default::default() });
    };

    while i < bytes.len() {
        let c = bytes[i];
        if c.is_ascii_whitespace() {
            let start = i;
            while i < bytes.len() && bytes[i].is_ascii_whitespace() {
                i += 1;
            }
            push(&mut job, &op_str[start..i], TokKind::Space);
        } else if c == b'0' && i + 1 < bytes.len() && (bytes[i + 1] | 0x20) == b'x' {
            // Hex literal 0x....
            let start = i;
            i += 2;
            while i < bytes.len() && bytes[i].is_ascii_hexdigit() {
                i += 1;
            }
            push(&mut job, &op_str[start..i], TokKind::Immediate);
        } else if c.is_ascii_digit() {
            let start = i;
            while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'.') {
                i += 1;
            }
            push(&mut job, &op_str[start..i], TokKind::Immediate);
        } else if c.is_ascii_alphabetic() || c == b'_' || c == b'%' || c == b'$' || c == b'.' {
            // Identifier (register, keyword, or label). Allow leading %/$ for
            // AT&T-style register/immediate sigils.
            let start = i;
            i += 1;
            while i < bytes.len()
                && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_' || bytes[i] == b'.')
            {
                i += 1;
            }
            let tok = &op_str[start..i];
            // AT&T immediate ($0x1) — sigil then number handled above; here a
            // leading '$' identifier is rare, treat normally.
            push(&mut job, tok, classify_ident(tok.trim_start_matches(['%', '$'])));
        } else {
            // Punctuation: [ ] + - * , : ! # { } etc.
            push(&mut job, &op_str[i..i + 1], TokKind::Punct);
            i += 1;
        }
    }
    job
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classes() {
        assert_eq!(mnemonic_color("call"), color::MN_FLOW);
        assert_eq!(mnemonic_color("jne"), color::MN_FLOW);
        assert_eq!(mnemonic_color("b.eq"), color::MN_FLOW);
        assert_eq!(mnemonic_color("push"), color::MN_STACK);
        assert_eq!(mnemonic_color("mov"), color::MN_DATA);
        assert_eq!(mnemonic_color("ldr"), color::MN_DATA);
        assert_eq!(mnemonic_color("add"), color::MN_ARITH);
        assert_eq!(mnemonic_color("nop"), color::MUTED);
    }

    #[test]
    fn operand_tokenises() {
        // Should not panic and should consume the whole string.
        let job = operand_job("qword ptr [rbp - 0x10], rax", 13.0);
        let rebuilt: String = job.text;
        assert_eq!(rebuilt, "qword ptr [rbp - 0x10], rax");
    }

    #[test]
    fn empty_ok() {
        let job = operand_job("", 13.0);
        assert!(job.text.is_empty());
    }
}
