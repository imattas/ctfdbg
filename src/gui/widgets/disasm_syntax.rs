//! Lightweight, architecture-agnostic syntax highlighting for disassembly and
//! for the debugger console.
//!
//! Mnemonics are coloured by instruction class (control flow / data movement /
//! arithmetic / stack), and operand strings are tokenised into registers,
//! immediates, memory-size keywords and punctuation.  The same machinery backs
//! [`console_line_job`], which colours plugin / command output: status tags,
//! addresses, flags, and full disassembly/gadget lines of the form
//! `0xADDR: <bytes> <mnemonic> <operands> [; <mnemonic> <operands> ...]`.
//!
//! The heuristics cover the capstone output for every architecture ctfdbg
//! disassembles; unknown tokens fall back to sensible defaults rather than
//! mis-colouring, and the full input text is always preserved verbatim.

use egui::text::{LayoutJob, TextFormat};
use egui::{Color32, FontId};

use crate::gui::theme::color;

// ------------------------------------------------------------- mnemonics ----

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
            | "bctr" | "bctrl" | "bdnz"
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

// --------------------------------------------------------------- helpers ----

fn push(job: &mut LayoutJob, font: &FontId, text: &str, c: Color32) {
    if text.is_empty() {
        return;
    }
    job.append(text, 0.0, TextFormat { font_id: font.clone(), color: c, ..Default::default() });
}

fn is_byte_token(tok: &str) -> bool {
    tok.len() == 2 && tok.bytes().all(|b| b.is_ascii_hexdigit())
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

fn tok_color(kind: TokKind) -> Color32 {
    match kind {
        TokKind::Register => color::REGISTER,
        TokKind::Immediate => color::IMMEDIATE,
        TokKind::MemKeyword => color::MEM_KW,
        TokKind::Punct => color::PUNCT,
        TokKind::Space => color::TEXT,
    }
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

// --------------------------------------------------------------- operands ---

/// Append a coloured operand string to `job`, preserving all characters.
fn append_operands(job: &mut LayoutJob, font: &FontId, op_str: &str) {
    let bytes = op_str.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i];
        if c.is_ascii_whitespace() {
            let start = i;
            while i < bytes.len() && bytes[i].is_ascii_whitespace() {
                i += 1;
            }
            push(job, font, &op_str[start..i], tok_color(TokKind::Space));
        } else if c == b'0' && i + 1 < bytes.len() && (bytes[i + 1] | 0x20) == b'x' {
            let start = i;
            i += 2;
            while i < bytes.len() && bytes[i].is_ascii_hexdigit() {
                i += 1;
            }
            push(job, font, &op_str[start..i], tok_color(TokKind::Immediate));
        } else if c.is_ascii_digit() {
            let start = i;
            while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'.') {
                i += 1;
            }
            push(job, font, &op_str[start..i], tok_color(TokKind::Immediate));
        } else if c.is_ascii_alphabetic() || c == b'_' || c == b'%' || c == b'$' || c == b'.' {
            let start = i;
            i += 1;
            while i < bytes.len()
                && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_' || bytes[i] == b'.')
            {
                i += 1;
            }
            let tok = &op_str[start..i];
            push(job, font, tok, tok_color(classify_ident(tok.trim_start_matches(['%', '$']))));
        } else {
            push(job, font, &op_str[i..i + 1], tok_color(TokKind::Punct));
            i += 1;
        }
    }
}

/// Build a coloured [`LayoutJob`] for an operand string at the given font size.
pub fn operand_job(op_str: &str, font_size: f32) -> LayoutJob {
    let font = FontId::monospace(font_size);
    let mut job = LayoutJob::default();
    append_operands(&mut job, &font, op_str);
    job
}

// ------------------------------------------------------- instruction text ---

/// Colour a single instruction (`mnemonic operands`), preserving spacing.
fn append_one_insn(job: &mut LayoutJob, font: &FontId, seg: &str) {
    let bytes = seg.as_bytes();
    let mut i = 0;
    // leading whitespace
    while i < bytes.len() && bytes[i].is_ascii_whitespace() {
        i += 1;
    }
    push(job, font, &seg[..i], color::TEXT);
    // mnemonic token
    let start = i;
    while i < bytes.len() && !bytes[i].is_ascii_whitespace() {
        i += 1;
    }
    let mnem = &seg[start..i];
    push(job, font, mnem, mnemonic_color(mnem));
    // remaining operands (includes the separating space)
    append_operands(job, font, &seg[i..]);
}

/// Colour a code string that may contain several `;`-separated instructions
/// (as gadget output does), preserving the separators and spacing.
fn append_code(job: &mut LayoutJob, font: &FontId, code: &str) {
    for (idx, seg) in code.split(';').enumerate() {
        if idx > 0 {
            push(job, font, ";", color::PUNCT);
        }
        append_one_insn(job, font, seg);
    }
}

// ----------------------------------------------------------- console lines --

/// Length of a leading `0x...` hex literal in `s`, or `None`.
fn leading_hex_len(s: &str) -> Option<usize> {
    let b = s.as_bytes();
    if b.len() >= 3 && b[0] == b'0' && (b[1] | 0x20) == b'x' {
        let mut i = 2;
        while i < b.len() && b[i].is_ascii_hexdigit() {
            i += 1;
        }
        if i > 2 {
            return Some(i);
        }
    }
    None
}

/// Generic colouring for non-instruction text: addresses, `flag{...}`-style
/// tokens, and trailing `;` comments; everything else stays default.
fn append_generic(job: &mut LayoutJob, font: &FontId, text: &str) {
    let b = text.as_bytes();
    let mut i = 0;
    let mut run = 0; // start of the pending default-coloured run
    while i < b.len() {
        if b[i] == b'0' && i + 1 < b.len() && (b[i + 1] | 0x20) == b'x' {
            push(job, font, &text[run..i], color::TEXT);
            let start = i;
            i += 2;
            while i < b.len() && b[i].is_ascii_hexdigit() {
                i += 1;
            }
            push(job, font, &text[start..i], color::ADDRESS);
            run = i;
            continue;
        }
        if b[i] == b';' {
            push(job, font, &text[run..i], color::TEXT);
            push(job, font, &text[i..], color::HINT);
            return;
        }
        if b[i].is_ascii_alphabetic() {
            let start = i;
            while i < b.len() && (b[i].is_ascii_alphanumeric() || b[i] == b'_') {
                i += 1;
            }
            if i < b.len() && b[i] == b'{' {
                if let Some(close) = text[i..].find('}') {
                    let end = i + close + 1;
                    push(job, font, &text[run..start], color::TEXT);
                    push(job, font, &text[start..end], color::STRING);
                    i = end;
                    run = i;
                    continue;
                }
            }
            // not a flag — leave the identifier in the pending run
            continue;
        }
        i += 1;
    }
    push(job, font, &text[run..], color::TEXT);
}

/// Colour the part of a disassembly line after the `address:` — an optional
/// hex byte column (muted) followed by one or more instructions.
fn append_after_colon(job: &mut LayoutJob, font: &FontId, rest: &str) {
    let trimmed = rest.trim_start_matches(' ');
    let lead = &rest[..rest.len() - trimmed.len()];
    push(job, font, lead, color::TEXT);

    // Consume a run of 2-hex-digit byte tokens as the byte column.
    let b = trimmed.as_bytes();
    let mut i = 0;
    loop {
        let tok_start = i;
        while i < b.len() && b[i] != b' ' {
            i += 1;
        }
        let tok = &trimmed[tok_start..i];
        if is_byte_token(tok) {
            while i < b.len() && b[i] == b' ' {
                i += 1;
            }
            continue;
        }
        // Instruction begins at tok_start.
        push(job, font, &trimmed[..tok_start], color::MUTED);
        append_code(job, font, &trimmed[tok_start..]);
        return;
    }
}

/// Build a coloured [`LayoutJob`] for a single debugger-console line.
pub fn console_line_job(line: &str, font_size: f32) -> LayoutJob {
    let font = FontId::monospace(font_size);
    let mut job = LayoutJob::default();
    let mut s = line;

    // Echoed command prompt.
    if let Some(rest) = s.strip_prefix("dbg>") {
        push(&mut job, &font, "dbg>", color::ACCENT);
        s = rest;
    }

    // Leading status / plugin-id tags, e.g. "[!]", "[event]", "[disasm]".
    loop {
        let trimmed = s.trim_start_matches(' ');
        push(&mut job, &font, &s[..s.len() - trimmed.len()], color::TEXT);
        s = trimmed;
        if s.starts_with('[') {
            if let Some(end) = s.find(']') {
                let tag = &s[..=end];
                let c = if tag == "[!]" {
                    color::ERROR
                } else if tag == "[+]" {
                    color::OK
                } else {
                    color::ACCENT
                };
                push(&mut job, &font, tag, c);
                s = &s[end + 1..];
                continue;
            }
        }
        break;
    }

    // Body: detect an address-led disassembly/listing line, else generic.
    let trimmed = s.trim_start_matches(' ');
    push(&mut job, &font, &s[..s.len() - trimmed.len()], color::TEXT);
    let body = trimmed;

    if let Some(hexlen) = leading_hex_len(body) {
        push(&mut job, &font, &body[..hexlen], color::ADDRESS);
        let after = &body[hexlen..];
        if let Some(rest) = after.strip_prefix(':') {
            push(&mut job, &font, ":", color::PUNCT);
            append_after_colon(&mut job, &font, rest);
        } else {
            // Address listing (e.g. `0x... symbol`): colour the rest generically.
            append_generic(&mut job, &font, after);
        }
    } else {
        append_generic(&mut job, &font, body);
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
        let job = operand_job("qword ptr [rbp - 0x10], rax", 13.0);
        assert_eq!(job.text, "qword ptr [rbp - 0x10], rax");
    }

    #[test]
    fn empty_ok() {
        let job = operand_job("", 13.0);
        assert!(job.text.is_empty());
    }

    // Every console line must be reproduced verbatim, regardless of shape.
    fn assert_roundtrip(line: &str) {
        let job = console_line_job(line, 13.0);
        assert_eq!(job.text, line, "round-trip mismatch for {line:?}");
    }

    #[test]
    fn console_roundtrips_all_shapes() {
        assert_roundtrip("[disasm] 0x0000000000401000: 55                       push rbp");
        assert_roundtrip("[disasm] 0x401001: 48 89 e5                 mov rbp, rsp");
        assert_roundtrip("[gadget] 0x0000000000401234: pop rdi ; ret");
        assert_roundtrip("  0x0000000000401000  pop rsi ; pop r15 ; ret");
        assert_roundtrip("[iocs] flag{some_flag_here}");
        assert_roundtrip("[!] something went wrong at 0xdeadbeef");
        assert_roundtrip("[+] ok");
        assert_roundtrip("dbg> disasm 0x401000 8");
        assert_roundtrip("plain text with no structure");
        assert_roundtrip("");
    }
}
