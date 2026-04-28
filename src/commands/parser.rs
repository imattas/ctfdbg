//! Tokenizing parser for the debugger console.

use crate::commands::ast::Command;
use crate::error::{DbgError, DbgResult};

pub fn parse_line(line: &str) -> DbgResult<Option<Command>> {
    let line = line.trim();
    if line.is_empty() { return Ok(None); }
    if line.starts_with('#') { return Ok(Some(Command::Comment(line[1..].trim().into()))); }

    let mut parts = line.split_whitespace();
    let head = parts.next().unwrap();
    let rest: Vec<&str> = parts.collect();
    let join_rest = || rest.join(" ");

    let cmd = match head {
        "run" | "r" => Command::Run,
        "restart" => Command::Restart,
        "continue" | "c" => Command::Continue,
        "pause" => Command::Pause,
        "stepi" | "si" => Command::StepInto,
        "step" | "step-over" | "n" => Command::StepOver,
        "step-return" | "finish" => Command::StepReturn,
        "break" | "b" => {
            let arg = first_arg(&rest, "break needs an address or symbol")?;
            Command::BreakAt(arg)
        }
        "delete" | "d" => Command::Delete(parse_u64(first_arg(&rest, "delete <id>")?.as_str())?),
        "enable" => Command::Enable(parse_u64(first_arg(&rest, "enable <id>")?.as_str())?),
        "disable" => Command::Disable(parse_u64(first_arg(&rest, "disable <id>")?.as_str())?),
        "condition" => {
            if rest.len() < 2 {
                return Err(DbgError::Command("condition <id> <expr>".into()));
            }
            let id = parse_u64(rest[0])?;
            let expr = rest[1..].join(" ");
            Command::Condition(id, expr)
        }
        "regs" => Command::Regs,
        "setreg" => {
            if rest.len() < 2 { return Err(DbgError::Command("setreg <name> <value>".into())); }
            Command::SetReg(rest[0].into(), rest[1].into())
        }
        "ip" => Command::Ip,
        "setip" => Command::SetIp(first_arg(&rest, "setip <address>")?),
        "stack" => Command::Stack,
        "threads" => Command::Threads,
        "modules" => Command::Modules,
        "vmmap" => Command::Vmmap,
        "symbols" => Command::Symbols,
        "imports" => Command::Imports,
        "exports" => Command::Exports,
        "checksec" => Command::Checksec,
        "disasm" | "u" => Command::Disasm(first_arg(&rest, "disasm <addr>")?),
        "search" => Command::Search(join_rest()),
        "cyclic" => Command::Cyclic(parse_usize(first_arg(&rest, "cyclic <len>")?.as_str())?),
        "cyclic-find" => Command::CyclicFind(first_arg(&rest, "cyclic-find <value>")?),
        "rop" => Command::Rop,
        "iat" => Command::Iat,
        "got" => Command::Got,
        "plt" => Command::Plt,
        "quit" | "q" | "exit" => Command::Quit,
        h if h.starts_with("x/") => parse_examine(&h[2..], &rest)?,
        other => return Err(DbgError::Command(format!("unknown command: {other}"))),
    };
    Ok(Some(cmd))
}

fn parse_examine(spec: &str, rest: &[&str]) -> DbgResult<Command> {
    // spec like "16gx" -> count 16, format chars 'g', 'x'
    let mut count_end = 0;
    for c in spec.chars() {
        if c.is_ascii_digit() { count_end += c.len_utf8(); } else { break; }
    }
    let count: u32 = if count_end == 0 { 1 } else {
        spec[..count_end].parse().map_err(|e: std::num::ParseIntError| DbgError::Command(e.to_string()))?
    };
    let fmt_chars = &spec[count_end..];
    let format = fmt_chars.chars().last().unwrap_or('x');
    let addr = first_arg(rest, "x/<count><fmt> <address>")?;
    Ok(Command::Examine { count, format, address: addr })
}

fn first_arg(rest: &[&str], help: &str) -> DbgResult<String> {
    rest.first().map(|s| s.to_string()).ok_or_else(|| DbgError::Command(help.into()))
}

pub fn parse_u64(s: &str) -> DbgResult<u64> {
    let s = s.trim();
    let (s, hex) = if let Some(stripped) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        (stripped, true)
    } else if s.chars().all(|c| c.is_ascii_digit()) {
        (s, false)
    } else {
        (s, true)
    };
    if hex {
        u64::from_str_radix(s, 16).map_err(|e| DbgError::Command(e.to_string()))
    } else {
        s.parse::<u64>().map_err(|e| DbgError::Command(e.to_string()))
    }
}

fn parse_usize(s: &str) -> DbgResult<usize> {
    parse_u64(s).map(|v| v as usize)
}
