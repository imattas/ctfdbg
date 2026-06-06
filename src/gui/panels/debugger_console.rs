use crate::commands::ast::Command;
use crate::commands::parser::{parse_line, parse_u64};
use crate::gui::actions::Action;
use crate::gui::state::{AppState, DebugCommand};
use egui::Ui;

pub fn show_tabbed(ui: &mut Ui, state: &mut AppState, actions: &mut Vec<Action>) {
    let id = ui.id().with("bottom_tab");
    let mut tab: usize = ui.memory_mut(|m| *m.data.get_temp_mut_or_insert_with(id, || 1usize));
    ui.horizontal(|ui| {
        if ui.selectable_label(tab == 0, "Target Console").clicked() { tab = 0; }
        if ui.selectable_label(tab == 1, "Debugger Console").clicked() { tab = 1; }
        if ui.selectable_label(tab == 2, "Stack Trace").clicked() { tab = 2; }
        if ui.selectable_label(tab == 3, "Modules").clicked() { tab = 3; }
        if ui.selectable_label(tab == 4, "Logs").clicked() { tab = 4; }
    });
    ui.memory_mut(|m| m.data.insert_temp(id, tab));
    ui.separator();
    match tab {
        0 => crate::gui::panels::target_console::show(ui, state),
        1 => debugger_console_panel(ui, state, actions),
        2 => crate::gui::panels::stack_trace::show(ui, state, actions),
        3 => crate::gui::panels::modules::show(ui, state, actions),
        4 => crate::gui::panels::logs::show(ui, state),
        _ => {}
    }
}

fn debugger_console_panel(ui: &mut Ui, state: &mut AppState, actions: &mut Vec<Action>) {
    show_console(ui, state, actions);
}

/// Standalone debugger-console view (used when each panel is its own dock tab).
pub fn show_console(ui: &mut Ui, state: &mut AppState, actions: &mut Vec<Action>) {
    egui::ScrollArea::vertical().stick_to_bottom(true).max_height(ui.available_height() - 36.0).show(ui, |ui| {
        for line in &state.console_output {
            ui.label(crate::gui::widgets::disasm_syntax::console_line_job(line, 13.0));
        }
    });
    ui.separator();
    ui.horizontal(|ui| {
        ui.label("dbg>");
        let resp = ui.add(
            egui::TextEdit::singleline(&mut state.console_input)
                .desired_width(f32::INFINITY)
                .font(egui::TextStyle::Monospace),
        );
        if resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
            let line = std::mem::take(&mut state.console_input);
            if !line.trim().is_empty() {
                state.console_history.push(line.clone());
                state.console_output.push(format!("dbg> {line}"));
                actions.push(Action::ConsoleCommand(line));
            }
            resp.request_focus();
        }
    });
}

/// Apply a typed console command to the state.
pub fn execute(state: &mut AppState, line: &str) {
    let parsed = parse_line(line);
    match parsed {
        Ok(None) => {}
        Err(e) => {
            // Before reporting a parse error, try the plugin registry —
            // anything of the form `<plugin-id> [arg ...]` should run.
            if try_run_plugin(state, line) { return; }
            state.console_output.push(format!("[!] {e}"));
        }
        Ok(Some(cmd)) => match cmd {
            Command::Run | Command::Continue => state.send(DebugCommand::Continue),
            Command::Restart => {
                state.send(DebugCommand::Kill);
                let t = state.adapter_target.clone();
                state.send(DebugCommand::Launch(t));
            }
            Command::Pause => state.send(DebugCommand::Pause),
            Command::StepInto => state.send(DebugCommand::StepInto),
            Command::StepOver => state.send(DebugCommand::StepOver),
            Command::StepReturn => state.send(DebugCommand::StepReturn),
            Command::BreakAt(arg) => {
                let arg = arg.trim_start_matches('*');
                if let Ok(addr) = parse_u64(arg) {
                    state.send(DebugCommand::SetBreakpoint(addr));
                } else if state.binary.is_none() {
                    state.console_output.push("[!] no binary or address".into());
                } else if let Some(addr) = state.binary.as_ref().and_then(|b| b.address_of_name(arg)) {
                    state.send(DebugCommand::SetBreakpoint(addr));
                } else {
                    state.console_output.push(format!("[!] symbol not found: {arg}"));
                }
            }
            Command::Delete(id) => state.send(DebugCommand::RemoveBreakpoint(id)),
            Command::Enable(id) => state.send(DebugCommand::EnableBreakpoint(id, true)),
            Command::Disable(id) => state.send(DebugCommand::EnableBreakpoint(id, false)),
            Command::Condition(id, expr) => state.send(DebugCommand::SetCondition(id, Some(expr))),
            Command::Regs => {
                for (k, v) in &state.registers.values {
                    state.console_output.push(format!("  {k:6} = 0x{v:016x}"));
                }
            }
            Command::SetReg(name, val) => {
                if let Ok(v) = parse_u64(&val) { state.send(DebugCommand::WriteRegister(name, v)); }
            }
            Command::Ip => {
                let pc = state.registers.pc().unwrap_or(0);
                state.console_output.push(format!("  ip = 0x{pc:x}"));
            }
            Command::SetIp(addr) => {
                if let Ok(a) = parse_u64(&addr) { state.send(DebugCommand::SetIp(a)); }
            }
            Command::Examine { count, format, address } => {
                let _ = format; let _ = count;
                if let Ok(a) = parse_u64(&address) {
                    state.memory_view_address = a;
                }
            }
            Command::Stack => {
                if state.stack_trace.is_empty() {
                    state.console_output.push("(no stack trace available; stop the target first)".into());
                } else {
                    for f in &state.stack_trace {
                        let loc = f.module.as_deref().unwrap_or("");
                        state.console_output.push(format!(
                            "  #{:<2} pc=0x{:016x} sp=0x{:x} {}",
                            f.frame_index, f.pc, f.sp, loc
                        ));
                    }
                }
            }
            Command::Threads => {
                for t in &state.threads { state.console_output.push(format!("  TID {}", t.thread_id)); }
            }
            Command::Modules => {
                for m in &state.modules {
                    state.console_output.push(format!("  0x{:016x}-0x{:016x}  {}", m.base, m.end(), m.name));
                }
            }
            Command::Vmmap => {
                if let Some(b) = &state.binary {
                    for s in &b.sections {
                        state.console_output.push(format!("  0x{:x}-0x{:x} [{:>4}] {}",
                            s.virtual_address, s.virtual_address + s.virtual_size, s.flags_text, s.name));
                    }
                }
            }
            Command::Symbols => {
                if let Some(b) = &state.binary {
                    for s in b.symbols.iter().take(200) {
                        state.console_output.push(format!("  0x{:016x}  {}", s.address, s.name));
                    }
                }
            }
            Command::Imports => {
                if let Some(b) = &state.binary {
                    for i in &b.imports { state.console_output.push(format!("  IAT 0x{:x}  {}!{}", i.address, i.library, i.name)); }
                }
            }
            Command::Exports => {
                if let Some(b) = &state.binary {
                    for e in &b.exports { state.console_output.push(format!("  EAT 0x{:x}  {}", e.address, e.name)); }
                }
            }
            Command::Checksec => {
                if let Some(b) = &state.binary {
                    let r = crate::analysis::checksec::checksec(b);
                    for (k, v) in r.lines { state.console_output.push(format!("  {k:20} {v}")); }
                }
            }
            Command::Disasm(addr) => {
                if let Ok(a) = parse_u64(&addr) { state.navigate_disasm(a); }
            }
            Command::Search(pat) => {
                for line in search_loaded(state, &pat) {
                    state.console_output.push(line);
                }
            }
            Command::Cyclic(n) => {
                let p = crate::pwn::cyclic::cyclic(n);
                state.console_output.push(String::from_utf8_lossy(&p).into_owned());
            }
            Command::CyclicFind(s) => {
                let needle: Vec<u8> = if let Ok(v) = parse_u64(&s) {
                    v.to_le_bytes()[..4].to_vec()
                } else { s.as_bytes().to_vec() };
                match crate::pwn::cyclic::cyclic_find(&needle) {
                    Some(off) => state.console_output.push(format!("offset = {off}")),
                    None => state.console_output.push("not found".into()),
                }
            }
            Command::Rop => {
                if let Some(b) = &state.binary {
                    if let Some(path) = &b.path {
                        if let Ok(bytes) = std::fs::read(path) {
                            if let Ok(g) = crate::analysis::rop::find_gadgets(&bytes, b.preferred_image_base, b.architecture) {
                                for x in g.iter().take(60) {
                                    state.console_output.push(format!("  0x{:016x}  {}", x.address, x.instructions.join(" ; ")));
                                }
                                state.console_output.push(format!("({} gadgets total)", g.len()));
                            }
                        }
                    }
                }
            }
            Command::Iat => {
                if let Some(b) = &state.binary {
                    for i in &b.imports { state.console_output.push(format!("  IAT 0x{:x}  {}!{}", i.address, i.library, i.name)); }
                }
            }
            Command::Got | Command::Plt => {
                for line in show_got_plt(state) {
                    state.console_output.push(line);
                }
            }
            Command::Quit => std::process::exit(0),
            Command::Comment(_) => {}
        },
    }
}

/// Interpret a search pattern as raw hex (optionally `0x`-prefixed) when it is
/// all hex digits of even length, otherwise as ASCII bytes.
fn parse_search_pattern(pat: &str) -> Vec<u8> {
    let t = pat.trim();
    let hexcand = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")).unwrap_or(t);
    if !hexcand.is_empty() && hexcand.len().is_multiple_of(2) && hexcand.bytes().all(|b| b.is_ascii_hexdigit()) {
        if let Ok(v) = hex::decode(hexcand) {
            return v;
        }
    }
    t.as_bytes().to_vec()
}

/// Search the loaded binary image for a byte/string pattern.
fn search_loaded(state: &AppState, pat: &str) -> Vec<String> {
    let Some(bytes) = state.binary_bytes.as_ref() else {
        return vec!["[!] no binary loaded".into()];
    };
    let needle = parse_search_pattern(pat);
    if needle.is_empty() {
        return vec!["[!] empty search pattern".into()];
    }
    let mut hits = Vec::new();
    let mut count = 0usize;
    let mut i = 0usize;
    while i + needle.len() <= bytes.len() {
        if &bytes[i..i + needle.len()] == needle.as_slice() {
            let va = state.binary.as_ref().and_then(|info| {
                info.sections
                    .iter()
                    .find(|s| {
                        let off = s.file_offset as usize;
                        i >= off && (i as u64) < s.file_offset + s.file_size
                    })
                    .map(|s| s.virtual_address + (i as u64 - s.file_offset))
            });
            match va {
                Some(v) => hits.push(format!("  file 0x{i:08x}   vaddr 0x{v:x}")),
                None => hits.push(format!("  file 0x{i:08x}")),
            }
            count += 1;
            if count >= 200 {
                hits.push("  ... (truncated at 200)".into());
                break;
            }
            i += needle.len().max(1);
        } else {
            i += 1;
        }
    }
    if hits.is_empty() {
        return vec![format!("no matches for {:02x?}", needle)];
    }
    hits.insert(0, format!("{count} match(es):"));
    hits
}

/// Show GOT/PLT sections (ELF) or the import table (PE).
fn show_got_plt(state: &AppState) -> Vec<String> {
    use crate::target::format::FileFormat;
    let Some(info) = state.binary.as_ref() else {
        return vec!["[!] no binary loaded".into()];
    };
    if info.format != FileFormat::Elf {
        if info.imports.is_empty() {
            return vec!["GOT/PLT is ELF-specific; this binary exposes no import table".into()];
        }
        let mut out = vec!["Imports (IAT):".to_string()];
        for imp in info.imports.iter().take(300) {
            out.push(format!("  0x{:x}  {}!{}", imp.address, imp.library, imp.name));
        }
        return out;
    }

    let ptr = info.architecture.pointer_size().max(1);
    let mut out = Vec::new();
    for secname in [".plt", ".plt.sec", ".plt.got", ".got", ".got.plt"] {
        let Some(s) = info.sections.iter().find(|s| s.name == secname) else { continue };
        out.push(format!(
            "{}: 0x{:x}-0x{:x} ({} bytes)",
            secname,
            s.virtual_address,
            s.virtual_address + s.virtual_size,
            s.virtual_size
        ));
        if secname.starts_with(".got") {
            if let Some(bytes) = state.binary_bytes.as_ref() {
                let start = s.file_offset as usize;
                let end = ((s.file_offset + s.file_size) as usize).min(bytes.len());
                let mut off = start;
                let mut idx = 0;
                while off + ptr <= end && idx < 64 {
                    let mut buf = [0u8; 8];
                    buf[..ptr].copy_from_slice(&bytes[off..off + ptr]);
                    let val = u64::from_le_bytes(buf);
                    let va = s.virtual_address + (off - start) as u64;
                    out.push(format!("  [0x{va:x}] = 0x{val:x}"));
                    off += ptr;
                    idx += 1;
                }
            }
        }
    }
    if out.is_empty() {
        out.push("no .got/.plt sections present in this binary".into());
    }
    out
}

/// Try interpreting `line` as `<plugin-id> [optional argument]` and
/// return `true` if a matching plugin was found and executed.
fn try_run_plugin(state: &mut AppState, line: &str) -> bool {
    let line = line.trim();
    if line.is_empty() { return false; }
    let (id_part, arg_part) = line.split_once(' ').unwrap_or((line, ""));
    // Take the registry out so we can pass `&AppState` to the plugin while
    // still mutating `state.console_output` afterwards.
    let registry = std::mem::take(&mut state.plugins);
    let result = registry.get(id_part).map(|p| p.run(state, if arg_part.is_empty() { None } else { Some(arg_part) }));
    state.plugins = registry;
    match result {
        Some(out) => {
            for l in out.lines {
                state.console_output.push(format!("[{id_part}] {l}"));
            }
            true
        }
        None => false,
    }
}
