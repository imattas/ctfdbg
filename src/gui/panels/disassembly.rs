use crate::analysis::flow::{self, FlowKind};
use crate::gui::actions::Action;
use crate::gui::state::{AppState, DisasmView};
use crate::gui::theme::color;
use crate::gui::widgets::address::parse_hex;
use crate::gui::widgets::disasm_syntax;
use egui::{pos2, Rect, RichText, Sense, Shape, Stroke, Ui};

pub fn show(ui: &mut Ui, state: &mut AppState, actions: &mut Vec<Action>) {
    // ---- toolbar: navigation across the whole disassembly -----------------
    ui.horizontal(|ui| {
        ui.label("Go to:");
        let resp = ui.add(
            egui::TextEdit::singleline(&mut state.disasm_goto)
                .desired_width(150.0)
                .hint_text("0x… or symbol")
                .font(egui::TextStyle::Monospace),
        );
        let go = (resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)))
            || ui.button("Go").clicked();
        if go {
            let query = state.disasm_goto.clone();
            if let Some(a) = resolve_goto(state, &query) {
                state.navigate_disasm(a);
            } else if !query.trim().is_empty() {
                state.console_output.push(format!("[!] can't resolve '{}'", query.trim()));
            }
        }

        let entry = state.binary.as_ref().map(|b| b.entry_point);
        if let Some(entry) = entry {
            if ui.button("Entry").on_hover_text("Jump to the entry point").clicked() {
                state.navigate_disasm(entry);
            }
        }
        if state.registers.pc().is_some()
            && ui.button("\u{27A4} PC").on_hover_text("Jump to the current instruction").clicked()
        {
            actions.push(Action::JumpToIp);
        }
        ui.checkbox(&mut state.disasm_following_pc, "Follow PC")
            .on_hover_text("Keep the view centred on the program counter while stepping");
        if ui.button("Refresh").on_hover_text("Re-decode from memory and refresh state").clicked() {
            state.disasm_cache = None;
            state.send(crate::gui::state::DebugCommand::Refresh);
        }
    });
    ui.separator();

    state.ensure_disasm();
    let Some(view) = state.disasm_cache.take() else {
        ui.label(
            RichText::new("(no code here — load a binary or navigate to an executable address)")
                .color(color::MUTED),
        );
        return;
    };

    let pc = state.registers.pc().unwrap_or(0);
    let bp_addrs: std::collections::HashSet<u64> =
        state.breakpoints.iter().filter(|b| b.enabled).map(|b| b.address).collect();

    let row_h = ui.text_style_height(&egui::TextStyle::Monospace);
    let total = view.insns.len();

    // A pending navigation scrolls its target row into view exactly once.
    let scroll_row = state.disasm_scroll_to.take().and_then(|a| nearest_row(&view, a));

    let mut area = egui::ScrollArea::vertical().auto_shrink([false; 2]);
    if let Some(r) = scroll_row {
        let pitch = row_h + ui.spacing().item_spacing.y;
        // Bias above centre so a little context above the target stays visible.
        let offset = (r as f32 * pitch - ui.available_height() * 0.4).max(0.0);
        area = area.vertical_scroll_offset(offset);
    }

    // Virtualised: only the visible rows of `view.insns` are laid out, so the
    // entire section can be scrolled without per-frame re-decoding.
    area.show_rows(ui, row_h, total, |ui, range| {
        // Branch arrows are only meaningful between rows that are both visible.
        let conv: Vec<crate::pwn::asm::DisasmInsn> =
            view.insns[range.clone()].iter().cloned().map(Into::into).collect();
        let (arrows, lanes) = flow::compute_arrows(&conv);
        let gutter_w = if lanes > 0 { lanes as f32 * 7.0 + 8.0 } else { 0.0 };
        let gutter_x0 = ui.min_rect().left();

        let mut row_y: Vec<(u64, f32)> = Vec::with_capacity(range.len());
        for i in range.clone() {
            let ins = &view.insns[i];
            let is_pc = ins.address == pc;
            let is_bp = bp_addrs.contains(&ins.address);
            let row_bg = if is_pc {
                color::CURRENT_LINE
            } else if is_bp {
                color::BREAKPOINT
            } else {
                egui::Color32::TRANSPARENT
            };
            // Reserve a paint slot so the row background lands behind the text.
            let bg_idx = ui.painter().add(Shape::Noop);

            let sym = symbol_label(state, ins);
            let resp = ui
                .horizontal(|ui| {
                    if gutter_w > 0.0 {
                        ui.add_space(gutter_w);
                    }
                    let marker = if is_pc { "\u{27A4}" } else if is_bp { "\u{2B24}" } else { " " };
                    ui.monospace(RichText::new(marker).color(if is_bp {
                        egui::Color32::from_rgb(0xff, 0x55, 0x55)
                    } else {
                        color::ACCENT
                    }));
                    ui.monospace(RichText::new(format!("{:016x}", ins.address)).color(color::ADDRESS));
                    let bytes_str =
                        ins.bytes.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" ");
                    ui.monospace(RichText::new(format!("{:<24}", bytes_str)).color(color::MUTED));
                    ui.monospace(
                        RichText::new(format!("{:<8}", ins.mnemonic))
                            .color(disasm_syntax::mnemonic_color(&ins.mnemonic))
                            .strong(),
                    );
                    if !ins.op_str.is_empty() {
                        ui.label(disasm_syntax::operand_job(&ins.op_str, 13.0));
                    }
                    if let Some(s) = &sym {
                        ui.monospace(RichText::new(format!("; {}", s)).color(color::HINT));
                    }
                })
                .response;

            let row_rect = Rect::from_min_max(
                pos2(gutter_x0, resp.rect.top()),
                pos2(ui.min_rect().right(), resp.rect.bottom()),
            );
            if row_bg != egui::Color32::TRANSPARENT {
                ui.painter()
                    .set(bg_idx, egui::epaint::RectShape::filled(row_rect, 0.0, row_bg));
            }
            row_y.push((ins.address, resp.rect.center().y));

            let line_resp = ui.interact(row_rect, ui.id().with(("disasm", ins.address)), Sense::click());
            if line_resp.clicked() {
                state.selected_address = Some(ins.address);
            }
            if line_resp.double_clicked() {
                actions.push(Action::ToggleBreakpointAt(ins.address));
            }
            line_resp.context_menu(|ui| row_context_menu(ui, state, ins, actions));
        }

        // Paint the branch arrows into the reserved gutter.
        if gutter_w > 0.0 && !arrows.is_empty() {
            let y_of = |addr: u64| row_y.iter().find(|(a, _)| *a == addr).map(|(_, y)| *y);
            let right_x = gutter_x0 + gutter_w - 3.0;
            let painter = ui.painter();
            for arr in &arrows {
                let (Some(y0), Some(y1)) = (y_of(arr.from), y_of(arr.to)) else { continue };
                let lane_x = gutter_x0 + 3.0 + arr.lane as f32 * 7.0;
                let col = match arr.kind {
                    FlowKind::CondJump => color::IMMEDIATE,
                    _ => color::ACCENT,
                };
                let stroke = Stroke::new(1.3, col);
                painter.line_segment([pos2(right_x, y0), pos2(lane_x, y0)], stroke);
                painter.line_segment([pos2(lane_x, y0), pos2(lane_x, y1)], stroke);
                painter.line_segment([pos2(lane_x, y1), pos2(right_x, y1)], stroke);
                painter.line_segment([pos2(right_x, y1), pos2(right_x - 4.0, y1 - 3.0)], stroke);
                painter.line_segment([pos2(right_x, y1), pos2(right_x - 4.0, y1 + 3.0)], stroke);
            }
        }
    });

    state.disasm_cache = Some(view);
}

fn row_context_menu(
    ui: &mut Ui,
    state: &mut AppState,
    ins: &crate::analysis::disasm::DisasmInsn,
    actions: &mut Vec<Action>,
) {
    if ui.button("Toggle Breakpoint").clicked() {
        actions.push(Action::ToggleBreakpointAt(ins.address));
        ui.close_menu();
    }
    if ui.button("Edit Breakpoint Condition...").clicked() {
        if let Some(bp) = state.breakpoints.iter().find(|b| b.address == ins.address) {
            actions.push(Action::EditConditionDialog(bp.id.0));
        }
        ui.close_menu();
    }
    if ui.button("Run To Here").clicked() {
        actions.push(Action::RunToAddress(ins.address));
        ui.close_menu();
    }
    if ui.button("Jump to IP").clicked() {
        actions.push(Action::JumpToIp);
        ui.close_menu();
    }
    if ui.button("Override IP").clicked() {
        actions.push(Action::OverrideIpDialog);
        ui.close_menu();
    }
    ui.separator();
    if ui.button("Find XRefs to here").clicked() {
        actions.push(Action::ConsoleCommand(format!("xref 0x{:x}", ins.address)));
        ui.close_menu();
    }
    if ui.button("Control-flow graph from here").clicked() {
        actions.push(Action::ConsoleCommand(format!("cfg 0x{:x}", ins.address)));
        ui.close_menu();
    }
    if let Some(t) = flow::branch_target(&ins.clone().into()) {
        if ui.button(format!("Follow branch \u{2192} 0x{t:x}")).clicked() {
            actions.push(Action::NavigateTo(t));
            ui.close_menu();
        }
    }
    ui.separator();
    if ui.button("Copy Address").clicked() {
        ui.output_mut(|o| o.copied_text = format!("0x{:x}", ins.address));
        ui.close_menu();
    }
    if ui.button("Copy Instruction").clicked() {
        ui.output_mut(|o| o.copied_text = format!("{} {}", ins.mnemonic, ins.op_str));
        ui.close_menu();
    }
}

/// Resolve a "Go to" query: a hex/decimal address or a symbol/export name.
fn resolve_goto(state: &AppState, text: &str) -> Option<u64> {
    let t = text.trim();
    if t.is_empty() {
        return None;
    }
    if let Some(a) = parse_hex(t) {
        return Some(a);
    }
    let b = state.binary.as_ref()?;
    b.symbols
        .iter()
        .find(|s| s.name == t)
        .map(|s| s.address)
        .or_else(|| b.exports.iter().find(|e| e.name == t).map(|e| e.address))
}

/// Row index to scroll to for `addr`: exact match if it is an instruction
/// boundary, otherwise the instruction whose byte range contains it.
fn nearest_row(view: &DisasmView, addr: u64) -> Option<usize> {
    if let Some(&r) = view.row_of.get(&addr) {
        return Some(r);
    }
    view.insns
        .iter()
        .position(|i| addr >= i.address && addr < i.address + (i.bytes.len().max(1)) as u64)
}

pub(crate) fn read_bytes_for_disasm(state: &AppState, address: u64, len: usize) -> Vec<u8> {
    // Map the virtual address to a section file offset and slice the already
    // loaded image bytes (no per-frame disk read). The per-section range check
    // is the only bound we need — an outer image-base/raw-size guard wrongly
    // rejects normal ELF sections that live at high virtual addresses.
    if let (Some(b), Some(file_bytes)) = (&state.binary, &state.binary_bytes) {
        for s in &b.sections {
            if address >= s.virtual_address && address < s.virtual_address + s.virtual_size.max(s.file_size) {
                let file_off = (s.file_offset + (address - s.virtual_address)) as usize;
                let end = (file_off + len).min(file_bytes.len());
                if file_off < end {
                    return file_bytes[file_off..end].to_vec();
                }
            }
        }
    }
    Vec::new()
}

fn symbol_label(state: &AppState, ins: &crate::analysis::disasm::DisasmInsn) -> Option<String> {
    // Reuse the shared branch-target resolver (handles indirect/bracketed
    // operands correctly) instead of re-parsing the operand string by hand.
    let target = flow::branch_target(&ins.clone().into())?;
    let b = state.binary.as_ref()?;
    if let Some(s) = b.symbols.iter().find(|s| s.address == target) {
        return Some(s.name.clone());
    }
    if let Some(m) = state.modules.iter().find(|m| m.contains(target)) {
        return Some(format!("{}+0x{:x}", m.name, target - m.base));
    }
    None
}
