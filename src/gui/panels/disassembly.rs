use crate::analysis::disasm::Disassembler;
use crate::analysis::flow::{self, FlowKind};
use crate::gui::actions::Action;
use crate::gui::state::{AppState, DebugCommand};
use crate::gui::theme::color;
use crate::gui::widgets::address::parse_hex;
use crate::gui::widgets::disasm_syntax;
use crate::target::arch::Architecture;
use egui::{pos2, RichText, Sense, Stroke, Ui};

pub fn show(ui: &mut Ui, state: &mut AppState, actions: &mut Vec<Action>) {
    ui.horizontal(|ui| {
        ui.label("Address:");
        let mut text = format!("0x{:x}", state.disasm_address);
        let resp = ui.text_edit_singleline(&mut text);
        if resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
            if let Some(a) = parse_hex(&text) { state.disasm_address = a; }
        }
        if ui.button("Refresh").clicked() {
            state.send(DebugCommand::Refresh);
        }
    });

    let arch = state.binary.as_ref().map(|b| b.architecture).unwrap_or(Architecture::X86_64);

    let bytes = read_bytes_for_disasm(state, state.disasm_address, 256);
    let dis = match Disassembler::new(arch) {
        Ok(d) => d,
        Err(e) => { ui.label(format!("disasm init failed: {e}")); return; }
    };
    let insns = dis.disassemble(&bytes, state.disasm_address, 60).unwrap_or_default();

    let pc = state.registers.pc().unwrap_or(0);
    let bp_addrs: std::collections::HashSet<u64> =
        state.breakpoints.iter().filter(|b| b.enabled).map(|b| b.address).collect();

    // Branch-arrow layout (IDA/Ghidra-style gutter showing where jumps go).
    let conv: Vec<crate::pwn::asm::DisasmInsn> = insns.iter().cloned().map(Into::into).collect();
    let (arrows, lanes) = flow::compute_arrows(&conv);
    let gutter_w = if lanes > 0 { lanes as f32 * 7.0 + 8.0 } else { 0.0 };

    egui::ScrollArea::vertical().auto_shrink([false; 2]).show(ui, |ui| {
        let gutter_x0 = ui.min_rect().left();
        let mut row_y: Vec<(u64, f32)> = Vec::with_capacity(insns.len());
        for ins in &insns {
            let is_pc = ins.address == pc;
            let is_bp = bp_addrs.contains(&ins.address);
            let row_bg = if is_pc { color::CURRENT_LINE }
                else if is_bp { color::BREAKPOINT }
                else { egui::Color32::TRANSPARENT };
            let frame = egui::Frame::none().fill(row_bg).inner_margin(egui::Margin::symmetric(2.0, 1.0));
            let fr = frame.show(ui, |ui| {
                let resp = ui.horizontal(|ui| {
                    if gutter_w > 0.0 { ui.add_space(gutter_w); }
                    let marker = if is_pc { "\u{27A4}" } else if is_bp { "\u{2B24}" } else { " " };
                    ui.monospace(RichText::new(marker).color(if is_bp { egui::Color32::from_rgb(0xff, 0x55, 0x55) } else { color::ACCENT }));
                    ui.monospace(RichText::new(format!("{:016x}", ins.address)).color(color::ADDRESS));
                    let bytes_str = ins.bytes.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" ");
                    ui.monospace(RichText::new(format!("{:<24}", bytes_str)).color(color::MUTED));
                    ui.monospace(
                        RichText::new(format!("{:<8}", ins.mnemonic))
                            .color(disasm_syntax::mnemonic_color(&ins.mnemonic))
                            .strong(),
                    );
                    if !ins.op_str.is_empty() {
                        ui.label(disasm_syntax::operand_job(&ins.op_str, 13.0));
                    }
                    if let Some(sym) = symbol_label(state, ins) {
                        ui.monospace(RichText::new(format!("; {}", sym)).color(color::HINT));
                    }
                }).response;
                let line_resp = ui.interact(resp.rect, ui.id().with(("disasm", ins.address)), Sense::click());
                if line_resp.clicked() { state.selected_address = Some(ins.address); }
                if line_resp.double_clicked() { actions.push(Action::ToggleBreakpointAt(ins.address)); }
                line_resp.context_menu(|ui| {
                    if ui.button("Toggle Breakpoint").clicked() { actions.push(Action::ToggleBreakpointAt(ins.address)); ui.close_menu(); }
                    if ui.button("Edit Breakpoint Condition...").clicked() {
                        if let Some(bp) = state.breakpoints.iter().find(|b| b.address == ins.address) {
                            actions.push(Action::EditConditionDialog(bp.id.0));
                        }
                        ui.close_menu();
                    }
                    if ui.button("Run To Here").clicked() { actions.push(Action::RunToAddress(ins.address)); ui.close_menu(); }
                    if ui.button("Jump to IP").clicked() { actions.push(Action::JumpToIp); ui.close_menu(); }
                    if ui.button("Override IP").clicked() { actions.push(Action::OverrideIpDialog); ui.close_menu(); }
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
                });
            });
            row_y.push((ins.address, fr.response.rect.center().y));
        }
        if insns.is_empty() {
            ui.label(RichText::new("(no bytes available - launch a process or load a binary)").color(color::MUTED));
        }

        // Paint the branch arrows into the reserved gutter.
        if gutter_w > 0.0 && !arrows.is_empty() {
            let painter = ui.painter();
            let y_of = |addr: u64| row_y.iter().find(|(a, _)| *a == addr).map(|(_, y)| *y);
            let right_x = gutter_x0 + gutter_w - 3.0;
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
                // Arrowhead at the target, pointing right into the instruction.
                painter.line_segment([pos2(right_x, y1), pos2(right_x - 4.0, y1 - 3.0)], stroke);
                painter.line_segment([pos2(right_x, y1), pos2(right_x - 4.0, y1 + 3.0)], stroke);
            }
        }
    });
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
