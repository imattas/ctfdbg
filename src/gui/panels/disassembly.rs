use crate::analysis::disasm::Disassembler;
use crate::gui::actions::Action;
use crate::gui::state::{AppState, DebugCommand};
use crate::gui::theme::color;
use crate::gui::widgets::address::parse_hex;
use crate::gui::widgets::disasm_syntax;
use crate::target::arch::Architecture;
use egui::{RichText, Sense, Ui};

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

    egui::ScrollArea::vertical().auto_shrink([false; 2]).show(ui, |ui| {
        for ins in &insns {
            let is_pc = ins.address == pc;
            let is_bp = bp_addrs.contains(&ins.address);
            let row_bg = if is_pc { color::CURRENT_LINE }
                else if is_bp { color::BREAKPOINT }
                else { egui::Color32::TRANSPARENT };
            let frame = egui::Frame::none().fill(row_bg).inner_margin(egui::Margin::symmetric(2.0, 1.0));
            frame.show(ui, |ui| {
                let resp = ui.horizontal(|ui| {
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
        }
        if insns.is_empty() {
            ui.label(RichText::new("(no bytes available - launch a process or load a binary)").color(color::MUTED));
        }
    });
}

fn read_bytes_for_disasm(state: &AppState, address: u64, len: usize) -> Vec<u8> {
    // First try live process via memory cache from latest event - we don't keep one,
    // so fall back to binary file content based on RVA.
    if let Some(b) = &state.binary {
        let base = b.loaded_image_base.max(b.preferred_image_base);
        if address >= base && address < base + b.raw_size + 0x1000 {
            // Try to map address to a section file offset.
            for s in &b.sections {
                if address >= s.virtual_address && address < s.virtual_address + s.virtual_size.max(s.file_size) {
                    let rva_off = address - s.virtual_address;
                    let file_off = (s.file_offset + rva_off) as usize;
                    if let Some(path) = &b.path {
                        if let Ok(file_bytes) = std::fs::read(path) {
                            let end = (file_off + len).min(file_bytes.len());
                            if file_off < end {
                                return file_bytes[file_off..end].to_vec();
                            }
                        }
                    }
                }
            }
        }
    }
    // Last resort: empty
    vec![0u8; 0]
}

fn symbol_label(state: &AppState, ins: &crate::analysis::disasm::DisasmInsn) -> Option<String> {
    if !(ins.mnemonic == "call" || ins.mnemonic.starts_with('j')) { return None; }
    let target = ins.op_str.trim().trim_start_matches("0x");
    let target_addr = u64::from_str_radix(target, 16).ok()?;
    if let Some(b) = &state.binary {
        if let Some(s) = b.symbols.iter().find(|s| s.address == target_addr) {
            return Some(s.name.clone());
        }
        if let Some(m) = state.modules.iter().find(|m| m.contains(target_addr)) {
            return Some(format!("{}+0x{:x}", m.name, target_addr - m.base));
        }
    }
    None
}
