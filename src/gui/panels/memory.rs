use crate::gui::actions::Action;
use crate::gui::state::{AppState, DebugCommand};
use crate::gui::widgets::address::parse_hex;
use crate::gui::widgets::hex_view::hex_view;
use egui::{RichText, Ui};

pub fn show(ui: &mut Ui, state: &mut AppState, _actions: &mut Vec<Action>) {
    ui.horizontal(|ui| {
        ui.label("Address:");
        let mut text = format!("0x{:x}", state.memory_view_address);
        if ui.text_edit_singleline(&mut text).lost_focus()
            && ui.input(|i| i.key_pressed(egui::Key::Enter))
        {
            if let Some(a) = parse_hex(&text) { state.memory_view_address = a; }
        }
        ui.label("Size:");
        let mut size_text = if state.memory_bytes.is_empty() { "256".to_string() }
                            else { state.memory_bytes.len().to_string() };
        ui.add(egui::TextEdit::singleline(&mut size_text).desired_width(60.0));
        let size: usize = size_text.parse().unwrap_or(256).clamp(16, 0x10000);
        if ui.button("Read").clicked() {
            state.send(DebugCommand::ReadMemory(state.memory_view_address, size));
        }
        if ui.button("\u{2190} -0x100").clicked() {
            state.memory_view_address = state.memory_view_address.saturating_sub(0x100);
            state.send(DebugCommand::ReadMemory(state.memory_view_address, size));
        }
        if ui.button("+0x100 \u{2192}").clicked() {
            state.memory_view_address = state.memory_view_address.wrapping_add(0x100);
            state.send(DebugCommand::ReadMemory(state.memory_view_address, size));
        }
    });

    // Search & patch row
    ui.horizontal(|ui| {
        ui.label("Find (hex):");
        ui.add(egui::TextEdit::singleline(&mut state.mem_search).desired_width(180.0).hint_text("deadbeef"));
        if ui.button("Find").clicked() {
            match hex::decode(state.mem_search.trim().replace(' ', "")) {
                Ok(needle) if !needle.is_empty() => {
                    if let Some(off) = find_subseq(&state.memory_bytes, &needle) {
                        let hit = state.memory_view_address + off as u64;
                        state.console_output.push(format!("[mem] hit at 0x{hit:x}"));
                        state.selected_address = Some(hit);
                    } else {
                        state.console_output.push("[mem] pattern not found in current window".into());
                    }
                }
                _ => state.console_output.push("[!] invalid hex pattern".into()),
            }
        }
        ui.separator();
        ui.label("Patch @ addr:");
        ui.add(egui::TextEdit::singleline(&mut state.mem_patch_addr).desired_width(140.0).hint_text("0x401000"));
        ui.label("hex:");
        ui.add(egui::TextEdit::singleline(&mut state.mem_patch_bytes).desired_width(180.0).hint_text("90 90 90"));
        if ui.button("Write").clicked() {
            let addr = parse_hex(&state.mem_patch_addr).unwrap_or(state.memory_view_address);
            match hex::decode(state.mem_patch_bytes.trim().replace(' ', "")) {
                Ok(bytes) if !bytes.is_empty() => {
                    state.send(DebugCommand::WriteMemory(addr, bytes));
                    state.console_output.push(format!("[mem] write queued at 0x{addr:x}"));
                }
                _ => state.console_output.push("[!] invalid hex bytes".into()),
            }
        }
    });
    ui.separator();

    if state.memory_bytes.is_empty() {
        ui.label(RichText::new("(no memory loaded yet — click Read once a process is running)").weak());
    } else {
        hex_view(ui, state.memory_view_address, &state.memory_bytes);
    }
}

fn find_subseq(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > hay.len() { return None; }
    hay.windows(needle.len()).position(|w| w == needle)
}
