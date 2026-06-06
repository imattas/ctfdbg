use crate::gui::actions::Action;
use crate::gui::state::{AppState, DebugCommand};
use crate::gui::theme::color;
use crate::gui::widgets::address::parse_hex;
use egui::{RichText, Ui};
use egui_extras::{Column, TableBuilder};

pub fn show(ui: &mut Ui, state: &mut AppState, _actions: &mut Vec<Action>) {
    ui.horizontal(|ui| {
        ui.label("Search registers:");
        ui.text_edit_singleline(&mut state.register_search);
        ui.checkbox(&mut state.hide_zero_registers, "Hide unused");
    });

    let arch = state.registers.architecture;
    let metas = arch.registers();
    let prev = state.previous_registers.clone();
    let edited = state.edited_registers.clone();
    let filter = state.register_search.to_ascii_lowercase();

    let mut to_send: Option<(String, u64)> = None;

    TableBuilder::new(ui)
        .striped(true)
        .resizable(true)
        .column(Column::auto().at_least(60.0))
        .column(Column::remainder().at_least(160.0))
        .column(Column::remainder().at_least(120.0))
        .header(20.0, |mut h| {
            h.col(|ui| { ui.strong("Name"); });
            h.col(|ui| { ui.strong("Value"); });
            h.col(|ui| { ui.strong("Hint"); });
        })
        .body(|mut body| {
            for m in metas {
                let name = m.name;
                let val = state.registers.get(name).unwrap_or(0);
                if state.hide_zero_registers && val == 0 && filter.is_empty() { continue; }
                if !filter.is_empty() && !name.to_ascii_lowercase().contains(&filter) { continue; }
                let changed = prev.get(name).copied().unwrap_or(val) != val;
                let was_edited = edited.get(name).copied().unwrap_or(0) != 0;

                body.row(18.0, |mut row| {
                    row.col(|ui| {
                        ui.monospace(RichText::new(name).color(color::ADDRESS));
                    });
                    row.col(|ui| {
                        let mut buf = format!("0x{val:016x}");
                        let id = ui.id().with(("regval", name));
                        let resp = ui.add(egui::TextEdit::singleline(&mut buf)
                            .id(id)
                            .desired_width(180.0)
                            .text_color(if was_edited { color::REG_EDITED }
                                else if changed { color::REG_CHANGED }
                                else { color::TEXT })
                            .font(egui::TextStyle::Monospace));
                        if resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                            if let Some(v) = parse_hex(&buf) {
                                to_send = Some((name.to_string(), v));
                            }
                        }
                        resp.context_menu(|ui| {
                            ui.checkbox(&mut state.hide_zero_registers, "Hide Unused Registers");
                            if ui.button("Copy Register").clicked() {
                                ui.output_mut(|o| o.copied_text = name.to_string()); ui.close_menu();
                            }
                            if ui.button("Copy Value").clicked() {
                                ui.output_mut(|o| o.copied_text = format!("0x{val:x}")); ui.close_menu();
                            }
                        });
                    });
                    row.col(|ui| {
                        ui.monospace(RichText::new(short_hint(val, state)).color(color::HINT));
                    });
                });
            }
        });

    if let Some((name, value)) = to_send {
        state.edited_registers.insert(name.clone(), value);
        state.send(DebugCommand::WriteRegister(name, value));
    }
}

fn short_hint(value: u64, state: &AppState) -> String {
    if value == 0 { return String::new(); }
    if let Some(m) = state.modules.iter().find(|m| m.contains(value)) {
        return format!("{}+0x{:x}", m.name, value - m.base);
    }
    if let Some(b) = &state.binary {
        if let Some(s) = b.section_containing(value) {
            return format!("{}+0x{:x}", s.name, value - s.virtual_address);
        }
    }
    String::new()
}
