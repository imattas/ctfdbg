use crate::gui::actions::Action;
use crate::gui::state::{AppState, DebugCommand};
use crate::gui::widgets::address::parse_hex;
use egui::Context;

pub fn show(ctx: &Context, state: &mut AppState, _actions: &mut Vec<Action>) {
    if !state.show_override_ip { return; }
    let mut open = true;
    let id = egui::Id::new("override_ip_buf");
    let mut text: String = ctx.data_mut(|d| d.get_temp::<String>(id)
        .unwrap_or_else(|| state.registers.pc().map(|v| format!("0x{v:x}")).unwrap_or_default()));
    let mut relative = ctx.data_mut(|d| d.get_temp::<bool>(egui::Id::new("override_ip_rel")).unwrap_or(false));
    let mut accept = false;

    egui::Window::new("Override IP").open(&mut open).show(ctx, |ui| {
        ui.horizontal(|ui| {
            ui.label("New IP:");
            ui.add(egui::TextEdit::singleline(&mut text).desired_width(220.0));
        });
        ui.checkbox(&mut relative, "Relative to current IP");
        ui.separator();
        ui.horizontal(|ui| {
            if ui.button("Close").clicked() { state.show_override_ip = false; }
            if ui.button("Accept").clicked() { accept = true; }
        });
    });
    ctx.data_mut(|d| { d.insert_temp(id, text.clone()); d.insert_temp(egui::Id::new("override_ip_rel"), relative); });

    if !open { state.show_override_ip = false; }
    if accept {
        if let Some(mut v) = parse_hex(&text).or_else(|| text.parse::<u64>().ok()) {
            if relative { v = state.registers.pc().unwrap_or(0).wrapping_add(v); }
            state.send(DebugCommand::SetIp(v));
        }
        state.show_override_ip = false;
    }
}
