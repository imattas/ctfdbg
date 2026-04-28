use crate::gui::actions::Action;
use crate::gui::state::{AppState, DebugCommand};
use crate::gui::widgets::address::parse_hex;
use egui::Context;

pub fn show(ctx: &Context, state: &mut AppState, _actions: &mut Vec<Action>) {
    if !state.show_add_breakpoint { return; }
    let mut open = true;
    let id_addr = egui::Id::new("addbp_addr");
    let id_cond = egui::Id::new("addbp_cond");
    let id_en = egui::Id::new("addbp_en");
    let mut addr: String = ctx.data_mut(|d| d.get_temp::<String>(id_addr).unwrap_or_default());
    let mut cond: String = ctx.data_mut(|d| d.get_temp::<String>(id_cond).unwrap_or_default());
    let mut enabled: bool = ctx.data_mut(|d| d.get_temp::<bool>(id_en).unwrap_or(true));
    let mut commit = false;

    egui::Window::new("Add Breakpoint").open(&mut open).show(ctx, |ui| {
        egui::Grid::new("addbp_g").num_columns(2).show(ui, |ui| {
            ui.label("Address:");
            ui.add(egui::TextEdit::singleline(&mut addr).desired_width(240.0).hint_text("0x401000"));
            ui.end_row();
            ui.label("Condition:");
            ui.add(egui::TextEdit::singleline(&mut cond).desired_width(240.0).hint_text("(optional, e.g. rax == 0)"));
            ui.end_row();
            ui.label("Enabled:");
            ui.checkbox(&mut enabled, "");
            ui.end_row();
        });
        ui.separator();
        ui.horizontal(|ui| {
            if ui.button("Cancel").clicked() { state.show_add_breakpoint = false; }
            if ui.button("Add").clicked() { commit = true; }
        });
    });
    ctx.data_mut(|d| {
        d.insert_temp(id_addr, addr.clone());
        d.insert_temp(id_cond, cond.clone());
        d.insert_temp(id_en, enabled);
    });

    if !open { state.show_add_breakpoint = false; }
    if commit {
        if let Some(a) = parse_hex(&addr) {
            state.send(DebugCommand::SetBreakpoint(a));
            // We don't yet know the assigned BreakpointId; condition+enabled are
            // applied opportunistically once the backend echoes the new BP list.
            if !cond.trim().is_empty() {
                state.console_output.push(format!("[i] add breakpoint @ 0x{a:x}; condition will be applied via console"));
            }
            if !enabled {
                state.console_output.push("[i] note: created enabled; toggle off in Breakpoints panel".into());
            }
            state.show_add_breakpoint = false;
        } else {
            state.console_output.push("[!] invalid address".into());
        }
    }
}
