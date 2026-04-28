use crate::gui::actions::Action;
use crate::gui::state::{AppState, DebugCommand};
use egui::Context;

pub fn show(ctx: &Context, state: &mut AppState, _actions: &mut Vec<Action>) {
    let Some(bp_id) = state.show_edit_condition_for else { return; };
    let mut open = true;
    let id = egui::Id::new(("editcond", bp_id));
    let mut text: String = ctx.data_mut(|d| d.get_temp::<String>(id).unwrap_or_else(|| {
        state.breakpoints.iter().find(|b| b.id.0 == bp_id)
            .and_then(|b| b.condition.clone()).unwrap_or_default()
    }));
    let mut commit = false;
    let mut clear = false;

    egui::Window::new(format!("Edit Condition (bp #{bp_id})")).open(&mut open).show(ctx, |ui| {
        ui.label("Examples:");
        ui.monospace("  rax == 0");
        ui.monospace("  rcx & 0xff == 0x41");
        ui.monospace("  rip == 0x401234");
        ui.separator();
        ui.add(egui::TextEdit::multiline(&mut text).desired_rows(3).desired_width(380.0));
        ui.separator();
        ui.horizontal(|ui| {
            if ui.button("Cancel").clicked() { state.show_edit_condition_for = None; }
            if ui.button("Clear").clicked() { clear = true; }
            if ui.button("Apply").clicked() { commit = true; }
        });
    });
    ctx.data_mut(|d| d.insert_temp(id, text.clone()));

    if !open { state.show_edit_condition_for = None; }
    if clear {
        state.send(DebugCommand::SetCondition(bp_id, None));
        state.show_edit_condition_for = None;
    }
    if commit {
        let cond = if text.trim().is_empty() { None } else { Some(text.trim().to_string()) };
        state.send(DebugCommand::SetCondition(bp_id, cond));
        state.show_edit_condition_for = None;
    }
}
