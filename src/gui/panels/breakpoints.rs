use crate::gui::actions::Action;
use crate::gui::state::{AppState, DebugCommand};
use crate::gui::theme::color;
use egui::{RichText, Ui};
use egui_extras::{Column, TableBuilder};

pub fn show(ui: &mut Ui, state: &mut AppState, actions: &mut Vec<Action>) {
    ui.horizontal(|ui| {
        if ui.button("Add Breakpoint...").clicked() { actions.push(Action::AddBreakpointDialog); }
        if ui.button("Add Hardware...").clicked() { actions.push(Action::HardwareBreakpointDialog); }
        if ui.button("Enable All").clicked() {
            for b in &state.breakpoints { state.send(DebugCommand::EnableBreakpoint(b.id.0, true)); }
        }
        if ui.button("Disable All").clicked() {
            for b in &state.breakpoints { state.send(DebugCommand::EnableBreakpoint(b.id.0, false)); }
        }
    });

    let bps = state.breakpoints.clone();
    TableBuilder::new(ui)
        .striped(true)
        .resizable(true)
        .column(Column::auto().at_least(20.0))
        .column(Column::auto().at_least(120.0))
        .column(Column::auto().at_least(140.0))
        .column(Column::remainder().at_least(120.0))
        .column(Column::auto().at_least(40.0))
        .header(20.0, |mut h| {
            h.col(|ui| { ui.strong("E"); });
            h.col(|ui| { ui.strong("Location"); });
            h.col(|ui| { ui.strong("Remote Address"); });
            h.col(|ui| { ui.strong("Condition"); });
            h.col(|ui| { ui.strong("Type"); });
        })
        .body(|mut body| {
            for bp in &bps {
                body.row(20.0, |mut row| {
                    row.col(|ui| {
                        let mut e = bp.enabled;
                        if ui.checkbox(&mut e, "").changed() {
                            state.send(DebugCommand::EnableBreakpoint(bp.id.0, e));
                        }
                    });
                    row.col(|ui| {
                        let r = ui.monospace(bp.location_label.clone());
                        if r.double_clicked() { actions.push(Action::NavigateTo(bp.address)); }
                        r.context_menu(|ui| context_menu(ui, bp.id.0, bp.address, state, actions));
                    });
                    row.col(|ui| {
                        let r = ui.monospace(RichText::new(format!("0x{:016x}", bp.address)).color(color::ADDRESS));
                        if r.double_clicked() { actions.push(Action::NavigateTo(bp.address)); }
                    });
                    row.col(|ui| {
                        ui.monospace(bp.condition.clone().unwrap_or_default());
                    });
                    row.col(|ui| {
                        ui.monospace(bp.kind.short_tag());
                    });
                });
            }
            if bps.is_empty() {
                body.row(20.0, |mut row| {
                    row.col(|ui| { ui.label(""); });
                    row.col(|ui| { ui.label(RichText::new("(no breakpoints)").color(color::MUTED)); });
                    row.col(|_| {}); row.col(|_| {}); row.col(|_| {});
                });
            }
        });
}

fn context_menu(ui: &mut Ui, id: u64, addr: u64, state: &AppState, actions: &mut Vec<Action>) {
    if ui.button("Jump to Breakpoint").clicked() { actions.push(Action::NavigateTo(addr)); ui.close_menu(); }
    if ui.button("Remove Breakpoint").clicked() { state.send(DebugCommand::RemoveBreakpoint(id)); ui.close_menu(); }
    if ui.button("Add Breakpoint...").clicked() { actions.push(Action::AddBreakpointDialog); ui.close_menu(); }
    if ui.button("Add Hardware Breakpoint...").clicked() { actions.push(Action::HardwareBreakpointDialog); ui.close_menu(); }
    if ui.button("Toggle Enabled").clicked() {
        let cur = state.breakpoints.iter().find(|b| b.id.0 == id).map(|b| b.enabled).unwrap_or(true);
        state.send(DebugCommand::EnableBreakpoint(id, !cur)); ui.close_menu();
    }
    if ui.button("Edit Condition...").clicked() { actions.push(Action::EditConditionDialog(id)); ui.close_menu(); }
    if ui.button("Enable All Breakpoints").clicked() {
        for b in &state.breakpoints { state.send(DebugCommand::EnableBreakpoint(b.id.0, true)); }
        ui.close_menu();
    }
    if ui.button("Disable All Breakpoints").clicked() {
        for b in &state.breakpoints { state.send(DebugCommand::EnableBreakpoint(b.id.0, false)); }
        ui.close_menu();
    }
    if ui.button("Solo Breakpoint").clicked() {
        for b in &state.breakpoints {
            state.send(DebugCommand::EnableBreakpoint(b.id.0, b.id.0 == id));
        }
        ui.close_menu();
    }
}
