use crate::gui::actions::Action;
use crate::gui::state::{AppState, DebugCommand};
use crate::gui::theme::color;
use egui::{Context, RichText, Sense};

pub fn show(ctx: &Context, state: &mut AppState, _actions: &mut Vec<Action>) {
    if !state.show_attach_dialog { return; }
    let mut open = true;
    let mut chosen: Option<u32> = None;
    egui::Window::new("Attach to Process")
        .open(&mut open)
        .default_width(560.0)
        .show(ctx, |ui| {
            ui.horizontal(|ui| {
                if ui.button("Refresh").clicked() {
                    state.processes_cache = list_processes();
                }
                ui.label("Search:");
                ui.text_edit_singleline(&mut state.processes_search);
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.label(RichText::new(format!("{} processes", state.processes_cache.len())).color(color::MUTED));
                });
            });
            if state.processes_cache.is_empty() {
                state.processes_cache = list_processes();
            }
            let needle = state.processes_search.to_ascii_lowercase();
            ui.separator();
            egui::ScrollArea::vertical().max_height(360.0).show(ui, |ui| {
                use egui_extras::{Column, TableBuilder};
                TableBuilder::new(ui)
                    .striped(true)
                    .sense(Sense::click())
                    .column(Column::auto().at_least(80.0))
                    .column(Column::remainder().at_least(280.0))
                    .header(20.0, |mut h| {
                        h.col(|ui| { ui.strong("PID"); });
                        h.col(|ui| { ui.strong("Name"); });
                    })
                    .body(|mut body| {
                        for (pid, name) in &state.processes_cache {
                            if !needle.is_empty()
                                && !name.to_ascii_lowercase().contains(&needle)
                                && !pid.to_string().contains(&needle)
                            { continue; }
                            let selected = state.selected_pid == Some(*pid);
                            body.row(18.0, |mut row| {
                                row.set_selected(selected);
                                row.col(|ui| {
                                    ui.monospace(RichText::new(pid.to_string()).color(color::ADDRESS));
                                });
                                row.col(|ui| {
                                    ui.monospace(name);
                                });
                                let resp = row.response();
                                if resp.clicked() {
                                    state.selected_pid = Some(*pid);
                                }
                                if resp.double_clicked() {
                                    chosen = Some(*pid);
                                }
                            });
                        }
                    });
            });
            ui.separator();
            ui.horizontal(|ui| {
                let can_attach = state.selected_pid.is_some();
                if ui.add_enabled(can_attach, egui::Button::new(
                    RichText::new("Attach").strong().color(color::ACCENT))
                ).clicked() {
                    if let Some(pid) = state.selected_pid { chosen = Some(pid); }
                }
                if let Some(pid) = state.selected_pid {
                    ui.label(RichText::new(format!("selected pid {pid}")).color(color::MUTED));
                }
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.button("Cancel").clicked() { state.show_attach_dialog = false; }
                });
            });
            ui.label(RichText::new(
                "Tip: double-click a row to attach. On Windows, attaching to processes \
                 owned by another user (or with higher integrity) requires running ctfdbg as Administrator \
                 and may need SeDebugPrivilege."
            ).color(color::MUTED).small());
        });
    if !open { state.show_attach_dialog = false; }
    if let Some(pid) = chosen {
        state.send(DebugCommand::Attach(pid));
        state.show_attach_dialog = false;
        state.status_message = format!("Attaching to pid {pid}\u{2026}");
    }
}

fn list_processes() -> Vec<(u32, String)> {
    #[cfg(windows)]
    {
        if let Ok(v) = crate::debugger::windows::process::list_system_processes() {
            let mut out: Vec<(u32, String)> = v.into_iter().map(|p| (p.pid, p.name)).collect();
            out.sort_by(|a, b| a.1.to_ascii_lowercase().cmp(&b.1.to_ascii_lowercase()));
            return out;
        }
    }
    use sysinfo::System;
    let mut sys = System::new();
    sys.refresh_processes(sysinfo::ProcessesToUpdate::All, true);
    let mut out: Vec<(u32, String)> = sys.processes().iter()
        .map(|(pid, p)| (pid.as_u32(), p.name().to_string_lossy().into_owned()))
        .collect();
    out.sort_by(|a, b| a.1.to_ascii_lowercase().cmp(&b.1.to_ascii_lowercase()));
    out
}
