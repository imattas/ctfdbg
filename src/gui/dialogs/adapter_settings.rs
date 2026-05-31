use crate::gui::actions::Action;
use crate::gui::state::{AppState, DebugCommand};
use egui::Context;
use std::path::PathBuf;

pub fn show(ctx: &Context, state: &mut AppState, _actions: &mut Vec<Action>) {
    if !state.show_adapter_settings { return; }
    let mut open = true;
    let mut do_save = false;
    let mut do_save_and_launch = false;

    egui::Window::new("Debug Adapter Settings")
        .open(&mut open)
        .default_width(560.0)
        .show(ctx, |ui| {
            egui::Grid::new("adapter_grid").num_columns(2).spacing([8.0, 6.0]).show(ui, |ui| {
                ui.label("Adapter:");
                let cur = match state.cfg.backend {
                    crate::config::BackendKind::WindowsDebugApi => "Windows Debug API",
                    crate::config::BackendKind::LinuxPtrace => "Linux ptrace",
                    crate::config::BackendKind::Auto => "Auto",
                };
                egui::ComboBox::from_id_salt("adapter_kind").selected_text(cur).show_ui(ui, |ui| {
                    use crate::config::BackendKind::*;
                    ui.selectable_value(&mut state.cfg.backend, Auto, "Auto");
                    ui.selectable_value(&mut state.cfg.backend, WindowsDebugApi, "Windows Debug API");
                    ui.selectable_value(&mut state.cfg.backend, LinuxPtrace, "Linux ptrace");
                });
                ui.end_row();

                ui.label("Executable:");
                let mut path = state.adapter_target.executable
                    .as_ref().map(|p| p.display().to_string()).unwrap_or_default();
                ui.horizontal(|ui| {
                    let resp = ui.add(egui::TextEdit::singleline(&mut path).desired_width(360.0));
                    if resp.changed() {
                        state.adapter_target.executable = if path.is_empty() { None } else { Some(PathBuf::from(&path)) };
                    }
                    if ui.button("Browse...").clicked() {
                        if let Some(p) = pick_executable() {
                            state.adapter_target.executable = Some(p);
                        }
                    }
                });
                ui.end_row();

                ui.label("Arguments:");
                ui.text_edit_singleline(&mut state.adapter_target.arguments);
                ui.end_row();

                ui.label("Working dir:");
                let mut wd = state.adapter_target.working_directory
                    .as_ref().map(|p| p.display().to_string()).unwrap_or_default();
                if ui.text_edit_singleline(&mut wd).changed() {
                    state.adapter_target.working_directory = if wd.is_empty() { None } else { Some(PathBuf::from(wd)) };
                }
                ui.end_row();

                ui.label("Environment:");
                ui.label("(extra env vars not yet wired)");
                ui.end_row();

                ui.label("External terminal:");
                ui.checkbox(&mut state.adapter_target.launch_in_external_terminal, "");
                ui.end_row();

                ui.label("Break on entry:");
                ui.checkbox(&mut state.adapter_target.break_on_entry, "");
                ui.end_row();

                ui.label("Break on TLS callback:");
                ui.checkbox(&mut state.adapter_target.break_on_tls_callbacks, "");
                ui.end_row();
            });
            ui.separator();
            ui.horizontal(|ui| {
                if ui.button("Save").clicked() { do_save = true; }
                if ui.button("Save and Launch").clicked() { do_save_and_launch = true; }
                if ui.button("Cancel").clicked() { state.show_adapter_settings = false; }
            });
        });

    if !open { state.show_adapter_settings = false; }
    if do_save { state.show_adapter_settings = false; }
    if do_save_and_launch {
        state.show_adapter_settings = false;
        state.cfg.target = state.adapter_target.executable.clone();
        state.cfg.break_entry = state.adapter_target.break_on_entry;
        state.send(DebugCommand::Launch(state.adapter_target.clone()));
    }
}

#[cfg(target_os = "windows")]
fn pick_executable() -> Option<PathBuf> {
    rfd::FileDialog::new()
        .add_filter("Executables", &["exe", "dll", "sys"])
        .add_filter("All files", &["*"])
        .pick_file()
}
#[cfg(not(target_os = "windows"))]
fn pick_executable() -> Option<PathBuf> {
    rfd::FileDialog::new().pick_file()
}
