use crate::gui::actions::Action;
use crate::gui::state::AppState;
use crate::gui::theme::color;
use egui::{Context, RichText, Ui};

pub fn activity_bar(ctx: &Context, state: &mut AppState, actions: &mut Vec<Action>) {
    egui::SidePanel::left("activity_bar")
        .resizable(false)
        .min_width(40.0)
        .max_width(40.0)
        .show(ctx, |ui| {
            ui.add_space(8.0);
            ui.vertical_centered(|ui| {
                let bug = ui.add(egui::Button::new("\u{1F41E}").min_size(egui::vec2(28.0, 28.0)))
                    .on_hover_text("Toggle Debugger Sidebar");
                if bug.clicked() { state.debugger_sidebar_open = !state.debugger_sidebar_open; }

                let _ = ui.add(egui::Button::new("\u{1F50D}").min_size(egui::vec2(28.0, 28.0)))
                    .on_hover_text("Search / navigation (placeholder)");
                let _ = ui.add(egui::Button::new("\u{1F4E6}").min_size(egui::vec2(28.0, 28.0)))
                    .on_hover_text("Modules (placeholder)");

                ui.add_space(8.0);
                let _ = ui.add(egui::Button::new("\u{2699}").min_size(egui::vec2(28.0, 28.0)))
                    .on_hover_text("Settings");
                if ui.input(|i| i.key_pressed(egui::Key::S) && i.modifiers.ctrl) {
                    actions.push(Action::AdapterSettingsDialog);
                }
            });
        });
}

pub fn debugger_sidebar(ui: &mut Ui, state: &mut AppState, actions: &mut Vec<Action>) {
    ui.heading("Debugger");
    ui.separator();
    control_buttons(ui, state, actions);
    ui.separator();

    enum Tab { Registers, Breakpoints }
    let id = ui.id().with("dbg_sidebar_tab");
    let mut tab: usize = ui.memory_mut(|m| *m.data.get_temp_mut_or_insert_with(id, || 0usize));
    ui.horizontal(|ui| {
        if ui.selectable_label(tab == 0, "Registers").clicked() { tab = 0; }
        if ui.selectable_label(tab == 1, "Breakpoints").clicked() { tab = 1; }
    });
    ui.memory_mut(|m| m.data.insert_temp(id, tab));
    ui.separator();

    if tab == 0 {
        crate::gui::panels::registers::show(ui, state, actions);
    } else {
        crate::gui::panels::breakpoints::show(ui, state, actions);
    }

    let _ = Tab::Registers; let _ = Tab::Breakpoints;
}

fn control_buttons(ui: &mut Ui, state: &AppState, actions: &mut Vec<Action>) {
    use crate::debugger::state::TargetState as TS;
    let s = state.state;
    let running = matches!(s, TS::Running);
    let stopped = matches!(s, TS::Stopped);
    let started = !matches!(s, TS::NotStarted);
    let exited = matches!(s, TS::Exited);

    ui.horizontal_wrapped(|ui| {
        let _ = small_button(ui, "\u{25B6}", "Launch (F6)", true).clicked()
            .then(|| actions.push(Action::Launch));
        let _ = small_button(ui, "\u{27F3}", "Restart", started || exited).clicked()
            .then(|| actions.push(Action::Restart));
        let _ = small_button(ui, "\u{23F8}", "Pause (F12)", running).clicked()
            .then(|| actions.push(Action::Pause));
        let _ = small_button(ui, "\u{25B6}\u{25B6}", "Resume (F9)", stopped).clicked()
            .then(|| actions.push(Action::Resume));
        let _ = small_button(ui, "\u{2BC8}", "Step Into (F7)", stopped).clicked()
            .then(|| actions.push(Action::StepInto));
        let _ = small_button(ui, "\u{21B7}", "Step Over (F8)", stopped).clicked()
            .then(|| actions.push(Action::StepOver));
        let _ = small_button(ui, "\u{21A9}", "Step Return (Ctrl+F9)", stopped).clicked()
            .then(|| actions.push(Action::StepReturn));
        let _ = small_button(ui, "\u{1F517}", "Attach to Process", true).clicked()
            .then(|| actions.push(Action::AttachDialog));
        let _ = small_button(ui, "\u{2699}", "Settings", true).clicked()
            .then(|| actions.push(Action::AdapterSettingsDialog));
    });

    ui.label(RichText::new(format!("State: {}", s.label())).color(color::MUTED));
    if let Some(pid) = state.pid {
        ui.label(RichText::new(format!("PID: {pid}")).color(color::MUTED));
    }
}

fn small_button(ui: &mut Ui, icon: &str, tooltip: &str, enabled: bool) -> egui::Response {
    let mut r = ui.add_enabled(enabled, egui::Button::new(icon).min_size(egui::vec2(34.0, 28.0)));
    r = r.on_hover_text(tooltip);
    r
}
