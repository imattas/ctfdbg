use crate::gui::actions::Action;
use crate::gui::state::AppState;
use crate::gui::theme::color;
use egui::{Context, RichText};

pub fn menu_bar(ctx: &Context, state: &mut AppState, actions: &mut Vec<Action>) {
    egui::TopBottomPanel::top("menu_bar").show(ctx, |ui| {
        egui::menu::bar(ui, |ui| {
            ui.menu_button("File", |ui| {
                if ui.button("Open binary...").clicked() {
                    actions.push(Action::OpenFileDialog);
                    ui.close_menu();
                }
                ui.separator();
                if ui.button("Quit").clicked() {
                    actions.push(Action::Quit);
                    ui.close_menu();
                }
            });
            ui.menu_button("Debugger", |ui| {
                if ui.button("Toggle Breakpoint  (F2)").clicked() {
                    if let Some(addr) = state.selected_address { actions.push(Action::ToggleBreakpointAt(addr)); }
                    ui.close_menu();
                }
                if ui.button("Pause             (F12)").clicked() { actions.push(Action::Pause); ui.close_menu(); }
                if ui.button("Resume            (F9)").clicked()  { actions.push(Action::Resume); ui.close_menu(); }
                if ui.button("Step Into         (F7)").clicked()  { actions.push(Action::StepInto); ui.close_menu(); }
                if ui.button("Step Over         (F8)").clicked()  { actions.push(Action::StepOver); ui.close_menu(); }
                if ui.button("Step Return  (Ctrl+F9)").clicked()  { actions.push(Action::StepReturn); ui.close_menu(); }
                ui.separator();
                if ui.button("Attach To Process...").clicked() { actions.push(Action::AttachDialog); ui.close_menu(); }
                if ui.button("Detach").clicked() { actions.push(Action::Detach); ui.close_menu(); }
                if ui.button("Kill").clicked() { actions.push(Action::Kill); ui.close_menu(); }
                if ui.button("Launch       (F6)").clicked() { actions.push(Action::Launch); ui.close_menu(); }
                if ui.button("Restart").clicked() { actions.push(Action::Restart); ui.close_menu(); }
                ui.separator();
                if ui.button("Jump to IP").clicked() { actions.push(Action::JumpToIp); ui.close_menu(); }
                if ui.button("Override IP...").clicked() { actions.push(Action::OverrideIpDialog); ui.close_menu(); }
                ui.separator();
                ui.checkbox(&mut state.debugger_sidebar_open, "Show Debugger Sidebar Widgets");
                if ui.button("Debug Adapter Settings...").clicked() { actions.push(Action::AdapterSettingsDialog); ui.close_menu(); }
            });
            ui.menu_button("View", |ui| {
                ui.checkbox(&mut state.debugger_sidebar_open, "Debugger Sidebar");
                ui.checkbox(&mut state.disasm_following_pc, "Follow PC in disassembly");
                ui.separator();
                ui.label("Show panel:");
                for kind in crate::gui::docking::PanelKind::ALL {
                    let already = state.dock.iter_all_tabs().any(|(_, t)| t == kind);
                    let label = if already { format!("\u{2713} {}", kind.title()) }
                                else { format!("    {}", kind.title()) };
                    if ui.button(label).clicked() {
                        crate::gui::docking::ensure_panel_visible(&mut state.dock, *kind);
                        ui.close_menu();
                    }
                }
                ui.separator();
                if ui.button("Reset layout to default").clicked() {
                    state.dock = crate::gui::docking::default_layout();
                    ui.close_menu();
                }
            });
            ui.menu_button("Plugins", |ui| { ui.label(RichText::new("(no plugins loaded)").color(color::MUTED)); });
            ui.menu_button("Window", |ui| {
                ui.label(RichText::new("Drag any panel tab to rearrange.").color(color::MUTED));
                ui.separator();
                if ui.button("Reset layout to default").clicked() {
                    state.dock = crate::gui::docking::default_layout();
                    ui.close_menu();
                }
            });
            ui.menu_button("Help", |ui| {
                ui.label("ctfdbg");
                ui.label("Windows-first graphical debugger for legal CTF / RE / authorized exploit-dev.");
                ui.separator();
                ui.label("Hotkeys: F2/F5/F6/F7/F8/F9/F12, Ctrl+F9");
            });
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                ui.label(RichText::new(state.last_event_label.clone()).color(color::MUTED));
            });
        });
    });

    // Hotkeys
    let i = ctx.input(|i| i.clone());
    if i.key_pressed(egui::Key::F2) {
        if let Some(addr) = state.selected_address { actions.push(Action::ToggleBreakpointAt(addr)); }
    }
    if i.key_pressed(egui::Key::F5) || i.key_pressed(egui::Key::F9) { actions.push(Action::Resume); }
    if i.key_pressed(egui::Key::F6) { actions.push(Action::Launch); }
    if i.key_pressed(egui::Key::F7) { actions.push(Action::StepInto); }
    if i.key_pressed(egui::Key::F8) { actions.push(Action::StepOver); }
    if i.key_pressed(egui::Key::F12) { actions.push(Action::Pause); }
    if i.modifiers.ctrl && i.key_pressed(egui::Key::F9) { actions.push(Action::StepReturn); }
}

pub fn top_toolbar(ctx: &Context, state: &mut AppState, actions: &mut Vec<Action>) {
    egui::TopBottomPanel::top("top_toolbar").show(ctx, |ui| {
        ui.horizontal(|ui| {
            if ui.button("\u{25B6} Launch").on_hover_text("Launch (F6)").clicked() { actions.push(Action::Launch); }
            if ui.button("\u{27F3} Restart").on_hover_text("Restart").clicked() { actions.push(Action::Restart); }
            if ui.button("\u{23F8} Pause").on_hover_text("Pause (F12)").clicked() { actions.push(Action::Pause); }
            if ui.button("\u{25B6}\u{25B6} Resume").on_hover_text("Resume (F9)").clicked() { actions.push(Action::Resume); }
            ui.separator();
            if ui.button("Step Into").on_hover_text("F7").clicked() { actions.push(Action::StepInto); }
            if ui.button("Step Over").on_hover_text("F8").clicked() { actions.push(Action::StepOver); }
            if ui.button("Step Return").on_hover_text("Ctrl+F9").clicked() { actions.push(Action::StepReturn); }
            ui.separator();
            if ui.button("Attach...").clicked() { actions.push(Action::AttachDialog); }
            if ui.button("Settings").clicked() { actions.push(Action::AdapterSettingsDialog); }
            ui.separator();
            ui.label(RichText::new(format!("State: {}", state.state.label())).color(color::MUTED));
            if let Some(pid) = state.pid {
                ui.label(RichText::new(format!("PID {pid}")).color(color::MUTED));
            }
        });
    });
}
