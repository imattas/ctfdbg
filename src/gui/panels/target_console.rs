use crate::gui::state::{AppState, DebugCommand};
use crate::gui::theme::color;
use egui::{RichText, Ui};

pub fn show(ui: &mut Ui, state: &mut AppState) {
    egui::ScrollArea::vertical()
        .auto_shrink([false; 2])
        .stick_to_bottom(true)
        .max_height(ui.available_height() - 30.0)
        .show(ui, |ui| {
            if state.target_console.is_empty() {
                ui.label(RichText::new("(target stdout/stderr appears here while the target runs)").color(color::MUTED));
            }
            for line in &state.target_console {
                ui.monospace(RichText::new(line).color(color::TEXT));
            }
        });
    ui.separator();
    ui.horizontal(|ui| {
        ui.label("stdin:");
        let resp = ui.add(
            egui::TextEdit::singleline(&mut state.target_stdin_input)
                .desired_width(f32::INFINITY)
                .hint_text("type input, press Enter to send to the target"),
        );
        if resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
            let mut line = std::mem::take(&mut state.target_stdin_input);
            line.push('\n');
            // Echo locally so the user sees what they sent.
            state.target_console.push(format!("> {}", line.trim_end()));
            state.target_console_open_line = false;
            state.send(DebugCommand::SendStdin(line.into_bytes()));
            resp.request_focus();
        }
    });
}
