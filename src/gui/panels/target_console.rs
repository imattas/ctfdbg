use crate::gui::state::AppState;
use crate::gui::theme::color;
use egui::{RichText, Ui};

pub fn show(ui: &mut Ui, state: &mut AppState) {
    egui::ScrollArea::vertical().auto_shrink([false; 2]).show(ui, |ui| {
        for line in &state.target_console {
            ui.monospace(RichText::new(line).color(color::TEXT));
        }
    });
    ui.separator();
    ui.horizontal(|ui| {
        ui.label("stdin:");
        let mut buf = String::new();
        ui.add_enabled(false, egui::TextEdit::singleline(&mut buf).desired_width(f32::INFINITY));
        ui.label(RichText::new("(redirected stdin not yet supported)").color(color::MUTED));
    });
}
