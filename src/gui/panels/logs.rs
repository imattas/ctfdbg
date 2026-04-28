use crate::gui::state::AppState;
use crate::gui::theme::color;
use egui::{RichText, Ui};

pub fn show(ui: &mut Ui, state: &AppState) {
    egui::ScrollArea::vertical().auto_shrink([false; 2]).stick_to_bottom(true).show(ui, |ui| {
        for line in &state.logs {
            let c = match line.level {
                tracing::Level::ERROR => egui::Color32::from_rgb(0xff, 0x6a, 0x6a),
                tracing::Level::WARN  => egui::Color32::from_rgb(0xff, 0xc8, 0x6a),
                tracing::Level::INFO  => color::TEXT,
                _                     => color::MUTED,
            };
            ui.monospace(RichText::new(format!("[{}] {}", line.level, line.text)).color(c));
        }
    });
}
