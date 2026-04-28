use crate::gui::state::AppState;
use crate::gui::theme::color;
use egui::{Context, RichText};

pub fn show(ctx: &Context, state: &AppState) {
    egui::TopBottomPanel::bottom("status_bar").show(ctx, |ui| {
        ui.horizontal(|ui| {
            ui.label(RichText::new(state.state.label()).color(color::ADDRESS).strong());
            ui.separator();
            if !state.last_event_label.is_empty() {
                ui.label(RichText::new(state.last_event_label.clone()).color(color::MUTED));
                ui.separator();
            }
            if let Some(pid) = state.pid { ui.label(format!("PID {pid}")); ui.separator(); }
            if let Some(tid) = state.active_thread { ui.label(format!("TID {tid}")); ui.separator(); }
            if let Some(b) = &state.binary {
                ui.label(format!("Arch {}", b.architecture));
                ui.separator();
                ui.label(format!("Format {}", b.format));
                ui.separator();
                if !b.sections.is_empty() {
                    let lo = b.sections.iter().map(|s| s.virtual_address).min().unwrap_or(0);
                    let hi = b.sections.iter().map(|s| s.virtual_address + s.virtual_size).max().unwrap_or(0);
                    ui.label(format!("Image 0x{lo:x}..0x{hi:x}"));
                    ui.separator();
                }
            }
            if let Some(addr) = state.selected_address {
                ui.label(RichText::new(format!("@ 0x{addr:x}")).color(color::ADDRESS));
                ui.separator();
            }
            if let Some(err) = &state.last_error {
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.label(RichText::new(format!("Error: {err}")).color(egui::Color32::from_rgb(0xff, 0x6a, 0x6a)));
                });
            } else {
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.label(RichText::new(state.status_message.clone()).color(color::MUTED));
                });
            }
        });
    });
}
