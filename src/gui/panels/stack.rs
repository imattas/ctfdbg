use crate::gui::actions::Action;
use crate::gui::state::AppState;
use crate::gui::theme::color;
use crate::gui::widgets::hex_view::hex_view;
use egui::{RichText, Ui};

pub fn show(ui: &mut Ui, state: &mut AppState, _actions: &mut Vec<Action>) {
    if let Some(sp) = state.registers.sp() {
        ui.label(RichText::new(format!("SP = 0x{sp:x}")).color(color::ADDRESS));
    } else {
        ui.label(RichText::new("(no stack pointer; not stopped)").color(color::MUTED));
    }
    ui.separator();
    if state.stack_bytes.is_empty() {
        ui.label(RichText::new("(stack bytes will appear after a stop)").color(color::MUTED));
    } else {
        hex_view(ui, state.stack_base, &state.stack_bytes);
    }
}
