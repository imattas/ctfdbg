use crate::gui::actions::Action;
use crate::gui::state::AppState;
use crate::gui::theme::color;
use egui::{RichText, Ui};

pub fn show(ui: &mut Ui, state: &AppState, actions: &mut Vec<Action>) {
    if state.stack_trace.is_empty() {
        ui.label(RichText::new("(no stack trace; not stopped)").color(color::MUTED));
        return;
    }
    for (i, frame) in state.stack_trace.iter().enumerate() {
        let r = ui.horizontal(|ui| {
            ui.monospace(format!("#{i:<2}"));
            ui.monospace(RichText::new(format!("0x{:016x}", frame.pc)).color(color::ADDRESS));
            ui.monospace(format!("sp=0x{:x}", frame.sp));
            if let Some(s) = &frame.function { ui.monospace(RichText::new(s).color(color::HINT)); }
            if let Some(m) = &frame.module { ui.monospace(RichText::new(format!("[{m}]")).color(color::MUTED)); }
        }).response;
        if r.double_clicked() { actions.push(Action::NavigateTo(frame.pc)); }
    }
}
