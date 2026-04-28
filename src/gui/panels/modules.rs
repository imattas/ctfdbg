use crate::gui::actions::Action;
use crate::gui::state::AppState;
use crate::gui::theme::color;
use egui::{RichText, Ui};
use egui_extras::{Column, TableBuilder};

pub fn show(ui: &mut Ui, state: &AppState, actions: &mut Vec<Action>) {
    if state.modules.is_empty() {
        ui.label(RichText::new("(no modules loaded)").color(color::MUTED));
        return;
    }
    TableBuilder::new(ui)
        .striped(true)
        .resizable(true)
        .column(Column::auto().at_least(140.0))
        .column(Column::auto().at_least(140.0))
        .column(Column::remainder().at_least(220.0))
        .header(20.0, |mut h| {
            h.col(|ui| { ui.strong("Base"); });
            h.col(|ui| { ui.strong("End"); });
            h.col(|ui| { ui.strong("Name / Path"); });
        })
        .body(|mut body| {
            for m in &state.modules {
                body.row(18.0, |mut row| {
                    row.col(|ui| { ui.monospace(RichText::new(format!("0x{:016x}", m.base)).color(color::ADDRESS)); });
                    row.col(|ui| { ui.monospace(RichText::new(format!("0x{:016x}", m.end())).color(color::ADDRESS)); });
                    row.col(|ui| {
                        let r = ui.monospace(format!("{}  ({})", m.name, m.path));
                        if r.double_clicked() { actions.push(Action::NavigateTo(m.base)); }
                    });
                });
            }
        });
}
