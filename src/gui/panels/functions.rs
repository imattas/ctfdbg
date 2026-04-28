//! Functions panel: list of functions discovered by Auto Analysis.

use egui::{RichText, Sense, Ui};

use crate::gui::actions::Action;
use crate::gui::state::AppState;
use crate::gui::theme::color;

pub fn show(ui: &mut Ui, state: &mut AppState, actions: &mut Vec<Action>) {
    ui.horizontal(|ui| {
        ui.heading("Functions");
        ui.separator();
        if ui.button("Re-analyze").clicked() {
            state.rerun_auto_analysis();
        }
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            let n = state.auto_analysis.as_ref().map(|a| a.functions.len()).unwrap_or(0);
            ui.label(RichText::new(format!("{n} candidate(s)")).color(color::MUTED));
        });
    });
    ui.separator();

    let Some(analysis) = state.auto_analysis.as_ref() else {
        ui.label(RichText::new("Load a binary to populate.").color(color::MUTED));
        return;
    };
    if analysis.functions.is_empty() {
        ui.label(RichText::new("No functions discovered.").color(color::MUTED));
        return;
    }

    egui::ScrollArea::vertical().auto_shrink([false; 2]).show(ui, |ui| {
        use egui_extras::{Column, TableBuilder};
        TableBuilder::new(ui)
            .striped(true)
            .sense(Sense::click())
            .column(Column::auto().at_least(120.0))
            .column(Column::auto().at_least(80.0))
            .column(Column::remainder())
            .header(20.0, |mut h| {
                h.col(|ui| { ui.strong("Address"); });
                h.col(|ui| { ui.strong("Source");  });
                h.col(|ui| { ui.strong("Name");    });
            })
            .body(|mut body| {
                for f in &analysis.functions {
                    body.row(18.0, |mut row| {
                        row.col(|ui| { ui.monospace(RichText::new(format!("{:#018x}", f.address)).color(color::ADDRESS)); });
                        row.col(|ui| { ui.label(format!("{:?}", f.source)); });
                        row.col(|ui| { ui.monospace(&f.name); });
                        let r = row.response();
                        if r.clicked() { actions.push(Action::NavigateTo(f.address)); }
                        if r.double_clicked() { actions.push(Action::RunToAddress(f.address)); }
                    });
                }
            });
    });
}
