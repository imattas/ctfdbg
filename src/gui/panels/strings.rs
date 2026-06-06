//! Strings panel: printable strings discovered during Auto Analysis.

use egui::{RichText, Sense, Ui};

use crate::gui::actions::Action;
use crate::gui::state::AppState;
use crate::gui::theme::color;

pub fn show(ui: &mut Ui, state: &mut AppState, actions: &mut Vec<Action>) {
    ui.horizontal(|ui| {
        ui.label("Filter:");
        ui.text_edit_singleline(&mut state.strings_search);
        if ui.button("Re-scan").clicked() {
            state.rerun_auto_analysis();
        }
    });
    ui.separator();

    let Some(analysis) = state.auto_analysis.as_ref() else {
        ui.label(RichText::new("Load a binary to populate.").color(color::MUTED));
        return;
    };
    let needle = state.strings_search.to_ascii_lowercase();

    egui::ScrollArea::vertical().auto_shrink([false; 2]).show(ui, |ui| {
        use egui_extras::{Column, TableBuilder};
        TableBuilder::new(ui)
            .striped(true)
            .sense(Sense::click())
            .column(Column::auto().at_least(140.0))
            .column(Column::auto().at_least(40.0))
            .column(Column::remainder())
            .header(20.0, |mut h| {
                h.col(|ui| { ui.strong("Address"); });
                h.col(|ui| { ui.strong("Type");    });
                h.col(|ui| { ui.strong("Value");   });
            })
            .body(|mut body| {
                for s in &analysis.strings {
                    let text = s.as_string_lossy();
                    if !needle.is_empty() && !text.to_ascii_lowercase().contains(&needle) { continue; }
                    body.row(18.0, |mut row| {
                        row.col(|ui| { ui.monospace(RichText::new(format!("{:#018x}", s.address)).color(color::ADDRESS)); });
                        row.col(|ui| { ui.label(if s.utf16 { "wide" } else { "ascii" }); });
                        row.col(|ui| { ui.monospace(text); });
                        let r = row.response();
                        if r.clicked() { actions.push(Action::NavigateTo(s.address)); }
                    });
                }
            });
    });
}
