//! Plugins panel: list and run all built-in / loaded plugins.

use egui::{RichText, Ui};

use crate::gui::actions::Action;
use crate::gui::state::AppState;
use crate::gui::theme::color;
use crate::plugins::PluginCategory;

pub fn show(ui: &mut Ui, state: &mut AppState, actions: &mut Vec<Action>) {
    ui.horizontal(|ui| {
        ui.heading("Plugins");
        ui.separator();
        ui.label(RichText::new(
            "Built-in commands. Each plugin runs against the current debugger state."
        ).color(color::MUTED).small());
    });
    ui.separator();

    // Collect ahead of time so we don't hold an immutable borrow of `state`
    // while later mutating `state.console_output` in the click handler.
    let metas = state.plugins.list();

    for &cat in PluginCategory::ALL {
        let group: Vec<_> = metas.iter().filter(|m| m.category == cat).cloned().collect();
        if group.is_empty() { continue; }
        ui.collapsing(RichText::new(cat.label()).strong(), |ui| {
            for m in group {
                ui.horizontal(|ui| {
                    ui.monospace(RichText::new(m.id).color(color::ACCENT));
                    if ui.button("Run").clicked() {
                        run_plugin(state, m.id, None, actions);
                    }
                    ui.label(m.name);
                });
                ui.label(RichText::new(m.description).color(color::MUTED).small());
                ui.add_space(4.0);
            }
        });
    }
    ui.separator();
    ui.label(RichText::new(
        "Tip: from the Debugger Console you can also run any plugin by typing its id, \
         e.g.  `cyclic 200`  or  `disasm 0x401000 32`."
    ).color(color::MUTED).small());
}

fn run_plugin(state: &mut AppState, id: &'static str, arg: Option<&str>, actions: &mut Vec<Action>) {
    // The plugin needs &AppState, but we hold &mut. Take the registry out
    // temporarily so the immutable read of `state` doesn't alias `state.plugins`.
    let registry = std::mem::take(&mut state.plugins);
    let output = registry.get(id).map(|p| p.run(state, arg));
    state.plugins = registry;
    match output {
        Some(out) => {
            for line in out.lines {
                state.console_output.push(format!("[{id}] {line}"));
            }
            actions.extend(out.actions);
        }
        None => state.console_output.push(format!("[!] unknown plugin: {id}")),
    }
}
