use crate::gui::actions::Action;
use crate::gui::state::AppState;
use egui::Context;

pub fn show(ctx: &Context, state: &mut AppState, _actions: &mut Vec<Action>) {
    if !state.show_hw_breakpoint { return; }
    let mut open = true;
    let id_addr = egui::Id::new("hwbp_addr");
    let id_kind = egui::Id::new("hwbp_kind");
    let id_size = egui::Id::new("hwbp_size");
    let mut addr: String = ctx.data_mut(|d| d.get_temp::<String>(id_addr).unwrap_or_default());
    let mut kind: u8 = ctx.data_mut(|d| d.get_temp::<u8>(id_kind).unwrap_or(0));
    let mut size: u8 = ctx.data_mut(|d| d.get_temp::<u8>(id_size).unwrap_or(1));

    egui::Window::new("Hardware Breakpoint").open(&mut open).show(ctx, |ui| {
        egui::Grid::new("hwbp_g").num_columns(2).show(ui, |ui| {
            ui.label("Address:");
            ui.add(egui::TextEdit::singleline(&mut addr).desired_width(220.0).hint_text("0x401000"));
            ui.end_row();
            ui.label("Type:");
            egui::ComboBox::from_id_source("hwbp_kind_cb")
                .selected_text(match kind { 0 => "Execute", 1 => "Read", 2 => "Write", _ => "Access (R/W)" })
                .show_ui(ui, |ui| {
                    ui.selectable_value(&mut kind, 0, "Execute");
                    ui.selectable_value(&mut kind, 1, "Read");
                    ui.selectable_value(&mut kind, 2, "Write");
                    ui.selectable_value(&mut kind, 3, "Access (R/W)");
                });
            ui.end_row();
            ui.label("Size:");
            egui::ComboBox::from_id_source("hwbp_size_cb")
                .selected_text(format!("{size}"))
                .show_ui(ui, |ui| {
                    for s in [1u8, 2, 4, 8] {
                        ui.selectable_value(&mut size, s, format!("{s}"));
                    }
                });
            ui.end_row();
        });
        ui.separator();
        ui.label("Note: hardware breakpoints are not yet implemented in the Windows backend; this dialog is provided for UI completeness. TODO: wire up via Dr0..Dr3 + Dr7.");
        ui.separator();
        ui.horizontal(|ui| {
            if ui.button("Cancel").clicked() { state.show_hw_breakpoint = false; }
            if ui.button("Add (TODO)").clicked() {
                state.console_output.push(format!("[!] hardware breakpoint not yet supported (addr={addr}, kind={kind}, size={size})"));
                state.show_hw_breakpoint = false;
            }
        });
    });
    ctx.data_mut(|d| {
        d.insert_temp(id_addr, addr.clone());
        d.insert_temp(id_kind, kind);
        d.insert_temp(id_size, size);
    });
    if !open { state.show_hw_breakpoint = false; }
}
