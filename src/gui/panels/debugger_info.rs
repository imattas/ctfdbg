use crate::gui::state::AppState;
use crate::gui::theme::color;
use crate::pwn::calling_convention::{extract_args, CallingConvention};
use egui::{RichText, Ui};

pub fn show(ui: &mut Ui, state: &AppState) {
    if let Some(addr) = state.selected_address {
        ui.label(RichText::new(format!("Selected: 0x{addr:x}")).color(color::ADDRESS).monospace());
    } else {
        ui.label(RichText::new("(no instruction selected)").color(color::MUTED));
        return;
    }

    if let Some(pc) = state.registers.pc() {
        ui.label(format!("PC: 0x{pc:x}"));
    }
    if let Some(sp) = state.registers.sp() {
        ui.label(format!("SP: 0x{sp:x}"));
    }

    ui.separator();
    ui.label(RichText::new("Likely call args (Windows x64 convention):").strong());
    let args = extract_args(CallingConvention::WindowsX64, &state.registers, |_| None);
    for a in args {
        ui.monospace(format!("  {} = 0x{:016x}    ; from {}", a.name, a.value, a.source));
    }
}
