use crate::gui::theme::color;
use egui::{Color32, RichText, Sense, Ui, Response};

/// Render a clickable address in green.
pub fn address(ui: &mut Ui, addr: u64) -> Response {
    let text = RichText::new(format!("0x{:016x}", addr))
        .monospace()
        .color(color::ADDRESS);
    ui.add(egui::Label::new(text).sense(Sense::click()))
}

pub fn parse_hex(s: &str) -> Option<u64> {
    let s = s.trim().trim_start_matches("0x").trim_start_matches("0X");
    u64::from_str_radix(s, 16).ok()
}

pub fn dim<S: Into<String>>(s: S) -> RichText {
    RichText::new(s.into()).color(Color32::from_rgb(0x6b, 0x70, 0x78))
}
