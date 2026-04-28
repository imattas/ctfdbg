//! Dark theme inspired by Binary Ninja.

use egui::{Color32, FontFamily, FontId, Stroke, TextStyle, Visuals};

pub mod color {
    use egui::Color32;
    pub const BG: Color32        = Color32::from_rgb(0x1b, 0x1d, 0x21);
    pub const PANEL: Color32     = Color32::from_rgb(0x24, 0x27, 0x2c);
    pub const PANEL2: Color32    = Color32::from_rgb(0x2c, 0x2f, 0x35);
    pub const HEADER: Color32    = Color32::from_rgb(0x33, 0x37, 0x3e);
    pub const TEXT: Color32      = Color32::from_rgb(0xd6, 0xd6, 0xd6);
    pub const MUTED: Color32     = Color32::from_rgb(0x8a, 0x8f, 0x99);
    pub const ADDRESS: Color32   = Color32::from_rgb(0x6a, 0xff, 0x6a);
    pub const REG_CHANGED: Color32 = Color32::from_rgb(0x6a, 0xb8, 0xff);
    pub const REG_EDITED: Color32  = Color32::from_rgb(0xff, 0xa1, 0x4a);
    pub const HINT: Color32      = Color32::from_rgb(0xe6, 0x86, 0xff);
    pub const STRING: Color32    = Color32::from_rgb(0xff, 0x9e, 0xc8);
    pub const CURRENT_LINE: Color32 = Color32::from_rgb(0x1f, 0x33, 0x55);
    pub const BREAKPOINT: Color32   = Color32::from_rgb(0x66, 0x1f, 0x1f);
    pub const ACCENT: Color32       = Color32::from_rgb(0x4d, 0x9d, 0xff);
}

pub fn install(ctx: &egui::Context) {
    let mut style = (*ctx.style()).clone();
    let mut v = Visuals::dark();
    v.window_fill = color::BG;
    v.panel_fill = color::PANEL;
    v.faint_bg_color = color::PANEL2;
    v.extreme_bg_color = color::BG;
    v.override_text_color = Some(color::TEXT);
    v.widgets.noninteractive.bg_fill = color::PANEL;
    v.widgets.noninteractive.bg_stroke = Stroke::new(1.0, color::HEADER);
    v.widgets.inactive.bg_fill = color::PANEL2;
    v.widgets.hovered.bg_fill = color::HEADER;
    v.widgets.active.bg_fill = color::ACCENT;
    v.selection.bg_fill = color::ACCENT.linear_multiply(0.5);
    style.visuals = v;

    style.text_styles.insert(
        TextStyle::Monospace,
        FontId::new(13.0, FontFamily::Monospace),
    );
    style.text_styles.insert(
        TextStyle::Body,
        FontId::new(13.0, FontFamily::Proportional),
    );
    style.text_styles.insert(
        TextStyle::Button,
        FontId::new(13.0, FontFamily::Proportional),
    );
    style.spacing.item_spacing = egui::vec2(6.0, 4.0);
    ctx.set_style(style);
}
