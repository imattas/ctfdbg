use crate::gui::theme::color;
use egui::{RichText, Ui};

/// Render bytes as a classic hex+ASCII view.
pub fn hex_view(ui: &mut Ui, base: u64, bytes: &[u8]) {
    egui::ScrollArea::vertical()
        .auto_shrink([false; 2])
        .show(ui, |ui| {
            for (i, chunk) in bytes.chunks(16).enumerate() {
                ui.horizontal(|ui| {
                    let addr = base + (i * 16) as u64;
                    ui.monospace(RichText::new(format!("{:016x}", addr)).color(color::ADDRESS));
                    ui.monospace("|");
                    let mut hex = String::with_capacity(48);
                    for j in 0..16 {
                        if j == 8 { hex.push(' '); }
                        if let Some(b) = chunk.get(j) {
                            use std::fmt::Write as _;
                            let _ = write!(hex, "{:02x} ", b);
                        } else {
                            hex.push_str("   ");
                        }
                    }
                    ui.monospace(hex);
                    ui.monospace("|");
                    let mut ascii = String::new();
                    for &b in chunk {
                        ascii.push(if (0x20..=0x7e).contains(&b) { b as char } else { '.' });
                    }
                    ui.monospace(RichText::new(ascii).color(color::STRING));
                });
            }
        });
}
