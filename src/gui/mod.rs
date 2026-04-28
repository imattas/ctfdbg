pub mod actions;
pub mod app;
pub mod docking;
pub mod state;
pub mod theme;

pub mod dialogs;
pub mod panels;
pub mod widgets;

use crate::config::DebugConfig;

pub fn run(cfg: DebugConfig) -> Result<(), eframe::Error> {
    let native_options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("ctfdbg")
            .with_inner_size([1500.0, 900.0])
            .with_min_inner_size([900.0, 600.0]),
        ..Default::default()
    };

    eframe::run_native(
        "ctfdbg",
        native_options,
        Box::new(move |cc| {
            theme::install(&cc.egui_ctx);
            Ok(Box::new(app::App::new(cfg)))
        }),
    )
}
