//! Malware Scanner GUI — eframe/egui desktop application.

mod app;
mod ui;

use app::ScannerApp;

fn main() -> eframe::Result {
    let options = eframe::NativeOptions {
        viewport: eframe::egui::ViewportBuilder::default()
            .with_title("Malware Scanner")
            .with_inner_size([900.0, 650.0])
            .with_min_inner_size([700.0, 450.0]),
        ..Default::default()
    };

    eframe::run_native(
        "Malware Scanner",
        options,
        Box::new(|cc| {
            ui::theme::apply_theme(&cc.egui_ctx);
            Ok(Box::new(ScannerApp::new()))
        }),
    )
}
