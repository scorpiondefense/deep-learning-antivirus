//! Left panel: model/config file pickers, target paths, settings, scan/cancel buttons.

use eframe::egui;

use crate::app::{ScanState, ScannerApp};

pub fn draw_sidebar(ctx: &egui::Context, app: &mut ScannerApp) {
    egui::SidePanel::left("sidebar")
        .resizable(true)
        .default_width(220.0)
        .min_width(180.0)
        .show(ctx, |ui| {
            ui.vertical(|ui| {
                ui.heading("MALWARE SCANNER");
                ui.label("v0.1.0");
                ui.separator();

                // Model file picker
                ui.label("MODEL");
                if ui.button("Select Model...").clicked() {
                    if let Some(path) = rfd::FileDialog::new()
                        .add_filter("ONNX Model", &["onnx"])
                        .pick_file()
                    {
                        app.model_path = Some(path);
                    }
                }
                if let Some(p) = &app.model_path {
                    ui.small(
                        p.file_name()
                            .map(|f| f.to_string_lossy().to_string())
                            .unwrap_or_else(|| "?".into()),
                    );
                }
                ui.add_space(4.0);

                // Config file picker
                ui.label("CONFIG");
                if ui.button("Select Config...").clicked() {
                    if let Some(path) = rfd::FileDialog::new()
                        .add_filter("JSON", &["json"])
                        .pick_file()
                    {
                        app.config_path = Some(path);
                    }
                }
                if let Some(p) = &app.config_path {
                    ui.small(
                        p.file_name()
                            .map(|f| f.to_string_lossy().to_string())
                            .unwrap_or_else(|| "?".into()),
                    );
                }
                ui.add_space(4.0);
                ui.separator();

                // Scan targets
                ui.label("SCAN TARGETS");
                let mut remove_idx = None;
                for (i, path) in app.target_paths.iter().enumerate() {
                    ui.horizontal(|ui| {
                        ui.small(path.display().to_string());
                        if ui.small_button("x").clicked() {
                            remove_idx = Some(i);
                        }
                    });
                }
                if let Some(i) = remove_idx {
                    app.target_paths.remove(i);
                }

                ui.horizontal(|ui| {
                    if ui.button("+ Add File").clicked() {
                        if let Some(path) = rfd::FileDialog::new().pick_file() {
                            app.target_paths.push(path);
                        }
                    }
                    if ui.button("+ Add Dir").clicked() {
                        if let Some(path) = rfd::FileDialog::new().pick_folder() {
                            app.target_paths.push(path);
                        }
                    }
                });

                ui.add_space(4.0);
                ui.separator();

                // Settings
                ui.label("SETTINGS");
                ui.horizontal(|ui| {
                    ui.label("Threshold:");
                    ui.add(egui::Slider::new(&mut app.threshold, 0.0..=1.0).step_by(0.05));
                });
                ui.checkbox(&mut app.executables_only, "Executables only");
                ui.checkbox(&mut app.virustotal, "Confirm with VirusTotal");

                ui.add_space(8.0);

                // Scan / Cancel buttons
                let is_scanning = app.state == ScanState::Scanning;
                ui.add_enabled_ui(!is_scanning, |ui| {
                    if ui
                        .add_sized([ui.available_width(), 32.0], egui::Button::new("SCAN"))
                        .clicked()
                    {
                        app.start_scan();
                    }
                });

                if is_scanning
                    && ui
                        .add_sized([ui.available_width(), 28.0], egui::Button::new("CANCEL"))
                        .clicked()
                {
                    app.cancel_scan();
                }

                // Error message
                if let Some(err) = &app.error_message {
                    ui.add_space(4.0);
                    ui.colored_label(super::theme::COLOR_ERROR, err);
                }
            });
        });
}
