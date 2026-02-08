//! Main panel: progress bar, results table, filter, summary stats.

use eframe::egui;

use crate::app::{ScanState, ScannerApp};
use crate::ui::theme;

pub fn draw_scan_view(ctx: &egui::Context, app: &mut ScannerApp) {
    egui::CentralPanel::default().show(ctx, |ui| {
        match app.state {
            ScanState::Idle => {
                ui.centered_and_justified(|ui| {
                    ui.label("Select a model, config, and scan targets, then click SCAN.");
                });
            }
            ScanState::Scanning => {
                draw_progress(ui, app);
            }
            ScanState::Complete => {
                draw_results(ui, app);
            }
        }
    });
}

fn draw_progress(ui: &mut egui::Ui, app: &ScannerApp) {
    ui.add_space(20.0);
    ui.heading("Scan Progress");
    ui.add_space(8.0);

    let scanned = app.scanned_count();
    let total = app.total_count();
    let fraction = if total > 0 {
        scanned as f32 / total as f32
    } else {
        0.0
    };

    ui.add(
        egui::ProgressBar::new(fraction)
            .text(format!("{scanned} / {total} files scanned"))
            .animate(true),
    );
}

fn draw_results(ui: &mut egui::Ui, app: &mut ScannerApp) {
    ui.heading("Results");
    ui.add_space(4.0);

    // Filter
    ui.horizontal(|ui| {
        ui.label("Filter:");
        ui.text_edit_singleline(&mut app.filter_text);
    });
    ui.add_space(4.0);

    let filter = app.filter_text.to_lowercase();

    // Scrollable results table
    egui::ScrollArea::vertical()
        .auto_shrink([false, false])
        .max_height(ui.available_height() - 80.0)
        .show(ui, |ui| {
            egui::Grid::new("results_grid")
                .striped(true)
                .min_col_width(60.0)
                .spacing([12.0, 4.0])
                .show(ui, |ui| {
                    // Header
                    ui.strong("Path");
                    ui.strong("Score");
                    ui.strong("Status");
                    ui.end_row();

                    for result in &app.results {
                        let path_str = result.path.display().to_string();
                        if !filter.is_empty() && !path_str.to_lowercase().contains(&filter) {
                            continue;
                        }

                        ui.monospace(&path_str);

                        if result.error.is_some() {
                            ui.label("—");
                            ui.colored_label(
                                theme::COLOR_ERROR,
                                result.error.as_deref().unwrap_or("ERROR"),
                            );
                        } else {
                            ui.monospace(format!("{:.4}", result.score));
                            if result.is_malicious {
                                ui.colored_label(theme::COLOR_MALICIOUS, "MALICIOUS");
                            } else {
                                ui.colored_label(theme::COLOR_CLEAN, "CLEAN");
                            }
                        }
                        ui.end_row();
                    }
                });
        });

    // Summary
    ui.separator();
    let total = app.results.len();
    let malicious = app.results.iter().filter(|r| r.is_malicious).count();
    let errors = app.results.iter().filter(|r| r.error.is_some()).count();
    let clean = total - malicious - errors;

    ui.horizontal(|ui| {
        ui.label(format!("Total: {total}"));
        ui.label(" | ");
        ui.colored_label(theme::COLOR_MALICIOUS, format!("Malicious: {malicious}"));
        ui.label(" | ");
        ui.colored_label(theme::COLOR_CLEAN, format!("Clean: {clean}"));
        ui.label(" | ");
        ui.colored_label(theme::COLOR_ERROR, format!("Errors: {errors}"));
        if let Some(dur) = app.scan_duration {
            ui.label(" | ");
            ui.label(format!("Duration: {dur:.1}s"));
        }
    });
}
