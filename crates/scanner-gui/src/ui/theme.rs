//! Dark security-tool theme with red/green/yellow accents.

use eframe::egui::{self, Color32, Visuals};

pub const COLOR_MALICIOUS: Color32 = Color32::from_rgb(230, 70, 70);
pub const COLOR_CLEAN: Color32 = Color32::from_rgb(70, 200, 100);
pub const COLOR_ERROR: Color32 = Color32::from_rgb(230, 180, 50);
pub fn apply_theme(ctx: &egui::Context) {
    let mut visuals = Visuals::dark();
    visuals.override_text_color = Some(Color32::from_rgb(220, 220, 220));
    ctx.set_visuals(visuals);

    let mut style = (*ctx.style()).clone();
    style.spacing.item_spacing = egui::vec2(8.0, 6.0);
    ctx.set_style(style);
}
