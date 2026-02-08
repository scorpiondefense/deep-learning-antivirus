//! Application state and scan management.

use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::mpsc;
use std::sync::Arc;
use std::time::Instant;

use scanner_core::report::ScanResult;
use scanner_core::scan::{ScanConfig, ScanProgress, run_scan};

/// Application state machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScanState {
    Idle,
    Scanning,
    Complete,
}

pub struct ScannerApp {
    // Configuration
    pub model_path: Option<PathBuf>,
    pub config_path: Option<PathBuf>,
    pub target_paths: Vec<PathBuf>,
    pub threshold: f32,
    pub executables_only: bool,

    // State
    pub state: ScanState,
    pub progress: Arc<ScanProgress>,
    pub results: Vec<ScanResult>,
    pub error_message: Option<String>,
    pub scan_duration: Option<f32>,
    pub filter_text: String,

    // Communication
    result_rx: Option<mpsc::Receiver<ScanOutcome>>,
}

enum ScanOutcome {
    Success(Vec<ScanResult>, f32),
    Error(String),
}

impl ScannerApp {
    pub fn new() -> Self {
        Self {
            model_path: None,
            config_path: None,
            target_paths: Vec::new(),
            threshold: 0.5,
            executables_only: false,
            state: ScanState::Idle,
            progress: Arc::new(ScanProgress::new()),
            results: Vec::new(),
            error_message: None,
            scan_duration: None,
            filter_text: String::new(),
            result_rx: None,
        }
    }

    pub fn start_scan(&mut self) {
        let Some(model_path) = self.model_path.clone() else {
            self.error_message = Some("No model file selected".into());
            return;
        };
        let Some(config_path) = self.config_path.clone() else {
            self.error_message = Some("No config file selected".into());
            return;
        };
        if self.target_paths.is_empty() {
            self.error_message = Some("No scan targets added".into());
            return;
        }

        self.error_message = None;
        self.results.clear();
        self.scan_duration = None;
        self.state = ScanState::Scanning;
        self.progress = Arc::new(ScanProgress::new());

        let config = ScanConfig {
            model_path,
            config_path,
            target_paths: self.target_paths.clone(),
            threshold: self.threshold,
            executables_only: self.executables_only,
        };

        let progress = Arc::clone(&self.progress);
        let (tx, rx) = mpsc::channel();
        self.result_rx = Some(rx);

        std::thread::spawn(move || {
            let start = Instant::now();
            match run_scan(&config, &progress) {
                Ok(results) => {
                    let duration = start.elapsed().as_secs_f32();
                    let _ = tx.send(ScanOutcome::Success(results, duration));
                }
                Err(e) => {
                    let _ = tx.send(ScanOutcome::Error(format!("{e}")));
                }
            }
        });
    }

    pub fn cancel_scan(&self) {
        self.progress.cancel.store(true, Ordering::Relaxed);
    }

    /// Poll for completion — called each frame.
    pub fn poll(&mut self) {
        if let Some(rx) = &self.result_rx {
            if let Ok(outcome) = rx.try_recv() {
                match outcome {
                    ScanOutcome::Success(results, duration) => {
                        self.results = results;
                        self.scan_duration = Some(duration);
                        self.state = ScanState::Complete;
                    }
                    ScanOutcome::Error(msg) => {
                        self.error_message = Some(msg);
                        self.state = ScanState::Idle;
                    }
                }
                self.result_rx = None;
            }
        }
    }

    pub fn scanned_count(&self) -> usize {
        self.progress.scanned_files.load(Ordering::Relaxed)
    }

    pub fn total_count(&self) -> usize {
        self.progress.total_files.load(Ordering::Relaxed)
    }
}

impl eframe::App for ScannerApp {
    fn update(&mut self, ctx: &eframe::egui::Context, _frame: &mut eframe::Frame) {
        self.poll();

        // Request repaint during scanning for progress updates
        if self.state == ScanState::Scanning {
            ctx.request_repaint();
        }

        crate::ui::sidebar::draw_sidebar(ctx, self);
        crate::ui::scan_view::draw_scan_view(ctx, self);
    }
}
