//! Malware Scanner CLI - scans directories using an ONNX ConvLSTM model.
//!
//! Usage:
//!   malware-scanner /path/to/scan --model model.onnx --config feature_config.json
//!   malware-scanner /path/to/scan --model model.onnx --config feature_config.json --threshold 0.7 --format json
//!   malware-scanner /path/to/scan --model model.onnx --config feature_config.json --executables-only

use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use anyhow::Result;
use clap::Parser;

use scanner_core::report::{OutputFormat, print_results};
use scanner_core::scan::{ScanConfig, ScanProgress, run_scan};

#[derive(Parser)]
#[command(name = "malware-scanner")]
#[command(about = "ONNX-based malware detection scanner")]
struct Cli {
    /// Paths to scan (files or directories)
    #[arg(required = true)]
    paths: Vec<PathBuf>,

    /// Path to the ONNX model file
    #[arg(short, long)]
    model: PathBuf,

    /// Path to feature_config.json
    #[arg(short, long)]
    config: PathBuf,

    /// Maliciousness threshold (0.0-1.0)
    #[arg(short, long, default_value = "0.5")]
    threshold: f32,

    /// Output format
    #[arg(short, long, default_value = "text")]
    format: OutputFormat,

    /// Only scan executable files (PE/ELF/Mach-O)
    #[arg(long)]
    executables_only: bool,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    eprintln!("[*] Loading model from {}...", cli.model.display());
    eprintln!("[*] Loading feature config from {}...", cli.config.display());

    let config = ScanConfig {
        model_path: cli.model,
        config_path: cli.config,
        target_paths: cli.paths,
        threshold: cli.threshold,
        executables_only: cli.executables_only,
    };

    let progress = Arc::new(ScanProgress::new());

    eprintln!("[*] Scanning...");
    let results = run_scan(&config, &progress)?;

    let total = progress.total_files.load(Ordering::Relaxed);
    eprintln!("[*] Scanned {} files", total);

    if results.is_empty() {
        eprintln!("[*] No files to scan.");
        return Ok(());
    }

    print_results(&results, cli.format);

    Ok(())
}
