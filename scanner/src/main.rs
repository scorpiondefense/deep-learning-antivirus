//! Malware Scanner CLI - scans directories using an ONNX ConvLSTM model.
//!
//! Usage:
//!   malware-scanner /path/to/scan --model model.onnx --config feature_config.json
//!   malware-scanner /path/to/scan --model model.onnx --config feature_config.json --threshold 0.7 --format json
//!   malware-scanner /path/to/scan --model model.onnx --config feature_config.json --executables-only

mod features;
mod inference;
mod report;

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Result;
use clap::Parser;
use rayon::prelude::*;
use walkdir::WalkDir;

use features::{extract_features, load_feature_config};
use inference::MalwareModel;
use report::{OutputFormat, ScanResult, print_results};

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

/// Check if a file is an executable (PE, ELF, or Mach-O) using goblin.
fn is_executable(path: &PathBuf) -> bool {
    let Ok(data) = std::fs::read(path) else {
        return false;
    };
    // Check for magic bytes without full parse for speed
    if data.len() < 4 {
        return false;
    }
    // ELF: 0x7f 'E' 'L' 'F'
    if data[0] == 0x7f && data[1] == b'E' && data[2] == b'L' && data[3] == b'F' {
        return true;
    }
    // PE: 'M' 'Z'
    if data[0] == b'M' && data[1] == b'Z' {
        return true;
    }
    // Mach-O: various magic numbers
    if data.len() >= 4 {
        let magic = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        // MH_MAGIC, MH_MAGIC_64, FAT_MAGIC, FAT_CIGAM
        if matches!(magic, 0xfeedface | 0xfeedfacf | 0xcafebabe | 0xbebafeca) {
            return true;
        }
    }
    false
}

/// Collect all file paths from the given paths (expanding directories).
fn collect_files(paths: &[PathBuf], executables_only: bool) -> Vec<PathBuf> {
    let mut files = Vec::new();

    for path in paths {
        if path.is_file() {
            if !executables_only || is_executable(path) {
                files.push(path.clone());
            }
        } else if path.is_dir() {
            for entry in WalkDir::new(path).follow_links(false).into_iter().flatten() {
                let p = entry.into_path();
                if p.is_file() {
                    if !executables_only || is_executable(&p) {
                        files.push(p);
                    }
                }
            }
        }
    }

    files
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    eprintln!("[*] Loading model from {}...", cli.model.display());
    let model = Arc::new(MalwareModel::load(&cli.model)?);

    eprintln!("[*] Loading feature config from {}...", cli.config.display());
    let config = load_feature_config(&cli.config)?;
    let bigram_table = Arc::new(config.bigram_table);

    eprintln!("[*] Collecting files...");
    let files = collect_files(&cli.paths, cli.executables_only);
    eprintln!("[*] Found {} files to scan", files.len());

    if files.is_empty() {
        eprintln!("[*] No files to scan.");
        return Ok(());
    }

    let threshold = cli.threshold;

    // Parallel scanning with rayon
    let results: Vec<ScanResult> = files
        .par_iter()
        .map(|path| {
            match extract_features(path, &bigram_table) {
                Ok(features) => match model.predict(&features) {
                    Ok(score) => ScanResult {
                        path: path.clone(),
                        score,
                        is_malicious: score >= threshold,
                        error: None,
                    },
                    Err(e) => ScanResult {
                        path: path.clone(),
                        score: 0.0,
                        is_malicious: false,
                        error: Some(format!("inference error: {e}")),
                    },
                },
                Err(e) => ScanResult {
                    path: path.clone(),
                    score: 0.0,
                    is_malicious: false,
                    error: Some(format!("feature extraction error: {e}")),
                },
            }
        })
        .collect();

    print_results(&results, cli.format);

    Ok(())
}
