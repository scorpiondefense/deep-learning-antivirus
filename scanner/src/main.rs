mod features;
mod model;

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Result;
use clap::Parser;
use rayon::prelude::*;
use walkdir::WalkDir;

use features::{extract_features, load_feature_config};
use model::Scanner;

#[derive(Parser)]
#[command(name = "malware-scanner")]
#[command(about = "ONNX-based malware detection scanner")]
struct Cli {
    /// Paths to scan (files or directories)
    #[arg(required = true)]
    paths: Vec<PathBuf>,

    /// Path to the ONNX model file
    #[arg(short, long, default_value = "../models/malware_convlstm.onnx")]
    model: PathBuf,

    /// Path to feature_config.json
    #[arg(short, long, default_value = "../models/feature_config.json")]
    config: PathBuf,

    /// Maliciousness threshold (0.0-1.0)
    #[arg(short, long, default_value = "0.5")]
    threshold: f32,
}

struct ScanResult {
    path: PathBuf,
    score: f32,
    is_malicious: bool,
    error: Option<String>,
}

/// Collect all file paths from the given paths (expanding directories with walkdir).
fn collect_files(paths: &[PathBuf]) -> Vec<PathBuf> {
    let mut files = Vec::new();

    for path in paths {
        if path.is_file() {
            files.push(path.clone());
        } else if path.is_dir() {
            for entry in WalkDir::new(path).follow_links(false).into_iter().flatten() {
                let p = entry.into_path();
                if p.is_file() {
                    files.push(p);
                }
            }
        }
    }

    files
}

fn print_results(results: &[ScanResult], threshold: f32) {
    let malicious: Vec<_> = results.iter().filter(|r| r.is_malicious).collect();
    let errors: Vec<_> = results.iter().filter(|r| r.error.is_some()).collect();
    let clean = results.len() - malicious.len() - errors.len();

    println!("\n{}", "=".repeat(70));
    println!("SCAN RESULTS (threshold: {:.2})", threshold);
    println!("{}", "=".repeat(70));

    if !malicious.is_empty() {
        println!("\nMALICIOUS FILES ({}):", malicious.len());
        for r in &malicious {
            println!("  [{:.4}] {}", r.score, r.path.display());
        }
    }

    if !errors.is_empty() {
        println!("\nERRORS ({}):", errors.len());
        for r in &errors {
            let err = r.error.as_deref().unwrap_or("unknown");
            println!("  [ERR ] {} -- {}", r.path.display(), err);
        }
    }

    println!("\nSUMMARY:");
    println!("  Total files scanned: {}", results.len());
    println!("  Malicious:           {}", malicious.len());
    println!("  Clean:               {}", clean);
    println!("  Errors:              {}", errors.len());
    println!("{}", "=".repeat(70));
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    eprintln!("[*] Loading model from {}...", cli.model.display());
    let scanner = Arc::new(Scanner::new(&cli.model)?);

    eprintln!("[*] Loading feature config from {}...", cli.config.display());
    let feature_config = load_feature_config(&cli.config)?;
    let bigram_table = Arc::new(feature_config.bigram_table);

    let files = collect_files(&cli.paths);
    eprintln!("[*] Found {} files to scan", files.len());

    if files.is_empty() {
        eprintln!("[*] No files to scan.");
        return Ok(());
    }

    let threshold = cli.threshold;

    let results: Vec<ScanResult> = files
        .par_iter()
        .map(|path| {
            match extract_features(path, &bigram_table) {
                Ok(features) => match scanner.predict(&features) {
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

    eprintln!("[*] Scanned {} files", results.len());
    print_results(&results, threshold);

    Ok(())
}
