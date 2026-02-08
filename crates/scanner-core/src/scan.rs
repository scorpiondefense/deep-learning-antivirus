//! Scan orchestrator with progress tracking for both CLI and GUI use.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;

use anyhow::Result;
use rayon::prelude::*;
use walkdir::WalkDir;

use crate::features::{extract_features, load_feature_config};
use crate::inference::MalwareModel;
use crate::report::ScanResult;

/// Configuration for a scan run.
#[derive(Debug, Clone)]
pub struct ScanConfig {
    pub model_path: PathBuf,
    pub config_path: PathBuf,
    pub target_paths: Vec<PathBuf>,
    pub threshold: f32,
    pub executables_only: bool,
}

/// Atomic progress tracking — no Mutex contention with the GUI thread.
pub struct ScanProgress {
    pub total_files: AtomicUsize,
    pub scanned_files: AtomicUsize,
    pub malicious_count: AtomicUsize,
    pub error_count: AtomicUsize,
    pub cancel: AtomicBool,
}

impl ScanProgress {
    pub fn new() -> Self {
        Self {
            total_files: AtomicUsize::new(0),
            scanned_files: AtomicUsize::new(0),
            malicious_count: AtomicUsize::new(0),
            error_count: AtomicUsize::new(0),
            cancel: AtomicBool::new(false),
        }
    }
}

impl Default for ScanProgress {
    fn default() -> Self {
        Self::new()
    }
}

/// Check if a file is an executable (PE, ELF, or Mach-O) by magic bytes.
pub fn is_executable(path: &PathBuf) -> bool {
    let Ok(data) = std::fs::read(path) else {
        return false;
    };
    if data.len() < 4 {
        return false;
    }
    // ELF
    if data[0] == 0x7f && data[1] == b'E' && data[2] == b'L' && data[3] == b'F' {
        return true;
    }
    // PE
    if data[0] == b'M' && data[1] == b'Z' {
        return true;
    }
    // Mach-O
    let magic = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    matches!(magic, 0xfeedface | 0xfeedfacf | 0xcafebabe | 0xbebafeca)
}

/// Collect all file paths from the given paths (expanding directories).
pub fn collect_files(paths: &[PathBuf], executables_only: bool) -> Vec<PathBuf> {
    let mut files = Vec::new();

    for path in paths {
        if path.is_file() {
            if !executables_only || is_executable(path) {
                files.push(path.clone());
            }
        } else if path.is_dir() {
            for entry in WalkDir::new(path).follow_links(false).into_iter().flatten() {
                let p = entry.into_path();
                if p.is_file() && (!executables_only || is_executable(&p)) {
                    files.push(p);
                }
            }
        }
    }

    files
}

/// Run a full scan with progress tracking. Blocking — call from a background thread.
pub fn run_scan(config: &ScanConfig, progress: &Arc<ScanProgress>) -> Result<Vec<ScanResult>> {
    let model = Arc::new(MalwareModel::load(&config.model_path)?);
    let feature_config = load_feature_config(&config.config_path)?;
    let bigram_table = Arc::new(feature_config.bigram_table);

    let files = collect_files(&config.target_paths, config.executables_only);
    progress.total_files.store(files.len(), Ordering::Relaxed);

    if files.is_empty() {
        return Ok(Vec::new());
    }

    let threshold = config.threshold;

    let results: Vec<ScanResult> = files
        .par_iter()
        .filter_map(|path| {
            if progress.cancel.load(Ordering::Relaxed) {
                return None;
            }

            let result = match extract_features(path, &bigram_table) {
                Ok(features) => match model.predict(&features) {
                    Ok(score) => {
                        let is_malicious = score >= threshold;
                        if is_malicious {
                            progress.malicious_count.fetch_add(1, Ordering::Relaxed);
                        }
                        ScanResult {
                            path: path.clone(),
                            score,
                            is_malicious,
                            error: None,
                        }
                    }
                    Err(e) => {
                        progress.error_count.fetch_add(1, Ordering::Relaxed);
                        ScanResult {
                            path: path.clone(),
                            score: 0.0,
                            is_malicious: false,
                            error: Some(format!("inference error: {e}")),
                        }
                    }
                },
                Err(e) => {
                    progress.error_count.fetch_add(1, Ordering::Relaxed);
                    ScanResult {
                        path: path.clone(),
                        score: 0.0,
                        is_malicious: false,
                        error: Some(format!("feature extraction error: {e}")),
                    }
                }
            };

            progress.scanned_files.fetch_add(1, Ordering::Relaxed);
            Some(result)
        })
        .collect();

    Ok(results)
}
