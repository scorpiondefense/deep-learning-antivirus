//! Output formatting for scan results.

use serde::Serialize;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize)]
pub struct ScanResult {
    pub path: PathBuf,
    pub score: f32,
    pub is_malicious: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vt_positives: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vt_total: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vt_permalink: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    Text,
    Json,
}

impl std::str::FromStr for OutputFormat {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "text" => Ok(OutputFormat::Text),
            "json" => Ok(OutputFormat::Json),
            _ => Err(format!("Unknown format: {s}. Use 'text' or 'json'.")),
        }
    }
}

pub fn print_results(results: &[ScanResult], format: OutputFormat) {
    match format {
        OutputFormat::Text => print_text(results),
        OutputFormat::Json => print_json(results),
    }
}

fn print_text(results: &[ScanResult]) {
    let malicious: Vec<_> = results.iter().filter(|r| r.is_malicious).collect();
    let errors: Vec<_> = results.iter().filter(|r| r.error.is_some()).collect();
    let clean = results.len() - malicious.len() - errors.len();

    println!("\n{}", "=".repeat(70));
    println!("SCAN RESULTS");
    println!("{}", "=".repeat(70));

    if !malicious.is_empty() {
        println!("\nMALICIOUS FILES ({}):", malicious.len());
        for r in &malicious {
            print!("  [{:.4}] {}", r.score, r.path.display());
            if let (Some(pos), Some(total)) = (r.vt_positives, r.vt_total) {
                print!("  [VT: {pos}/{total}]");
            }
            println!();
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

fn print_json(results: &[ScanResult]) {
    let output = serde_json::json!({
        "results": results,
        "summary": {
            "total": results.len(),
            "malicious": results.iter().filter(|r| r.is_malicious).count(),
            "clean": results.iter().filter(|r| !r.is_malicious && r.error.is_none()).count(),
            "errors": results.iter().filter(|r| r.error.is_some()).count(),
        }
    });
    println!("{}", serde_json::to_string_pretty(&output).unwrap_or_default());
}
