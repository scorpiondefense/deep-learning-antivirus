//! VirusTotal API client for cross-referencing scan results.
//!
//! Uses the VT v3 API to look up file hashes and retrieve detection data.
//! The API key is read from the `VIRUSTOTAL_API_KEY` environment variable.
//! Built-in rate limiting keeps requests under the free-tier 4 req/min limit.

use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use serde::Serialize;

const VT_API_BASE: &str = "https://www.virustotal.com/api/v3";

/// Minimum interval between API calls (15.5 seconds = ~3.87 req/min, safely under 4/min).
const RATE_LIMIT_INTERVAL: Duration = Duration::from_millis(15_500);

#[derive(Debug, Clone, Serialize)]
pub struct VtReport {
    pub sha256: String,
    pub positives: u32,
    pub total: u32,
    pub permalink: String,
    pub detection_names: Vec<String>,
}

pub struct VirusTotalClient {
    api_key: String,
    client: reqwest::blocking::Client,
    last_request: Option<Instant>,
}

impl VirusTotalClient {
    /// Create a client from the `VIRUSTOTAL_API_KEY` environment variable.
    pub fn from_env() -> Result<Self> {
        let api_key = std::env::var("VIRUSTOTAL_API_KEY")
            .context("VIRUSTOTAL_API_KEY environment variable not set")?;
        if api_key.is_empty() {
            bail!("VIRUSTOTAL_API_KEY is empty");
        }
        Ok(Self {
            api_key,
            client: reqwest::blocking::Client::new(),
            last_request: None,
        })
    }

    /// Enforce rate limiting by sleeping if needed.
    fn rate_limit(&mut self) {
        if let Some(last) = self.last_request {
            let elapsed = last.elapsed();
            if elapsed < RATE_LIMIT_INTERVAL {
                std::thread::sleep(RATE_LIMIT_INTERVAL - elapsed);
            }
        }
        self.last_request = Some(Instant::now());
    }

    /// Look up a SHA-256 hash on VirusTotal.
    /// Returns `Ok(None)` if the file is not found (404).
    /// Returns `Ok(Some(report))` with detection data on success.
    pub fn lookup_hash(&mut self, sha256: &str) -> Result<Option<VtReport>> {
        self.rate_limit();

        let url = format!("{VT_API_BASE}/files/{sha256}");
        let resp = self
            .client
            .get(&url)
            .header("x-apikey", &self.api_key)
            .send()
            .context("VirusTotal API request failed")?;

        let status = resp.status();
        if status == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !status.is_success() {
            let body = resp.text().unwrap_or_default();
            bail!("VirusTotal API error (HTTP {status}): {body}");
        }

        let json: serde_json::Value = resp.json().context("Failed to parse VT response")?;

        let data = &json["data"]["attributes"];
        let stats = &data["last_analysis_stats"];
        let results = &data["last_analysis_results"];

        let positives = stats["malicious"].as_u64().unwrap_or(0)
            + stats["suspicious"].as_u64().unwrap_or(0);
        let total = positives
            + stats["undetected"].as_u64().unwrap_or(0)
            + stats["harmless"].as_u64().unwrap_or(0)
            + stats["timeout"].as_u64().unwrap_or(0)
            + stats["failure"].as_u64().unwrap_or(0);

        let mut detection_names = Vec::new();
        if let Some(obj) = results.as_object() {
            for (engine, result) in obj {
                if let Some(cat) = result["category"].as_str() {
                    if cat == "malicious" || cat == "suspicious" {
                        let name = result["result"]
                            .as_str()
                            .unwrap_or("unknown");
                        detection_names.push(format!("{engine}:{name}"));
                    }
                }
            }
        }
        detection_names.sort();

        let permalink = format!("https://www.virustotal.com/gui/file/{sha256}");

        Ok(Some(VtReport {
            sha256: sha256.to_string(),
            positives: positives as u32,
            total: total as u32,
            permalink,
            detection_names,
        }))
    }
}

/// Compute SHA-256 hash of a file.
pub fn sha256_file(path: &std::path::Path) -> Result<String> {
    use sha2::{Digest, Sha256};

    let data = std::fs::read(path).with_context(|| format!("Cannot read {}", path.display()))?;
    let hash = Sha256::digest(&data);
    Ok(format!("{:x}", hash))
}
