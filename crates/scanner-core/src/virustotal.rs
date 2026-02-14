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

#[derive(Debug)]
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
        Ok(Some(parse_vt_response(sha256, &json)))
    }
}

/// Parse a VT v3 API JSON response into a `VtReport`.
pub fn parse_vt_response(sha256: &str, json: &serde_json::Value) -> VtReport {
    let data = &json["data"]["attributes"];
    let stats = &data["last_analysis_stats"];
    let results = &data["last_analysis_results"];

    let positives =
        stats["malicious"].as_u64().unwrap_or(0) + stats["suspicious"].as_u64().unwrap_or(0);
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
                    let name = result["result"].as_str().unwrap_or("unknown");
                    detection_names.push(format!("{engine}:{name}"));
                }
            }
        }
    }
    detection_names.sort();

    let permalink = format!("https://www.virustotal.com/gui/file/{sha256}");

    VtReport {
        sha256: sha256.to_string(),
        positives: positives as u32,
        total: total as u32,
        permalink,
        detection_names,
    }
}

/// Compute SHA-256 hash of a file.
pub fn sha256_file(path: &std::path::Path) -> Result<String> {
    use sha2::{Digest, Sha256};

    let data = std::fs::read(path).with_context(|| format!("Cannot read {}", path.display()))?;
    let hash = Sha256::digest(&data);
    Ok(format!("{:x}", hash))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn sha256_file_known_content() {
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        tmp.write_all(b"hello world").unwrap();
        tmp.flush().unwrap();

        let hash = sha256_file(tmp.path()).unwrap();
        // SHA-256 of "hello world"
        assert_eq!(
            hash,
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }

    #[test]
    fn sha256_file_empty() {
        let tmp = tempfile::NamedTempFile::new().unwrap();

        let hash = sha256_file(tmp.path()).unwrap();
        // SHA-256 of empty string
        assert_eq!(
            hash,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn sha256_file_not_found() {
        let result = sha256_file(std::path::Path::new("/nonexistent/file"));
        assert!(result.is_err());
    }

    #[test]
    fn parse_vt_response_malicious_file() {
        let json: serde_json::Value = serde_json::json!({
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 45,
                        "suspicious": 2,
                        "undetected": 10,
                        "harmless": 0,
                        "timeout": 1,
                        "failure": 0
                    },
                    "last_analysis_results": {
                        "EngineA": {
                            "category": "malicious",
                            "result": "Trojan.GenericKD"
                        },
                        "EngineB": {
                            "category": "malicious",
                            "result": "Win32.Malware"
                        },
                        "EngineC": {
                            "category": "undetected",
                            "result": null
                        },
                        "EngineD": {
                            "category": "suspicious",
                            "result": "Heuristic.Suspect"
                        }
                    }
                }
            }
        });

        let hash = "abc123def456";
        let report = parse_vt_response(hash, &json);

        assert_eq!(report.sha256, "abc123def456");
        assert_eq!(report.positives, 47); // 45 malicious + 2 suspicious
        assert_eq!(report.total, 58); // 47 + 10 + 0 + 1 + 0
        assert_eq!(
            report.permalink,
            "https://www.virustotal.com/gui/file/abc123def456"
        );
        assert_eq!(report.detection_names.len(), 3);
        // Sorted alphabetically
        assert_eq!(report.detection_names[0], "EngineA:Trojan.GenericKD");
        assert_eq!(report.detection_names[1], "EngineB:Win32.Malware");
        assert_eq!(report.detection_names[2], "EngineD:Heuristic.Suspect");
    }

    #[test]
    fn parse_vt_response_clean_file() {
        let json: serde_json::Value = serde_json::json!({
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 0,
                        "suspicious": 0,
                        "undetected": 5,
                        "harmless": 60,
                        "timeout": 0,
                        "failure": 0
                    },
                    "last_analysis_results": {
                        "EngineA": {
                            "category": "harmless",
                            "result": null
                        }
                    }
                }
            }
        });

        let report = parse_vt_response("cleanfile", &json);

        assert_eq!(report.positives, 0);
        assert_eq!(report.total, 65);
        assert!(report.detection_names.is_empty());
    }

    #[test]
    fn parse_vt_response_missing_fields() {
        // Minimal/empty response — should not panic
        let json: serde_json::Value = serde_json::json!({
            "data": {
                "attributes": {}
            }
        });

        let report = parse_vt_response("minimal", &json);

        assert_eq!(report.positives, 0);
        assert_eq!(report.total, 0);
        assert!(report.detection_names.is_empty());
    }

    #[test]
    fn parse_vt_response_no_result_field() {
        // Engine reports malicious but has no "result" string
        let json: serde_json::Value = serde_json::json!({
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 1,
                        "suspicious": 0,
                        "undetected": 0,
                        "harmless": 0,
                        "timeout": 0,
                        "failure": 0
                    },
                    "last_analysis_results": {
                        "WeirdEngine": {
                            "category": "malicious"
                        }
                    }
                }
            }
        });

        let report = parse_vt_response("noresult", &json);

        assert_eq!(report.positives, 1);
        assert_eq!(report.detection_names, vec!["WeirdEngine:unknown"]);
    }

    #[test]
    fn vt_report_serializes_to_json() {
        let report = VtReport {
            sha256: "abc123".into(),
            positives: 10,
            total: 70,
            permalink: "https://www.virustotal.com/gui/file/abc123".into(),
            detection_names: vec!["EngineA:Trojan".into()],
        };

        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(json["sha256"], "abc123");
        assert_eq!(json["positives"], 10);
        assert_eq!(json["total"], 70);
        assert_eq!(json["detection_names"][0], "EngineA:Trojan");
    }

    #[test]
    fn from_env_fails_without_env_var() {
        // Temporarily remove the env var to ensure the test is valid
        let saved = std::env::var("VIRUSTOTAL_API_KEY").ok();
        std::env::remove_var("VIRUSTOTAL_API_KEY");

        let result = VirusTotalClient::from_env();
        assert!(result.is_err());

        // Restore if it was set
        if let Some(val) = saved {
            std::env::set_var("VIRUSTOTAL_API_KEY", val);
        }
    }

    #[test]
    fn from_env_fails_with_empty_key() {
        let saved = std::env::var("VIRUSTOTAL_API_KEY").ok();
        std::env::set_var("VIRUSTOTAL_API_KEY", "");

        let result = VirusTotalClient::from_env();
        assert!(result.is_err());
        assert!(
            format!("{}", result.unwrap_err()).contains("empty"),
            "Error should mention empty key"
        );

        // Restore
        match saved {
            Some(val) => std::env::set_var("VIRUSTOTAL_API_KEY", val),
            None => std::env::remove_var("VIRUSTOTAL_API_KEY"),
        }
    }
}
