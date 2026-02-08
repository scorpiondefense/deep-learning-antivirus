//! scanner-core — shared library for malware scanning.
//!
//! Provides feature extraction, ONNX inference, scan orchestration,
//! and result reporting used by both the CLI and GUI frontends.

pub mod features;
pub mod inference;
pub mod report;
pub mod scan;
