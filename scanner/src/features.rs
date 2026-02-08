//! Feature extraction - mirrors the Python implementation exactly.
//!
//! Each binary file → fixed tensor of shape (64, 3, 16, 16):
//! - Read up to 2MB of the file (zero-pad if smaller)
//! - Split into 64 chunks of 32,768 bytes each
//! - Per chunk, compute 3 channels (each 16x16 = 256 values):
//!   - Channel 0: Byte-value histogram (256 bins, normalized by max)
//!   - Channel 1: Sliding-window Shannon entropy (256 windows of 128 bytes, normalized by 8.0)
//!   - Channel 2: Bigram density (top-256 bigrams, normalized by max)

use std::fs;
use std::io::Read;
use std::path::Path;

use anyhow::Result;
use ndarray::Array4;
use serde::Deserialize;

const MAX_FILE_SIZE: usize = 2 * 1024 * 1024; // 2MB
const NUM_CHUNKS: usize = 64;
const CHUNK_SIZE: usize = MAX_FILE_SIZE / NUM_CHUNKS; // 32768
const NUM_BINS: usize = 256;
const SPATIAL_DIM: usize = 16;
const ENTROPY_WINDOW: usize = 128;
const NUM_ENTROPY_WINDOWS: usize = 256;
const TOP_BIGRAMS: usize = 256;

#[derive(Debug, Deserialize)]
pub struct FeatureConfig {
    pub bigram_table: Vec<(u8, u8)>,
}

pub fn load_feature_config(path: &Path) -> Result<FeatureConfig> {
    let data = fs::read_to_string(path)?;
    let config: FeatureConfig = serde_json::from_str(&data)?;
    Ok(config)
}

/// Read a file up to MAX_FILE_SIZE bytes, zero-pad if smaller.
fn read_file_bytes(path: &Path) -> Result<Vec<u8>> {
    let mut file = fs::File::open(path)?;
    let mut buf = vec![0u8; MAX_FILE_SIZE];
    let mut total = 0;

    loop {
        let remaining = MAX_FILE_SIZE - total;
        if remaining == 0 {
            break;
        }
        match file.read(&mut buf[total..])? {
            0 => break,
            n => total += n,
        }
    }
    // buf is already zero-padded (initialized with 0)
    Ok(buf)
}

/// Compute normalized byte-value histogram (256 bins).
fn byte_histogram(chunk: &[u8]) -> [f32; NUM_BINS] {
    let mut hist = [0u32; NUM_BINS];
    for &b in chunk {
        hist[b as usize] += 1;
    }

    let max_val = *hist.iter().max().unwrap_or(&1) as f32;
    let mut result = [0.0f32; NUM_BINS];
    if max_val > 0.0 {
        for i in 0..NUM_BINS {
            result[i] = hist[i] as f32 / max_val;
        }
    }
    result
}

/// Compute sliding-window Shannon entropy over 256 windows of 128 bytes.
fn shannon_entropy_map(chunk: &[u8]) -> [f32; NUM_ENTROPY_WINDOWS] {
    let mut result = [0.0f32; NUM_ENTROPY_WINDOWS];
    let chunk_len = chunk.len();

    if chunk_len < ENTROPY_WINDOW {
        return result;
    }

    let stride = if NUM_ENTROPY_WINDOWS > 1 {
        std::cmp::max(1, (chunk_len - ENTROPY_WINDOW) / (NUM_ENTROPY_WINDOWS - 1))
    } else {
        1
    };

    for i in 0..NUM_ENTROPY_WINDOWS {
        let start = std::cmp::min(i * stride, chunk_len - ENTROPY_WINDOW);
        let window = &chunk[start..start + ENTROPY_WINDOW];

        let mut counts = [0u32; 256];
        for &b in window {
            counts[b as usize] += 1;
        }

        let mut entropy = 0.0f32;
        let total = ENTROPY_WINDOW as f32;
        for &c in &counts {
            if c > 0 {
                let p = c as f32 / total;
                entropy -= p * p.log2();
            }
        }

        result[i] = entropy / 8.0; // Normalize by max possible entropy
    }
    result
}

/// Compute bigram density for the top-256 bigrams.
fn bigram_density(chunk: &[u8], bigram_table: &[(u8, u8)]) -> [f32; TOP_BIGRAMS] {
    let mut result = [0.0f32; TOP_BIGRAMS];

    if chunk.len() < 2 {
        return result;
    }

    // Count bigrams in chunk using a flat 256x256 table for O(1) lookup
    let mut bigram_counts = vec![0u32; 256 * 256];
    for pair in chunk.windows(2) {
        let idx = (pair[0] as usize) * 256 + pair[1] as usize;
        bigram_counts[idx] += 1;
    }

    for (i, &(a, b)) in bigram_table.iter().enumerate().take(TOP_BIGRAMS) {
        let idx = (a as usize) * 256 + b as usize;
        result[i] = bigram_counts[idx] as f32;
    }

    let max_val = result.iter().cloned().fold(0.0f32, f32::max);
    if max_val > 0.0 {
        for v in &mut result {
            *v /= max_val;
        }
    }
    result
}

/// Extract features from a single file → array of shape (64, 3, 16, 16).
pub fn extract_features(path: &Path, bigram_table: &[(u8, u8)]) -> Result<Array4<f32>> {
    let data = read_file_bytes(path)?;

    let mut features = Array4::<f32>::zeros((NUM_CHUNKS, 3, SPATIAL_DIM, SPATIAL_DIM));

    for t in 0..NUM_CHUNKS {
        let chunk_start = t * CHUNK_SIZE;
        let chunk = &data[chunk_start..chunk_start + CHUNK_SIZE];

        // Channel 0: byte histogram
        let hist = byte_histogram(chunk);
        for (i, &v) in hist.iter().enumerate() {
            let row = i / SPATIAL_DIM;
            let col = i % SPATIAL_DIM;
            features[[t, 0, row, col]] = v;
        }

        // Channel 1: entropy map
        let entropy = shannon_entropy_map(chunk);
        for (i, &v) in entropy.iter().enumerate() {
            let row = i / SPATIAL_DIM;
            let col = i % SPATIAL_DIM;
            features[[t, 1, row, col]] = v;
        }

        // Channel 2: bigram density
        let bigrams = bigram_density(chunk, bigram_table);
        for (i, &v) in bigrams.iter().enumerate() {
            let row = i / SPATIAL_DIM;
            let col = i % SPATIAL_DIM;
            features[[t, 2, row, col]] = v;
        }
    }

    Ok(features)
}
