"""Feature extraction for malware detection.

Each binary file -> fixed tensor of shape (64, 3, 16, 16):
- Read up to 2MB of the file (zero-pad if smaller)
- Split into 64 chunks of 32,768 bytes each (temporal dimension)
- Per chunk, compute 3 channels (each 16x16 = 256 values):
  - Channel 0: Byte-value histogram (256 bins, normalized by max)
  - Channel 1: Sliding-window Shannon entropy (256 windows of 128 bytes, normalized by 8.0)
  - Channel 2: Bigram density (top-256 bigrams from training corpus, normalized by max)
"""

import json
import math
import os
from collections import Counter
from pathlib import Path
from typing import Optional

import numpy as np
import torch

MAX_FILE_SIZE = 2 * 1024 * 1024  # 2MB
NUM_CHUNKS = 64
CHUNK_SIZE = MAX_FILE_SIZE // NUM_CHUNKS  # 32768
NUM_BINS = 256
SPATIAL_DIM = 16  # 16x16 = 256
ENTROPY_WINDOW = 128
NUM_ENTROPY_WINDOWS = NUM_BINS  # 256
TOP_BIGRAMS = 256


def read_file_bytes(filepath: str, max_size: int = MAX_FILE_SIZE) -> np.ndarray:
    """Read a file up to max_size bytes, zero-pad if smaller."""
    with open(filepath, "rb") as f:
        raw = f.read(max_size)
    data = np.frombuffer(raw, dtype=np.uint8)
    if len(data) < max_size:
        data = np.pad(data, (0, max_size - len(data)), mode="constant")
    return data


def byte_histogram(chunk: np.ndarray) -> np.ndarray:
    """Compute normalized byte-value histogram (256 bins)."""
    hist = np.bincount(chunk, minlength=256).astype(np.float32)
    max_val = hist.max()
    if max_val > 0:
        hist /= max_val
    return hist


def shannon_entropy_map(chunk: np.ndarray) -> np.ndarray:
    """Compute sliding-window Shannon entropy over 256 windows of 128 bytes."""
    result = np.zeros(NUM_ENTROPY_WINDOWS, dtype=np.float32)
    chunk_len = len(chunk)

    if chunk_len < ENTROPY_WINDOW:
        return result

    # Distribute windows evenly across the chunk
    stride = max(1, (chunk_len - ENTROPY_WINDOW) // (NUM_ENTROPY_WINDOWS - 1)) if NUM_ENTROPY_WINDOWS > 1 else 1

    for i in range(NUM_ENTROPY_WINDOWS):
        start = min(i * stride, chunk_len - ENTROPY_WINDOW)
        window = chunk[start:start + ENTROPY_WINDOW]
        counts = np.bincount(window, minlength=256)
        probs = counts[counts > 0].astype(np.float32) / ENTROPY_WINDOW
        entropy = -np.sum(probs * np.log2(probs))
        result[i] = entropy / 8.0  # Normalize by max possible entropy

    return result


def bigram_density(chunk: np.ndarray, bigram_table: list[tuple[int, int]]) -> np.ndarray:
    """Compute bigram density for the top-256 bigrams."""
    result = np.zeros(TOP_BIGRAMS, dtype=np.float32)

    if len(chunk) < 2:
        return result

    # Count bigrams in chunk
    bigrams = np.stack([chunk[:-1], chunk[1:]], axis=1)
    bigram_counts: Counter = Counter(map(tuple, bigrams.tolist()))

    for idx, bg in enumerate(bigram_table):
        result[idx] = bigram_counts.get(bg, 0)

    max_val = result.max()
    if max_val > 0:
        result /= max_val
    return result


def build_bigram_table(file_paths: list[str], max_files: int = 200) -> list[tuple[int, int]]:
    """Build top-256 bigram table from a corpus of files."""
    global_counts: Counter = Counter()

    for fp in file_paths[:max_files]:
        try:
            data = read_file_bytes(fp)
            # Only count non-zero portion for efficiency
            nonzero_end = np.max(np.nonzero(data)[0]) + 1 if np.any(data) else 0
            if nonzero_end < 2:
                continue
            data = data[:nonzero_end]
            bigrams = np.stack([data[:-1], data[1:]], axis=1)
            global_counts.update(map(tuple, bigrams.tolist()))
        except (OSError, ValueError):
            continue

    top = global_counts.most_common(TOP_BIGRAMS)
    return [bg for bg, _ in top]


def extract_features(
    filepath: str,
    bigram_table: list[tuple[int, int]],
) -> torch.Tensor:
    """Extract features from a single file -> tensor of shape (64, 3, 16, 16)."""
    data = read_file_bytes(filepath)
    chunks = data.reshape(NUM_CHUNKS, CHUNK_SIZE)

    features = np.zeros((NUM_CHUNKS, 3, SPATIAL_DIM, SPATIAL_DIM), dtype=np.float32)

    for t in range(NUM_CHUNKS):
        chunk = chunks[t]
        # Channel 0: byte histogram
        features[t, 0] = byte_histogram(chunk).reshape(SPATIAL_DIM, SPATIAL_DIM)
        # Channel 1: entropy map
        features[t, 1] = shannon_entropy_map(chunk).reshape(SPATIAL_DIM, SPATIAL_DIM)
        # Channel 2: bigram density
        features[t, 2] = bigram_density(chunk, bigram_table).reshape(SPATIAL_DIM, SPATIAL_DIM)

    return torch.from_numpy(features)


def save_feature_config(bigram_table: list[tuple[int, int]], output_dir: str) -> str:
    """Save bigram table to feature_config.json."""
    os.makedirs(output_dir, exist_ok=True)
    config_path = os.path.join(output_dir, "feature_config.json")
    config = {
        "max_file_size": MAX_FILE_SIZE,
        "num_chunks": NUM_CHUNKS,
        "chunk_size": CHUNK_SIZE,
        "num_bins": NUM_BINS,
        "spatial_dim": SPATIAL_DIM,
        "entropy_window": ENTROPY_WINDOW,
        "num_entropy_windows": NUM_ENTROPY_WINDOWS,
        "top_bigrams": TOP_BIGRAMS,
        "bigram_table": bigram_table,
    }
    with open(config_path, "w") as f:
        json.dump(config, f, indent=2)
    return config_path


def load_feature_config(config_path: str) -> list[tuple[int, int]]:
    """Load bigram table from feature_config.json."""
    with open(config_path, "r") as f:
        config = json.load(f)
    return [tuple(bg) for bg in config["bigram_table"]]
