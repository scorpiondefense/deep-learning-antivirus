# Malware Detection System — Technical Documentation

## Overview

This system detects malware using a ConvLSTM deep learning model that analyzes binary file structure. It has two components:

1. **Python Learner** (`learner/`) — Downloads samples, extracts features, trains a ConvLSTM, exports ONNX
2. **Rust Scanner** (`crates/`) — Loads the ONNX model, scans files with parallel processing, provides CLI and GUI interfaces

## Architecture

```
                    Training Pipeline (Python)
┌─────────────┐    ┌──────────────┐    ┌──────────────┐    ┌────────────┐
│ MalwareBazaar│───>│  Downloader  │───>│   Trainer    │───>│   Export   │
│ System Bins  │    │ (samples)    │    │ (ConvLSTM)   │    │  (ONNX)    │
└─────────────┘    └──────────────┘    └──────────────┘    └─────┬──────┘
                                                                 │
                                                    malware_convlstm.onnx
                                                    feature_config.json
                                                                 │
                    Inference Pipeline (Rust)                     │
┌─────────────┐    ┌──────────────┐    ┌──────────────┐    ┌─────▼──────┐
│  Files to    │───>│  Feature     │───>│   ONNX       │───>│  Results   │
│  Scan        │    │  Extraction  │    │   Runtime    │    │  Report    │
└─────────────┘    └──────────────┘    └──────────────┘    └────────────┘
```

---

## Deep Learning Architecture

### ConvLSTM Model

The model is a Convolutional LSTM that processes binary files as spatiotemporal sequences, treating byte patterns as "video frames" where temporal structure (how byte patterns change across the file) is informative.

**Input shape:** `(batch_size, 64, 3, 16, 16)`

```
                    64 temporal chunks
            ┌───┬───┬───┬───┬─── ─── ───┬───┐
            │ t0│ t1│ t2│ t3│    ...     │t63│
            └─┬─┴─┬─┴─┬─┴─┬─┴─── ─── ───┴─┬─┘
              │   │   │   │                 │
              ▼   ▼   ▼   ▼                 ▼
         ┌─────────────────────────────────────┐
         │        3 channels x 16x16           │
         │  Ch0: byte histogram (256 bins)     │
         │  Ch1: entropy map (256 windows)     │
         │  Ch2: bigram density (256 bigrams)  │
         └─────────────────────────────────────┘
```

### Network Layers

```
Input: (batch, 64, 3, 16, 16)
  │
  ▼
ConvLSTM Layer 1
  - ConvLSTMCell: 3 → 32 channels, 3x3 kernel, padding=1
  - Processes all 64 timesteps sequentially
  - BatchNorm2d(32) applied per timestep
  │
  ▼ (batch, 64, 32, 16, 16)
  │
ConvLSTM Layer 2
  - ConvLSTMCell: 32 → 64 channels, 3x3 kernel, padding=1
  - BatchNorm2d(64) applied per timestep
  │
  ▼ (batch, 64, 64, 16, 16)
  │
Take last timestep hidden state
  │
  ▼ (batch, 64, 16, 16)
  │
AdaptiveAvgPool2d → (4, 4)
  │
  ▼ (batch, 64, 4, 4)
  │
Flatten → 1024
  │
  ▼
Linear(1024 → 256) + ReLU + Dropout(0.3)
Linear(256 → 64)   + ReLU + Dropout(0.3)
Linear(64 → 1)     + Sigmoid
  │
  ▼
Score ∈ [0.0, 1.0]
```

### ConvLSTM Cell

Each ConvLSTM cell computes gates using convolution instead of matrix multiplication, preserving spatial structure:

```
x_t = input at timestep t
h_{t-1} = previous hidden state

combined = Conv2d([x_t, h_{t-1}]) → 4 * hidden_channels

i = sigmoid(combined[0])     # input gate
f = sigmoid(combined[1])     # forget gate
g = tanh(combined[2])        # cell candidate
o = sigmoid(combined[3])     # output gate

c_t = f * c_{t-1} + i * g    # cell state update
h_t = o * tanh(c_t)          # hidden state output
```

### Why ConvLSTM for Malware Detection

- **Temporal patterns:** Malware often has distinct structure at file beginning (headers), middle (payload), and end (signatures). ConvLSTM captures these sequential dependencies.
- **Spatial patterns:** Byte distributions, entropy profiles, and bigram frequencies are arranged in 16x16 grids. Convolution detects local patterns in these representations.
- **Combined:** The model learns spatiotemporal signatures — e.g., "high entropy in the middle chunks combined with unusual bigram patterns at the start."

---

## Feature Extraction Pipeline

Each binary file is converted to a fixed-size tensor `(64, 3, 16, 16)` through this pipeline:

### Step 1: File Reading

- Read up to 2 MB (2,097,152 bytes) of the file
- Zero-pad if the file is smaller
- Result: exactly 2,097,152 bytes

### Step 2: Chunking

- Split into 64 equal chunks of 32,768 bytes each
- Each chunk represents a temporal "slice" of the file

### Step 3: Per-Chunk Features (3 Channels)

**Channel 0 — Byte Histogram (16x16 = 256 values)**

Count occurrences of each byte value 0x00–0xFF in the chunk. Normalize by the maximum count. Reshape to 16x16.

```
Byte values:  [0x00, 0x01, ..., 0xFF]
Counts:       [1203,  847, ...,    42]
Normalized:   [1.00, 0.70, ..., 0.03]  (divide by max)
Reshaped:     16 x 16 grid
```

Reveals: byte distribution patterns (packed/encrypted files have flat histograms, text files peak around ASCII range).

**Channel 1 — Shannon Entropy Map (16x16 = 256 values)**

Compute Shannon entropy in a 128-byte sliding window at 256 evenly-spaced positions across the chunk. Normalize by 8.0 (maximum entropy for 256 symbols).

```
H(window) = -Σ p(x) * log2(p(x))

Values in [0.0, 1.0]:
  0.0 = completely uniform (e.g., all zeros)
  1.0 = maximum entropy (e.g., encrypted/compressed data)
```

Reveals: encryption, compression, and code vs. data sections.

**Channel 2 — Bigram Density (16x16 = 256 values)**

Count occurrences of the top-256 most common bigrams (2-byte sequences) in the chunk. The bigram table is pre-computed from the training corpus and stored in `feature_config.json`. Normalize by the maximum count.

Reveals: instruction patterns (x86 has common opcode pairs), string patterns, structural signatures.

### Shared Configuration

The `feature_config.json` file contains the bigram table used by both Python and Rust:

```json
{
  "bigram_table": [[0, 0], [0, 1], [255, 255], ...]
}
```

This ensures feature extraction is identical across training and inference.

---

## Scanner Internals (Rust)

### Crate Structure

```
crates/
  scanner-core/     Shared library
    features.rs     Feature extraction (mirrors Python exactly)
    inference.rs    ONNX model loading and prediction
    report.rs       ScanResult struct and output formatting
    scan.rs         Scan orchestrator with progress tracking
  scanner-cli/      CLI binary (thin wrapper around core)
  scanner-gui/      Desktop GUI (eframe/egui)
```

### Inference Pipeline

1. **Load model** — `ort::Session` wraps the ONNX Runtime. The session is wrapped in a `Mutex` because `session.run()` takes `&mut self`.

2. **Feature extraction** — Each file is read (up to 2 MB), split into 64 chunks, and processed into a `(64, 3, 16, 16)` ndarray. The implementation mirrors the Python version exactly.

3. **Batch dimension** — The array is reshaped from `(64, 3, 16, 16)` to `(1, 64, 3, 16, 16)` to add the batch dimension.

4. **ONNX inference** — `TensorRef::from_array_view` creates a zero-copy input. The session runs the graph and returns the output score.

5. **Threshold** — Scores >= threshold (default 0.5) are classified as malicious.

### Parallel Scanning

The scan orchestrator uses `rayon` for parallel file processing:

```
Files → rayon::par_iter → [extract_features → model.predict] → collect results
```

Progress is tracked with atomics (`AtomicUsize`, `AtomicBool`) to avoid Mutex contention with the GUI thread. The GUI reads progress via `Ordering::Relaxed` loads, while worker threads do `fetch_add`.

### Executable Detection

Before scanning (when `--executables-only` is set), files are checked for magic bytes:

| Format  | Magic Bytes              |
|---------|--------------------------|
| ELF     | `7F 45 4C 46`           |
| PE      | `4D 5A`                 |
| Mach-O  | `feedface` / `feedfacf` / `cafebabe` / `bebafeca` |

---

## Training Pipeline

### End-to-End Workflow

```bash
# 1. Download malware samples + collect system binaries
python learner.py --download --malware-count 100 --benign-count 100

# 2. Train the ConvLSTM model
python learner.py --train --epochs 100 --batch-size 8 --lr 1e-4

# 3. Export to ONNX for the Rust scanner
python learner.py --export

# Or run all three phases at once:
python learner.py --download --train --export
```

### Training Hyperparameters

| Parameter     | Default | Description                    |
|---------------|---------|--------------------------------|
| epochs        | 100     | Maximum training epochs        |
| batch_size    | 8       | Samples per mini-batch         |
| lr            | 1e-4    | Adam learning rate             |
| patience      | 10      | Early stopping patience        |
| val_split     | 0.2     | Validation set fraction        |

### Training Details

- **Loss:** Binary Cross Entropy (BCELoss)
- **Optimizer:** Adam
- **Early stopping:** Monitors validation loss, saves best model, stops after 10 epochs without improvement
- **Device:** Auto-detects CUDA, MPS (Apple Silicon), or CPU

### Output Artifacts

| File                              | Description                      |
|-----------------------------------|----------------------------------|
| `data/malware/`                   | Downloaded malware samples       |
| `data/benign/`                    | Collected system binaries        |
| `data/malware_manifest.json`      | Malware sample metadata          |
| `data/benign_manifest.json`       | Benign sample metadata           |
| `models/feature_config.json`      | Bigram table (shared with Rust)  |
| `models/malware_convlstm.pth`     | Trained PyTorch model            |
| `models/malware_convlstm.onnx`    | ONNX model for deployment       |
