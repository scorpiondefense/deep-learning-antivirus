#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
DIST_DIR="$PROJECT_ROOT/dist/macos"

echo "[*] Building release binaries for macOS..."
cd "$PROJECT_ROOT"
cargo build --release -p scanner-cli -p scanner-gui

echo "[*] Copying binaries to $DIST_DIR/"
cp target/release/malware-scanner "$DIST_DIR/"
cp target/release/malware-scanner-gui "$DIST_DIR/"

echo "[*] Done. Binaries are in $DIST_DIR/"
ls -lh "$DIST_DIR"/malware-scanner*
