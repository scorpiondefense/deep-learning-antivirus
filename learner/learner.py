#!/usr/bin/env python3
"""CLI orchestrator for the malware detection learner.

Usage:
    python learner.py --download          # Download malware + collect benign samples
    python learner.py --train             # Train the ConvLSTM model
    python learner.py --export            # Export to ONNX
    python learner.py --download --train --export  # Full pipeline
"""

import argparse
import json
import os
import sys
from pathlib import Path

from downloader import (
    collect_benign_samples,
    download_malware_samples,
    load_manifest,
    save_manifest,
)
from features import build_bigram_table, load_feature_config, save_feature_config
from train import train_model
from export import export_onnx


def get_project_root() -> Path:
    return Path(__file__).resolve().parent.parent


def main():
    parser = argparse.ArgumentParser(description="Malware Detection Learner")
    parser.add_argument("--download", action="store_true", help="Download/collect samples")
    parser.add_argument("--train", action="store_true", help="Train the model")
    parser.add_argument("--export", action="store_true", help="Export model to ONNX")
    parser.add_argument("--data-dir", type=str, default=None, help="Data directory")
    parser.add_argument("--model-dir", type=str, default=None, help="Model output directory")
    parser.add_argument("--malware-count", type=int, default=100, help="Number of malware samples")
    parser.add_argument("--benign-count", type=int, default=100, help="Number of benign samples")
    parser.add_argument("--vt-download", action="store_true", help="Also download samples from VirusTotal (requires VIRUSTOTAL_API_KEY)")
    parser.add_argument("--vt-malware-count", type=int, default=100, help="Number of VT malware samples to download")
    parser.add_argument("--epochs", type=int, default=100, help="Max training epochs")
    parser.add_argument("--batch-size", type=int, default=8, help="Training batch size")
    parser.add_argument("--lr", type=float, default=1e-4, help="Learning rate")
    parser.add_argument("--patience", type=int, default=10, help="Early stopping patience")
    parser.add_argument("--device", type=str, default=None, help="Device (cpu/cuda/mps)")

    args = parser.parse_args()

    if not any([args.download, args.train, args.export]):
        parser.print_help()
        sys.exit(1)

    root = get_project_root()
    data_dir = Path(args.data_dir) if args.data_dir else root / "data"
    model_dir = Path(args.model_dir) if args.model_dir else root / "models"
    malware_dir = data_dir / "malware"
    benign_dir = data_dir / "benign"
    malware_manifest = data_dir / "malware_manifest.json"
    benign_manifest = data_dir / "benign_manifest.json"
    config_path = model_dir / "feature_config.json"

    # --- Download ---
    if args.download:
        print("=" * 60)
        print("PHASE 1: Sample Acquisition")
        print("=" * 60)

        mal_manifest = download_malware_samples(
            str(malware_dir), count=args.malware_count
        )
        save_manifest(mal_manifest, str(malware_manifest))

        ben_manifest = collect_benign_samples(
            str(benign_dir), count=args.benign_count
        )
        save_manifest(ben_manifest, str(benign_manifest))

        # VirusTotal sample download (optional)
        if args.vt_download:
            try:
                from vt_downloader import VirusTotalDownloader

                vt_dir = data_dir / "malware_vt"
                downloader = VirusTotalDownloader()
                vt_manifest = downloader.download_malware_samples(
                    str(vt_dir), count=args.vt_malware_count
                )
                if vt_manifest:
                    mal_manifest.extend(vt_manifest)
                    save_manifest(mal_manifest, str(malware_manifest))
                    print(f"[*] Added {len(vt_manifest)} VT samples to malware manifest")
            except Exception as e:
                print(f"[!] VirusTotal download failed: {e}")
                print("[*] Continuing with MalwareBazaar samples only...")

        # Build bigram table from all samples
        all_paths = [e["path"] for e in mal_manifest + ben_manifest]
        print(f"\n[*] Building bigram table from {len(all_paths)} files...")
        bigram_table = build_bigram_table(all_paths)
        cfg_path = save_feature_config(bigram_table, str(model_dir))
        print(f"[*] Feature config saved to {cfg_path}")

    # --- Train ---
    if args.train:
        print("\n" + "=" * 60)
        print("PHASE 2: Training")
        print("=" * 60)

        if not malware_manifest.exists() or not benign_manifest.exists():
            print("[!] Manifests not found. Run --download first.")
            sys.exit(1)
        if not config_path.exists():
            print("[!] Feature config not found. Run --download first.")
            sys.exit(1)

        mal_entries = load_manifest(str(malware_manifest))
        ben_entries = load_manifest(str(benign_manifest))

        # Filter to existing files
        mal_paths = [e["path"] for e in mal_entries if os.path.exists(e["path"])]
        ben_paths = [e["path"] for e in ben_entries if os.path.exists(e["path"])]

        if not mal_paths or not ben_paths:
            print("[!] No valid samples found. Run --download first.")
            sys.exit(1)

        bigram_table = load_feature_config(str(config_path))

        best_model = train_model(
            malware_paths=mal_paths,
            benign_paths=ben_paths,
            bigram_table=bigram_table,
            output_dir=str(model_dir),
            epochs=args.epochs,
            batch_size=args.batch_size,
            lr=args.lr,
            patience=args.patience,
            device=args.device,
        )
        print(f"[*] Best model: {best_model}")

    # --- Export ---
    if args.export:
        print("\n" + "=" * 60)
        print("PHASE 3: ONNX Export")
        print("=" * 60)

        pth_path = model_dir / "malware_convlstm.pth"
        if not pth_path.exists():
            print("[!] Trained model not found. Run --train first.")
            sys.exit(1)

        onnx_path = export_onnx(str(pth_path), str(model_dir))
        print(f"[*] ONNX model: {onnx_path}")

    print("\n[*] Done.")


if __name__ == "__main__":
    main()
