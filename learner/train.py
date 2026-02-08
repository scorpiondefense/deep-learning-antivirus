"""Training loop with early stopping for malware ConvLSTM model."""

import os
import time
from pathlib import Path

import numpy as np
import torch
import torch.nn as nn
from torch.utils.data import DataLoader, Dataset, random_split

from features import extract_features, load_feature_config
from model import MalwareConvLSTM


class MalwareDataset(Dataset):
    """Dataset of pre-extracted feature tensors with binary labels."""

    def __init__(
        self,
        malware_paths: list[str],
        benign_paths: list[str],
        bigram_table: list[tuple[int, int]],
    ):
        self.samples: list[tuple[str, float]] = []
        self.bigram_table = bigram_table

        for p in malware_paths:
            self.samples.append((p, 1.0))
        for p in benign_paths:
            self.samples.append((p, 0.0))

        # Cache extracted features
        self._cache: dict[str, torch.Tensor] = {}

    def __len__(self) -> int:
        return len(self.samples)

    def __getitem__(self, idx: int) -> tuple[torch.Tensor, torch.Tensor]:
        path, label = self.samples[idx]

        if path not in self._cache:
            try:
                features = extract_features(path, self.bigram_table)
            except (OSError, ValueError):
                features = torch.zeros(64, 3, 16, 16)
            self._cache[path] = features

        return self._cache[path], torch.tensor([label], dtype=torch.float32)


def train_model(
    malware_paths: list[str],
    benign_paths: list[str],
    bigram_table: list[tuple[int, int]],
    output_dir: str,
    epochs: int = 100,
    batch_size: int = 8,
    lr: float = 1e-4,
    patience: int = 10,
    val_split: float = 0.2,
    device: str | None = None,
) -> str:
    """Train the MalwareConvLSTM model with early stopping.

    Returns path to the best saved model.
    """
    if device is None:
        if torch.cuda.is_available():
            device = "cuda"
        elif hasattr(torch.backends, "mps") and torch.backends.mps.is_available():
            device = "mps"
        else:
            device = "cpu"

    print(f"[*] Using device: {device}")
    print(f"[*] Malware samples: {len(malware_paths)}, Benign samples: {len(benign_paths)}")

    dataset = MalwareDataset(malware_paths, benign_paths, bigram_table)

    # Split into train/val
    val_size = max(1, int(len(dataset) * val_split))
    train_size = len(dataset) - val_size
    train_dataset, val_dataset = random_split(
        dataset, [train_size, val_size], generator=torch.Generator().manual_seed(42)
    )

    train_loader = DataLoader(train_dataset, batch_size=batch_size, shuffle=True, num_workers=0)
    val_loader = DataLoader(val_dataset, batch_size=batch_size, shuffle=False, num_workers=0)

    print(f"[*] Train: {train_size}, Val: {val_size}")

    model = MalwareConvLSTM().to(device)
    criterion = nn.BCELoss()
    optimizer = torch.optim.Adam(model.parameters(), lr=lr)

    os.makedirs(output_dir, exist_ok=True)
    best_model_path = os.path.join(output_dir, "malware_convlstm.pth")

    best_val_loss = float("inf")
    epochs_no_improve = 0

    for epoch in range(1, epochs + 1):
        # Train
        model.train()
        train_loss = 0.0
        train_correct = 0
        train_total = 0

        for features, labels in train_loader:
            features = features.to(device)
            labels = labels.to(device)

            optimizer.zero_grad()
            outputs = model(features)
            loss = criterion(outputs, labels)
            loss.backward()
            optimizer.step()

            train_loss += loss.item() * features.size(0)
            preds = (outputs >= 0.5).float()
            train_correct += (preds == labels).sum().item()
            train_total += labels.size(0)

        train_loss /= train_total
        train_acc = train_correct / train_total

        # Validate
        model.eval()
        val_loss = 0.0
        val_correct = 0
        val_total = 0

        with torch.no_grad():
            for features, labels in val_loader:
                features = features.to(device)
                labels = labels.to(device)

                outputs = model(features)
                loss = criterion(outputs, labels)

                val_loss += loss.item() * features.size(0)
                preds = (outputs >= 0.5).float()
                val_correct += (preds == labels).sum().item()
                val_total += labels.size(0)

        val_loss /= val_total
        val_acc = val_correct / val_total

        print(
            f"  Epoch {epoch:3d}/{epochs} | "
            f"Train Loss: {train_loss:.4f} Acc: {train_acc:.4f} | "
            f"Val Loss: {val_loss:.4f} Acc: {val_acc:.4f}"
        )

        # Early stopping check
        if val_loss < best_val_loss:
            best_val_loss = val_loss
            epochs_no_improve = 0
            torch.save(model.state_dict(), best_model_path)
            print(f"  -> Saved best model (val_loss={val_loss:.4f})")
        else:
            epochs_no_improve += 1
            if epochs_no_improve >= patience:
                print(f"[*] Early stopping at epoch {epoch} (patience={patience})")
                break

    print(f"[*] Training complete. Best model saved to {best_model_path}")
    return best_model_path
