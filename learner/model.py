"""ConvLSTM model for malware detection.

Architecture:
  Input: (batch, T=64, C=3, H=16, W=16)
    -> ConvLSTMLayer(3->32, kernel=3x3) + BatchNorm2d
    -> ConvLSTMLayer(32->64, kernel=3x3) + BatchNorm2d
    -> Take last timestep: (batch, 64, 16, 16)
    -> AdaptiveAvgPool2d(4,4) -> Flatten(1024)
    -> Linear(1024->256) + ReLU + Dropout(0.3)
    -> Linear(256->64) + ReLU + Dropout(0.3)
    -> Linear(64->1) + Sigmoid
  Output: score in [0.0, 1.0]
"""

import torch
import torch.nn as nn


class ConvLSTMCell(nn.Module):
    """Single ConvLSTM cell."""

    def __init__(self, input_channels: int, hidden_channels: int, kernel_size: int = 3):
        super().__init__()
        self.hidden_channels = hidden_channels
        padding = kernel_size // 2
        # Combined gates: input, forget, cell, output
        self.conv = nn.Conv2d(
            input_channels + hidden_channels,
            4 * hidden_channels,
            kernel_size=kernel_size,
            padding=padding,
            bias=True,
        )

    def forward(
        self, x: torch.Tensor, h: torch.Tensor, c: torch.Tensor
    ) -> tuple[torch.Tensor, torch.Tensor]:
        """
        Args:
            x: (batch, input_channels, H, W)
            h: (batch, hidden_channels, H, W)
            c: (batch, hidden_channels, H, W)
        Returns:
            h_next, c_next
        """
        combined = torch.cat([x, h], dim=1)
        gates = self.conv(combined)
        i, f, g, o = gates.chunk(4, dim=1)
        i = torch.sigmoid(i)
        f = torch.sigmoid(f)
        g = torch.tanh(g)
        o = torch.sigmoid(o)
        c_next = f * c + i * g
        h_next = o * torch.tanh(c_next)
        return h_next, c_next


class ConvLSTMLayer(nn.Module):
    """ConvLSTM layer that processes a sequence and returns all hidden states."""

    def __init__(self, input_channels: int, hidden_channels: int, kernel_size: int = 3):
        super().__init__()
        self.hidden_channels = hidden_channels
        self.cell = ConvLSTMCell(input_channels, hidden_channels, kernel_size)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """
        Args:
            x: (batch, T, C, H, W)
        Returns:
            outputs: (batch, T, hidden_channels, H, W)
        """
        batch, seq_len, _, h, w = x.size()
        device = x.device

        h_t = torch.zeros(batch, self.hidden_channels, h, w, device=device)
        c_t = torch.zeros(batch, self.hidden_channels, h, w, device=device)

        outputs = []
        for t in range(seq_len):
            h_t, c_t = self.cell(x[:, t], h_t, c_t)
            outputs.append(h_t)

        return torch.stack(outputs, dim=1)


class MalwareConvLSTM(nn.Module):
    """Full malware detection model using ConvLSTM."""

    def __init__(self):
        super().__init__()
        # ConvLSTM layers
        self.convlstm1 = ConvLSTMLayer(3, 32, kernel_size=3)
        self.bn1 = nn.BatchNorm2d(32)
        self.convlstm2 = ConvLSTMLayer(32, 64, kernel_size=3)
        self.bn2 = nn.BatchNorm2d(64)

        # Classifier head
        self.pool = nn.AdaptiveAvgPool2d((4, 4))
        self.classifier = nn.Sequential(
            nn.Flatten(),
            nn.Linear(64 * 4 * 4, 256),
            nn.ReLU(),
            nn.Dropout(0.3),
            nn.Linear(256, 64),
            nn.ReLU(),
            nn.Dropout(0.3),
            nn.Linear(64, 1),
            nn.Sigmoid(),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """
        Args:
            x: (batch, T=64, C=3, H=16, W=16)
        Returns:
            score: (batch, 1) in [0.0, 1.0]
        """
        batch, seq_len = x.shape[0], x.shape[1]

        # First ConvLSTM + BatchNorm
        out = self.convlstm1(x)  # (batch, T, 32, H, W)
        # Apply BatchNorm per timestep
        out_bn = []
        for t in range(seq_len):
            out_bn.append(self.bn1(out[:, t]))
        out = torch.stack(out_bn, dim=1)  # (batch, T, 32, H, W)

        # Second ConvLSTM + BatchNorm
        out = self.convlstm2(out)  # (batch, T, 64, H, W)
        out_bn = []
        for t in range(seq_len):
            out_bn.append(self.bn2(out[:, t]))
        out = torch.stack(out_bn, dim=1)  # (batch, T, 64, H, W)

        # Take last timestep
        last = out[:, -1]  # (batch, 64, 16, 16)

        # Pool and classify
        pooled = self.pool(last)  # (batch, 64, 4, 4)
        score = self.classifier(pooled)  # (batch, 1)
        return score
