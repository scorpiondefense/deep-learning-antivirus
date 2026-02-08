"""ONNX export with numerical verification."""

import os

import numpy as np
import onnx
import onnxruntime as ort
import torch

from model import MalwareConvLSTM


def export_onnx(
    model_path: str,
    output_dir: str,
    opset_version: int = 17,
    atol: float = 1e-5,
) -> str:
    """Export trained model to ONNX and verify numerical equivalence.

    Args:
        model_path: Path to the .pth state dict
        output_dir: Directory for the output .onnx file
        opset_version: ONNX opset version
        atol: Absolute tolerance for numerical verification

    Returns:
        Path to the exported .onnx file
    """
    os.makedirs(output_dir, exist_ok=True)
    onnx_path = os.path.join(output_dir, "malware_convlstm.onnx")

    # Load PyTorch model
    model = MalwareConvLSTM()
    model.load_state_dict(torch.load(model_path, map_location="cpu", weights_only=True))
    model.eval()

    # Create dummy input (batch=1, T=64, C=3, H=16, W=16)
    dummy_input = torch.randn(1, 64, 3, 16, 16)

    # Get PyTorch output for verification
    with torch.no_grad():
        torch_output = model(dummy_input).numpy()

    print(f"[*] Exporting to ONNX (opset {opset_version})...")

    # Export to ONNX
    torch.onnx.export(
        model,
        dummy_input,
        onnx_path,
        opset_version=opset_version,
        input_names=["input"],
        output_names=["output"],
        dynamic_axes={"input": {0: "batch_size"}, "output": {0: "batch_size"}},
    )

    # Validate ONNX model
    onnx_model = onnx.load(onnx_path)
    onnx.checker.check_model(onnx_model)
    print("[*] ONNX model validation passed")

    # Numerical verification with ONNX Runtime
    print("[*] Verifying numerical equivalence...")
    session = ort.InferenceSession(onnx_path)
    ort_output = session.run(None, {"input": dummy_input.numpy()})[0]

    max_diff = np.max(np.abs(torch_output - ort_output))
    print(f"  Max absolute difference: {max_diff:.2e}")

    if max_diff > atol:
        print(f"[!] WARNING: Difference {max_diff:.2e} exceeds tolerance {atol:.2e}")
    else:
        print(f"[*] Verification passed (atol={atol:.2e})")

    print(f"[*] ONNX model saved to {onnx_path}")
    return onnx_path
