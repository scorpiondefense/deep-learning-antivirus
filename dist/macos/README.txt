Malware Scanner — macOS
=======================

Prerequisites:
  - macOS 12+ (Monterey or later)

Files:
  - malware-scanner        CLI scanner
  - malware-scanner-gui    Desktop GUI scanner

Usage (CLI):
  ./malware-scanner /path/to/scan --model model.onnx --config feature_config.json

Usage (GUI):
  Double-click malware-scanner-gui or run from terminal:
  ./malware-scanner-gui

Building from source:
  cd <project-root>
  ./build/build-macos.sh

Notes:
  - On first launch, macOS may block the binary. Go to System Settings >
    Privacy & Security and click "Open Anyway".
  - The ONNX Runtime library is statically linked — no extra dependencies needed.
