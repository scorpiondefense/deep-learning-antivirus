Malware Scanner — Windows
=========================

Prerequisites:
  - Windows 10 or later (x86_64)
  - Visual C++ Redistributable 2019+ (usually already installed)

Files:
  - malware-scanner.exe        CLI scanner
  - malware-scanner-gui.exe    Desktop GUI scanner

Usage (CLI):
  malware-scanner.exe C:\path\to\scan --model model.onnx --config feature_config.json

Usage (GUI):
  Double-click malware-scanner-gui.exe

Building from source:
  cd <project-root>
  powershell -ExecutionPolicy Bypass -File build\build-windows.ps1

Notes:
  - Windows Defender may flag the scanner on first run. Add an exclusion or
    click "More info" > "Run anyway" in the SmartScreen prompt.
