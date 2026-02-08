Malware Scanner — Linux
=======================

Prerequisites:
  - Linux x86_64 (glibc 2.17+)
  - For GUI: X11 or Wayland display server

Files:
  - malware-scanner              CLI scanner
  - malware-scanner-gui          Desktop GUI scanner
  - malware-scanner-gui.desktop  Desktop entry (optional)

Usage (CLI):
  ./malware-scanner /path/to/scan --model model.onnx --config feature_config.json

Usage (GUI):
  ./malware-scanner-gui

Desktop integration (optional):
  cp malware-scanner-gui.desktop ~/.local/share/applications/
  chmod +x ~/.local/share/applications/malware-scanner-gui.desktop

Building from source:
  cd <project-root>
  ./build/build-linux.sh
