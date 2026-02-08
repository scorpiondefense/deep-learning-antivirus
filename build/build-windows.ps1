$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectRoot = Split-Path -Parent $ScriptDir
$DistDir = Join-Path $ProjectRoot "dist\windows"

Write-Host "[*] Building release binaries for Windows..."
Set-Location $ProjectRoot
cargo build --release -p scanner-cli -p scanner-gui

Write-Host "[*] Copying binaries to $DistDir\"
Copy-Item "target\release\malware-scanner.exe" -Destination $DistDir
Copy-Item "target\release\malware-scanner-gui.exe" -Destination $DistDir

Write-Host "[*] Done. Binaries are in $DistDir\"
Get-ChildItem "$DistDir\malware-scanner*" | Format-Table Name, Length
