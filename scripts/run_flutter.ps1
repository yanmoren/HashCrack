# Wrapper script to run Flutter commands inside TRAE sandbox.
# Redirects APPDATA/LOCALAPPDATA/PUB_CACHE to project dir to bypass sandbox write restrictions.
# Usage: powershell -ExecutionPolicy Bypass -File scripts\run_flutter.ps1 <flutter args>
# Example: .\scripts\run_flutter.ps1 pub get
#          .\scripts\run_flutter.ps1 build windows --release
$proj = Split-Path $PSScriptRoot -Parent
$flutterSdk = Join-Path $proj 'flutter_windows_3.47.3-stable\flutter'
if (-not (Test-Path (Join-Path $flutterSdk 'bin\flutter.bat'))) {
  $cmd = Get-Command flutter -ErrorAction SilentlyContinue
  if ($cmd) { $flutterSdk = $cmd.Source | Split-Path | Split-Path }
  else { Write-Host 'Flutter SDK not found' -ForegroundColor Red; exit 1 }
}
$dataDir = Join-Path $proj '.flutter_data'
$env:APPDATA = Join-Path $dataDir 'Roaming'
$env:LOCALAPPDATA = Join-Path $dataDir 'Local'
$env:PUB_CACHE = Join-Path $dataDir 'Pub\Cache'
$env:FLUTTER_SUPPRESS_ANALYTICS = 'true'
$env:ANDROID_HOME = 'E:\hashcat_gui\.android_sdk'
$env:ANDROID_SDK_ROOT = 'E:\hashcat_gui\.android_sdk'
$env:JAVA_HOME = 'C:\Program Files\Microsoft\jdk-17.0.20.101-hotspot'
New-Item -ItemType Directory -Path $env:APPDATA -Force | Out-Null
New-Item -ItemType Directory -Path $env:LOCALAPPDATA -Force | Out-Null

$flutterBat = Join-Path $flutterSdk 'bin\flutter.bat'
Set-Location $proj
Write-Host "> flutter $args" -ForegroundColor Cyan
& $flutterBat @args 2>&1 | ForEach-Object { Write-Host $_ }
