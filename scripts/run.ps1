# HashCrack - Quick Run (development mode)
# Starts the Flutter app in debug mode on Windows desktop.
# Usage: powershell -ExecutionPolicy Bypass -File scripts\run.ps1

$proj = Split-Path $PSScriptRoot -Parent
$dataDir = Join-Path $proj '.flutter_data'
$env:APPDATA = Join-Path $dataDir 'Roaming'
$env:LOCALAPPDATA = Join-Path $dataDir 'Local'
$env:PUB_CACHE = Join-Path $dataDir 'Pub\Cache'
$env:FLUTTER_SUPPRESS_ANALYTICS = 'true'
New-Item -ItemType Directory -Path $env:APPDATA -Force | Out-Null
New-Item -ItemType Directory -Path $env:LOCALAPPDATA -Force | Out-Null

$flutterSdk = Join-Path $proj 'flutter_windows_3.47.3-stable\flutter'
if (-not (Test-Path (Join-Path $flutterSdk 'bin\flutter.bat'))) {
    $cmd = Get-Command flutter -ErrorAction SilentlyContinue
    if ($cmd) { $flutterSdk = $cmd.Source | Split-Path | Split-Path }
    else { Write-Host "Flutter SDK not found" -ForegroundColor Red; exit 1 }
}

$flutterBat = Join-Path $flutterSdk 'bin\flutter.bat'
Set-Location $proj

Write-Host "Starting HashCrack in debug mode..." -ForegroundColor Cyan
Write-Host "Press 'r' for hot reload, 'q' to quit.`n" -ForegroundColor Gray
& $flutterBat run -d windows
