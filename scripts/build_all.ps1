# HashCrack Build Script - Builds Windows EXE and Android APK
# Prerequisites: Run setup.ps1 first to install build dependencies.
# Usage:
#   powershell -ExecutionPolicy Bypass -File scripts\build_all.ps1
#   powershell -ExecutionPolicy Bypass -File scripts\build_all.ps1 -WindowsOnly
#   powershell -ExecutionPolicy Bypass -File scripts\build_all.ps1 -AndroidOnly

param(
    [switch]$WindowsOnly,
    [switch]$AndroidOnly
)

$ErrorActionPreference = "Stop"
$proj = Split-Path $PSScriptRoot -Parent
Set-Location $proj

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

function Write-Step($msg) { Write-Host "`n=== $msg ===" -ForegroundColor Cyan }
function Write-OK($msg)   { Write-Host "  [OK] $msg" -ForegroundColor Green }
function Write-Err($msg)   { Write-Host "  [X]  $msg" -ForegroundColor Red }

$buildWindows = -not $AndroidOnly
$buildAndroid = -not $WindowsOnly

# ---- 1. Pub Get ----
Write-Step "Resolving dependencies"
& $flutterBat pub get 2>&1 | ForEach-Object { Write-Host "  $_" }
if ($LASTEXITCODE -ne 0) { Write-Err "pub get failed"; exit 1 }
Write-OK "Dependencies resolved"

# ---- 2. Build Windows ----
if ($buildWindows) {
    Write-Step "Building Windows desktop app (release)"
    & $flutterBat build windows --release 2>&1 | ForEach-Object { Write-Host "  $_" }

    $exePath = Join-Path $proj 'build\windows\x64\runner\Release\hashcat_gui.exe'
    if (Test-Path $exePath) {
        $size = [math]::Round((Get-Item $exePath).Length / 1MB, 2)
        Write-OK "Windows EXE built: $exePath ($size MB)"

        # Copy to dist folder
        $distDir = Join-Path $proj 'dist'
        New-Item -ItemType Directory -Path $distDir -Force | Out-Null
        $releaseDir = Join-Path $proj 'build\windows\x64\runner\Release'
        Copy-Item -Path "$releaseDir\*" -Destination $distDir -Recurse -Force
        Write-OK "Copied to: $distDir\hashcat_gui.exe"
    } else {
        Write-Err "Windows build may have failed. EXE not found at expected path."
        Write-Host "  Check output above. Run 'flutter doctor' to verify VS C++ tools."
    }
}

# ---- 3. Build Android ----
if ($buildAndroid) {
    Write-Step "Building Android APK (release)"
    & $flutterBat build apk --release 2>&1 | ForEach-Object { Write-Host "  $_" }

    $apkPath = Join-Path $proj 'build\app\outputs\flutter-apk\app-release.apk'
    if (Test-Path $apkPath) {
        $size = [math]::Round((Get-Item $apkPath).Length / 1MB, 2)
        Write-OK "Android APK built: $apkPath ($size MB)"

        $distDir = Join-Path $proj 'dist'
        New-Item -ItemType Directory -Path $distDir -Force | Out-Null
        Copy-Item -Path $apkPath -Destination (Join-Path $distDir 'HashCrack.apk') -Force
        Write-OK "Copied to: $distDir\HashCrack.apk"
    } else {
        Write-Err "Android build may have failed. APK not found at expected path."
        Write-Host "  Ensure Java JDK and Android SDK are installed."
        Write-Host "  Run: powershell -ExecutionPolicy Bypass -File scripts\setup.ps1"
    }
}

# ---- Summary ----
Write-Step "Build Summary"
if ($buildWindows) {
    $exe = Join-Path $proj 'dist\hashcat_gui.exe'
    if (Test-Path $exe) { Write-OK "Windows: $exe" }
    else { Write-Err "Windows: build failed" }
}
if ($buildAndroid) {
    $apk = Join-Path $proj 'dist\HashCrack.apk'
    if (Test-Path $apk) { Write-OK "Android: $apk" }
    else { Write-Err "Android: build failed" }
}
