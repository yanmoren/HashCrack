# HashCrack Build Environment Setup Script
# Run this script FIRST to install all missing build dependencies.
# Open PowerShell as Administrator, then run:
#   powershell -ExecutionPolicy Bypass -File scripts\setup.ps1

param(
    [switch]$SkipVsTools,
    [switch]$SkipAndroid,
    [switch]$Verbose
)

$ErrorActionPreference = "Stop"
$proj = Split-Path $PSScriptRoot -Parent
Set-Location $proj

function Write-Step($msg) { Write-Host "`n=== $msg ===" -ForegroundColor Cyan }
function Write-OK($msg)   { Write-Host "  [OK] $msg" -ForegroundColor Green }
function Write-Warn($msg)  { Write-Host "  [!]  $msg" -ForegroundColor Yellow }
function Write-Err($msg)   { Write-Host "  [X]  $msg" -ForegroundColor Red }

Write-Host "HashCrack Build Environment Setup" -ForegroundColor White
Write-Host "This script installs: Visual Studio C++ tools, Java JDK, Android SDK"

# ---- 1. Visual Studio C++ Build Tools ----
if (-not $SkipVsTools) {
    Write-Step "Checking Visual Studio C++ tools"

    $vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
    $hasCpp = $false
    if (Test-Path $vswhere) {
        $vsPath = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath 2>$null
        $hasCpp = [bool]$vsPath
    }

    if ($hasCpp) {
        Write-OK "Visual Studio C++ tools already installed at $vsPath"
    } else {
        Write-Warn "C++ tools missing. Adding to existing Visual Studio installation..."

        $vsInstallPath = & $vswhere -latest -property installationPath 2>$null
        if (-not $vsInstallPath) {
            Write-Err "Visual Studio not found. Please install Visual Studio Community first:"
            Write-Host "    https://visualstudio.microsoft.com/vs/community/"
            Write-Host "  Then re-run this script."
        } else {
            Write-Host "  VS found at: $vsInstallPath"
            Write-Host "  Adding C++ workload (this may take 5-15 minutes)..."
            Write-Host "  NOTE: This will open the VS Installer GUI."
            Write-Host "  Click 'Modify' in the GUI and wait for installation to complete."
            $setupExe = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\setup.exe"
            $args = @(
                'modify',
                "--installPath", "`"$vsInstallPath`"",
                '--add', 'Microsoft.VisualStudio.Workload.NativeDesktop',
                '--add', 'Microsoft.VisualStudio.Component.VC.Tools.x86.x64',
                '--add', 'Microsoft.VisualStudio.Component.Windows11SDK.26100',
                '--add', 'Microsoft.VisualStudio.Component.VC.CMake.Project',
                '--norestart'
            )
            Write-Host "  Running: setup.exe $($args -join ' ')"
            Start-Process -FilePath $setupExe -ArgumentList $args -Wait
            Write-OK "VS installer finished. Verify with: flutter doctor -v"
        }
    }
}

# ---- 2. Java JDK ----
if (-not $SkipAndroid) {
    Write-Step "Checking Java JDK"

    $javaExe = Get-Command java -ErrorAction SilentlyContinue
    if ($javaExe) {
        $javaVer = (& java -version 2>&1 | Select-Object -First 1).ToString()
        Write-OK "Java found: $javaVer"
    } else {
        Write-Warn "Java not found. Installing Microsoft OpenJDK 17..."
        winget install Microsoft.OpenJDK.17 --accept-package-agreements --accept-source-agreements 2>$null
        if ($LASTEXITCODE -eq 0) {
            Write-OK "OpenJDK 17 installed"
            $env:JAVA_HOME = "${env:ProgramFiles}\Microsoft\jdk-17"
            if (Test-Path "${env:ProgramFiles}\Microsoft\jdk-17*") {
                $jdkDir = Get-ChildItem "${env:ProgramFiles}\Microsoft\jdk-17*" -Directory | Select-Object -First 1
                $env:JAVA_HOME = $jdkDir.FullName
            }
        } else {
            Write-Err "winget failed. Please install JDK manually:"
            Write-Host "    https://learn.microsoft.com/en-us/java/openjdk/download"
        }
    }
}

# ---- 3. Android SDK ----
if (-not $SkipAndroid) {
    Write-Step "Checking Android SDK"

    $androidSdk = "${env:LOCALAPPDATA}\Android\Sdk"
    $env:ANDROID_HOME = $androidSdk

    $hasCmdline = Test-Path "$androidSdk\cmdline-tools"
    $hasBuildTools = Test-Path "$androidSdk\build-tools"
    $hasPlatform = Test-Path "$androidSdk\platforms"

    if ($hasCmdline -and $hasBuildTools -and $hasPlatform) {
        Write-OK "Android SDK components already installed"
    } else {
        Write-Warn "Android SDK incomplete. Installing missing components..."

        # Download cmdline-tools if missing
        if (-not $hasCmdline) {
            Write-Host "  Downloading Android command-line tools..."
            $url = "https://dl.google.com/android/repository/commandlinetools-win-11076708_latest.zip"
            $zip = "$env:TEMP\cmdline-tools.zip"
            try {
                Invoke-WebRequest -Uri $url -OutFile $zip -UseBasicParsing
                $extractDir = "$androidSdk\cmdline-tools-tmp"
                Expand-Archive -Path $zip -DestinationPath $extractDir -Force
                New-Item -ItemType Directory -Path "$androidSdk\cmdline-tools\latest" -Force | Out-Null
                # The zip contains a cmdline-tools/ folder, move its contents into latest/
                $innerDir = "$extractDir\cmdline-tools"
                if (Test-Path $innerDir) {
                    Get-ChildItem $innerDir | Move-Item -Destination "$androidSdk\cmdline-tools\latest\" -Force
                } else {
                    Get-ChildItem "$extractDir\*" | Move-Item -Destination "$androidSdk\cmdline-tools\latest\" -Force
                }
                Remove-Item $extractDir -Recurse -Force
                Remove-Item $zip -Force
                Write-OK "Command-line tools installed"
            } catch {
                Write-Err "Failed to download cmdline-tools: $_"
                Write-Host "  Please install Android Studio: https://developer.android.com/studio"
            }
        } else {
            # Fix nested cmdline-tools directory structure if needed
            $nestedDir = "$androidSdk\cmdline-tools\latest\cmdline-tools"
            if (Test-Path "$nestedDir\bin\sdkmanager.bat") {
                Write-Host "  Fixing cmdline-tools directory structure..."
                Get-ChildItem $nestedDir | Move-Item -Destination "$androidSdk\cmdline-tools\latest\" -Force
                Remove-Item $nestedDir -Recurse -Force -ErrorAction SilentlyContinue
                Write-OK "Directory structure fixed"
            }
        }

        # Install SDK packages
        $sdkmanager = "$androidSdk\cmdline-tools\latest\bin\sdkmanager.bat"
        if (Test-Path $sdkmanager) {
            Write-Host "  Installing build-tools, platform-tools, platforms..."
            $packages = @(
                'platform-tools',
                'build-tools;34.0.0',
                'platforms;android-34'
            )
            foreach ($pkg in $packages) {
                Write-Host "    -> $pkg"
                & $sdkmanager --install $pkg 2>&1 | ForEach-Object {
                    if ($Verbose) { Write-Host "      $_" }
                }
            }
            Write-OK "Android SDK packages installed"
        } else {
            Write-Err "sdkmanager not found. Install Android Studio manually."
        }
    }
}

# ---- 4. Flutter Doctor ----
Write-Step "Running flutter doctor"
$flutterBat = Join-Path $proj 'flutter_windows_3.47.3-stable\flutter\bin\flutter.bat'
if (Test-Path $flutterBat) {
    & $flutterBat doctor 2>&1 | ForEach-Object { Write-Host "  $_" }
} else {
    $flutterExe = Get-Command flutter -ErrorAction SilentlyContinue
    if ($flutterExe) {
        & flutter doctor 2>&1 | ForEach-Object { Write-Host "  $_" }
    } else {
        Write-Err "Flutter not found. Ensure Flutter SDK is in PATH."
    }
}

Write-Step "Setup Complete"
Write-Host "If all items show [OK] or green checkmarks in flutter doctor,"
Write-Host "run: powershell -ExecutionPolicy Bypass -File scripts\build_all.ps1"
