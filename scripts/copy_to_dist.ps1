$proj = Split-Path $PSScriptRoot -Parent
$dist = Join-Path $proj 'dist'

# Clean old dist
if (Test-Path $dist) { Remove-Item -Recurse -Force $dist }
New-Item -ItemType Directory -Path $dist -Force | Out-Null

# Copy Windows build
$winSrc = Join-Path $proj 'build\windows\x64\runner\Release'
$winDst = Join-Path $dist 'windows'
if (Test-Path $winSrc) {
    New-Item -ItemType Directory -Path $winDst -Force | Out-Null
    Copy-Item -Path (Join-Path $winSrc '*') -Destination $winDst -Recurse -Force
    Write-Host "Windows build copied to dist\windows"
} else {
    Write-Host "Windows build not found at $winSrc" -ForegroundColor Yellow
}

# Copy Android APK
$apkSrc = Join-Path $proj 'build\app\outputs\flutter-apk\app-release.apk'
$apkDst = Join-Path $dist 'hashcat_gui.apk'
if (Test-Path $apkSrc) {
    Copy-Item -Path $apkSrc -Destination $apkDst -Force
    Write-Host "Android APK copied to dist\hashcat_gui.apk"
} else {
    Write-Host "Android APK not found at $apkSrc" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "=== Build artifacts in dist ===" -ForegroundColor Green
Get-ChildItem $dist -Recurse | Select-Object FullName, Length | Format-Table -AutoSize
