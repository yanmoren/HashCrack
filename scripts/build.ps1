<#
.SYNOPSIS
  一键构建 HashCrack 应用
#>
param(
  [switch]$Windows,
  [switch]$Android,
  [switch]$FetchTools,
  [switch]$Run
)

$ErrorActionPreference = 'Stop'
$proj = Split-Path $PSScriptRoot -Parent
Write-Host "项目目录: $proj" -ForegroundColor Cyan

Set-Location $proj

Write-Host "`n[1] 安装依赖..." -ForegroundColor Cyan
flutter pub get

if ($FetchTools) {
  Write-Host "`n[2] 获取哈希提取工具..." -ForegroundColor Cyan
  & "$PSScriptRoot\fetch_tools.ps1"
}

if ($Windows -or (-not $Android -and -not $Run)) {
  Write-Host "`n[3] 构建 Windows 桌面应用..." -ForegroundColor Cyan
  flutter build windows --release
  $outWin = Join-Path $proj 'build\windows\runner\Release'
  if (Test-Path $outWin) {
    Write-Host "  ✓ 产物: $outWin\hashcat_gui.exe" -ForegroundColor Green
  }
}

if ($Android) {
  Write-Host "`n[4] 构建 Android APK..." -ForegroundColor Cyan
  flutter build apk --release
  $outApk = Join-Path $proj 'build\app\outputs\flutter-apk\app-release.apk'
  if (Test-Path $outApk) {
    Write-Host "  ✓ 产物: $outApk" -ForegroundColor Green
  }
}

if ($Run) {
  Write-Host "`n[5] 运行..." -ForegroundColor Cyan
  flutter run -d windows
}

Write-Host "`n完成。" -ForegroundColor Green
