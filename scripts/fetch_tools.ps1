<#
.SYNOPSIS
  获取 hashcat 哈希提取工具（zip2john / pdf2john / office2john / hcxpcaptool）
  放到项目 tools 目录，供 HashCrack 调用。
#>
param(
  [string]$ToolsDir = "$PSScriptRoot\..\assets\tools"
)

$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'

if (-not (Test-Path $ToolsDir)) { New-Item -ItemType Directory -Path $ToolsDir -Force | Out-Null }
Write-Host "工具目录: $ToolsDir" -ForegroundColor Cyan

$web = (Get-Command Invoke-WebRequest -ErrorAction SilentlyContinue) -ne $null
function TryDownload($url, $dest) {
  Write-Host "  下载: $url" -ForegroundColor Gray
  try {
    Invoke-WebRequest -Uri $url -OutFile $dest -UseBasicParsing -TimeoutSec 60
    if (Test-Path $dest) { Write-Host "  ✓ 成功 -> $dest" -ForegroundColor Green; return $true }
  } catch { Write-Host "  ✗ 失败: $($_.Exception.Message)" -ForegroundColor Yellow }
  return $false
}

# 1. JohnTheRipper 的 Python 脚本（单文件、无第三方依赖）
$pyBase = 'https://raw.githubusercontent.com/openwall/john/bleeding-jumbo/run'
$pyTools = @(
  @{ name = 'pdf2john.py';     url = "$pyBase/pdf2john.py" },
  @{ name = 'office2john.py';  url = "$pyBase/office2john.py" }
)
Write-Host "`n[1/4] 下载 JohnTheRipper Python 提取脚本..." -ForegroundColor Cyan
foreach ($t in $pyTools) {
  $dest = Join-Path $ToolsDir $t.name
  if (Test-Path $dest) { Write-Host "  已存在，跳过: $($t.name)" -ForegroundColor DarkGray; continue }
  [void](TryDownload $t.url $dest)
}

# 2. zip2john —— 优先用随附的 zip2john.py（基于 zipfile），否则尝试下载 john 二进制
Write-Host "`n[2/4] zip2john..." -ForegroundColor Cyan
$bundledZip = Join-Path $ToolsDir 'zip2john.py'
if (-not (Test-Path $bundledZip)) {
  $bundled = "$PSScriptRoot\zip2john.py"
  if (Test-Path $bundled) { Copy-Item $bundled $bundledZip -Force; Write-Host "  ✓ 使用随附 zip2john.py" -ForegroundColor Green }
}
if (Test-Path (Join-Path $ToolsDir 'zip2john.exe')) {
  Write-Host "  zip2john.exe 已存在" -ForegroundColor DarkGray
}

# 3. hcxpcaptool —— 从 hcxtools release 获取 Windows 版本
Write-Host "`n[3/4] hcxpcaptool（WiFi 握手包转换）..." -ForegroundColor Cyan
$hcxExe = Join-Path $ToolsDir 'hcxpcaptool.exe'
if (Test-Path $hcxExe) {
  Write-Host "  已存在" -ForegroundColor DarkGray
} else {
  $hcxUrls = @(
    'https://github.com/ZerBea/hcxtools/releases/latest/download/hcxpcaptool.exe',
    'https://github.com/ZerBea/hcxtools/releases/download/6.3.5/hcxpcaptool.exe'
  )
  $got = $false
  foreach ($u in $hcxUrls) { if (TryDownload $u $hcxExe) { $got = $true; break } }
  if (-not $got) {
    Write-Host "  ! 自动下载失败。请手动从 https://github.com/ZerBea/hcxtools/releases" -ForegroundColor Yellow
    Write-Host "    下载 hcxpcaptool.exe 放到: $ToolsDir" -ForegroundColor Yellow
  }
}

# 4. JohnTheRipper Windows 二进制（可选，提供 zip2john.exe / office2john.exe 的原生版）
Write-Host "`n[4/4] JohnTheRipper Windows 二进制（可选）..." -ForegroundColor Cyan
$johnZip = Join-Path $env:TEMP 'john-win64.zip'
$johnDir = Join-Path $env:TEMP 'john-extract'
$johnUrls = @(
  'https://openwall.info/john/john-1.9.0-jumbo-1-win64.zip',
  'https://github.com/openwall/john/releases/download/1.9.0-jumbo-1/john-1.9.0-jumbo-1-win64.zip'
)
$gotJohn = $false
foreach ($u in $johnUrls) { if (TryDownload $u $johnZip) { $gotJohn = $true; break } }
if ($gotJohn) {
  Expand-Archive -Path $johnZip -DestinationPath $johnDir -Force
  $johnBin = Get-ChildItem -Path $johnDir -Recurse -Filter 'zip2john.exe' | Select-Object -First 1
  if ($johnBin) {
    Copy-Item $johnBin.FullName (Join-Path $ToolsDir 'zip2john.exe') -Force
    Write-Host "  ✓ 提取 zip2john.exe" -ForegroundColor Green
  }
  $officeBin = Get-ChildItem -Path $johnDir -Recurse -Filter 'office2john.exe' | Select-Object -First 1
  if ($officeBin) {
    Copy-Item $officeBin.FullName (Join-Path $ToolsDir 'office2john.exe') -Force
    Write-Host "  ✓ 提取 office2john.exe" -ForegroundColor Green
  }
  Remove-Item $johnZip -Force -ErrorAction SilentlyContinue
} else {
  Write-Host "  ! 跳过（Python 版脚本已足够处理 PDF/Office/ZIP）" -ForegroundColor DarkGray
}

# 结果汇总
Write-Host "`n================ 工具清单 ================" -ForegroundColor Cyan
Get-ChildItem $ToolsDir -File | ForEach-Object {
  Write-Host ("  {0,-22} {1,10}" -f $_.Name, $_.Length) -ForegroundColor White
}
Write-Host "========================================`n" -ForegroundColor Cyan
Write-Host "提示：Python 脚本需系统已安装 Python。如未安装，请从 python.org 下载。" -ForegroundColor DarkGray
