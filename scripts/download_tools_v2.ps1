$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'

$toolsDir = 'E:\hashcat_gui\assets\tools'

Write-Host "=== Retry downloading hcxpcaptool ===" -ForegroundColor Cyan

$dest = Join-Path $toolsDir 'hcxpcaptool.exe'

$urls = @(
    'https://github.com/ZerBea/hcxtools/releases/download/6.3.5/hcxpcaptool.exe',
    'https://github.com/ZerBea/hcxtools/releases/download/6.3.4/hcxpcaptool.exe',
    'https://github.com/ZerBea/hcxtools/releases/download/6.3.3/hcxpcaptool.exe',
    'https://github.com/ZerBea/hcxtools/releases/download/6.3.2/hcxpcaptool.exe',
    'https://github.com/ZerBea/hcxtools/releases/download/6.3.1/hcxpcaptool.exe',
    'https://github.com/ZerBea/hcxtools/releases/download/6.3.0/hcxpcaptool.exe'
)

$ok = $false
foreach ($url in $urls) {
    Write-Host "Trying: $url" -ForegroundColor Gray
    try {
        Invoke-WebRequest -Uri $url -OutFile $dest -UseBasicParsing -TimeoutSec 180
        if (Test-Path $dest) {
            $size = (Get-Item $dest).Length
            if ($size -gt 10000) {
                $sizeKB = [math]::Round($size / 1KB, 1)
                Write-Host "SUCCESS: $sizeKB KB" -ForegroundColor Green
                $ok = $true
                break
            } else {
                Write-Host "File too small ($size bytes), probably an error page" -ForegroundColor Yellow
                Remove-Item $dest -Force
            }
        }
    } catch {
        Write-Host "Failed: $($_.Exception.Message)" -ForegroundColor Yellow
    }
}

if (-not $ok) {
    Write-Host "All hcxpcaptool downloads failed" -ForegroundColor Red
}

Write-Host ""
Write-Host "=== Try john scripts from cdn.jsdelivr.net ===" -ForegroundColor Cyan

$cdnBase = 'https://cdn.jsdelivr.net/gh/openwall/john@bleeding-jumbo/run'

# pdf2john
$pdfPy = Join-Path $toolsDir 'pdf2john.py'
if (-not (Test-Path $pdfPy) -or (Get-Item $pdfPy).Length -lt 1000) {
    Write-Host "Downloading pdf2john.py from jsdelivr..." -ForegroundColor Yellow
    try {
        Invoke-WebRequest -Uri "$cdnBase/pdf2john.py" -OutFile $pdfPy -UseBasicParsing -TimeoutSec 60
        if ((Get-Item $pdfPy).Length -gt 1000) {
            Write-Host "OK" -ForegroundColor Green
        } else {
            Write-Host "File too small" -ForegroundColor Red
        }
    } catch {
        Write-Host "Failed: $($_.Exception.Message)" -ForegroundColor Red
    }
} else {
    Write-Host "pdf2john.py already exists" -ForegroundColor DarkGray
}

# office2john
$officePy = Join-Path $toolsDir 'office2john.py'
if (-not (Test-Path $officePy) -or (Get-Item $officePy).Length -lt 1000) {
    Write-Host "Downloading office2john.py from jsdelivr..." -ForegroundColor Yellow
    try {
        Invoke-WebRequest -Uri "$cdnBase/office2john.py" -OutFile $officePy -UseBasicParsing -TimeoutSec 60
        if ((Get-Item $officePy).Length -gt 1000) {
            Write-Host "OK" -ForegroundColor Green
        } else {
            Write-Host "File too small" -ForegroundColor Red
        }
    } catch {
        Write-Host "Failed: $($_.Exception.Message)" -ForegroundColor Red
    }
} else {
    Write-Host "office2john.py already exists" -ForegroundColor DarkGray
}

Write-Host ""
Write-Host "=== Final Tool List ===" -ForegroundColor Cyan
Get-ChildItem $toolsDir -File | Where-Object { $_.Name -ne '.gitkeep' } | ForEach-Object {
    $sizeKB = [math]::Round($_.Length / 1KB, 1)
    Write-Host "  $($_.Name)  ($sizeKB KB)" -ForegroundColor White
}
Write-Host "======================" -ForegroundColor Cyan
