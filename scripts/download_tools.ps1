$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'

$toolsDir = 'E:\hashcat_gui\assets\tools'
if (-not (Test-Path $toolsDir)) {
    New-Item -ItemType Directory -Path $toolsDir -Force | Out-Null
}

Write-Host "=== Downloading hash extraction tools ===" -ForegroundColor Cyan

# 1. hcxpcaptool (WiFi handshake converter)
Write-Host ""
Write-Host "[1/4] hcxpcaptool.exe..." -ForegroundColor Yellow
$hcxExe = Join-Path $toolsDir 'hcxpcaptool.exe'
if (Test-Path $hcxExe) {
    Write-Host "  Already exists" -ForegroundColor DarkGray
} else {
    $urls = @(
        'https://github.com/ZerBea/hcxtools/releases/latest/download/hcxpcaptool.exe'
    )
    $ok = $false
    foreach ($url in $urls) {
        Write-Host "  Trying: $url" -ForegroundColor Gray
        try {
            Invoke-WebRequest -Uri $url -OutFile $hcxExe -UseBasicParsing -TimeoutSec 120
            if (Test-Path $hcxExe -and (Get-Item $hcxExe).Length -gt 10000) {
                $sizeKB = [math]::Round((Get-Item $hcxExe).Length / 1KB, 1)
                Write-Host "  OK ($sizeKB KB)" -ForegroundColor Green
                $ok = $true
                break
            }
        } catch {
            Write-Host "  Failed: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
    if (-not $ok) {
        Write-Host "  hcxpcaptool download FAILED" -ForegroundColor Red
    }
}

# 2. zip2john.py
Write-Host ""
Write-Host "[2/4] zip2john.py..." -ForegroundColor Yellow
$zipPy = Join-Path $toolsDir 'zip2john.py'
if (Test-Path $zipPy) {
    Write-Host "  Already exists" -ForegroundColor DarkGray
} else {
    $pyCode = @"
#!/usr/bin/env python3
import sys
import zipfile
import os

def extract_zip_hash(zip_path):
    try:
        zf = zipfile.ZipFile(zip_path)
    except Exception as e:
        print("Error: %s" % e, file=sys.stderr)
        return 1

    encrypted_file = None
    for info in zf.infolist():
        if info.flag_bits & 0x1:
            encrypted_file = info
            break

    if not encrypted_file:
        print("No encrypted files found in zip", file=sys.stderr)
        return 1

    if encrypted_file.compress_type == 99:
        print("AES encrypted zip not supported by this simple extractor", file=sys.stderr)
        return 1

    name = os.path.basename(zip_path)
    crc = "%08x" % encrypted_file.CRC
    comp_size = encrypted_file.compress_size
    uncomp_size = encrypted_file.file_size

    with open(zip_path, 'rb') as f:
        data = f.read()
        pos = data.find(b'PK\x03\x04')
        if pos < 0:
            print("Cannot find local file header", file=sys.stderr)
            return 1
        fname_len = int.from_bytes(data[pos+26:pos+28], 'little')
        extra_len = int.from_bytes(data[pos+28:pos+30], 'little')
        data_start = pos + 30 + fname_len + extra_len
        enc_data = data[data_start:data_start + min(comp_size, 128)]

    enc_hex = enc_data.hex()
    fname_hex = encrypted_file.filename.encode('utf-8').hex()
    fname_len_bytes = len(encrypted_file.filename.encode('utf-8'))
    hash_line = "%s:\$zip2\$0*0*0*0*%d*%d*%s*%d*%s*%s*\$/zip2\$" % (
        name, comp_size, uncomp_size, crc, fname_len_bytes, fname_hex, enc_hex)
    print(hash_line)
    return 0

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: zip2john.py <zipfile>", file=sys.stderr)
        sys.exit(1)
    sys.exit(extract_zip_hash(sys.argv[1]))
"@
    Set-Content -Path $zipPy -Value $pyCode -Encoding ASCII
    Write-Host "  Created (Python version)" -ForegroundColor Green
}

# 3. pdf2john.py
Write-Host ""
Write-Host "[3/4] pdf2john.py..." -ForegroundColor Yellow
$pdfPy = Join-Path $toolsDir 'pdf2john.py'
if (Test-Path $pdfPy) {
    Write-Host "  Already exists" -ForegroundColor DarkGray
} else {
    $url = 'https://raw.githubusercontent.com/openwall/john/bleeding-jumbo/run/pdf2john.py'
    Write-Host "  Downloading: $url" -ForegroundColor Gray
    try {
        Invoke-WebRequest -Uri $url -OutFile $pdfPy -UseBasicParsing -TimeoutSec 60
        if (Test-Path $pdfPy -and (Get-Item $pdfPy).Length -gt 1000) {
            Write-Host "  OK" -ForegroundColor Green
        } else {
            Write-Host "  File too small, download may have failed" -ForegroundColor Yellow
        }
    } catch {
        Write-Host "  Download failed: $($_.Exception.Message)" -ForegroundColor Yellow
    }
}

# 4. office2john.py
Write-Host ""
Write-Host "[4/4] office2john.py..." -ForegroundColor Yellow
$officePy = Join-Path $toolsDir 'office2john.py'
if (Test-Path $officePy) {
    Write-Host "  Already exists" -ForegroundColor DarkGray
} else {
    $url = 'https://raw.githubusercontent.com/openwall/john/bleeding-jumbo/run/office2john.py'
    Write-Host "  Downloading: $url" -ForegroundColor Gray
    try {
        Invoke-WebRequest -Uri $url -OutFile $officePy -UseBasicParsing -TimeoutSec 60
        if (Test-Path $officePy -and (Get-Item $officePy).Length -gt 1000) {
            Write-Host "  OK" -ForegroundColor Green
        } else {
            Write-Host "  File too small, download may have failed" -ForegroundColor Yellow
        }
    } catch {
        Write-Host "  Download failed: $($_.Exception.Message)" -ForegroundColor Yellow
    }
}

Write-Host ""
Write-Host "=== Tool List ===" -ForegroundColor Cyan
Get-ChildItem $toolsDir -File | Where-Object { $_.Name -ne '.gitkeep' } | ForEach-Object {
    $sizeKB = [math]::Round($_.Length / 1KB, 1)
    Write-Host "  $($_.Name)  ($sizeKB KB)" -ForegroundColor White
}
Write-Host "================" -ForegroundColor Cyan
