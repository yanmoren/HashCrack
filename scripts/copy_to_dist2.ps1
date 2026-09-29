$build = 'E:\hashcat_gui\build\windows\x64\runner\Release'
$dist = 'E:\hashcat_gui\dist\windows'

# Copy build output to dist
Copy-Item -Path "$build\*" -Destination $dist -Recurse -Force
Write-Host "Copied build to dist"

# Verify hashcat exists in dist
$hashcatPath = "$dist\hashcat\hashcat.exe"
if (Test-Path $hashcatPath) {
    $size = (Get-Item $hashcatPath).Length
    Write-Host "hashcat.exe exists: $hashcatPath ($size bytes)"
} else {
    Write-Host "hashcat.exe NOT found, copying from D:\app\hashcat-7.1.2"
    Copy-Item -Path 'D:\app\hashcat-7.1.2' -Destination "$dist\hashcat" -Recurse -Force
}

# Verify main exe
$guiExe = "$dist\hashcat_gui.exe"
if (Test-Path $guiExe) {
    Write-Host "hashcat_gui.exe exists: $guiExe"
} else {
    Write-Host "ERROR: hashcat_gui.exe NOT found!"
}

# List key files
Write-Host "`n=== Key files in dist\windows ==="
Get-ChildItem $dist -File | Select-Object Name, Length | Format-Table -AutoSize
Write-Host "`n=== hashcat directory ==="
Get-ChildItem "$dist\hashcat" -File | Select-Object Name, Length | Format-Table -AutoSize
