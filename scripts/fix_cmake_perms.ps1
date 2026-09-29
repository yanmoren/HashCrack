$cxxBase = 'E:\flutter_data\Pub\Cache\hosted\pub.dev\jni-1.0.3\android\.cxx'
if (-not (Test-Path $cxxBase)) {
    New-Item -ItemType Directory -Path $cxxBase -Force | Out-Null
}
Get-ChildItem -Path $cxxBase -Recurse -Force -ErrorAction SilentlyContinue | ForEach-Object {
    $_.Attributes = 'Normal'
}
Write-Host 'Permissions fixed on .cxx directory'
