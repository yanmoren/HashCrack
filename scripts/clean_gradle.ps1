$env:JAVA_HOME = 'C:\Program Files\Microsoft\jdk-17.0.20.101-hotspot'
$env:ANDROID_HOME = 'E:\hashcat_gui\.android_sdk'
$env:ANDROID_SDK_ROOT = 'E:\hashcat_gui\.android_sdk'

# Stop Gradle daemons
$gradleExe = Get-ChildItem -Path 'E:\hashcat_gui' -Filter 'gradlew.bat' -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
if ($gradleExe) {
    Start-Process -FilePath $gradleExe.FullName -ArgumentList '--stop' -Wait -NoNewWindow
}

# Kill any lingering Gradle/Java processes related to this build
Get-Process -Name 'java','gradle' -ErrorAction SilentlyContinue | Where-Object { $_.CommandLine -like '*hashcat_gui*' -or $_.CommandLine -like '*flutter_data*' } | Stop-Process -Force -ErrorAction SilentlyContinue

# Remove .cxx directory completely
Remove-Item -Recurse -Force 'E:\flutter_data\Pub\Cache\hosted\pub.dev\jni-1.0.3\android\.cxx' -ErrorAction SilentlyContinue
Remove-Item -Recurse -Force 'E:\hashcat_gui\android\.cxx' -ErrorAction SilentlyContinue
Remove-Item -Recurse -Force 'E:\hashcat_gui\android\.gradle' -ErrorAction SilentlyContinue

Write-Host 'Gradle daemons stopped and .cxx directories removed'
