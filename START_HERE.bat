@echo off
chcp 65001 >nul 2>&1
title HashCrack - Start Here
cls
echo.
echo  ===============================================
echo   HashCrack - hashcat GUI Build & Run
echo  ===============================================
echo.
echo  [1] Run setup (install build dependencies - first time only)
echo  [2] Build Windows EXE + Android APK
echo  [3] Build Windows only
echo  [4] Build Android only
echo  [5] Run in debug mode (Windows)
echo  [6] Exit
echo.
set /p choice="Select option (1-6): "

if "%choice%"=="1" (
    powershell -ExecutionPolicy Bypass -File scripts\setup.ps1
    pause
)
if "%choice%"=="2" (
    powershell -ExecutionPolicy Bypass -File scripts\build_all.ps1
    pause
)
if "%choice%"=="3" (
    powershell -ExecutionPolicy Bypass -File scripts\build_all.ps1 -WindowsOnly
    pause
)
if "%choice%"=="4" (
    powershell -ExecutionPolicy Bypass -File scripts\build_all.ps1 -AndroidOnly
    pause
)
if "%choice%"=="5" (
    powershell -ExecutionPolicy Bypass -File scripts\run.ps1
)
if "%choice%"=="6" exit
