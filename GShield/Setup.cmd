@echo off
Title GShield && Color 0b

:: Step 1: Elevate
>nul 2>&1 fsutil dirty query %systemdrive% || echo CreateObject^("Shell.Application"^).ShellExecute "%~0", "ELEVATED", "", "runas", 1 > "%temp%\uac.vbs" && "%temp%\uac.vbs" && exit /b
DEL /F /Q "%temp%\uac.vbs"

:: Step 2: Move to the script directory
cd /d %~dp0

:: Step 3: Working folder
cd Bin

:: Step 4: Initialize environment 
setlocal EnableExtensions EnableDelayedExpansion

:: Step 5: Execute PowerShell (.ps1) files alphabetically
for /f "tokens=*" %%B in ('dir /b /o:n *.ps1') do (
    powershell -ExecutionPolicy Bypass -File "%%B"
)

:: Step 6: Resident Protection
mkdir %windir%\Setup\Scripts
copy /y GSecurity.ps1 %windir%\Setup\Scripts\GSecurity.ps1
schtasks /create /tn "GSecurity" /xml "GSecurity.xml" /ru "SYSTEM"

:: Step 7: Execute Registry (.reg) files alphabetically
for /f "tokens=*" %%R in ('dir /b /o:n *.reg') do (
    reg import "%%R"
)

:: Step 8: Execute CMD (.cmd) files alphabetically
for /f "tokens=*" %%A in ('dir /b /o:n *.cmd') do (
    call "%%A"
)
