@echo off
Title GPerf && Color 0b

:: Step 1: Elevate
>nul 2>&1 fsutil dirty query %systemdrive% || echo CreateObject^("Shell.Application"^).ShellExecute "%~0", "ELEVATED", "", "runas", 1 > "%temp%\uac.vbs" && "%temp%\uac.vbs" && exit /b
DEL /F /Q "%temp%\uac.vbs"

:: Step 2: Move to the script directory
cd /d %~dp0

:: Step 3: Working folder
cd Bin

:: Step 4: Initialize environment 
setlocal EnableExtensions DisableDelayedExpansion

:: Step 5: Execute CMD
call GPerf.cmd

:: Step 6: Execute Registry
reg import GPerf.reg

:: Step 7: Install RamCleaner
copy /y emptystandbylist.exe %windir%\Setup\Scripts\emptystandbylist.exe
copy /y RamCleaner.bat %windir%\Setup\Scripts\RamCleaner.bat
schtasks /create /tn "RamCleaner" /xml "RamCleaner.xml" /ru "SYSTEM"
