@echo off
:: BTX Offline Wallet Generator - Windows Batch File
:: Runs the pre-compiled executable directly

echo 🔐 BTX Offline Wallet Generator
echo ==============================
echo.
echo This will run the secure BTX wallet generator completely offline.
echo No Python installation is required!
echo.

:: Run the compiled executable
cd /d %~dp0
if exist btx-offline-wallet-generator.exe (
    btx-offline-wallet-generator.exe
) else (
    echo ❌ Error: btx-offline-wallet-generator.exe not found!
    echo Please make sure you extracted all files from the ZIP archive.
)

pause
