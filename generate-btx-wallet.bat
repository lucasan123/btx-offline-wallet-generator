@echo off
:: BTX Offline Wallet Generator - Windows Batch File
:: This script generates a BTX wallet offline

echo 🔐 BTX Offline Wallet Generator
echo ==============================
echo.
echo This will generate a secure BTX wallet offline.
echo You need Python installed to run this script.
echo.

:: Check if Python is installed
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ❌ Python is not installed or not in PATH.
    echo.
    echo Please install Python from https://www.python.org/downloads/
    echo Make sure to check "Add Python to PATH" during installation.
    echo.
    pause
    exit /b 1
)

:: Check if required libraries are installed
python -c "import ecdsa, base58" >nul 2>&1
if %errorlevel% neq 0 (
    echo 📦 Installing required Python libraries...
    echo.

    :: Install ecdsa
    pip install ecdsa
    if %errorlevel% neq 0 (
        echo ❌ Failed to install ecdsa
        pause
        exit /b 1
    )

    :: Install base58
    pip install base58
    if %errorlevel% neq 0 (
        echo ❌ Failed to install base58
        pause
        exit /b 1
    )

    echo ✅ Libraries installed successfully!
    echo.
)

:: Run the wallet generator
echo 🚀 Generating BTX wallet...
echo.
cd /d %~dp0
python btx-offline-wallet-generator.py

if %errorlevel% equ 0 (
    echo.
    echo 🎉 Wallet generation complete!
    echo.
    echo 📝 IMPORTANT SECURITY NOTES:
    echo 1. Backup the generated JSON file securely
    echo 2. Store multiple copies in different locations
    echo 3. Never share your private key with anyone
    echo 4. Test with small amounts before sending large transactions
    echo.
) else (
    echo.
    echo ❌ Wallet generation failed.
    echo.
)

pause