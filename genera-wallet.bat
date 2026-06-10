@echo off
REM ============================================================
REM  BTX Wallet Generator - PURE PYTHON, zero dipendenze.
REM  Reimplementa la derivazione indirizzi BTX dal sorgente btxd
REM  (pqhd + ML-DSA-44 + SLH-DSA-128s + merkle mr + bech32m).
REM  NON serve btxd ne' Internet. Serve solo Python 3.
REM
REM  Uso:  genera-wallet.bat              genera nuovo wallet (+ backup)
REM        genera-wallet.bat 5            genera nuovo wallet con 5 indirizzi
REM        genera-wallet.bat --test       self-test vs golden vector
REM ============================================================
cd /d "%~dp0"
if "%~1"=="" ( python btx_address.py & goto :eof )
if "%~1"=="--test" ( python btx_address.py --test & goto :eof )
echo %~1| findstr /r "^[0-9][0-9]*$" >nul && ( python btx_address.py --count %~1 & goto :eof )
python btx_address.py %*
