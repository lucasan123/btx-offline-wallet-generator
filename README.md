# 🔐 BTX Offline Wallet Generator
 btx.dev
**Secure offline wallet generator for BTX (BTX.dev) - Windows Edition**

This tool generates BTX wallets completely offline, ensuring your private keys never touch the internet. Perfect for cold storage and secure wallet creation.

## 📁 Files Included

- `btx-offline-wallet-generator.exe` - Pre-compiled Windows executable (No Python required!)
- `run-generator-exe.bat` - Windows batch file to run the pre-compiled executable directly
- `btx-offline-wallet-generator.py` - Main Python script
- `generate-btx-wallet.bat` - Windows batch file to run using Python
- `verify-btx-address.py` - Address verification tool
- `README-BTX-WALLET-GENERATOR.md` - This file

## 🚀 Quick Start

### Method 1: Using the Pre-compiled Executable (Easiest)
1. Double-click `run-generator-exe.bat`
2. Follow the on-screen instructions
3. Backup your wallet files securely

### Method 2: Using the Python Batch File
1. Double-click `generate-btx-wallet.bat`
2. Follow the on-screen instructions

### Method 3: Using Python Directly
```bash
python btx-offline-wallet-generator.py
```

## 📦 Requirements (Only for Method 2 & 3)

- **Python 3.6+** (https://www.python.org/downloads/)
- Python libraries: `ecdsa`, `base58`, `pqcrypto` (installed automatically)

## 🔒 Security Features

✅ **Completely Offline** - No internet connection required
✅ **Secure Random Generation** - Uses cryptographically secure random numbers
✅ **SPHINCS+ (P2MR) Support** - Post-Quantum secure wallets (starts with 'btx1z')
✅ **ECDSA Support** - Standard secure wallets
✅ **Offline Checksum Calculation** - 100% offline generation of valid descriptors with checksums

## 💼 Wallet Formats

### 1. SPHINCS+ (P2MR - Post-Quantum)
- **Address Type**: Pay-to-Merkle-Root (starts with 'btx1z')
- **Backup**: Master Seed (32-byte hex) + P2MR Descriptor
- **Descriptor**: `mr(pqhd(seed/0h/0h/0/*),pk_slh(pqhd(seed/0h/0h/0/*)))#checksum`

### 2. ECDSA (Standard)
- **Address Type**: Pay-to-Witness-PubKey-Hash (starts with 'btx1q')
- **Backup**: Private Key (WIF) + Descriptor
- **Descriptor**: `wpkh(wif_key)#checksum`

## 🔄 Importing to BTX Wallet

### Method 1: Importing Descriptor (Recommended for both ECDSA & SPHINCS+)
1. Open BTX wallet CLI
2. Run `importdescriptors` command using the JSON payload generated in your backup `.txt` file:
```bash
btx-cli -chain=main -rpcwallet=MyWallet importdescriptors '[{"desc": "DESCRIPTOR_WITH_CHECKSUM", "timestamp": TIMESTAMP, "active": false}]'
```
3. Rescan blockchain if needed: `rescanblockchain`

### Method 2: Importing Private Key (ECDSA Only)
1. Open BTX wallet CLI
2. Run: `importprivkey "YOUR_PRIVATE_KEY_WIF" "wallet_label"`
3. Rescan blockchain if needed: `rescanblockchain`

## ⚠️ SECURITY WARNINGS

🔴 **NEVER share your private key or master seed with anyone**
🔴 **Always test with small amounts first**
🔴 **Make multiple secure backups**
🔴 **Store backups in different physical locations**
🔴 **Use encrypted storage for digital backups**

---

**Stay safe, keep your keys offline! 🔐**
