#!/usr/bin/env python3
"""
BTX Offline Wallet Generator
Creates BTX Bech32 addresses and descriptors offline for secure wallet generation
"""

import os
import hashlib
import hmac
import base58
import ecdsa
import secrets
import json
from datetime import datetime
import subprocess

# SPHINCS+ import (post-quantum cryptography)
try:
    from pqcrypto.sign.sphincs_sha2_128f_simple import generate_keypair, sign, verify
    from pqcrypto.sign.sphincs_sha2_128f_simple import PUBLIC_KEY_SIZE, SECRET_KEY_SIZE
    SPHINCS_AVAILABLE = True
except ImportError:
    SPHINCS_AVAILABLE = False
    print("⚠️  SPHINCS+ library not available. SPHINCS+ wallet generation will be disabled.")

# BTX Network Parameters
BTX_MAINNET = {
    'PUBKEY_ADDRESS': bytes([25]),      # 0x19 - Legacy addresses (B...)
    'SCRIPT_ADDRESS': bytes([50]),      # 0x32 - P2SH addresses
    'SECRET_KEY': bytes([153]),         # 0x99 - WIF private keys (P...)
    'EXT_PUBLIC_KEY': bytes([0x04, 0x88, 0xB2, 0x1E]),
    'EXT_SECRET_KEY': bytes([0x04, 0x88, 0xAD, 0xE4]),
    'BECH32_HRP': 'btx'                 # Bech32 addresses (btx1...)
}

# Bech32 character set
BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

def polymod(c, val):
    c0 = c >> 35
    c = ((c & 0x7ffffffff) << 5) ^ val
    if c0 & 1:
        c ^= 0xf5dee51989
    if c0 & 2:
        c ^= 0xa9fdca3312
    if c0 & 4:
        c ^= 0x1bab10e32d
    if c0 & 8:
        c ^= 0x3706b1677a
    if c0 & 16:
        c ^= 0x644d626ffd
    return c

def calculate_descriptor_checksum(desc):
    INPUT_CHARSET = (
        "0123456789()[],'/*abcdefgh@:$%{}"
        "IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~"
        "ijklmnopqrstuvwxyzABCDEFGH`#\"\\ "
    )
    CHECKSUM_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

    c = 1
    cls = 0
    clscount = 0
    for ch in desc:
        pos = INPUT_CHARSET.find(ch)
        if pos == -1:
            return ""
        c = polymod(c, pos & 31)
        cls = cls * 3 + (pos >> 5)
        clscount += 1
        if clscount == 3:
            c = polymod(c, cls)
            cls = 0
            clscount = 0
            
    if clscount > 0:
        c = polymod(c, cls)
        
    for j in range(8):
        c = polymod(c, 0)
        
    c ^= 1
    
    ret = []
    for j in range(8):
        ret.append(CHECKSUM_CHARSET[(c >> (5 * (7 - j))) & 31])
    return "".join(ret)

def bech32_polymod(values):
    """Bech32 checksum calculation"""
    generator = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for value in values:
        top = chk >> 25
        chk = (chk & 0x1ffffff) << 5 ^ value
        for i in range(5):
            chk ^= generator[i] if ((top >> i) & 1) else 0
    return chk

def bech32_encode(hrp, data):
    """Encode data as Bech32 address"""
    # Combine HRP and data
    combined = []
    for c in hrp:
        combined.append(ord(c) >> 5)
    combined.append(0)
    for c in hrp:
        combined.append(ord(c) & 31)
    for d in data:
        combined.append(d)

    # Calculate checksum
    polymod = bech32_polymod(combined + [0, 0, 0, 0, 0, 0]) ^ 1
    checksum = []
    for i in range(6):
        checksum.append((polymod >> 5 * (5 - i)) & 31)

    # Combine and encode
    combined = combined + checksum

    # Convert to Bech32 string
    result = hrp + '1' + ''.join([BECH32_CHARSET[d] for d in combined[len(hrp)*2+1:]])
    return result

def bech32_decode(bech):
    """Decode Bech32 address"""
    # Convert characters to values
    values = []
    for c in bech:
        if c not in BECH32_CHARSET:
            return None, None
        values.append(BECH32_CHARSET.index(c))

    # Check checksum
    if bech32_polymod(values) != 1:
        return None, None

    # Separate HRP and data
    hrp_length = 0
    while values[hrp_length] >> 5 != 0:
        hrp_length += 1

    hrp = ''.join([chr((values[i] >> 5) | (values[i+1] << 3)) for i in range(hrp_length)])
    data = values[hrp_length+1:-6]

    return hrp, data

def base58_check_encode(data, prefix):
    """Encode data with Base58Check encoding"""
    extended = prefix + data
    checksum = hashlib.sha256(hashlib.sha256(extended).digest()).digest()[:4]
    return base58.b58encode(extended + checksum).decode('utf-8')

def generate_private_key():
    """Generate a random private key"""
    # Generate a random 32-byte private key
    private_key_bytes = secrets.token_bytes(32)

    # Ensure the private key is valid (not zero and less than the curve order)
    # For secp256k1, the order is 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    # We'll just regenerate if it's invalid (extremely unlikely)
    while len(private_key_bytes) != 32 or all(b == 0 for b in private_key_bytes):
        private_key_bytes = secrets.token_bytes(32)

    return private_key_bytes

def get_public_key(private_key_bytes, compressed=True):
    """Get public key from private key"""
    # Use ecdsa library to get public key
    sk = ecdsa.SigningKey.from_string(private_key_bytes, curve=ecdsa.SECP256k1)
    vk = sk.get_verifying_key()

    # Get public key in uncompressed format (65 bytes: 0x04 + 32-byte X + 32-byte Y)
    public_key_uncompressed = bytes([0x04]) + vk.to_string()

    if compressed:
        # Compress public key (33 bytes: 0x02/0x03 + 32-byte X)
        x = public_key_uncompressed[1:33]
        y = public_key_uncompressed[33:65]
        prefix = bytes([0x02 + (int.from_bytes(y, 'big') % 2)])
        return prefix + x
    else:
        return public_key_uncompressed

def hash160(data):
    """RIPEMD160(SHA256(data))"""
    sha256_hash = hashlib.sha256(data).digest()
    ripemd160 = hashlib.new('ripemd160')
    ripemd160.update(sha256_hash)
    return ripemd160.digest()

def convertbits(data, frombits, tobits, pad=True):
    """General power-of-2 base conversion."""
    acc = 0
    bits = 0
    ret = []
    maxv = (1 << tobits) - 1
    max_acc = (1 << (frombits + tobits - 1)) - 1
    for value in data:
        if value < 0 or (value >> frombits):
            return None
        acc = ((acc << frombits) | value) & max_acc
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad:
        if bits:
            ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        return None
    return ret

def generate_p2pkh_address(public_key_bytes):
    """Generate P2PKH address from public key"""
    # Hash the public key
    pubkey_hash = hash160(public_key_bytes)

    # Encode with Base58Check using BTX prefix
    return base58_check_encode(pubkey_hash, BTX_MAINNET['PUBKEY_ADDRESS'])

def generate_bech32_address(public_key_bytes):
    """Generate Bech32 (SegWit) address from public key - btx1... format"""
    # Hash the public key for witness program
    pubkey_hash = hash160(public_key_bytes)

    # Convert to witness program version 0 (P2WPKH)
    witness_version = 0

    # Convert 8-bit to 5-bit
    converted = convertbits(pubkey_hash, 8, 5)
    
    # Prepend the witness version (0)
    data = [witness_version] + converted

    # Encode as Bech32
    return bech32_encode(BTX_MAINNET['BECH32_HRP'], data)

def generate_wif_private_key(private_key_bytes):
    """Generate Wallet Import Format (WIF) private key"""
    # Add compression flag (0x01) for compressed public keys
    extended_key = private_key_bytes + bytes([0x01])

    # Encode with Base58Check using BTX secret key prefix
    return base58_check_encode(extended_key, BTX_MAINNET['SECRET_KEY'])

def generate_sphincs_plus_keys():
    """Generate SPHINCS+ key pair using post-quantum cryptography"""
    if not SPHINCS_AVAILABLE:
        raise RuntimeError("SPHINCS+ library not available")

    # Generate key pair using SPHINCS+ SHA2-128f-simple
    public_key, private_key = generate_keypair()

    return {
        'public_key': public_key,
        'private_key': private_key,
        'algorithm': 'sphincs_sha2_128f_simple',
        'public_key_size': len(public_key),
        'private_key_size': len(private_key)
    }

def generate_sphincs_plus_address(public_key_bytes):
    """Generate BTX address from SPHINCS+ public key"""
    # SPHINCS+ public keys are much larger than ECDSA keys
    # We need to hash them to create a compatible address format

    # Use SHA256 hash of the public key to create a consistent identifier
    pubkey_hash = hashlib.sha256(public_key_bytes).digest()

    # For Bech32 address, we need to convert to witness program format
    # Convert 8-bit to 5-bit for Bech32 encoding
    converted = convertbits(list(pubkey_hash), 8, 5)

    # Prepend the witness version (0 for P2WPKH compatibility)
    witness_version = 0
    data = [witness_version] + converted

    # Encode as Bech32 using BTX HRP
    return bech32_encode(BTX_MAINNET['BECH32_HRP'], data)

def generate_sphincs_plus_wif(private_key_bytes):
    """Generate WIF-like format for SPHINCS+ private key"""
    # SPHINCS+ keys are binary and much larger than ECDSA keys
    # We'll use a custom prefix to distinguish them from ECDSA keys

    # Use a custom prefix for SPHINCS+ keys (0xA0 = 160 in decimal)
    sphincs_prefix = bytes([160])  # 'Q' prefix for SPHINCS+ keys

    # Create extended key with algorithm identifier
    # Format: prefix + algorithm_byte + private_key
    algorithm_byte = bytes([0x01])  # 0x01 = SPHINCS+ SHA2-128f-simple
    extended_key = sphincs_prefix + algorithm_byte + private_key_bytes

    # Encode with Base58Check
    return base58_check_encode(extended_key, sphincs_prefix)

def generate_descriptor(private_key_bytes, public_key_bytes):
    """Generate BTX descriptor for wallet import"""
    # Get WIF private key
    wif_key = generate_wif_private_key(private_key_bytes)

    # Create descriptor string: wpkh(WIF_key) for P2WPKH
    descriptor = f"wpkh({wif_key})"

    # Generate timestamp - use current time for new wallets
    timestamp = int(datetime.now().timestamp())

    # Calculate checksum completely offline
    checksum = calculate_descriptor_checksum(descriptor)

    # Create full descriptor import JSON
    descriptor_import = {
        "desc": f"{descriptor}#{checksum}" if checksum else descriptor,
        "timestamp": timestamp,
        "active": False,
        "label": "Offline Wallet Import"
    }

    return {
        "descriptor_string": f"{descriptor}#{checksum}" if checksum else descriptor,
        "import_json": json.dumps([descriptor_import], indent=2)
    }

def generate_wallet(algorithm='ecdsa'):
    """Generate a complete BTX wallet with Bech32 address and descriptor"""
    wallet_data = {
        "wallet_info": {
            "network": "BTX Mainnet",
            "generation_date": datetime.now().isoformat(),
            "algorithm": algorithm
        }
    }

    if algorithm == 'sphincs':
        # SPHINCS+ (P2MR) wallet uses hierarchical derivation from a master seed.
        # Generate a random 32-byte master seed
        seed_bytes = secrets.token_bytes(32)
        seed_hex = seed_bytes.hex()
        
        # Calculate fingerprint (first 4 bytes of SHA256 of the master seed)
        h = hashlib.sha256(seed_bytes).digest()
        fingerprint_hex = h[:4].hex()

        # Construct the P2MR SPHINCS+ descriptor: mr(pqhd(seed/0h/0h/0/*), pk_slh(pqhd(seed/0h/0h/0/*)))
        sphincs_descriptor_string = f"mr(pqhd({seed_hex}/0h/0h/0/*),pk_slh(pqhd({seed_hex}/0h/0h/0/*)))"
        timestamp = int(datetime.now().timestamp())

        # Calculate checksum completely offline
        checksum = calculate_descriptor_checksum(sphincs_descriptor_string)
        descriptor_with_checksum = f"{sphincs_descriptor_string}#{checksum}" if checksum else sphincs_descriptor_string

        # Create descriptor import data with timestamp (ranged descriptors cannot have a label)
        sphincs_descriptor_import = {
            "desc": descriptor_with_checksum,
            "timestamp": timestamp,
            "active": False
        }

        # Attempt to derive address using btx-cli if available (including WSL)
        bech32_address = "Derived by BTX node upon descriptor import"
        try:
            # First try native btx-cli
            result = subprocess.check_output([
                'btx-cli', 'deriveaddresses', descriptor_with_checksum, '[0,0]'
            ], text=True)
            info = json.loads(result)
            bech32_address = info[0]
        except Exception:
            # Fallback: try invoking via WSL if available
            try:
                wsl_cmd_str = (
                    f"/home/lcs/btx/btx-0.30.1/bin/btx-cli "
                    f"-datadir=/home/lcs/.btx -chain=main deriveaddresses \"{descriptor_with_checksum}\" \"[0,0]\""
                )
                result = subprocess.check_output(['wsl', 'bash', '-c', wsl_cmd_str], text=True)
                info = json.loads(result)
                bech32_address = info[0]
            except Exception:
                pass

        # Create wallet data for SPHINCS+ (P2MR)
        wallet_data.update({
            "addresses": {
                "bech32_segwit": bech32_address,
                "legacy_p2pkh": "N/A (P2MR post-quantum address)"
            },
            "keys": {
                "private_key_wif": f"N/A (Master Seed: {seed_hex})",
                "private_key_hex": seed_hex,
                "public_key_hex": f"Derived hierarchically (Master Fingerprint: {fingerprint_hex})"
            },
            "explorer_urls": {
                "bech32": f'https://explorer.minebtx.com/address/{bech32_address}' if bech32_address != "Derived by BTX node upon descriptor import" else "N/A",
                "legacy": "N/A"
            },
            "descriptor": {
                "string": descriptor_with_checksum,
                "import_json_data": sphincs_descriptor_import
            }
        })

    else:
        # Original ECDSA implementation
        # Generate private key
        private_key = generate_private_key()

        # Get public key (compressed)
        public_key = get_public_key(private_key, compressed=True)

        # Generate both address formats
        legacy_address = generate_p2pkh_address(public_key)  # Starts with B
        bech32_address = generate_bech32_address(public_key)  # Starts with btx1

        # Generate WIF private key
        wif_private_key = generate_wif_private_key(private_key)

        # Generate descriptor
        descriptor = generate_descriptor(private_key, public_key)

        # Create wallet data for ECDSA
        wallet_data.update({
            "addresses": {
                "bech32_segwit": bech32_address,
                "legacy_p2pkh": legacy_address
            },
            "keys": {
                "private_key_wif": wif_private_key,
                "private_key_hex": private_key.hex(),
                "public_key_hex": public_key.hex()
            },
            "descriptor": {
                "string": descriptor["descriptor_string"],
                "import_json_data": json.loads(descriptor["import_json"])[0]
            },
            "explorer_urls": {
                "bech32": f'https://explorer.minebtx.com/address/{bech32_address}',
                "legacy": f'https://explorer.minebtx.com/address/{legacy_address}'
            }
        })

    return wallet_data

def save_wallet(wallet_data, filename_base=None):
    """Save wallet data to file"""
    if filename_base is None:
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename_base = f'btx_wallet_backup_{timestamp}'

    json_filename = f'{filename_base}.json'
    txt_filename = f'{filename_base}.txt'

    # Save JSON securely and properly formatted
    with open(json_filename, 'w', encoding='utf-8') as f:
        json.dump(wallet_data, f, indent=4, ensure_ascii=False)

    # Save TXT visually readable
    with open(txt_filename, 'w', encoding='utf-8') as f:
        f.write("=================================================================\n")
        f.write("                 BTX OFFLINE WALLET BACKUP                       \n")
        f.write("=================================================================\n\n")
        f.write(f"Generated on: {wallet_data['wallet_info']['generation_date']}\n")
        f.write(f"Network:      {wallet_data['wallet_info']['network']}\n")
        f.write(f"Algorithm:    {wallet_data['wallet_info']['algorithm'].upper()}\n\n")

        # Check if this is a SPHINCS+ wallet
        is_sphincs = wallet_data['wallet_info']['algorithm'] == 'sphincs'

        f.write("--- PUBLIC ADDRESSES (Share to receive BTX) ---\n")
        f.write(f"Bech32 Address              : {wallet_data['addresses']['bech32_segwit']}\n")
        f.write(f"Legacy Address               : {wallet_data['addresses']['legacy_p2pkh']}\n\n")

        f.write("--- PRIVATE KEYS (SECRET - NEVER SHARE WITH ANYONE!) ---\n")
        f.write(f"Private Key (WIF)            : {wallet_data['keys']['private_key_wif']}\n\n")

        if is_sphincs and 'algorithm_info' in wallet_data['keys']:
            f.write("--- SPHINCS+ KEY INFORMATION ---\n")
            f.write(f"Algorithm Type               : {wallet_data['keys']['algorithm_info']['type']}\n")
            f.write(f"Public Key Size             : {wallet_data['keys']['algorithm_info']['public_key_size']} bytes\n")
            f.write(f"Private Key Size            : {wallet_data['keys']['algorithm_info']['private_key_size']} bytes\n")
            f.write(f"Security Level              : Post-Quantum Secure (SHA2-128f)\n\n")

        f.write("--- DESCRIPTOR (To import your wallet) ---\n")
        f.write(f"Descriptor String            : {wallet_data['descriptor']['string']}\n\n")

        # Prepare the json string for copy paste without external spaces
        json_import_str = json.dumps([wallet_data['descriptor']['import_json_data']], indent=2)

        f.write("--- HOW TO IMPORT IN BTX WALLET ---\n")
        f.write("From Linux / WSL:\n")
        f.write(f"btx-cli -chain=main -rpcwallet=MyWallet importdescriptors '{json_import_str}'\n\n")

        if not is_sphincs:
            f.write("From Windows:\n")
            f.write(f"btx-cli.exe importprivkey \"{wallet_data['keys']['private_key_wif']}\" \"MyOfflineWallet\"\n\n")

        f.write("=================================================================\n")
        f.write(" SECURITY WARNINGS:\n")
        f.write(" 1. Print this file or save it on a secure USB drive.\n")
        f.write(" 2. DO NOT save this file on a computer connected to the internet.\n")
        f.write(" 3. Anyone with access to your Private Key can steal your funds.\n")

        if is_sphincs:
            f.write(" 4. SPHINCS+ keys are EXPERIMENTAL - test with small amounts first.\n")
            f.write(" 5. Post-quantum wallets may not be compatible with all services.\n")

        f.write("=================================================================\n")

    print(f'\n💰 Wallet generated successfully!')
    print(f'📝 Saved JSON to: {json_filename}')
    print(f'📝 Saved TXT to:  {txt_filename}')
    print(f'🔗 Bech32 Address: {wallet_data["addresses"]["bech32_segwit"]}')
    print(f'🔗 Legacy Address: {wallet_data["addresses"]["legacy_p2pkh"]}')
    print(f'⚠️  IMPORTANT: Backup the TXT and JSON files securely!')

    return json_filename, txt_filename

def main():
    """Main function"""
    print("🔐 BTX Offline Wallet Generator")
    print("=" * 50)
    print("Generating a secure BTX wallet offline...")
    print("This wallet uses Bech32 (btx1...) addresses with descriptor support")
    print()

    # Ask user for algorithm choice
    algorithm = 'ecdsa'  # Default to ECDSA
    if SPHINCS_AVAILABLE:
        print("🔮 Select wallet algorithm:")
        print("1. ECDSA (Standard)")
        print("2. SPHINCS+ (Post-Quantum - Experimental)")
        print()

        choice = input("Enter your choice (1-2, default=1): ").strip()
        if choice == '2':
            algorithm = 'sphincs'
            print("✅ SPHINCS+ post-quantum wallet selected")
        else:
            print("✅ ECDSA standard wallet selected")
        print()

    try:
        # Generate wallet with selected algorithm
        wallet = generate_wallet(algorithm)

        # Save wallet
        json_file, txt_file = save_wallet(wallet)

        # Display appropriate completion message based on algorithm
        if algorithm == 'sphincs':
            print(f'\n✅ SPHINCS+ Post-Quantum Wallet generation complete!')
            print(f'📋 Bech32 Address: {wallet["addresses"]["bech32_segwit"]}')
            print(f'📋 Legacy Address: {wallet["addresses"]["legacy_p2pkh"]}')
            print(f'🔑 Private Key (WIF): {wallet["keys"]["private_key_wif"]}')
            print(f'🌐 Check balance: {wallet["explorer_urls"]["bech32"]}')
            print(f'🔬 Algorithm: {wallet["wallet_info"]["algorithm"]} (Post-Quantum Secure)')
        else:
            print(f'\n✅ ECDSA Wallet generation complete!')
            print(f'📋 Bech32 Address: {wallet["addresses"]["bech32_segwit"]}')
            print(f'📋 Legacy Address: {wallet["addresses"]["legacy_p2pkh"]}')
            print(f'🔑 Private Key (WIF): {wallet["keys"]["private_key_wif"]}')
            print(f'🌐 Check balance: {wallet["explorer_urls"]["bech32"]}')

        # Show backup instructions
        print(f'\n📝 BACKUP INSTRUCTIONS:')
        print('1. Make multiple copies of the JSON file')
        print('2. Store in secure locations (USB drives, encrypted storage)')
        print('3. Never share your private key or descriptor')
        print('4. Test by sending a small amount first')

        # Show appropriate import instructions based on algorithm
        print(f'\n🔧 TO IMPORT TO BTX WALLET:')
        print('Check the generated TXT file for detailed import commands!')

        print()
        print('Method 1 (Descriptors):')
        print(f'1. Open BTX wallet CLI')
        json_import_str = json.dumps([wallet["descriptor"]["import_json_data"]])
        print(f'2. Run: importdescriptors \'{json_import_str}\'')
        print('3. Rescan blockchain if needed')

        if algorithm != 'sphincs':
            print()
            print('Method 2 (Legacy - Private Key):')
            print(f'1. Open BTX wallet CLI')
            print(f'2. Run: importprivkey "{wallet["keys"]["private_key_wif"]}" "wallet_label"')
            print('3. Rescan blockchain if needed')

    except Exception as e:
        print(f'❌ Error generating wallet: {e}')
        return 1

    return 0

if __name__ == '__main__':
    import sys
    # Check if required libraries are available
    try:
        import ecdsa
        import base58
    except ImportError:
        print("⚠️  Required libraries not found!")
        print("Installing required packages...")

        # Try to install required packages
        try:
            import subprocess

            # Install ecdsa
            subprocess.check_call([sys.executable, "-m", "pip", "install", "ecdsa"])

            # Install base58
            subprocess.check_call([sys.executable, "-m", "pip", "install", "base58"])

            print("✅ Libraries installed successfully!")
            print("Please run the script again.")

        except Exception as e:
            print(f"❌ Failed to install libraries: {e}")
            print("Please install manually:")
            print("  pip install ecdsa base58")
            sys.exit(1)

        sys.exit(0)

    # Run main function
    sys.exit(main())
