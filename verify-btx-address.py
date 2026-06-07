#!/usr/bin/env python3
"""
BTX Address Verification Script
Verifies that generated BTX addresses are valid
"""

import hashlib
import base58
import ecdsa

# BTX Network Parameters
BTX_MAINNET = {
    'PUBKEY_ADDRESS': bytes([25]),      # 0x19 - should produce addresses starting with 'B'
    'SECRET_KEY': bytes([153]),         # 0x99 - should produce WIF keys starting with 'P'
}

def base58_check_decode(address):
    """Decode Base58Check address"""
    try:
        data = base58.b58decode(address)
        if len(data) < 5:  # prefix + hash + checksum (at least 1 + 20 + 4 = 25 bytes)
            return None, None
        checksum = data[-4:]
        payload = data[:-4]
        expected_checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
        if checksum != expected_checksum:
            return None, None
        prefix = bytes([payload[0]])
        hash_part = payload[1:]
        return prefix, hash_part
    except Exception:
        return None, None

def verify_address(address):
    """Verify BTX address"""
    prefix, hash_part = base58_check_decode(address)
    if prefix is None:
        return False, "Invalid Base58Check encoding"

    if prefix != BTX_MAINNET['PUBKEY_ADDRESS']:
        return False, f"Invalid prefix. Expected {BTX_MAINNET['PUBKEY_ADDRESS'].hex()}, got {prefix.hex()}"

    if len(hash_part) != 20:
        return False, f"Invalid hash length. Expected 20 bytes, got {len(hash_part)}"

    if not address.startswith('B'):
        return False, f"BTX address should start with 'B', but starts with '{address[0]}'"

    return True, "Valid BTX address"

def verify_wif(wif_key):
    """Verify BTX WIF private key"""
    prefix, key_data = base58_check_decode(wif_key)
    if prefix is None:
        return False, "Invalid Base58Check encoding"

    if prefix != BTX_MAINNET['SECRET_KEY']:
        return False, f"Invalid prefix. Expected {BTX_MAINNET['SECRET_KEY'].hex()}, got {prefix.hex()}"

    if len(key_data) != 33:  # 32 bytes key + 1 byte compression flag
        return False, f"Invalid key length. Expected 33 bytes, got {len(key_data)}"

    if not wif_key.startswith('P'):
        return False, f"BTX WIF should start with 'P', but starts with '{wif_key[0]}'"

    # Check if the private key is valid (not zero)
    private_key = key_data[:-1]
    if all(b == 0 for b in private_key):
        return False, "Private key cannot be zero"

    return True, "Valid BTX WIF private key"

def verify_public_key_hex(public_key_hex):
    """Verify public key format"""
    try:
        public_key_bytes = bytes.fromhex(public_key_hex)
    except ValueError:
        return False, "Invalid hex format"

    if len(public_key_bytes) != 33:  # Compressed public key should be 33 bytes
        return False, f"Invalid public key length. Expected 33 bytes, got {len(public_key_bytes)}"

    # Check if it's a valid compressed public key
    if public_key_bytes[0] not in [0x02, 0x03]:
        return False, "Invalid public key prefix. Expected 0x02 or 0x03 for compressed key"

    return True, "Valid compressed public key"

def main():
    """Main verification function"""
    print("🔍 BTX Address Verification Tool")
    print("=" * 40)

    # Test with the generated wallet data
    import json
    import glob

    # Find the most recent wallet file
    wallet_files = glob.glob('btx_wallet_backup_*.json')
    if not wallet_files:
        print("❌ No wallet backup files found")
        return

    # Sort by modification time, get the newest
    wallet_files.sort(key=lambda x: os.path.getmtime(x), reverse=True)
    wallet_file = wallet_files[0]

    print(f"📄 Verifying wallet: {wallet_file}")

    with open(wallet_file, 'r') as f:
        wallet_data = json.load(f)

    print(f"\n🔹 Address: {wallet_data['address']}")
    valid_addr, addr_msg = verify_address(wallet_data['address'])
    print(f"   {'✅' if valid_addr else '❌'} {addr_msg}")

    print(f"\n🔹 WIF Private Key: {wallet_data['private_key_wif']}")
    valid_wif, wif_msg = verify_wif(wallet_data['private_key_wif'])
    print(f"   {'✅' if valid_wif else '❌'} {wif_msg}")

    print(f"\n🔹 Public Key: {wallet_data['public_key_hex']}")
    valid_pub, pub_msg = verify_public_key_hex(wallet_data['public_key_hex'])
    print(f"   {'✅' if valid_pub else '❌'} {pub_msg}")

    # Test address generation consistency
    print(f"\n🔄 Testing address generation consistency...")

    # Re-generate address from public key to verify consistency
    try:
        from btx_offline_wallet_generator import generate_p2pkh_address, get_public_key

        # Get public key from private key
        private_key_bytes = bytes.fromhex(wallet_data['private_key_hex'])
        public_key_bytes = get_public_key(private_key_bytes, compressed=True)

        # Generate address
        regenerated_address = generate_p2pkh_address(public_key_bytes)

        if regenerated_address == wallet_data['address']:
            print("✅ Address generation is consistent")
        else:
            print(f"❌ Address mismatch! Original: {wallet_data['address']}, Regenerated: {regenerated_address}")

    except Exception as e:
        print(f"⚠️  Could not test consistency: {e}")

    print(f"\n📋 Summary:")
    if valid_addr and valid_wif and valid_pub:
        print("✅ All checks passed! This appears to be a valid BTX wallet.")
        print(f"🌐 Explorer URL: {wallet_data['explorer_url']}")
    else:
        print("❌ Some checks failed. Please review the issues above.")

    print(f"\n💡 Tip: You can verify any BTX address by running:")
    print(f"   python verify-btx-address.py")

if __name__ == '__main__':
    import os
    main()