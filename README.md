# 🔐 BTX Offline Wallet Generator — pure Python, zero dependencies

> 🇮🇹 Versione italiana: [README-it.md](README-it.md)

Generate **BTX** addresses (post-quantum, P2MR / BIP-360) **fully offline**, from a
**single Python file** with **zero external dependencies** (only `hashlib`/`hmac`
from the standard library). No btxd, no Internet, no `pip install`.

The derivation is **re-implemented byte-for-byte from the `btxd` source** and
**validated** against the official node's golden vectors (see below).

## What it does, in short

```
master_seed (32 random bytes)
  └─ pqhd  (HKDF-SHA256, "BTX-PQ-BIP87-HKDF-V1")        → per-algo seed per index
       ├─ ML-DSA-44   (FIPS 204, Dilithium ref)         → 1312B pubkey  → leaf
       └─ SLH-DSA-SHAKE-128s (FIPS 205, SPHINCS+ ref)   → 32B pubkey    → leaf
            └─ merkle root mr() (tag "P2MRLeaf"/"P2MRBranch") → 32B program
                 └─ bech32m (hrp "btx", witness v2)      → address btx1z...
```

BTX addresses are **P2MR** (Pay-to-Merkle-Root, BIP-360 style): a bech32m witness-v2
address whose 32-byte program is a Taproot-like merkle root committing to two
post-quantum keys — **ML-DSA-44** (primary, FIPS 204) and **SLH-DSA-SHAKE-128s**
(backup, FIPS 205 / SPHINCS+).

## Usage

```bash
# generate a new wallet (random seed) + backup file
python btx_address.py

# new wallet with N receiving addresses
python btx_address.py --count 5

# re-derive / verify addresses from an existing seed (offline, idempotent)
python btx_address.py --seed <64-hex> --count 3

# self-test: compares leaves, root, addresses and checksum vs btxd golden vectors
python btx_address.py --test
```

On Windows you can double-click **`btx-wallet.exe`** (standalone release, no Python
needed) or use `genera-wallet.bat` (`genera-wallet.bat`, `genera-wallet.bat 5`,
`genera-wallet.bat --test`).

## What it produces

It prints the addresses + descriptors and writes
`btx-wallet-backup-YYYYMMDD-HHMMSS.txt` containing:

- **MASTER SEED** (32-byte hex) — *the secret*: whoever has it controls the funds.
- Receiving addresses (`btx1z...`, witness v2).
- The receive/change **descriptors with checksum** (ready to import into btxd).
- The `createwallet` + `importdescriptors` instructions to restore/spend.

## Restore / spend

On a BTX node with the blockchain (descriptor wallet):

```bash
btx-cli createwallet "mywallet" false true "" false true
btx-cli -rpcwallet=mywallet importdescriptors '[{"desc":"<descriptor#checksum from backup>","timestamp":"now","active":true,"range":[0,99]}]'
btx-cli -rpcwallet=mywallet rescanblockchain
```

Importing the **private form** of the descriptor (the one with the seed, as in the
backup) gives the wallet the post-quantum keys, so it **can sign/spend**. The
`Not all private keys provided` warning and `solvable: false` only refer to the
*legacy ECDSA* check (P2MR pubkeys are not secp256k1) and do **not** prevent P2MR
spending.

## Validation (reproducible)

`python btx_address.py --test` checks byte-for-byte against `btxd`
(test seed `0102…20`):

| item | expected |
|---|---|
| ML-DSA leaf  | `612d80…03b3` |
| SLH-DSA leaf | `188706f8…1678` |
| merkle root #0 | `cd623f05…752d` |
| address #0   | `btx1ze43r7pv…su5f7r` |
| descriptor checksum | `uc5vpulu` |

End-to-end (`e2e-import-test.sh`, via WSL+btxd): a random seed → Python addresses
**==** `btxd deriveaddresses`, and `importdescriptors` → `getnewaddress` returns the
same `[0]` address (`ismine: true`). **Match confirmed.**

## Files

- **`btx_address.py`** — THE generator (library + CLI), single-file, zero deps.
- `dist/btx-wallet.exe` — standalone Windows release (PyInstaller).
- `SPEC-btx-address.md` — reverse-engineered spec of the derivation.
- `golden-vector.sh` / `golden-leaves.sh` — extract the golden vectors from btxd.
- `e2e-import-test.sh` — Python ↔ btxd round-trip test (needs WSL+btxd).
- `_VECCHIO_ROTTO_NON_USARE/` — old btxd-driven tool, archived.

## ⚠️ Security

- Generate **on an offline machine**. The MASTER SEED is the only secret: whoever
  holds it holds the funds.
- **Never share** the seed or the private form of the descriptors.
- Keep the backup **offline** (USB/paper), in **multiple copies** in different places.
- Only the `btx1z...` address is public; the seed never appears in any address.
- For maximum trust, run the **`.py` script** (auditable) rather than the exe.
