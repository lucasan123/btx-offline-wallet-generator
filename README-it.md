# 🔐 BTX Offline Wallet Generator — pure Python, zero dipendenze

> 🌐 English version: [README.md](README.md)

Genera indirizzi **BTX** (post-quantum, P2MR / BIP-360) **completamente offline**,
con **un solo file Python** e **zero dipendenze esterne** (solo `hashlib`/`hmac`
della standard library). Niente btxd, niente Internet, niente `pip install`.

La derivazione è **reimplementata byte-per-byte dal sorgente** `btxd` e
**validata** contro i golden vector del nodo ufficiale (vedi sotto).

## Cosa fa, in breve

```
master_seed (32B casuali)
  └─ pqhd  (HKDF-SHA256, "BTX-PQ-BIP87-HKDF-V1")        → seed per-algo per indice
       ├─ ML-DSA-44   (FIPS 204, Dilithium ref)         → pubkey 1312B  → foglia
       └─ SLH-DSA-SHAKE-128s (FIPS 205, SPHINCS+ ref)   → pubkey 32B    → foglia
            └─ merkle root mr() (tag "P2MRLeaf"/"P2MRBranch") → programma 32B
                 └─ bech32m (hrp "btx", witness v2)      → indirizzo btx1z...
```

## Uso

```bash
# genera un nuovo wallet (seed casuale) + file di backup
python btx_address.py

# nuovo wallet con N indirizzi di ricezione
python btx_address.py --count 5

# rigenera / verifica gli indirizzi da un seed esistente (offline, idempotente)
python btx_address.py --seed <64-hex> --count 3

# self-test: confronta foglie, root, indirizzi e checksum coi golden vector di btxd
python btx_address.py --test
```

Su Windows: doppio click su **`btx-wallet.exe`** (release standalone, non serve
Python) oppure usa `genera-wallet.bat` (`genera-wallet.bat`, `genera-wallet.bat 5`,
`genera-wallet.bat --test`).

## Cosa produce

Stampa a video gli indirizzi + i descriptor, e salva
`btx-wallet-backup-AAAAMMGG-hhmmss.txt` con:

- **MASTER SEED** (32 byte hex) — *il segreto*: chi lo ha controlla i fondi.
- Indirizzi di ricezione (`btx1z...`, witness v2).
- I **descriptor** ricezione/resto **con checksum** (pronti da importare in btxd).
- Le istruzioni `createwallet` + `importdescriptors` per ripristinare/spendere.

## Ripristino / spesa

Su un nodo BTX con la blockchain (wallet descriptor):

```bash
btx-cli createwallet "mio" false true "" false true
btx-cli -rpcwallet=mio importdescriptors '[{"desc":"<descriptor#checksum dal backup>","timestamp":"now","active":true,"range":[0,99]}]'
btx-cli -rpcwallet=mio rescanblockchain
```

Importando la **forma privata** del descriptor (quella col seed, come nel backup) il
wallet ottiene le chiavi post-quantum e **può firmare/spendere**. L'eventuale avviso
`Not all private keys provided` e `solvable: false` riguarda solo il check ECDSA
*legacy* (i pubkey P2MR non sono secp256k1) e **non** impedisce la spesa P2MR.

## Validazione (riproducibile)

`python btx_address.py --test` verifica byte-per-byte contro `btxd`
(seed di test `0102…20`):

| elemento | atteso |
|---|---|
| foglia ML-DSA  | `612d80…03b3` |
| foglia SLH-DSA | `188706f8…1678` |
| merkle root #0 | `cd623f05…752d` |
| indirizzo #0   | `btx1ze43r7pv…su5f7r` |
| checksum descriptor | `uc5vpulu` |

End-to-end (`e2e-import-test.sh`, via WSL+btxd): seed casuale → indirizzi Python
**==** `btxd deriveaddresses`, e `importdescriptors` → `getnewaddress` ritorna lo
stesso indirizzo `[0]` (`ismine: true`). **Match confermato.**

## File

- **`btx_address.py`** — IL generatore (libreria + CLI), single-file, zero deps.
- `dist/btx-wallet.exe` — release standalone Windows (PyInstaller).
- `SPEC-btx-address.md` — spec reverse-engineered della derivazione.
- `golden-vector.sh` / `golden-leaves.sh` — estraggono i golden vector da btxd.
- `e2e-import-test.sh` — test round-trip Python ↔ btxd (richiede WSL+btxd).
- `_VECCHIO_ROTTO_NON_USARE/` — vecchio tool btxd-driven, archiviato.

## ⚠️ Sicurezza

- Genera **su un PC offline**. Il MASTER SEED è l'unico segreto: chi lo ha, ha i fondi.
- **Non condividere** seed né la forma privata dei descriptor.
- Conserva il backup **offline** (USB/carta), in **più copie** in luoghi diversi.
- Il pubblico è solo l'indirizzo `btx1z...`; il seed non compare mai negli indirizzi.
- Per massima fiducia, esegui lo **script `.py`** (ispezionabile) invece dell'exe.
