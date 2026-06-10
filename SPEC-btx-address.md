# BTX address derivation — reverse-engineered spec (per replica Python pura)

Catena: P2MR / BIP-360 post-quantum. Indirizzo `btx1z...` = bech32m witness v2,
programma 32 byte = merkle root che impegna ML-DSA-44 (primaria) + SLH-DSA-SHAKE-128s.

## Golden vector (da btxd deriveaddresses)
- master_seed (test) = `0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20`
- descriptor = `mr(pqhd(SEED/0h/0h/0/*),pk_slh(pqhd(SEED/0h/0h/0/*)))`  (checksum uc5vpulu)
- index 0 → `btx1ze43r7pvqfld9guktkqnru2ca4dedpzw4xaahx2ardt3vwt5pw5kssu5f7r`
  - merkle root = `cd623f05804fda5472cbb0263e2b1dab72d089d5377b732ba36ae2c72e81752d`
- index 1 → `btx1zwr9qh2z6t5ffazz60ppt4ljshvvfe748lh6qjd9hph4m2ea38gesnt3s96`
- index 2 → `btx1zktql9uazt4zy9mpnndvtflwse8quatk4nueh2f77eg3x6cqhggyqfgn0d7`

## 1) pqhd: master_seed -> seed32 per-algo  (src/pq/pq_keyderivation.cpp)
HKDF-SHA256 (CHKDF_HMAC_SHA256_L32):
- PRK  = HMAC-SHA256(key="BTX-PQ-BIP87-HKDF-V1", msg=master_seed)
- info = b"m/87h" + BE32(87|0x80000000) + BE32(coin|0x80000000)
         + BE32(account|0x80000000) + BE32(change) + BE32(index) + bytes([algo])
- seed32 = HMAC-SHA256(key=PRK, msg=info + b"\x01")[:32]
Path /0h/0h/0/i  => coin=0, account=0, change=0, index=i.  algo: ML_DSA_44=0, SLH_DSA_128S=1.

## 2) seed32 -> entropy 128B  (src/pqkey.cpp MakeDeterministicKey)
entropy = concat_{counter=0..3} SHA256( serialize(seed32) || LE32(counter) )
  dove HashWriter{} << seed32(Span) << counter(uint32). [DA CONFERMARE: serialize di Span
  = raw 32 byte? o con length-prefix? counter = 4 byte LE]. GetSHA256 = SHA256 singolo.

## 3) keygen  (libbitcoinpqc)
- ML-DSA-44: crypto_sign_keypair (dilithium/ref), randombytes->entropy => xi = entropy[0:32].
  pubkey = 1312 byte (rho||t1 packed).
- SLH-DSA-128s: crypto_sign_seed_keypair(pk,sk, entropy) => seed[0:48] = SK.seed||SK.prf||PK.seed
  (3*n, n=16). pubkey = PK.seed(16) || PK.root(16) = 32 byte. Variante SHAKE-128s.

## 4) leaf script  (src/script/pqm.cpp BuildP2MRScript)
- ML: PUSHDATA2(0x4d) + LE16(1312) + pk_ml + OP_CHECKSIG_MLDSA
- SLH: 0x20 + pk_slh + OP_CHECKSIG_SLHDSA
(OP_CHECKSIG_MLDSA / OP_CHECKSIG_SLHDSA: valori in src/script/script.h — DA LEGGERE)

## 5) leaf hash  (P2MR_LEAF_VERSION=0xc2)
lh = TaggedSHA256("P2MRLeaf", bytes([0xc2]) + CompactSize(len(script)) + script)
TaggedSHA256(tag,msg) = SHA256( SHA256(tag) + SHA256(tag) + msg )   (BIP340)

## 6) merkle root  (P2MRBranch, rami ordinati lexicografici)
branch(l,r) = TaggedSHA256("P2MRBranch", min(l,r)+max(l,r))
root su [lh_ml, lh_slh] (2 foglie) = branch(lh_ml, lh_slh)

## 7) indirizzo
bech32m(hrp="btx", witver=2, program=root)
