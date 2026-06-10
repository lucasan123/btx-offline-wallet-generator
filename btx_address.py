#!/usr/bin/env python3
# =============================================================================
#  BTX address derivation — PURE PYTHON, zero dipendenze (solo hashlib/hmac).
#  Replica byte-per-byte la derivazione del sorgente btxd:
#    master_seed -> pqhd(HKDF) -> ML-DSA-44 + SLH-DSA-128s keygen -> mr() -> bech32m
#  Vedi SPEC-btx-address.md. Validato contro i golden vector di btxd.
#
#  STATO: ML-DSA-44 + glue completi e validati sull'anchor della foglia ML-DSA.
#         SLH-DSA-128s in arrivo.
# =============================================================================
import hashlib, hmac, struct

# ── primitive hash ───────────────────────────────────────────────────────────
def sha256(b): return hashlib.sha256(b).digest()
def shake128(b, n): return hashlib.shake_128(b).digest(n)
def shake256(b, n): return hashlib.shake_256(b).digest(n)
def hmac_sha256(key, msg): return hmac.new(key, msg, hashlib.sha256).digest()

def tagged_hash(tag, msg):
    t = sha256(tag.encode())
    return sha256(t + t + msg)

def compact_size(n):
    if n < 0xfd: return bytes([n])
    if n <= 0xffff: return b'\xfd' + struct.pack('<H', n)
    if n <= 0xffffffff: return b'\xfe' + struct.pack('<I', n)
    return b'\xff' + struct.pack('<Q', n)

# ── pqhd: master_seed -> seed32 (per algo)  (src/pq/pq_keyderivation.cpp) ──────
HARD = 0x80000000
def pqhd_seed(master_seed, algo, coin=0, account=0, change=0, index=0):
    prk = hmac_sha256(b"BTX-PQ-BIP87-HKDF-V1", master_seed)
    info  = b"m/87h"
    info += struct.pack('>I', 87 | HARD)
    info += struct.pack('>I', coin | HARD)
    info += struct.pack('>I', account | HARD)
    info += struct.pack('>I', change)
    info += struct.pack('>I', index)
    info += bytes([algo])
    return hmac_sha256(prk, info + b'\x01')[:32]  # HKDF-Expand, L=32

# ── seed32 -> 128B entropy  (src/pqkey.cpp MakeDeterministicKey) ──────────────
def keygen_entropy(seed32):
    # HashWriter{} << seed32 << counter ; GetSHA256.  Provo: seed32 raw (32B) + counter LE32.
    out = b''
    counter = 0
    while len(out) < 128:
        out += sha256(seed32 + struct.pack('<I', counter))
        counter += 1
    return out[:128]

# ── ML-DSA-44 (Dilithium MODE 2) keygen — port del reference dilithium/ref ────
Q = 8380417
N = 256
D = 13
K = 4
L = 4
ETA = 2
QINV = 58728449  # q^-1 mod 2^32
MONT_F = 41978   # mont^2/256 per invntt_tomont

ZETAS = [
         0,    25847, -2608894,  -518909,   237124,  -777960,  -876248,   466468,
   1826347,  2353451,  -359251, -2091905,  3119733, -2884855,  3111497,  2680103,
   2725464,  1024112, -1079900,  3585928,  -549488, -1119584,  2619752, -2108549,
  -2118186, -3859737, -1399561, -3277672,  1757237,   -19422,  4010497,   280005,
   2706023,    95776,  3077325,  3530437, -1661693, -3592148, -2537516,  3915439,
  -3861115, -3043716,  3574422, -2867647,  3539968,  -300467,  2348700,  -539299,
  -1699267, -1643818,  3505694, -3821735,  3507263, -2140649, -1600420,  3699596,
    811944,   531354,   954230,  3881043,  3900724, -2556880,  2071892, -2797779,
  -3930395, -1528703, -3677745, -3041255, -1452451,  3475950,  2176455, -1585221,
  -1257611,  1939314, -4083598, -1000202, -3190144, -3157330, -3632928,   126922,
   3412210,  -983419,  2147896,  2715295, -2967645, -3693493,  -411027, -2477047,
   -671102, -1228525,   -22981, -1308169,  -381987,  1349076,  1852771, -1430430,
  -3343383,   264944,   508951,  3097992,    44288, -1100098,   904516,  3958618,
  -3724342,    -8578,  1653064, -3249728,  2389356,  -210977,   759969, -1316856,
    189548, -3553272,  3159746, -1851402, -2409325,  -177440,  1315589,  1341330,
   1285669, -1584928,  -812732, -1439742, -3019102, -3881060, -3628969,  3839961,
   2091667,  3407706,  2316500,  3817976, -3342478,  2244091, -2446433, -3562462,
    266997,  2434439, -1235728,  3513181, -3520352, -3759364, -1197226, -3193378,
    900702,  1859098,   909542,   819034,   495491, -1613174,   -43260,  -522500,
   -655327, -3122442,  2031748,  3207046, -3556995,  -525098,  -768622, -3595838,
    342297,   286988, -2437823,  4108315,  3437287, -3342277,  1735879,   203044,
   2842341,  2691481, -2590150,  1265009,  4055324,  1247620,  2486353,  1595974,
  -3767016,  1250494,  2635921, -3548272, -2994039,  1869119,  1903435, -1050970,
  -1333058,  1237275, -3318210, -1430225,  -451100,  1312455,  3306115, -1962642,
  -1279661,  1917081, -2546312, -1374803,  1500165,   777191,  2235880,  3406031,
   -542412, -2831860, -1671176, -1846953, -2584293, -3724270,   594136, -3776993,
  -2013608,  2432395,  2454455,  -164721,  1957272,  3369112,   185531, -1207385,
  -3183426,   162844,  1616392,  3014001,   810149,  1652634, -3694233, -1799107,
  -3038916,  3523897,  3866901,   269760,  2213111,  -975884,  1717735,   472078,
   -426683,  1723600, -1803090,  1910376, -1667432, -1104333,  -260646, -3833893,
  -2939036, -2235985,  -420899, -2286327,   183443,  -976891,  1612842, -3545687,
   -554416,  3919660,   -48306, -1362209,  3937738,  1400424,  -846154,  1976782]

def _s32(x):
    x &= 0xffffffff
    return x - 0x100000000 if x >= 0x80000000 else x

def montgomery_reduce(a):  # a: int64; ritorna r ≡ a*2^-32 mod Q, -Q<r<Q
    t = _s32(a * QINV)
    return (a - t * Q) >> 32

def reduce32(a):
    t = (a + (1 << 22)) >> 23
    return a - t * Q

def caddq(a):
    return a + ((a >> 31) & Q)

def ntt(a):  # in-place forward NTT (start avanza di 2*len, come il C)
    k = 0
    length = 128
    while length > 0:
        start = 0
        while start < N:
            k += 1
            zeta = ZETAS[k]
            for j in range(start, start + length):
                t = montgomery_reduce(zeta * a[j + length])
                a[j + length] = a[j] - t
                a[j] = a[j] + t
            start += 2 * length
        length >>= 1

def invntt_tomont(a):
    k = 256
    length = 1
    while length < N:
        start = 0
        while start < N:
            k -= 1
            zeta = -ZETAS[k]
            for j in range(start, start + length):
                t = a[j]
                a[j] = t + a[j + length]
                a[j + length] = t - a[j + length]
                a[j + length] = montgomery_reduce(zeta * a[j + length])
            start += 2 * length
        length <<= 1
    for j in range(N):
        a[j] = montgomery_reduce(MONT_F * a[j])

def poly_uniform(rho, nonce):
    # SHAKE128(rho || nonce_le16) -> rej uniform < Q, 256 coeff
    seed = rho + bytes([nonce & 0xff, (nonce >> 8) & 0xff])
    buf = shake128(seed, 168 * 6)
    a = []
    pos = 0
    while len(a) < N:
        if pos + 3 > len(buf):
            buf += shake128(seed, len(buf) + 168)[len(buf):]  # estendi (raro)
        t = buf[pos] | (buf[pos+1] << 8) | ((buf[pos+2] & 0x7f) << 16)
        pos += 3
        if t < Q:
            a.append(t)
    return a

def poly_uniform_eta(rho, nonce):
    seed = rho + bytes([nonce & 0xff, (nonce >> 8) & 0xff])
    buf = shake256(seed, 136 * 4)
    a = []
    pos = 0
    while len(a) < N:
        if pos >= len(buf):
            buf += shake256(seed, len(buf) + 136)[len(buf):]
        b = buf[pos]; pos += 1
        t0 = b & 0x0f
        t1 = b >> 4
        if t0 < 15:
            t0 = t0 - (205 * t0 >> 10) * 5
            a.append(2 - t0)
        if t1 < 15 and len(a) < N:
            t1 = t1 - (205 * t1 >> 10) * 5
            a.append(2 - t1)
    return a

def power2round(a):  # ritorna a1
    a1 = (a + (1 << (D - 1)) - 1) >> D
    return a1

def polyt1_pack(t1):  # 256 coeff (10 bit) -> 320 byte
    r = bytearray(320)
    for i in range(N // 4):
        c0, c1, c2, c3 = t1[4*i], t1[4*i+1], t1[4*i+2], t1[4*i+3]
        r[5*i+0] = c0 & 0xff
        r[5*i+1] = ((c0 >> 8) | (c1 << 2)) & 0xff
        r[5*i+2] = ((c1 >> 6) | (c2 << 4)) & 0xff
        r[5*i+3] = ((c2 >> 4) | (c3 << 6)) & 0xff
        r[5*i+4] = (c3 >> 2) & 0xff
    return bytes(r)

def mldsa44_pubkey(entropy128):
    xi = entropy128[:32]
    sb = shake256(xi + bytes([K, L]), 32 + 64 + 32)
    rho = sb[:32]; rhoprime = sb[32:96]
    # matrice A in dominio NTT (poly_uniform)
    mat = [[poly_uniform(rho, (i << 8) + j) for j in range(L)] for i in range(K)]
    s1 = [poly_uniform_eta(rhoprime, n) for n in range(L)]
    s2 = [poly_uniform_eta(rhoprime, L + n) for n in range(K)]
    s1hat = [s[:] for s in s1]
    for s in s1hat: ntt(s)
    t = []
    for i in range(K):
        acc = [0] * N
        for j in range(L):
            for n in range(N):
                acc[n] += montgomery_reduce(mat[i][j][n] * s1hat[j][n])
        for n in range(N):
            acc[n] = reduce32(acc[n])
        invntt_tomont(acc)
        for n in range(N):
            acc[n] = acc[n] + s2[i][n]
            acc[n] = caddq(acc[n])
        t.append(acc)
    t1 = [[power2round(t[i][n]) for n in range(N)] for i in range(K)]
    pk = bytes(rho)
    for i in range(K):
        pk += polyt1_pack(t1[i])
    return pk

# ── SLH-DSA-SHAKE-128s (SPHINCS+) keygen — port del reference sphincsplus/ref ──
#   Param (params-sphincs-shake-128s.h): N=16, W=16, LOGW=4, LEN1=32, LEN2=3,
#   LEN=35, D=7, TREE_HEIGHT=9 (=> 512 foglie nel subtree top, layer D-1=6).
#   Hash (SHAKE-simple):  prf  = SHAKE256(pub_seed||ADRS(32)||sk_seed, 16)
#                         thash= SHAKE256(pub_seed||ADRS(32)||M,        16)
#   ADRS = 32 byte, campi big-endian agli offset di shake_offsets.h.
SPX_N        = 16
SPX_WOTS_W   = 16
SPX_WOTS_LEN = 35           # LEN1(32) + LEN2(3)
SPX_TREE_HEIGHT = 9
SPX_D        = 7
# ADRS byte offsets
A_LAYER = 3
A_TREE  = 8                 # 8 byte
A_TYPE  = 19
A_KP    = 20                # 4 byte
A_CHAIN = 27
A_HASH  = 31
A_THGT  = 27
A_TIDX  = 28                # 4 byte
# ADRS type
T_WOTS = 0; T_WOTSPK = 1; T_HASHTREE = 2; T_WOTSPRF = 5

def _adrs():            return bytearray(32)
def set_layer(a, v):    a[A_LAYER] = v & 0xff
def set_tree(a, v):     a[A_TREE:A_TREE+8] = v.to_bytes(8, 'big')
def set_type(a, v):     a[A_TYPE] = v & 0xff
def set_kp(a, v):       a[A_KP:A_KP+4] = (v & 0xffffffff).to_bytes(4, 'big')
def set_chain(a, v):    a[A_CHAIN] = v & 0xff
def set_hash(a, v):     a[A_HASH] = v & 0xff
def set_theight(a, v):  a[A_THGT] = v & 0xff
def set_tindex(a, v):   a[A_TIDX:A_TIDX+4] = (v & 0xffffffff).to_bytes(4, 'big')

def _prf(pub_seed, sk_seed, adrs):
    return shake256(pub_seed + bytes(adrs) + sk_seed, SPX_N)

def _thash(pub_seed, adrs, msg):   # msg = inblocks*N byte
    return shake256(pub_seed + bytes(adrs) + msg, SPX_N)

def _wots_gen_leaf(pub_seed, sk_seed, leaf_idx, leaf_t, pk_t):
    leaf = bytearray(leaf_t); pk = bytearray(pk_t)
    set_kp(leaf, leaf_idx); set_kp(pk, leaf_idx)
    pk_buf = bytearray()
    for i in range(SPX_WOTS_LEN):           # 35 catene
        set_chain(leaf, i); set_hash(leaf, 0)
        set_type(leaf, T_WOTSPRF)
        buf = _prf(pub_seed, sk_seed, leaf)
        set_type(leaf, T_WOTS)
        for k in range(SPX_WOTS_W - 1):     # 15 passi: hash_addr = 0..14
            set_hash(leaf, k)
            buf = _thash(pub_seed, leaf, buf)
        pk_buf += buf
    return _thash(pub_seed, pk, bytes(pk_buf))   # thash su 35 blocchi -> foglia (16B)

def _treehash_root(pub_seed, sk_seed, height, idx_offset, leaf_t, pk_t, tree_t):
    stack = []                              # (node16, h)
    max_idx = (1 << height) - 1
    for idx in range(1 << height):
        current = _wots_gen_leaf(pub_seed, sk_seed, idx + idx_offset, leaf_t, pk_t)
        internal_off = idx_offset
        internal_idx = idx
        h = 0
        while True:
            if h == height:
                return current
            if (internal_idx & 1) == 0 and idx < max_idx:
                break
            internal_off >>= 1
            ta = bytearray(tree_t)
            set_theight(ta, h + 1)
            set_tindex(ta, (internal_idx >> 1) + internal_off)
            left, _ = stack.pop()
            current = _thash(pub_seed, ta, left + current)
            h += 1
            internal_idx >>= 1
        stack.append((current, h))

def slhdsa128s_pubkey(entropy):
    # entropy>=48: SK.seed||SK.prf||PK.seed = entropy[0:16]||[16:32]||[32:48]
    sk_seed  = entropy[0:SPX_N]
    pub_seed = entropy[2*SPX_N:3*SPX_N]
    # merkle_gen_root: subtree top, layer D-1
    leaf_t = _adrs(); set_layer(leaf_t, SPX_D - 1)                   # wots_addr (leaf)
    pk_t   = _adrs(); set_layer(pk_t, SPX_D - 1); set_type(pk_t, T_WOTSPK)
    tree_t = _adrs(); set_layer(tree_t, SPX_D - 1); set_type(tree_t, T_HASHTREE)
    root = _treehash_root(pub_seed, sk_seed, SPX_TREE_HEIGHT, 0, leaf_t, pk_t, tree_t)
    return pub_seed + root                  # PK.seed(16) || PK.root(16) = 32B

# ── leaf script + leaf hash (P2MR)  (src/script/pqm.cpp) ──────────────────────
OP_CHECKSIG_MLDSA = 0xbb
OP_CHECKSIG_SLHDSA = 0xbc
OP_PUSHDATA2 = 0x4d
P2MR_LEAF_VERSION = 0xc2

def build_leaf_script(algo_opcode, pubkey):
    n = len(pubkey)
    if n <= 75:
        s = bytes([n]) + pubkey
    elif n <= 0xff:
        s = bytes([0x4c, n]) + pubkey
    else:
        s = bytes([OP_PUSHDATA2, n & 0xff, (n >> 8) & 0xff]) + pubkey
    return s + bytes([algo_opcode])

def leaf_hash(script):
    return tagged_hash("P2MRLeaf", bytes([P2MR_LEAF_VERSION]) + compact_size(len(script)) + script)

# ── merkle root P2MR  (src/script/pqm.cpp ComputeP2MRBranchHash/MerkleRoot) ────
def branch_hash(l, r):
    a, b = (l, r) if l <= r else (r, l)     # ordine lessicografico
    return tagged_hash("P2MRBranch", a + b)

def merkle_root(leaf_hashes):
    if len(leaf_hashes) == 1:
        return leaf_hashes[0]
    level = list(leaf_hashes)
    while len(level) > 1:
        nxt = []
        for i in range(0, len(level), 2):
            if i + 1 < len(level):
                nxt.append(branch_hash(level[i], level[i+1]))
            else:
                nxt.append(level[i])         # nodo dispari -> sale invariato
        level = nxt
    return level[0]

# ── bech32m  (BIP-350) ────────────────────────────────────────────────────────
_CH = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
def _polymod(values):
    GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for v in values:
        b = chk >> 25
        chk = ((chk & 0x1ffffff) << 5) ^ v
        for i in range(5):
            chk ^= GEN[i] if ((b >> i) & 1) else 0
    return chk
def _hrp_expand(hrp):
    return [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]
def _convertbits(data, frm, to, pad=True):
    acc = 0; bits = 0; ret = []; maxv = (1 << to) - 1
    for b in data:
        acc = (acc << frm) | b; bits += frm
        while bits >= to:
            bits -= to; ret.append((acc >> bits) & maxv)
    if pad and bits:
        ret.append((acc << (to - bits)) & maxv)
    return ret
def bech32m_encode(hrp, witver, program):
    data = [witver] + _convertbits(program, 8, 5)
    BECH32M = 0x2bc830a3
    pm = _polymod(_hrp_expand(hrp) + data + [0,0,0,0,0,0]) ^ BECH32M
    chk = [(pm >> 5 * (5 - i)) & 31 for i in range(6)]
    return hrp + "1" + "".join(_CH[d] for d in data + chk)

# ── descriptor checksum  (src/script/descriptor.cpp DescriptorChecksum) ───────
_DESC_IN = ("0123456789()[],'/*abcdefgh@:$%{}"
            "IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~"
            "ijklmnopqrstuvwxyzABCDEFGH`#\"\\ ")
def _desc_polymod(c, val):
    c0 = c >> 35
    c = ((c & 0x7ffffffff) << 5) ^ val
    if c0 & 1:  c ^= 0xf5dee51989
    if c0 & 2:  c ^= 0xa9fdca3312
    if c0 & 4:  c ^= 0x1bab10e32d
    if c0 & 8:  c ^= 0x3706b1677a
    if c0 & 16: c ^= 0x644d626ffd
    return c
def descriptor_checksum(s):
    c = 1; cls = 0; clscount = 0
    for ch in s:
        pos = _DESC_IN.find(ch)
        if pos < 0: return ""
        c = _desc_polymod(c, pos & 31)
        cls = cls * 3 + (pos >> 5)
        clscount += 1
        if clscount == 3:
            c = _desc_polymod(c, cls); cls = 0; clscount = 0
    if clscount > 0: c = _desc_polymod(c, cls)
    for _ in range(8): c = _desc_polymod(c, 0)
    c ^= 1
    return "".join(_CH[(c >> (5 * (7 - j))) & 31] for j in range(8))

def wallet_descriptor(seed_hex, coin=0, account=0, change=0):
    """Descriptor P2MR (con checksum) importabile in btxd via importdescriptors."""
    inner = f"pqhd({seed_hex}/{coin}h/{account}h/{change}/*)"
    body = f"mr({inner},pk_slh({inner}))"
    return body + "#" + descriptor_checksum(body)

def derive_address(master_seed, index, coin=0, account=0, change=0, hrp="btx"):
    """master_seed -> indirizzo btx1z... per l'indice dato (ML-DSA + SLH-DSA)."""
    e_ml  = keygen_entropy(pqhd_seed(master_seed, 0, coin, account, change, index))
    e_slh = keygen_entropy(pqhd_seed(master_seed, 1, coin, account, change, index))
    pk_ml  = mldsa44_pubkey(e_ml)
    pk_slh = slhdsa128s_pubkey(e_slh)
    lh_ml  = leaf_hash(build_leaf_script(OP_CHECKSIG_MLDSA,  pk_ml))
    lh_slh = leaf_hash(build_leaf_script(OP_CHECKSIG_SLHDSA, pk_slh))
    root = merkle_root([lh_ml, lh_slh])
    return bech32m_encode(hrp, 2, root), root

# ── self-test: validazione byte-esatta vs golden vector di btxd ───────────────
def selftest():
    seed = bytes(range(1, 33))  # 0102..20
    EXP_ML_LEAF  = "612d805863982f917a72bc5e36cc875298c7a9e7d035b14c3084f56b9b8003b3"
    EXP_SLH_LEAF = "188706f8a4dd890a228f145fc3969b95f4a41f6c3ce76a16792612235c381678"
    EXP_ROOT0    = "cd623f05804fda5472cbb0263e2b1dab72d089d5377b732ba36ae2c72e81752d"
    EXP_ADDR = ["btx1ze43r7pvqfld9guktkqnru2ca4dedpzw4xaahx2ardt3vwt5pw5kssu5f7r",
                "btx1zwr9qh2z6t5ffazz60ppt4ljshvvfe748lh6qjd9hph4m2ea38gesnt3s96",
                "btx1zktql9uazt4zy9mpnndvtflwse8quatk4nueh2f77eg3x6cqhggyqfgn0d7"]
    ok = True
    pk_ml = mldsa44_pubkey(keygen_entropy(pqhd_seed(seed, 0, 0, 0, 0, 0)))
    lh_ml = leaf_hash(build_leaf_script(OP_CHECKSIG_MLDSA, pk_ml)).hex()
    print(f"foglia ML-DSA : {lh_ml}  {'OK' if lh_ml==EXP_ML_LEAF else 'FAIL'}"); ok &= lh_ml==EXP_ML_LEAF
    pk_slh = slhdsa128s_pubkey(keygen_entropy(pqhd_seed(seed, 1, 0, 0, 0, 0)))
    lh_slh = leaf_hash(build_leaf_script(OP_CHECKSIG_SLHDSA, pk_slh)).hex()
    print(f"foglia SLH-DSA: {lh_slh}  {'OK' if lh_slh==EXP_SLH_LEAF else 'FAIL'}"); ok &= lh_slh==EXP_SLH_LEAF
    desc = wallet_descriptor(seed.hex())
    print(f"descriptor    : {desc}")
    print(f"  checksum     : {desc.split('#')[1]}  {'OK' if desc.split('#')[1]=='uc5vpulu' else 'FAIL (atteso uc5vpulu)'}")
    ok &= desc.split('#')[1] == 'uc5vpulu'
    for i in range(3):
        addr, root = derive_address(seed, i)
        m = addr == EXP_ADDR[i]; ok &= m
        if i == 0: ok &= root.hex() == EXP_ROOT0
        print(f"index {i}      : {addr}  {'OK' if m else 'FAIL'}")
    print("\n=== SELF-TEST:", "TUTTO OK" if ok else "FALLITO", "===")
    return ok

# ── generazione wallet + backup ───────────────────────────────────────────────
def genera_wallet(count=1, seed_hex=None, out_dir="."):
    import os, secrets, datetime
    if seed_hex:
        seed = bytes.fromhex(seed_hex.strip())
        nuovo = False
    else:
        seed = secrets.token_bytes(32)
        nuovo = True
    sh = seed.hex()
    desc_ext = wallet_descriptor(sh, change=0)
    desc_int = wallet_descriptor(sh, change=1)
    addrs = [derive_address(seed, i)[0] for i in range(count)]

    print("=" * 70)
    print("  BTX WALLET  -  generato offline (pure Python, post-quantum P2MR)")
    print("=" * 70)
    print(f"\nMASTER SEED (SEGRETO!):  {sh}\n")
    print("Indirizzi di ricezione:")
    for i, a in enumerate(addrs):
        print(f"  [{i}]  {a}")
    print(f"\nDescriptor (ricezione)  : {desc_ext}")
    print(f"Descriptor (resto/change): {desc_int}")

    if nuovo:
        ts = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
        path = os.path.join(out_dir, f"btx-wallet-backup-{ts}.txt")
        with open(path, "w", encoding="utf-8") as f:
            f.write("BTX WALLET BACKUP - CONSERVA AL SICURO, NON CONDIVIDERE\n")
            f.write("=" * 60 + "\n")
            f.write(f"creato: {datetime.datetime.now().isoformat(timespec='seconds')}\n\n")
            f.write("MASTER SEED (32 byte hex) - chi ha questo controlla i fondi:\n")
            f.write(f"  {sh}\n\n")
            f.write("Indirizzi di ricezione (P2MR / bech32m witness v2):\n")
            for i, a in enumerate(addrs):
                f.write(f"  [{i}]  {a}\n")
            f.write("\nDescriptor importabili in btxd (descriptor wallet):\n")
            f.write(f"  ricezione : {desc_ext}\n")
            f.write(f"  resto     : {desc_int}\n\n")
            f.write("RIPRISTINO / SPESA (richiede btxd con wallet descriptor):\n")
            f.write("  btx-cli createwallet \"mio\" false true \"\" false true\n")
            f.write("  btx-cli -rpcwallet=mio importdescriptors '[{\"desc\":\"" + desc_ext +
                    "\",\"timestamp\":\"now\",\"active\":true,\"range\":[0,99]},"
                    "{\"desc\":\"" + desc_int + "\",\"timestamp\":\"now\",\"active\":true,"
                    "\"internal\":true,\"range\":[0,99]}]'\n")
            f.write("  Nota: importando la forma PRIVATA (col seed, come sopra) il wallet\n")
            f.write("  ottiene le chiavi post-quantum e puo' FIRMARE/SPENDERE. L'eventuale\n")
            f.write("  avviso 'Not all private keys' e 'solvable:false' riguarda solo il\n")
            f.write("  check ECDSA legacy: non impedisce la spesa P2MR post-quantum.\n\n")
            f.write("Oppure rigenera/verifica gli indirizzi offline con:\n")
            f.write(f"  python btx_address.py --seed {sh} --count {max(count,3)}\n")
        print(f"\n>>> BACKUP salvato in: {path}")
        print(">>> Conserva quel file al sicuro. Chi ha il MASTER SEED ha i fondi.")
    print("=" * 70)

# ── CLI ───────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import sys
    args = sys.argv[1:]
    if "--test" in args or "--selftest" in args:
        sys.exit(0 if selftest() else 1)
    seed_hex = None; count = 1
    i = 0
    while i < len(args):
        if args[i] == "--seed" and i + 1 < len(args):
            seed_hex = args[i+1]; i += 2
        elif args[i] == "--count" and i + 1 < len(args):
            count = int(args[i+1]); i += 2
        elif args[i] in ("-h", "--help"):
            print("Uso:\n"
                  "  python btx_address.py                 genera un nuovo wallet (+ backup)\n"
                  "  python btx_address.py --count 5       genera nuovo wallet, 5 indirizzi\n"
                  "  python btx_address.py --seed <hex>    rigenera/verifica da un seed esistente\n"
                  "  python btx_address.py --test          self-test vs golden vector di btxd")
            sys.exit(0)
        else:
            i += 1
    genera_wallet(count=count, seed_hex=seed_hex)
