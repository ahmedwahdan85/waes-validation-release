"""Bit-exact model of waes_a53.c (AESE / AESMC / TBL semantics) checked
against golden/rijndael_ref.py, before running on the board."""
import os
import random
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..', 'reference'))
from rijndael_ref import encrypt_block, expand_key, _make_sbox, gmul  # noqa: E402

SBOX = _make_sbox()
if isinstance(SBOX, tuple):
    SBOX = SBOX[0]


def aese(x, k):  # SubBytes(ShiftRows128(x ^ k)), AES column-major byte order
    v = bytes(a ^ b for a, b in zip(x, k))
    sr = bytes(v[r + 4 * ((c + r) % 4)] for c in range(4) for r in range(4))
    return bytes(SBOX[b] for b in sr)


def aesmc(x):
    out = bytearray(16)
    for c in range(4):
        a = x[4 * c:4 * c + 4]
        for r in range(4):
            out[4 * c + r] = (gmul(a[r], 2) ^ gmul(a[(r + 1) % 4], 3) ^ a[(r + 2) % 4] ^ a[(r + 3) % 4])
    return bytes(out)


def perm_index():
    s = [0, 1, 3, 4]
    idx = [0] * 32
    for h in range(2):
        for cp in range(4):
            for r in range(4):
                col = (4 * h + ((cp + 4 - r) % 4) + s[r]) % 8
                idx[r + 4 * (4 * h + cp)] = r + 4 * col
    return idx


IDX = perm_index()


def perm(s):
    return bytes(s[i] for i in IDX)


def enc(block, key):
    rk = expand_key(key, 8)
    rk = [bytes(sum(r, [])) if isinstance(r[0], list) else bytes(r) for r in rk]
    prk = [perm(k) for k in rk[:14]]
    s = block
    for r in range(13):
        x = perm(s)
        s = aesmc(aese(x[:16], prk[r][:16])) + aesmc(aese(x[16:], prk[r][16:]))
    x = perm(s)
    s = aese(x[:16], prk[13][:16]) + aese(x[16:], prk[13][16:])
    return bytes(a ^ b for a, b in zip(s, rk[14]))


rng = random.Random(1)
bad = 0
for _ in range(50):
    key = bytes(rng.getrandbits(8) for _ in range(32))
    p = bytes(rng.getrandbits(8) for _ in range(32))
    bad += enc(p, key) != encrypt_block(p, key, 8)
print('model mismatches:', bad, 'of 50')
