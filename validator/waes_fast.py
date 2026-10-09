"""Vectorized WAES-256 (Rijndael Nb=8, Nk=8, Nr=14) encryption with NumPy.

Encrypts many 32-byte blocks at once; used by the packet validator. Byte
order follows the Rijndael specification: block byte r + 4*c is state row r,
column c. Cross-checked against the scalar reference model rijndael_ref.py
(see selftest()).
"""

import numpy as np


def _xt(a):
    return ((a << 1) ^ (0x11B if a & 0x80 else 0)) & 0xFF


def _make_tables():
    def gmul(a, b):
        r = 0
        while b:
            if b & 1:
                r ^= a
            a = _xt(a)
            b >>= 1
        return r

    sbox = np.zeros(256, np.uint8)
    for x in range(256):
        inv = 0 if x == 0 else next(y for y in range(1, 256) if gmul(x, y) == 1)
        s = 0x63
        for i in range(8):
            bit = ((inv >> i) ^ (inv >> ((i + 4) % 8)) ^ (inv >> ((i + 5) % 8))
                   ^ (inv >> ((i + 6) % 8)) ^ (inv >> ((i + 7) % 8))) & 1
            s ^= bit << i
        sbox[x] = s
    mul2 = np.array([gmul(x, 2) for x in range(256)], np.uint8)
    mul3 = np.array([gmul(x, 3) for x in range(256)], np.uint8)
    return sbox, mul2, mul3


SBOX, MUL2, MUL3 = _make_tables()

# ShiftRows for Nb = 8, offsets (0, 1, 3, 4): out[r + 4c] = in[r + 4((c + s_r) mod 8)]
_SHIFTS = (0, 1, 3, 4)
SHIFT_IDX = np.array([r + 4 * ((c + _SHIFTS[r]) % 8) for c in range(8) for r in range(4)])


def expand_key(key):
    """Return round keys as a (15, 32) uint8 array (Rijndael byte order)."""
    nk, nb, nr = 8, 8, 14
    w = [list(key[4 * i:4 * i + 4]) for i in range(nk)]
    rcon = 1
    for i in range(nk, nb * (nr + 1)):
        t = list(w[i - 1])
        if i % nk == 0:
            t = t[1:] + t[:1]
            t = [int(SBOX[b]) for b in t]
            t[0] ^= rcon
            rcon = _xt(rcon)
        elif i % nk == 4:
            t = [int(SBOX[b]) for b in t]
        w.append([a ^ b for a, b in zip(w[i - nk], t)])
    return np.array([sum(w[r * nb:(r + 1) * nb], []) for r in range(nr + 1)], np.uint8)


def _mix_columns(s):
    a = s.reshape(-1, 8, 4)
    a0, a1, a2, a3 = a[:, :, 0], a[:, :, 1], a[:, :, 2], a[:, :, 3]
    out = np.empty_like(a)
    out[:, :, 0] = MUL2[a0] ^ MUL3[a1] ^ a2 ^ a3
    out[:, :, 1] = a0 ^ MUL2[a1] ^ MUL3[a2] ^ a3
    out[:, :, 2] = a0 ^ a1 ^ MUL2[a2] ^ MUL3[a3]
    out[:, :, 3] = MUL3[a0] ^ a1 ^ a2 ^ MUL2[a3]
    return out.reshape(-1, 32)


def encrypt_blocks(blocks, round_keys):
    """blocks: (N, 32) uint8; round_keys: (15, 32) uint8 -> (N, 32) uint8."""
    s = blocks ^ round_keys[0]
    for r in range(1, 14):
        s = SBOX[s][:, SHIFT_IDX]
        s = _mix_columns(s) ^ round_keys[r]
    s = SBOX[s][:, SHIFT_IDX]
    return s ^ round_keys[14]


def encrypt_blocks_rk(blocks, rk):
    """Like encrypt_blocks, but each block has its own round keys.

    blocks: (N, 32) uint8; rk: (N, 15, 32) uint8 -> (N, 32) uint8.
    Lets blocks of many different keys be encrypted in one call.
    """
    s = blocks ^ rk[:, 0]
    for r in range(1, 14):
        s = SBOX[s][:, SHIFT_IDX]
        s = _mix_columns(s) ^ rk[:, r]
    s = SBOX[s][:, SHIFT_IDX]
    return s ^ rk[:, 14]


def selftest():
    import os
    import sys
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                    "..", "reference"))
    try:
        from rijndael_ref import encrypt_block
    except ImportError:
        print("rijndael_ref.py not found; skipping cross-check")
        return
    rng = np.random.default_rng(1)
    for _ in range(8):
        key = rng.integers(0, 256, 32, np.uint8)
        blocks = rng.integers(0, 256, (16, 32), np.uint8)
        fast = encrypt_blocks(blocks, expand_key(bytes(key)))
        for b, f in zip(blocks, fast):
            assert encrypt_block(bytes(b), bytes(key)) == bytes(f)
    print("waes_fast self-test: PASS (matches rijndael_ref on 128 random blocks)")


if __name__ == "__main__":
    selftest()
