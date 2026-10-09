"""Reference model of Rijndael with variable block size (Nb) and key size (Nk).

WAES-256 = Rijndael with Nb = 8, Nk = 8, Nr = 14.
Byte order follows the Rijndael specification / FIPS-197:
    state[r][c] = in[r + 4*c]   (column-major, byte 0 = row 0 of column 0)

Self-checks (run this file directly):
  1. Nb=4, Nk=8 reproduces the FIPS-197 Appendix C.3 AES-256 vector.
  2. Nb=8, Nk=8 key expansion reproduces the 15 golden round keys of the
     WAES-256 key schedule for the FIPS-197 AES-256 test key.
  3. Nb=8 decryption inverts encryption for random keys/blocks.
"""

import os

# ----------------------------------------------------------------------------
# GF(2^8) helpers and S-box (computed, not tabulated, so it is independent of
# the ROM256X1 INIT strings used in the RTL)
# ----------------------------------------------------------------------------

def gmul(a, b):
    r = 0
    while b:
        if b & 1:
            r ^= a
        a = ((a << 1) ^ 0x11B) if a & 0x80 else (a << 1)
        b >>= 1
    return r


def _make_sbox():
    sbox = [0] * 256
    for x in range(256):
        inv = 0 if x == 0 else next(y for y in range(1, 256) if gmul(x, y) == 1)
        s = 0x63
        for i in range(8):
            bit = ((inv >> i) ^ (inv >> ((i + 4) % 8)) ^ (inv >> ((i + 5) % 8))
                   ^ (inv >> ((i + 6) % 8)) ^ (inv >> ((i + 7) % 8))) & 1
            s ^= bit << i
        sbox[x] = s
    inv_sbox = [0] * 256
    for x, y in enumerate(sbox):
        inv_sbox[y] = x
    return sbox, inv_sbox


SBOX, INV_SBOX = _make_sbox()

# ShiftRows offsets (C1, C2, C3) from the Rijndael specification
SHIFTS = {4: (0, 1, 2, 3), 5: (0, 1, 2, 3), 6: (0, 1, 2, 3), 7: (0, 1, 2, 4), 8: (0, 1, 3, 4)}


def num_rounds(nb, nk):
    return max(nb, nk) + 6


# ----------------------------------------------------------------------------
# Key expansion: returns Nr+1 round keys, each a list of 4*Nb bytes in the
# same column-major order as the state.
# ----------------------------------------------------------------------------

def expand_key(key, nb):
    nk = len(key) // 4
    nr = num_rounds(nb, nk)
    w = [list(key[4 * i:4 * i + 4]) for i in range(nk)]
    rcon = 1
    for i in range(nk, nb * (nr + 1)):
        t = list(w[i - 1])
        if i % nk == 0:
            t = t[1:] + t[:1]
            t = [SBOX[b] for b in t]
            t[0] ^= rcon
            rcon = gmul(rcon, 2)
        elif nk > 6 and i % nk == 4:
            t = [SBOX[b] for b in t]
        w.append([a ^ b for a, b in zip(w[i - nk], t)])
    return [sum(w[r * nb:(r + 1) * nb], []) for r in range(nr + 1)]


# ----------------------------------------------------------------------------
# Cipher
# ----------------------------------------------------------------------------

def _shift_rows(s, nb, inverse=False):
    out = list(s)
    for r in range(1, 4):
        sh = SHIFTS[nb][r]
        for c in range(nb):
            src = (c - sh) % nb if inverse else (c + sh) % nb
            out[r + 4 * c] = s[r + 4 * src]
    return out


def _mix_columns(s, nb, inverse=False):
    m = (0x0E, 0x0B, 0x0D, 0x09) if inverse else (0x02, 0x03, 0x01, 0x01)
    out = list(s)
    for c in range(nb):
        col = s[4 * c:4 * c + 4]
        for r in range(4):
            out[4 * c + r] = (gmul(m[0], col[r]) ^ gmul(m[1], col[(r + 1) % 4])
                              ^ gmul(m[2], col[(r + 2) % 4]) ^ gmul(m[3], col[(r + 3) % 4]))
    return out


def _add(s, k):
    return [a ^ b for a, b in zip(s, k)]


def encrypt_block(block, key, nb=8, round_keys=None):
    rk = round_keys or expand_key(key, nb)
    nr = len(rk) - 1
    s = _add(list(block), rk[0])
    for r in range(1, nr):
        s = [SBOX[b] for b in s]
        s = _shift_rows(s, nb)
        s = _mix_columns(s, nb)
        s = _add(s, rk[r])
    s = [SBOX[b] for b in s]
    s = _shift_rows(s, nb)
    s = _add(s, rk[nr])
    return bytes(s)


def decrypt_block(block, key, nb=8):
    rk = expand_key(key, nb)
    nr = len(rk) - 1
    s = _add(list(block), rk[nr])
    s = _shift_rows(s, nb, inverse=True)
    s = [INV_SBOX[b] for b in s]
    for r in range(nr - 1, 0, -1):
        s = _add(s, rk[r])
        s = _mix_columns(s, nb, inverse=True)
        s = _shift_rows(s, nb, inverse=True)
        s = [INV_SBOX[b] for b in s]
    s = _add(s, rk[0])
    return bytes(s)


# ----------------------------------------------------------------------------
# Counter mode (keystream generator). The counter-block format is a parameter
# so the model can follow whatever format the rebuilt CTR wrapper adopts.
# Default: 256-bit block = nonce (16 bytes) || counter (16 bytes, big-endian).
# ----------------------------------------------------------------------------

def ctr_keystream(key, nonce, n_blocks, start=0, nb=8):
    bs = 4 * nb
    ctr_len = bs - len(nonce)
    rk = expand_key(key, nb)
    for i in range(start, start + n_blocks):
        cb = bytes(nonce) + (i % (1 << (8 * ctr_len))).to_bytes(ctr_len, "big")
        yield encrypt_block(cb, key, nb, rk)


def ctr_xcrypt(data, key, nonce, nb=8):
    bs = 4 * nb
    ks = b"".join(ctr_keystream(key, nonce, (len(data) + bs - 1) // bs, nb=nb))
    return bytes(a ^ b for a, b in zip(data, ks))


# ----------------------------------------------------------------------------
# Self-checks
# ----------------------------------------------------------------------------

def _selftest():
    h = bytes.fromhex
    # 1. FIPS-197 Appendix C.3 (AES-256, Nb=4)
    k = h("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
    p = h("00112233445566778899aabbccddeeff")
    assert encrypt_block(p, k, nb=4).hex() == "8ea2b7ca516745bfeafc49904b496089", "FIPS-197 C.3"
    assert decrypt_block(h("8ea2b7ca516745bfeafc49904b496089"), k, nb=4) == p

    # 2. WAES-256 key expansion vs. golden round keys
    k = h("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4")
    golden = [
        "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
        "9ba354118e6925afa51a8b5f2067fcdea8b09c1a93d194cdbe49846eb75d5b9a",
        "d59aecb85bf3c917fee94248de8ebe96b5a9328a2678a647983122292f6c79b3",
        "812c81addadf48ba24360af2fab8b46498c5bfc9bebd198e268c3ba709e04214",
        "68007bacb2df331696e939e46c518d80c814e20476a9fb8a5025c02d59c58239",
        "de1369676ccc5a71fa2563959674ee155886ca5d2e2f31d77e0af1fa27cf73c3",
        "749c47ab18501ddae2757e4f7401905acafaaae3e4d59b349adf6acebd10190d",
        "fe4890d1e6188d0b046df344706c631e9baa51917f7fcaa5e5a0a06b58b0b966",
        "991ea3bb7f062eb07b6bddf40b07beeab06fff16cf1035b32ab095d872002cbe",
        "e16f0dfb9e69234be502febfee0540559804f6ea5714c3597da456810fa47a3f",
        "9eb5788d00dc5bc6e5dea5790bdbe52cb3bd2f9be4a9ecc2990dba4396a9c07c",
        "210f681d21d333dbc40d96a2cfd6738e394ba082dde24c4044eff603d246367f",
        "a30abaa882d9897346d41fd189026c5f9e3cf04d43debc0d07314a0ed5777c71",
        "fd1a19ab7fc390d839178f09b015e3567965e1fc3abb5df13d8a17ffe8fd6b8e",
        "e46500309ba690e8a2b11fe112a4fcb7b02c51558a970ca4b71d1b5b5fe070d5",
    ]
    rk = expand_key(k, nb=8)
    assert [bytes(x).hex() for x in rk] == golden, "WAES key expansion"

    # 3. Round trip
    for _ in range(20):
        k, p = os.urandom(32), os.urandom(32)
        assert decrypt_block(encrypt_block(p, k), k) == p
    print("rijndael_ref self-test: PASS (FIPS-197 C.3, WAES key schedule golden, round trip)")


if __name__ == "__main__":
    _selftest()
