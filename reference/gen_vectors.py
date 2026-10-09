"""Generate WAES-256 known-answer vectors (one test per line, hex).

Output format (one test per line, hex, byte 0 first):
    K <key>                 start of a new key
    V <plaintext> <ciphertext>
Each key gets: an all-zero block, an all-ones block, CTR counter blocks
(nonce || i) for i = 0..N-1, and random blocks.
"""

import os
import random
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from rijndael_ref import encrypt_block, expand_key  # noqa: E402

SEED = 20261009
N_CTR = 48
N_RAND = 48


def main(out_path):
    rng = random.Random(SEED)
    keys = [
        bytes.fromhex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"),
        bytes(32),
        bytes([0xFF] * 32),
        bytes(range(32)),
    ] + [bytes(rng.getrandbits(8) for _ in range(32)) for _ in range(4)]

    n = 0
    with open(out_path, "w") as f:
        for key in keys:
            rk = expand_key(key, 8)
            f.write(f"K {key.hex()}\n")
            nonce = bytes(rng.getrandbits(8) for _ in range(16))
            blocks = [bytes(32), bytes([0xFF] * 32)]
            blocks += [nonce + i.to_bytes(16, "big") for i in range(N_CTR)]
            blocks += [bytes(rng.getrandbits(8) for _ in range(32)) for _ in range(N_RAND)]
            for p in blocks:
                f.write(f"V {p.hex()} {encrypt_block(p, key, 8, rk).hex()}\n")
                n += 1
    print(f"wrote {n} vectors for {len(keys)} keys to {out_path}")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "waes_vectors.txt")
