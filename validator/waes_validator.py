"""Validation of WAES-256 counter-mode test packets produced by waes_ctr_test.

Packet (UDP payload, 1472 bytes) = 64-byte header + 11 records of 128 bytes.
Header (big-endian):
   0 "WAES" | 4 version | 5 records/packet | 6 record size (2)
   8 packet sequence (4) | 12 session id (4) | 16 packet index in session (2)
  18 stall profile | 19 0 | 20 packets per session (2) | 22..31 0 | 32 key (32)
Record: counter block nonce||ctr (32) | plaintext P (32) | ciphertext C (32)
        | decrypted D (32)

Per record the validator checks:
  cipher     C == P xor WAES-256_K(counter block)   (reference model)
  roundtrip  D == P                                   (plaintext/decrypted)
  counter    nonce constant within the session and
             ctr == packet_index * 11 + record_index  (increment rule)

Usable as a module (validate_batch, used by the GUI) or from the command line:
  python waes_validator.py packets.txt     (one hex payload per line)
"""

import os
import sys

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import waes_fast  # noqa: E402

MAGIC = b"WAES"
HDR_LEN = 64
REC_LEN = 128
N_REC = 11
PAYLOAD_LEN = HDR_LEN + N_REC * REC_LEN

_rk_cache = {}


def _round_keys(key):
    rk = _rk_cache.get(key)
    if rk is None:
        if len(_rk_cache) > 4096:
            _rk_cache.clear()
        rk = _rk_cache[key] = waes_fast.expand_key(key)
    return rk


def new_stats():
    return {
        "packets": 0, "records": 0, "format_err": 0,
        "cipher_err": 0, "roundtrip_err": 0, "counter_err": 0,
        "seq_min": None, "seq_max": None,
        "sessions": set(), "keys": set(), "nonces": set(),
        "profile_records": [0, 0, 0, 0],
        "errors": [],                     # (kind, seq, record, detail) samples
    }


def merge_stats(total, part, max_errors=50):
    for k in ("packets", "records", "format_err", "cipher_err",
              "roundtrip_err", "counter_err"):
        total[k] += part[k]
    for k, f in (("seq_min", min), ("seq_max", max)):
        if part[k] is not None:
            total[k] = part[k] if total[k] is None else f(total[k], part[k])
    for k in ("sessions", "keys", "nonces"):
        total[k] |= part[k]
    for i in range(4):
        total["profile_records"][i] += part["profile_records"][i]
    room = max_errors - len(total["errors"])
    if room > 0:
        total["errors"].extend(part["errors"][:room])
    return total


_POS = np.arange(N_REC, dtype=np.uint64)


def validate_batch(packets, max_errors=20):
    """Validate a list of payloads (bytes). Returns a stats dict.

    Vectorized over the whole batch: packets are stacked into one array,
    grouped by session key, and every check is a NumPy operation.
    """
    st = new_stats()
    st["packets"] = len(packets)
    good = [p for p in packets if len(p) == PAYLOAD_LEN]
    n_bad_len = len(packets) - len(good)
    st["format_err"] += n_bad_len
    for p in packets:
        if len(p) != PAYLOAD_LEN and len(st["errors"]) < max_errors:
            st["errors"].append(("format", None, None, bytes(p[:16]).hex()))
    if not good:
        return st

    arr = np.frombuffer(b"".join(good), np.uint8).reshape(len(good), PAYLOAD_LEN)
    fmt_ok = (np.all(arr[:, 0:4] == np.frombuffer(MAGIC, np.uint8), axis=1)
              & (arr[:, 4] == 1) & (arr[:, 5] == N_REC)
              & (arr[:, 6] == (REC_LEN >> 8)) & (arr[:, 7] == (REC_LEN & 0xFF)))
    if not fmt_ok.all():
        for i in np.flatnonzero(~fmt_ok):
            st["format_err"] += 1
            if len(st["errors"]) < max_errors:
                st["errors"].append(("format", None, None, bytes(arr[i, :16]).hex()))
        arr = arr[fmt_ok]
        if len(arr) == 0:
            return st
    n = len(arr)

    seq = np.ascontiguousarray(arr[:, 8:12]).view(">u4").reshape(n).astype(np.int64)
    session = np.ascontiguousarray(arr[:, 12:16]).view(">u4").reshape(n)
    pidx = np.ascontiguousarray(arr[:, 16:18]).view(">u2").reshape(n).astype(np.uint64)
    profile = arr[:, 18] & 3
    keys = arr[:, 32:64]

    st["seq_min"], st["seq_max"] = int(seq.min()), int(seq.max())
    st["sessions"] |= set(session.tolist())

    rec = arr[:, HDR_LEN:].reshape(n, N_REC, REC_LEN)
    cb, p, c, d = rec[:, :, 0:32], rec[:, :, 32:64], rec[:, :, 64:96], rec[:, :, 96:128]

    # keystream for the whole batch in one call: every block carries the
    # round keys of its packet's session key
    ukeys, inv = np.unique(keys, axis=0, return_inverse=True)
    inv = inv.reshape(-1)
    rk_u = np.stack([_round_keys(bytes(k)) for k in ukeys])          # (u, 15, 32)
    for k in ukeys:
        st["keys"].add(bytes(k))
    rk_blk = np.repeat(rk_u[inv], N_REC, axis=0)                       # (n*11, 15, 32)
    ks = waes_fast.encrypt_blocks_rk(np.ascontiguousarray(cb).reshape(-1, 32),
                                     rk_blk).reshape(n, N_REC, 32)

    bad_c = np.any(c != (p ^ ks), axis=2)                      # (n, 11)
    bad_d = np.any(d != p, axis=2)

    nonce_ok = np.all(cb[:, :, 0:16] == cb[:, 0:1, 0:16], axis=(1, 2))
    ctr_hi_zero = np.all(cb[:, :, 16:24] == 0, axis=2)
    ctr_lo = np.ascontiguousarray(cb[:, :, 24:32]).view(">u8").reshape(n, N_REC)
    exp = pidx[:, None] * np.uint64(N_REC) + _POS[None, :]
    bad_n = (~ctr_hi_zero) | (ctr_lo != exp) | (~nonce_ok)[:, None]
    for x in np.unique(np.ascontiguousarray(cb[:, 0, 0:16]), axis=0):
        st["nonces"].add(bytes(x))

    st["records"] += n * N_REC
    cnt = np.bincount(profile, minlength=4)
    for i in range(4):
        st["profile_records"][i] += int(cnt[i]) * N_REC
    st["cipher_err"] += int(bad_c.sum())
    st["roundtrip_err"] += int(bad_d.sum())
    st["counter_err"] += int(bad_n.sum())

    if len(st["errors"]) < max_errors and (bad_c.any() or bad_d.any() or bad_n.any()):
        for kind, mask in (("cipher", bad_c), ("roundtrip", bad_d), ("counter", bad_n)):
            for j, i in zip(*np.nonzero(mask)):
                if len(st["errors"]) >= max_errors:
                    break
                if kind == "cipher":
                    det = (f"CB={bytes(cb[j, i]).hex()} P={bytes(p[j, i]).hex()} "
                           f"C={bytes(c[j, i]).hex()} exp={bytes(p[j, i] ^ ks[j, i]).hex()}")
                elif kind == "roundtrip":
                    det = f"P={bytes(p[j, i]).hex()} D={bytes(d[j, i]).hex()}"
                else:
                    det = (f"session={int(session[j])} pkt_idx={int(pidx[j])} "
                           f"ctr={int.from_bytes(bytes(cb[j, i, 16:32]), 'big')} exp={int(exp[j, i])}")
                st["errors"].append((kind, int(seq[j]), int(i), det))
    return st


def summary(st):
    recv = st["packets"]
    span = 0 if st["seq_min"] is None else st["seq_max"] - st["seq_min"] + 1
    lines = [
        f"packets received        : {recv}",
        f"packets lost (seq gaps) : {max(span - recv, 0)}",
        f"records verified        : {st['records']}  "
        f"({st['records'] * 32} plaintext bytes)",
        f"sessions / keys / nonces: {len(st['sessions'])} / {len(st['keys'])} / "
        f"{len(st['nonces'])}",
        "records per stall profile (0/25/50/75 %): "
        + " / ".join(str(x) for x in st["profile_records"]),
        f"format errors           : {st['format_err']}",
        f"cipher mismatches       : {st['cipher_err']}",
        f"plaintext/decrypted mismatches: {st['roundtrip_err']}",
        f"counter-rule violations : {st['counter_err']}",
    ]
    return "\n".join(lines)


def main(path):
    with open(path) as f:
        packets = [bytes.fromhex(line.strip()) for line in f if line.strip()]
    st = validate_batch(packets)
    print(summary(st))
    for e in st["errors"][:10]:
        print("ERROR", e)
    ok = st["packets"] > 0 and not (st["format_err"] or st["cipher_err"]
                                    or st["roundtrip_err"] or st["counter_err"])
    print("RESULT:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
