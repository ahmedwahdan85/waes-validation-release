# WAES-256 counter-mode hardware validation

Validation software, reference model and test results for the quantitative hardware validation of the WAES-256 counter-mode data path (Section 6, Table 10 of the paper).

## Test principle
On the FPGA, pseudo-random plaintext `P` is encrypted in counter mode, `C = P xor K_e`, passed through a stall injector, and decrypted by a second, independent keystream generator, `D = C xor K_d`. A new random 256-bit key and 128-bit nonce are loaded every 704 blocks. The data path is stalled in 0, 25, 50 or 75 % of the clock cycles (rotating per session), in addition to the back-pressure of the Ethernet interface.

For every 256-bit block, the FPGA sends the counter block, `P`, `C` and `D` to a host PC over UDP. The host checks each block against an independent software reference model of WAES-256:

- **ciphertext:** `C == P xor WAES-256_K(nonce || counter)`
- **plaintext/decrypted:** `D == P`
- **counter rule:** the nonce is constant within a session, and the counter equals `packet_index x 11 + record_index`

## Packet format (UDP payload, 1472 bytes, big-endian)

| Offset | Size | Field |
|---|---|---|
| 0 | 4 | magic `"WAES"` |
| 4 | 1 | version (1) |
| 5 | 1 | records per packet (11) |
| 6 | 2 | record size (128) |
| 8 | 4 | packet sequence number |
| 12 | 4 | session id |
| 16 | 2 | packet index in session |
| 18 | 1 | stall profile (0..3 = 0/25/50/75 %) |
| 20 | 2 | packets per session |
| 32 | 32 | session key |
| 64 | 11 x 128 | records: counter block (nonce ‖ counter, 32 B), plaintext (32 B), ciphertext (32 B), decrypted (32 B) |

All 256-bit fields are in Rijndael byte order (byte 0 first).

## Contents

| Path | Description |
|---|---|
| `reference/rijndael_ref.py` | Generic Rijndael reference model (variable block size). Self-test: FIPS-197 AES-256 known-answer vector, WAES-256 key-schedule round keys, decrypt/encrypt round trip. |
| `reference/gen_vectors.py` | WAES-256 known-answer vector generator. |
| `validator/waes_fast.py` | Vectorized WAES-256 implementation used for validation, cross-checked against `rijndael_ref.py`. |
| `validator/waes_validator.py` | Packet checks (also a command-line tool for captured packets). |
| `validator/waes_monitor.py` | Validation application: receiver process (loss detection from sequence numbers), parallel validator processes, live statistics and report. |
| `sample/sample_packets.txt` | 40 sample packets (one hex payload per line). |
| `results/waes_ctr_validation_report.json`, `.txt` | Report of the 1-hour run in the paper. |

## Running

```
pip install -r requirements.txt
python reference/rijndael_ref.py                         # reference self-test
python validator/waes_fast.py                            # cross-check vs. reference
python validator/waes_validator.py sample/sample_packets.txt
python validator/waes_monitor.py                         # live validation (FPGA 192.168.1.50 -> UDP 17767)
```

## Result (1-hour run)

| Quantity | Value |
|---|---|
| Duration | 3604.4 s |
| Packets sent / received | 113,085,178 / 113,085,178 |
| Blocks compared (256-bit) | 1,243,936,958 |
| Plaintext compared | 39.81 GB |
| Keys / nonces | 1,766,957 / 1,766,957 |
| Plaintext/decrypted mismatches | 0 |
| Ciphertext mismatches | 0 |
| Counter-rule violations | 0 |
