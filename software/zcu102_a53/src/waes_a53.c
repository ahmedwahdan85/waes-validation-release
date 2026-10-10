/* WAES-256 (Rijndael Nb=8, Nk=8, Nr=14) in counter mode with the ARMv8
 * Cryptography Extensions (Cortex-A53).
 *
 * The 256-bit state is held as two 128-bit halves A (columns 0..3) and
 * B (columns 4..7). AESE(x, k) computes SubBytes(ShiftRows128(x ^ k)). A
 * byte permutation P with ShiftRows128(P(s)) = ShiftRows256(s) is applied to
 * the state (one TBL per half) before every AESE; since P is linear, the round
 * keys are permuted once, so AESE(P(s), P(rk)) = SubBytes(ShiftRows256(s ^ rk)).
 * AESMC then completes the round with MixColumns.
 */
#include "waes_a53.h"

#ifndef NBLK
#define NBLK 8 /* blocks processed in parallel to hide the AESE/AESMC latency */
#endif

static uint8_t gmul(uint8_t a, uint8_t b)
{
    uint8_t r = 0;
    while (b) {
        if (b & 1) r ^= a;
        a = (a & 0x80) ? (uint8_t)((a << 1) ^ 0x1b) : (uint8_t)(a << 1);
        b >>= 1;
    }
    return r;
}

static void make_sbox(uint8_t s[256])
{
    for (int x = 0; x < 256; x++) {
        uint8_t inv = 0;
        if (x) for (int y = 1; y < 256; y++) if (gmul((uint8_t)x, (uint8_t)y) == 1) { inv = (uint8_t)y; break; }
        uint8_t v = 0x63;
        for (int i = 0; i < 8; i++) {
            uint8_t bit = ((inv >> i) ^ (inv >> ((i + 4) % 8)) ^ (inv >> ((i + 5) % 8)) ^
                           (inv >> ((i + 6) % 8)) ^ (inv >> ((i + 7) % 8))) & 1;
            v ^= (uint8_t)(bit << i);
        }
        s[x] = v;
    }
}

static void expand_key(const uint8_t key[32], uint8_t rk[15][32])
{
    static uint8_t sbox[256];
    static int have_sbox;
    uint8_t w[120][4];
    uint8_t rcon = 1;
    if (!have_sbox) { make_sbox(sbox); have_sbox = 1; }
    for (int i = 0; i < 8; i++)
        for (int j = 0; j < 4; j++) w[i][j] = key[4 * i + j];
    for (int i = 8; i < 120; i++) {
        uint8_t t[4] = { w[i - 1][0], w[i - 1][1], w[i - 1][2], w[i - 1][3] };
        if (i % 8 == 0) {
            uint8_t t0 = t[0];
            t[0] = sbox[t[1]]; t[1] = sbox[t[2]]; t[2] = sbox[t[3]]; t[3] = sbox[t0];
            t[0] ^= rcon;
            rcon = gmul(rcon, 2);
        } else if (i % 8 == 4) {
            for (int j = 0; j < 4; j++) t[j] = sbox[t[j]];
        }
        for (int j = 0; j < 4; j++) w[i][j] = w[i - 8][j] ^ t[j];
    }
    for (int r = 0; r < 15; r++)
        for (int c = 0; c < 8; c++)
            for (int j = 0; j < 4; j++) rk[r][4 * c + j] = w[8 * r + c][j];
}

/* Source byte of every output byte of P, with ShiftRows128(P(s)) = ShiftRows256(s). */
static void perm_index(uint8_t idx[32])
{
    static const int s[4] = { 0, 1, 3, 4 };
    for (int h = 0; h < 2; h++)
        for (int cp = 0; cp < 4; cp++)
            for (int r = 0; r < 4; r++) {
                int col = (4 * h + ((cp + 4 - r) % 4) + s[r]) % 8;
                idx[r + 4 * (4 * h + cp)] = (uint8_t)(r + 4 * col);
            }
}

#define PERM(c, a, b, x, y) do {                       \
        uint8x16x2_t t_ = { { (a), (b) } };            \
        (x) = vqtbl2q_u8(t_, (c)->ia);                 \
        (y) = vqtbl2q_u8(t_, (c)->ib);                 \
    } while (0)

void waes_init(waes_ctx *c, const uint8_t key[32])
{
    uint8_t rk[15][32], idx[32];
    expand_key(key, rk);
    perm_index(idx);
    c->ia = vld1q_u8(idx);
    c->ib = vld1q_u8(idx + 16);
    for (int r = 0; r < 14; r++)
        PERM(c, vld1q_u8(rk[r]), vld1q_u8(rk[r] + 16), c->prka[r], c->prkb[r]);
    c->rka14 = vld1q_u8(rk[14]);
    c->rkb14 = vld1q_u8(rk[14] + 16);
}

static inline __attribute__((always_inline))
void enc_n(const waes_ctx *c, uint8x16_t *a, uint8x16_t *b, const int n)
{
    uint8x16_t x, y;
    for (int r = 0; r < 13; r++)
        for (int i = 0; i < n; i++) {
            PERM(c, a[i], b[i], x, y);
            a[i] = vaesmcq_u8(vaeseq_u8(x, c->prka[r]));
            b[i] = vaesmcq_u8(vaeseq_u8(y, c->prkb[r]));
        }
    for (int i = 0; i < n; i++) {
        PERM(c, a[i], b[i], x, y);
        a[i] = veorq_u8(vaeseq_u8(x, c->prka[13]), c->rka14);
        b[i] = veorq_u8(vaeseq_u8(y, c->prkb[13]), c->rkb14);
    }
}

void waes_encrypt_block(const waes_ctx *c, const uint8_t in[32], uint8_t out[32])
{
    uint8x16_t a[1] = { vld1q_u8(in) }, b[1] = { vld1q_u8(in + 16) };
    enc_n(c, a, b, 1);
    vst1q_u8(out, a[0]);
    vst1q_u8(out + 16, b[0]);
}

static inline uint8x16_t ctr_half(unsigned __int128 v)
{
    uint64_t hi = (uint64_t)(v >> 64), lo = (uint64_t)v;
    return vcombine_u8(vrev64_u8(vcreate_u8(hi)), vrev64_u8(vcreate_u8(lo)));
}

void waes_ctr_xor(const waes_ctx *c, const uint8_t nonce[16], unsigned __int128 ctr0,
                  uint8_t *buf, size_t len)
{
    const uint8x16_t na = vld1q_u8(nonce);
    size_t nblk = len / 32, i = 0;
    unsigned __int128 ctr = ctr0;
    uint8x16_t a[NBLK], b[NBLK];
    while (i + NBLK <= nblk) {
        for (int k = 0; k < NBLK; k++) { a[k] = na; b[k] = ctr_half(ctr + (unsigned)k); }
        enc_n(c, a, b, NBLK);
        for (int k = 0; k < NBLK; k++) {
            uint8_t *p = buf + (i + k) * 32;
            vst1q_u8(p, veorq_u8(vld1q_u8(p), a[k]));
            vst1q_u8(p + 16, veorq_u8(vld1q_u8(p + 16), b[k]));
        }
        ctr += NBLK;
        i += NBLK;
    }
    for (; i < nblk; i++, ctr++) {
        a[0] = na; b[0] = ctr_half(ctr);
        enc_n(c, a, b, 1);
        uint8_t *p = buf + i * 32;
        vst1q_u8(p, veorq_u8(vld1q_u8(p), a[0]));
        vst1q_u8(p + 16, veorq_u8(vld1q_u8(p + 16), b[0]));
    }
}
