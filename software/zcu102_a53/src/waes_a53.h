/* WAES-256 (Rijndael Nb=8, Nk=8, Nr=14) with the ARMv8 Cryptography Extensions. */
#ifndef WAES_A53_H
#define WAES_A53_H

#include <stdint.h>
#include <stddef.h>
#include <arm_neon.h>

typedef struct {
    uint8x16_t prka[14], prkb[14]; /* permuted round keys 0..13, halves A and B */
    uint8x16_t rka14, rkb14;       /* last round key (not permuted) */
    uint8x16_t ia, ib;             /* TBL indices of the ShiftRows permutation */
} waes_ctx;

void waes_init(waes_ctx *c, const uint8_t key[32]);
void waes_encrypt_block(const waes_ctx *c, const uint8_t in[32], uint8_t out[32]);
/* Counter mode: buf ^= keystream; counter block = nonce(16) || ctr(16, big-endian). */
void waes_ctr_xor(const waes_ctx *c, const uint8_t nonce[16], unsigned __int128 ctr0,
                  uint8_t *buf, size_t len);

#endif
