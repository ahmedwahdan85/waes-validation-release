/* WAES-256 counter-mode software benchmark on the ZCU102 PS (Cortex-A53),
 * bare-metal, no PL. The same image runs on each A53 core (built for its own
 * DDR region); core 0 is the master and prints over the UART.
 *
 *   1. verify: 784 WAES-256 known-answer vectors and a 37-block counter-mode
 *      keystream from the reference model
 *   2. bench:  counter mode for 10 s on core 0 alone, then 10 s on all 4 cores
 *
 * Mirrors software/waes_aesni.rs: same key, nonce and per-thread counter
 * start, buffer XORed in place with the keystream.
 */
#include <stdint.h>
#include <string.h>
#include "xil_printf.h"
#include "xil_cache.h"
#include "xil_mmu.h"
#include "xiltimer.h"
#include "xtimer_config.h"
#include "xparameters.h"
#include "waes_a53.h"
#include "vectors.h"

#ifndef NBLK
#define NBLK        8
#endif
#define NCORES      4
#define BENCH_S     10
#define BUF         (128 * 1024) /* per core, held in cache: measures the cipher */
#define SHARED_ADDR 0x7FE00000UL /* 2 MB block, non-cacheable on every core */
#define MAGIC       0x57414553U  /* "WAES" */

typedef struct {
    volatile uint32_t magic;
    volatile uint32_t seq;           /* incremented by core 0 for every run */
    volatile uint64_t t_start, t_end;
    volatile uint32_t ready[NCORES];
    volatile uint32_t done_seq[NCORES];
    volatile uint64_t bytes[NCORES];
    volatile uint64_t t_stop[NCORES];
} shared_t;

static uint8_t buf[BUF] __attribute__((aligned(64)));

static inline uint32_t core_id(void)
{
    uint64_t m;
    __asm__ volatile("mrs %0, mpidr_el1" : "=r"(m));
    return (uint32_t)(m & 0xff);
}

static inline uint64_t now(void)
{
    XTime t;
    XTime_GetTime(&t);
    return (uint64_t)t;
}

/* CPU clock measured with the PMU cycle counter against the generic timer. */
static uint64_t cpu_hz(void)
{
    uint64_t c0, c1, pmcr;
    __asm__ volatile("mrs %0, pmcr_el0" : "=r"(pmcr));
    /* E = 1 (enable), D = 0 (count every cycle, not every 64th) */
    __asm__ volatile("msr pmcr_el0, %0" ::"r"((pmcr | 1) & ~(uint64_t)(1 << 3)));
    __asm__ volatile("msr pmcntenset_el0, %0" ::"r"(1UL << 31));
    __asm__ volatile("isb");
    uint64_t t0 = now() + COUNTS_PER_SECOND / 100, t1 = t0 + COUNTS_PER_SECOND / 2;
    while (now() < t0) { }
    __asm__ volatile("mrs %0, pmccntr_el0" : "=r"(c0));
    while (now() < t1) { }
    __asm__ volatile("mrs %0, pmccntr_el0" : "=r"(c1));
    return (c1 - c0) * 2;
}

static void bench_key(waes_ctx *c, uint8_t nonce[16])
{
    uint8_t key[32];
    for (int i = 0; i < 32; i++) key[i] = (uint8_t)(i * 37 + 11);
    for (int i = 0; i < 16; i++) nonce[i] = (uint8_t)(i * 91 + 5);
    waes_init(c, key);
}

/* Encrypt the buffer repeatedly between t_start and t_end; returns bytes. */
static uint64_t run(const waes_ctx *c, const uint8_t nonce[16], uint32_t id,
                    uint64_t t_start, uint64_t t_end, uint64_t *t_stop)
{
    unsigned __int128 ctr = (unsigned __int128)id << 64;
    uint64_t bytes = 0;
    while (now() < t_start) { }
    while (now() < t_end) {
        waes_ctr_xor(c, nonce, ctr, buf, BUF);
        ctr += BUF / 32;
        bytes += BUF;
    }
    *t_stop = now();
    __asm__ volatile("" ::"r"(buf) : "memory");
    return bytes;
}

static void print_gbps(const char *label, uint64_t bytes, uint64_t ticks)
{
    /* Gbps = bytes * 8 / (ticks / COUNTS_PER_SECOND) / 1e9, printed with 2 decimals */
    uint64_t centi = (uint64_t)((double)bytes * 8.0 * (double)COUNTS_PER_SECOND /
                                (double)ticks / 1e7 + 0.5);
    xil_printf("%s: %4d.%02d Gbps\r\n", label, (int)(centi / 100), (int)(centi % 100));
}

static void worker(shared_t *sh, uint32_t id)
{
    waes_ctx c;
    uint8_t nonce[16];
    uint32_t seen = 0;
    bench_key(&c, nonce);
    memset(buf, 0x5a, BUF);
    sh->ready[id] = 1;
    for (;;) {
        while (sh->seq == seen) { }
        seen = sh->seq;
        uint64_t t_stop;
        uint64_t b = run(&c, nonce, id, sh->t_start, sh->t_end, &t_stop);
        sh->bytes[id] = b;
        sh->t_stop[id] = t_stop;
        __asm__ volatile("dsb sy" ::: "memory");
        sh->done_seq[id] = seen;
    }
}

static int verify(void)
{
    waes_ctx c;
    uint8_t out[32];
    int bad = 0, last = -1;
    for (int i = 0; i < N_VEC; i++) {
        if (vec_kidx[i] != last) { last = vec_kidx[i]; waes_init(&c, vec_key[last]); }
        waes_encrypt_block(&c, vec_pt[i], out);
        bad += memcmp(out, vec_ct[i], 32) != 0;
    }
    xil_printf("verify: %d vectors, %d mismatches\r\n", N_VEC, bad);

    static uint8_t ks[KS_N * 32];
    int ks_bad = 0;
    memset(ks, 0, sizeof ks);
    waes_init(&c, ks_key);
    waes_ctr_xor(&c, ks_nonce, 0, ks, sizeof ks);
    for (int i = 0; i < KS_N; i++) ks_bad += memcmp(ks + 32 * i, ks_ref[i], 32) != 0;
    xil_printf("verify: counter-mode keystream, %d blocks, %d mismatches\r\n", KS_N, ks_bad);
    return bad == 0 && ks_bad == 0;
}

int main(void)
{
    shared_t *sh = (shared_t *)SHARED_ADDR;
    uint32_t id = core_id();
    Xil_SetTlbAttributes(SHARED_ADDR, NORM_NONCACHE);

    if (id != 0) {
        while (sh->magic != MAGIC) { }
        worker(sh, id);
    }

    memset((void *)sh, 0, sizeof *sh);
    sh->magic = MAGIC;
    __asm__ volatile("dsb sy" ::: "memory");

    xil_printf("\r\nWAES-256 CTR, ARMv8 Cryptography Extensions, ZCU102 PS (Cortex-A53), bare-metal\r\n");
    xil_printf("CPU clock   : %d MHz (measured)\r\n", (int)(cpu_hz() / 1000000));
    xil_printf("Timer clock : %d Hz\r\n", (int)COUNTS_PER_SECOND);
    xil_printf("Buffer      : %d KiB per core, %d s per measurement\r\n", BUF / 1024, BENCH_S);
    xil_printf("Interleave  : %d blocks in flight per core\r\n", NBLK);

    if (!verify()) {
        xil_printf("VERIFY FAILED, benchmark not run\r\n");
        for (;;) { }
    }

    waes_ctx c;
    uint8_t nonce[16];
    bench_key(&c, nonce);
    memset(buf, 0x5a, BUF);
    const uint64_t dur = (uint64_t)BENCH_S * COUNTS_PER_SECOND;

    /* 1 core */
    uint64_t t0 = now() + COUNTS_PER_SECOND / 10, t_stop;
    uint64_t b = run(&c, nonce, 0, t0, t0 + dur, &t_stop);
    print_gbps("WAES-256 CTR, ARMv8-CE, 1 core ", b, t_stop - t0);

    /* all cores: wait (up to 5 s) for the other cores to report ready */
    uint64_t deadline = now() + 5ULL * COUNTS_PER_SECOND;
    int n = 1;
    while (now() < deadline) {
        n = 1;
        for (int i = 1; i < NCORES; i++) n += sh->ready[i] != 0;
        if (n == NCORES) break;
    }
    if (n != NCORES) xil_printf("note: only %d of %d cores running\r\n", n, NCORES);

    t0 = now() + COUNTS_PER_SECOND / 10;
    sh->t_start = t0;
    sh->t_end = t0 + dur;
    __asm__ volatile("dsb sy" ::: "memory");
    sh->seq = 1;
    uint64_t total = run(&c, nonce, 0, t0, t0 + dur, &t_stop);
    uint64_t t_last = t_stop;
    for (int i = 1; i < NCORES; i++) {
        if (!sh->ready[i]) continue;
        while (sh->done_seq[i] != 1) { }
        total += sh->bytes[i];
        if (sh->t_stop[i] > t_last) t_last = sh->t_stop[i];
    }
    char label[48] = "WAES-256 CTR, ARMv8-CE, x cores";
    label[24] = (char)('0' + n);
    print_gbps(label, total, t_last - t0);
    xil_printf("done\r\n");
    for (;;) { }
}
