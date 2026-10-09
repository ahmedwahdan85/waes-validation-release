//! WAES-256 (Rijndael Nb=8, Nk=8, Nr=14) in counter mode with AES-NI.
//!
//! The 256-bit state is held as two 128-bit halves A (columns 0..3) and
//! B (columns 4..7). AESENC applies the AES ShiftRows (offsets 0,1,2,3) within
//! each half; a cross-half byte permutation applied before every AESENC
//! (two PSHUFB per half, ORed) turns this into the WAES-256 ShiftRows
//! (offsets 0,1,3,4 over 8 columns). SubBytes commutes with the permutation,
//! so AESENC / AESENCLAST then complete the round.
//!
//! Usage:
//!   waes_aesni verify <vectors.txt>   check against the reference vectors
//!   waes_aesni ks <key> <nonce> <n>   print n counter-mode keystream blocks
//!   waes_aesni bench [seconds]        CTR throughput, 1 thread and all threads

use std::arch::x86_64::*;
use std::time::{Duration, Instant};

// ----------------------------------------------------------------------------
// S-box and key expansion (scalar; done once per key)
// ----------------------------------------------------------------------------
fn gmul(mut a: u8, mut b: u8) -> u8 {
    let mut r = 0u8;
    while b != 0 {
        if b & 1 != 0 { r ^= a; }
        a = if a & 0x80 != 0 { (a << 1) ^ 0x1b } else { a << 1 };
        b >>= 1;
    }
    r
}

fn make_sbox() -> [u8; 256] {
    let mut s = [0u8; 256];
    for x in 0..256usize {
        let inv = if x == 0 { 0 } else { (1..=255u8).find(|&y| gmul(x as u8, y) == 1).unwrap() };
        let mut v = 0x63u8;
        for i in 0..8 {
            let bit = ((inv >> i) ^ (inv >> ((i + 4) % 8)) ^ (inv >> ((i + 5) % 8))
                ^ (inv >> ((i + 6) % 8)) ^ (inv >> ((i + 7) % 8))) & 1;
            v ^= bit << i;
        }
        s[x] = v;
    }
    s
}

fn expand_key(key: &[u8; 32], sbox: &[u8; 256]) -> [[u8; 32]; 15] {
    let (nk, nb, nr) = (8usize, 8usize, 14usize);
    let mut w: Vec<[u8; 4]> = (0..nk).map(|i| [key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]]).collect();
    let mut rcon = 1u8;
    for i in nk..nb * (nr + 1) {
        let mut t = w[i - 1];
        if i % nk == 0 {
            t = [t[1], t[2], t[3], t[0]];
            for b in t.iter_mut() { *b = sbox[*b as usize]; }
            t[0] ^= rcon;
            rcon = gmul(rcon, 2);
        } else if i % nk == 4 {
            for b in t.iter_mut() { *b = sbox[*b as usize]; }
        }
        let p = w[i - nk];
        w.push([p[0] ^ t[0], p[1] ^ t[1], p[2] ^ t[2], p[3] ^ t[3]]);
    }
    let mut rk = [[0u8; 32]; 15];
    for r in 0..=nr {
        for c in 0..nb {
            rk[r][4 * c..4 * c + 4].copy_from_slice(&w[r * nb + c]);
        }
    }
    rk
}

// ----------------------------------------------------------------------------
// AES-NI kernel
// ----------------------------------------------------------------------------
#[derive(Clone, Copy)]
struct Ctx {
    rka: [__m128i; 15],
    rkb: [__m128i; 15],
    m_aa: __m128i, // output half A, bytes taken from A
    m_ba: __m128i, // output half A, bytes taken from B
    m_ab: __m128i, // output half B, bytes taken from A
    m_bb: __m128i, // output half B, bytes taken from B
}

/// Byte masks for the pre-AESENC permutation X with SR128(X) = SR256(state).
fn perm_masks() -> ([i8; 16], [i8; 16], [i8; 16], [i8; 16]) {
    let s = [0usize, 1, 3, 4];
    let mut src = [0usize; 32];
    for h in 0..2 {
        for cp in 0..4 {
            for r in 0..4 {
                let col = (4 * h + ((cp + 4 - r) % 4) + s[r]) % 8;
                src[r + 4 * (4 * h + cp)] = r + 4 * col;
            }
        }
    }
    let (mut aa, mut ba, mut ab, mut bb) = ([-128i8; 16], [-128i8; 16], [-128i8; 16], [-128i8; 16]);
    for j in 0..16 {
        let sa = src[j];
        if sa < 16 { aa[j] = sa as i8 } else { ba[j] = (sa - 16) as i8 }
        let sb = src[16 + j];
        if sb < 16 { ab[j] = sb as i8 } else { bb[j] = (sb - 16) as i8 }
    }
    (aa, ba, ab, bb)
}

unsafe fn load(b: &[u8]) -> __m128i { _mm_loadu_si128(b.as_ptr() as *const __m128i) }

#[target_feature(enable = "aes,ssse3,sse2")]
unsafe fn make_ctx(rk: &[[u8; 32]; 15]) -> Ctx {
    let (aa, ba, ab, bb) = perm_masks();
    let mut c = Ctx {
        rka: [_mm_setzero_si128(); 15], rkb: [_mm_setzero_si128(); 15],
        m_aa: _mm_loadu_si128(aa.as_ptr() as *const __m128i),
        m_ba: _mm_loadu_si128(ba.as_ptr() as *const __m128i),
        m_ab: _mm_loadu_si128(ab.as_ptr() as *const __m128i),
        m_bb: _mm_loadu_si128(bb.as_ptr() as *const __m128i),
    };
    for r in 0..15 {
        c.rka[r] = load(&rk[r][0..16]);
        c.rkb[r] = load(&rk[r][16..32]);
    }
    c
}

#[inline(always)]
unsafe fn perm(c: &Ctx, a: __m128i, b: __m128i) -> (__m128i, __m128i) {
    (
        _mm_or_si128(_mm_shuffle_epi8(a, c.m_aa), _mm_shuffle_epi8(b, c.m_ba)),
        _mm_or_si128(_mm_shuffle_epi8(a, c.m_ab), _mm_shuffle_epi8(b, c.m_bb)),
    )
}

/// Encrypt N blocks in parallel (interleaved to hide AESENC latency).
#[inline(always)]
unsafe fn encrypt_n<const N: usize>(c: &Ctx, a: &mut [__m128i; N], b: &mut [__m128i; N]) {
    for i in 0..N { a[i] = _mm_xor_si128(a[i], c.rka[0]); b[i] = _mm_xor_si128(b[i], c.rkb[0]); }
    for r in 1..14 {
        for i in 0..N {
            let (x, y) = perm(c, a[i], b[i]);
            a[i] = _mm_aesenc_si128(x, c.rka[r]);
            b[i] = _mm_aesenc_si128(y, c.rkb[r]);
        }
    }
    for i in 0..N {
        let (x, y) = perm(c, a[i], b[i]);
        a[i] = _mm_aesenclast_si128(x, c.rka[14]);
        b[i] = _mm_aesenclast_si128(y, c.rkb[14]);
    }
}

#[target_feature(enable = "aes,ssse3,sse2")]
unsafe fn encrypt_block(c: &Ctx, input: &[u8; 32]) -> [u8; 32] {
    let mut a = [load(&input[0..16])];
    let mut b = [load(&input[16..32])];
    encrypt_n::<1>(c, &mut a, &mut b);
    let mut out = [0u8; 32];
    _mm_storeu_si128(out.as_mut_ptr() as *mut __m128i, a[0]);
    _mm_storeu_si128(out[16..].as_mut_ptr() as *mut __m128i, b[0]);
    out
}

/// Counter mode: buf ^= keystream, counter block = nonce(16) || ctr(16, big-endian).
#[target_feature(enable = "aes,ssse3,sse2")]
unsafe fn ctr_xor(c: &Ctx, nonce: &[u8; 16], ctr0: u128, buf: &mut [u8]) {
    const N: usize = 4;
    let na = load(nonce);
    let bswap = _mm_set_epi8(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
    let nblk = buf.len() / 32;
    let mut ctr = ctr0;
    let mut i = 0;
    while i + N <= nblk {
        let mut a = [na; N];
        let mut b = [_mm_setzero_si128(); N];
        for k in 0..N {
            let v = ctr + k as u128;
            let lo = _mm_set_epi64x((v >> 64) as i64, v as i64);
            b[k] = _mm_shuffle_epi8(lo, bswap);
        }
        encrypt_n::<N>(c, &mut a, &mut b);
        for k in 0..N {
            let p = buf.as_mut_ptr().add((i + k) * 32) as *mut __m128i;
            _mm_storeu_si128(p, _mm_xor_si128(_mm_loadu_si128(p), a[k]));
            _mm_storeu_si128(p.add(1), _mm_xor_si128(_mm_loadu_si128(p.add(1)), b[k]));
        }
        ctr += N as u128;
        i += N;
    }
    while i < nblk {
        let mut a = [na];
        let v = ctr;
        let mut b = [_mm_shuffle_epi8(_mm_set_epi64x((v >> 64) as i64, v as i64), bswap)];
        encrypt_n::<1>(c, &mut a, &mut b);
        let p = buf.as_mut_ptr().add(i * 32) as *mut __m128i;
        _mm_storeu_si128(p, _mm_xor_si128(_mm_loadu_si128(p), a[0]));
        _mm_storeu_si128(p.add(1), _mm_xor_si128(_mm_loadu_si128(p.add(1)), b[0]));
        ctr += 1;
        i += 1;
    }
}

// ----------------------------------------------------------------------------
fn hex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fn verify(path: &str, sbox: &[u8; 256]) -> bool {
    let text = std::fs::read_to_string(path).expect("vectors file");
    let (mut ctx, mut n, mut bad) = (None, 0usize, 0usize);
    for line in text.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.is_empty() { continue; }
        if f[0] == "K" {
            let k: [u8; 32] = hex(f[1]).try_into().unwrap();
            ctx = Some(unsafe { make_ctx(&expand_key(&k, sbox)) });
        } else {
            let p: [u8; 32] = hex(f[1]).try_into().unwrap();
            let c: Vec<u8> = hex(f[2]);
            let out = unsafe { encrypt_block(ctx.as_ref().unwrap(), &p) };
            n += 1;
            if out[..] != c[..] { bad += 1; }
        }
    }
    println!("verify: {} vectors, {} mismatches", n, bad);
    n > 0 && bad == 0
}

fn bench(seconds: f64, sbox: &[u8; 256]) {
    let key: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_mul(37).wrapping_add(11));
    let nonce: [u8; 16] = core::array::from_fn(|i| (i as u8).wrapping_mul(91).wrapping_add(5));
    let ctx = unsafe { make_ctx(&expand_key(&key, sbox)) };
    const BUF: usize = 1 << 20; // 1 MiB per call, stays in cache: measures the cipher

    let run = |threads: usize| -> f64 {
        let dur = Duration::from_secs_f64(seconds);
        let total: u64 = std::thread::scope(|sc| {
            let hs: Vec<_> = (0..threads).map(|t| {
                let ctx = ctx;
                sc.spawn(move || {
                    let mut buf = vec![0x5au8; BUF];
                    let mut ctr: u128 = (t as u128) << 64;
                    let mut bytes = 0u64;
                    let t0 = Instant::now();
                    while t0.elapsed() < dur {
                        unsafe { ctr_xor(&ctx, &nonce, ctr, &mut buf) };
                        ctr += (BUF / 32) as u128;
                        bytes += BUF as u64;
                    }
                    std::hint::black_box(&buf);
                    bytes
                })
            }).collect();
            hs.into_iter().map(|h| h.join().unwrap()).sum()
        });
        total as f64 * 8.0 / seconds / 1e9
    };

    let nthreads = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1);
    let g1 = run(1);
    println!("WAES-256 CTR, AES-NI, 1 thread       : {:8.2} Gbps", g1);
    let gn = run(nthreads);
    println!("WAES-256 CTR, AES-NI, {:2} threads     : {:8.2} Gbps", nthreads, gn);
}

fn main() {
    assert!(is_x86_feature_detected!("aes") && is_x86_feature_detected!("ssse3"), "AES-NI/SSSE3 required");
    let sbox = make_sbox();
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(|s| s.as_str()) {
        Some("verify") => { if !verify(&args[2], &sbox) { std::process::exit(1) } }
        Some("ks") => {
            // keystream of n blocks: ks <key hex> <nonce hex> <n>
            let k: [u8; 32] = hex(&args[2]).try_into().unwrap();
            let nonce: [u8; 16] = hex(&args[3]).try_into().unwrap();
            let n: usize = args[4].parse().unwrap();
            let ctx = unsafe { make_ctx(&expand_key(&k, &sbox)) };
            let mut buf = vec![0u8; 32 * n];
            unsafe { ctr_xor(&ctx, &nonce, 0, &mut buf) };
            for b in buf.chunks(32) { println!("{}", b.iter().map(|x| format!("{:02x}", x)).collect::<String>()); }
        }
        Some("bench") => bench(args.get(2).and_then(|s| s.parse().ok()).unwrap_or(10.0), &sbox),
        _ => eprintln!("usage: waes_aesni verify <vectors.txt> | ks <key> <nonce> <n> | bench [seconds]"),
    }
}
