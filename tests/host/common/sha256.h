/* SHA-256 (FIPS 180-4), so the host harnesses need no crypto library. Checked by
 * `make -C tests/host check-sha256`. */
#ifndef SM_SHA256_H
#define SM_SHA256_H
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define SM_SHA256_LEN 32

static const uint32_t SM_SHA256_K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

static inline uint32_t sm_rotr(uint32_t x, unsigned n) {
    return (x >> n) | (x << (32 - n));
}

/* Processes one 64-byte block into the running state. */
static inline void sm_sha256_block(uint32_t h[8], const uint8_t *p) {
    uint32_t w[64];
    for (unsigned i = 0; i < 16; i++) {
        w[i] = ((uint32_t) p[4 * i] << 24) | ((uint32_t) p[4 * i + 1] << 16) |
               ((uint32_t) p[4 * i + 2] << 8) | (uint32_t) p[4 * i + 3];
    }
    for (unsigned i = 16; i < 64; i++) {
        uint32_t s0 = sm_rotr(w[i - 15], 7) ^ sm_rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = sm_rotr(w[i - 2], 17) ^ sm_rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], k = h[7];
    for (unsigned i = 0; i < 64; i++) {
        uint32_t t1 = k + (sm_rotr(e, 6) ^ sm_rotr(e, 11) ^ sm_rotr(e, 25)) + ((e & f) ^ (~e & g)) +
                      SM_SHA256_K[i] + w[i];
        uint32_t t2 = (sm_rotr(a, 2) ^ sm_rotr(a, 13) ^ sm_rotr(a, 22)) + ((a & b) ^ (a & c) ^ (b & c));
        k = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }
    h[0] += a;
    h[1] += b;
    h[2] += c;
    h[3] += d;
    h[4] += e;
    h[5] += f;
    h[6] += g;
    h[7] += k;
}

/* Writes SHA-256 of in[0..len) to out. */
static inline void sm_sha256(const uint8_t *in, size_t len, uint8_t out[SM_SHA256_LEN]) {
    uint32_t h[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                     0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
    uint8_t tail[128];
    size_t full = len - len % 64;
    for (size_t off = 0; off < full; off += 64) sm_sha256_block(h, in + off);

    size_t rest = len - full;
    size_t tail_len = rest < 56 ? 64 : 128;
    memset(tail, 0, sizeof(tail));
    memcpy(tail, in + full, rest);
    tail[rest] = 0x80;
    uint64_t bits = (uint64_t) len * 8;
    for (unsigned i = 0; i < 8; i++) tail[tail_len - 1 - i] = (uint8_t) (bits >> (8 * i));
    for (size_t off = 0; off < tail_len; off += 64) sm_sha256_block(h, tail + off);

    for (unsigned i = 0; i < 8; i++) {
        out[4 * i] = (uint8_t) (h[i] >> 24);
        out[4 * i + 1] = (uint8_t) (h[i] >> 16);
        out[4 * i + 2] = (uint8_t) (h[i] >> 8);
        out[4 * i + 3] = (uint8_t) h[i];
    }
}
#endif
