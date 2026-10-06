/* Host stub for cx.h. SHA-256 is real, so rendered addresses and their widths are real;
 * RIPEMD-160 writes a fixed pattern, needed only by the unused public key path. */
#ifndef STUB_CX_H
#define STUB_CX_H
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include "sha256.h"

#define CX_LAST 1
#define CX_CURVE_256R1 0
#define CX_OK 0
typedef uint32_t cx_err_t;

typedef struct { int header; unsigned char state[64]; } cx_sha256_t;
typedef struct { int header; unsigned char state[64]; } cx_ripemd160_t;

static inline cx_err_t cx_ripemd160_init_no_throw(cx_ripemd160_t *h) { memset(h, 0, sizeof(*h)); return CX_OK; }
static inline cx_err_t cx_hash_no_throw(void *header, int mode, const unsigned char *in, size_t inlen,
                                        unsigned char *out, size_t outlen) {
    (void) header; (void) mode; (void) in; (void) inlen;
    for (size_t i = 0; out && i < outlen; i++) out[i] = (unsigned char) (0xA0 + (i & 0x1F));
    return CX_OK;
}
static inline size_t cx_hash_sha256(const unsigned char *in, size_t inlen, unsigned char *out, size_t outlen) {
    unsigned char md[SM_SHA256_LEN];
    sm_sha256(in, inlen, md);
    memcpy(out, md, outlen < SM_SHA256_LEN ? outlen : SM_SHA256_LEN);
    return SM_SHA256_LEN;
}
#endif
