/* Harness stub: cx.h. SHA-256 is real, so a wrong signed digest shows, and the signature embeds
 * the digest it signed, so the driver sees exactly what was signed. */
#ifndef SM_CX_H
#define SM_CX_H
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "sha256.h"

#define CX_LAST 1
#define CX_CURVE_256R1 0
#define CX_RND_RFC6979 0
#define CX_SHA256 0

typedef struct { int header; unsigned char state[64]; } cx_ripemd160_t;
/* SHA-256 in parts: buffered and hashed whole at the end. The header tells it from the
 * RIPEMD-160 stand-in, whose header is 0. */
#define SM_SHA256_HEADER 0x5348
#define SM_SHA256_PARTS_MAX 1024
typedef struct { int header; size_t len; unsigned char buf[SM_SHA256_PARTS_MAX]; } cx_sha256_t;
/* Driver switches: make SHA-256 in parts or the RIPEMD-160 stand-in fail as the SDK call can,
 * still writing the output, the worst case. Static: see g_derive_path in os.h. */
static int g_fail_sha256_parts;
static int g_fail_ripemd;
/* Driver hooks, static too: see or fault every SHA-256 input before it is hashed, and every
 * RIPEMD-160 output once written. */
static void (*g_hash_input_hook)(const unsigned char *in, size_t inlen);
static void (*g_ripemd_output_hook)(unsigned char *out, size_t outlen);
static inline uint32_t cx_sha256_init_no_throw(cx_sha256_t *h) {
    h->header = SM_SHA256_HEADER;
    h->len = 0;
    return 0;
}
typedef struct { unsigned int curve; size_t d_len; unsigned char d[32]; } cx_ecfp_private_key_t;
typedef struct { unsigned int curve; size_t W_len; unsigned char W[65]; } cx_ecfp_public_key_t;

/* Driver hook around one signing call, to fault state between the checks before and after the
 * hash; if g_sha_hook_input is set, only a hash of that buffer calls it. */
extern void (*g_sha_hook)(void);
extern const unsigned char *g_sha_hook_input;
static inline size_t cx_hash_sha256(const unsigned char *in, size_t inlen, unsigned char *out, size_t outlen) {
    if (g_sha_hook && (g_sha_hook_input == NULL || in == g_sha_hook_input)) g_sha_hook();
    if (g_hash_input_hook) g_hash_input_hook(in, inlen);
    unsigned char md[SM_SHA256_LEN];
    sm_sha256(in, inlen, md);
    memcpy(out, md, outlen < SM_SHA256_LEN ? outlen : SM_SHA256_LEN);
    return 32;
}
static inline uint32_t cx_ripemd160_init_no_throw(cx_ripemd160_t *h) { memset(h, 0, sizeof(*h)); return 0; }
/* RIPEMD-160 stand-in that depends on its input, so keys get distinct addresses. sm_fuzz.c and
 * gen_corpus.py compute it on their own. */
static inline uint32_t cx_hash_no_throw(void *header, int mode, const unsigned char *in, size_t inlen,
                                        unsigned char *out, size_t outlen) {
    if (*(int *) header == SM_SHA256_HEADER) {
        cx_sha256_t *h = (cx_sha256_t *) header;
        if (g_hash_input_hook) g_hash_input_hook(in, inlen);
        if (inlen > SM_SHA256_PARTS_MAX - h->len) return 1;
        memcpy(h->buf + h->len, in, inlen);
        h->len += inlen;
        if (mode & CX_LAST) {
            unsigned char md[SM_SHA256_LEN];
            sm_sha256(h->buf, h->len, md);
            memcpy(out, md, outlen < SM_SHA256_LEN ? outlen : SM_SHA256_LEN);
        }
        return g_fail_sha256_parts ? 1 : 0;
    }
    (void) mode;
    unsigned char md[SM_SHA256_LEN];
    sm_sha256(in, inlen, md);
    for (size_t i = 0; out && i < outlen && i < SM_SHA256_LEN; i++) out[i] = (unsigned char) (md[i] ^ 0x3C);
    if (g_ripemd_output_hook && out) g_ripemd_output_hook(out, outlen < SM_SHA256_LEN ? outlen : SM_SHA256_LEN);
    return g_fail_ripemd ? 1 : 0;
}
extern cx_ecfp_private_key_t *g_private_key;
static inline uint32_t cx_ecfp_init_private_key_no_throw(unsigned int curve, const unsigned char *raw,
                                                         size_t len, cx_ecfp_private_key_t *k) {
    k->curve = curve; k->d_len = len; memcpy(k->d, raw, len <= 32 ? len : 32);
    g_private_key = k;
    return g_fail_init_key ? 1 : 0;
}
static inline uint32_t cx_ecfp_generate_pair_no_throw(unsigned int curve, cx_ecfp_public_key_t *pub,
                                                      cx_ecfp_private_key_t *priv, bool keep) {
    (void) curve; (void) keep;
    pub->W_len = 65; pub->W[0] = 4;
    for (int i = 1; i < 65; i++) pub->W[i] = (unsigned char) (priv->d[i % 32] ^ i);
    return g_fail_pair ? 1 : 0;
}
/* implemented by the driver: sees every digest and key that reaches the signing call */
void sm_on_sign(const unsigned char *digest, const unsigned char *key_d);

/* "signature" = 0x30 0x22 0x04 0x20 || digest: shaped like DER, carries the signed digest */
static inline uint32_t cx_ecdsa_sign_no_throw(const cx_ecfp_private_key_t *k, uint32_t mode, int hashid,
                                              const unsigned char *hash, size_t hashlen,
                                              unsigned char *out, size_t *outlen, uint32_t *info) {
    (void) k; (void) mode; (void) hashid; (void) info;
    if (*outlen < 36 || hashlen != 32 || g_fail_sign) return 1;
    sm_on_sign(hash, k->d);
    out[0] = 0x30; out[1] = 0x22; out[2] = 0x04; out[3] = 0x20;
    memcpy(out + 4, hash, 32);
    *outlen = 36;
    return 0;
}
#endif
