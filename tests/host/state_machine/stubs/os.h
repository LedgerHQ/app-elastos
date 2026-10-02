/* Harness stub: os.h. THROW and TRY go through a jmp_buf pointer so the driver can set its own
 * exception context around direct calls. */
#ifndef SM_OS_H
#define SM_OS_H
#include <string.h>
#include <strings.h>
#include <setjmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>

#define os_memmove memmove
#define os_memcpy memcpy
#define os_memset memset
#define os_memcmp memcmp
#define UNUSED(x) (void) (x)

extern jmp_buf g_ela_jmp_app;
extern jmp_buf *g_ela_jmp_ptr;
extern unsigned int g_last_throw;
extern jmp_buf g_case_jmp;

#define BEGIN_TRY
#define END_TRY
#define TRY if ((g_last_throw = (unsigned int) setjmp(*g_ela_jmp_ptr)) == 0)
#define CATCH_OTHER(e) else for (unsigned int e = g_last_throw, _once = 1; _once; _once = 0)
#define CATCH(x) else if (g_last_throw == (unsigned int) (x))
/* A break inside CATCH_OTHER leaves only its one-pass loop. No exception reaches main()'s
 * handler on the host, so main() runs as on the device. */
#define CLOSE_TRY
#define FINALLY
#define THROW(x) longjmp(*g_ela_jmp_ptr, (int) ((x) == 0 ? 1 : (x)))

#define CHANNEL_APDU 0x00
#define CHANNEL_KEYBOARD 0x01
#define CHANNEL_SPI 0x02
#define IO_RETURN_AFTER_TX 0x10
#define IO_ASYNCH_REPLY 0x20
#define IO_RESET_AFTER_REPLIED 0x40
#define IO_FLAGS 0xF0
#define INVALID_PARAMETER 0x6700
#define EXCEPTION_IO_RESET 0x5
#define INVALID_STATE 0x4

static inline unsigned int os_seph_features(void) { return 0x00; /* small screen: Nano S paths */ }
static inline void os_boot(void) {}
static inline void os_sched_exit(int code) { (void) code; longjmp(g_case_jmp, 2); }
static inline void reset(void) { longjmp(g_case_jmp, 3); }
static inline unsigned int os_setting_get(unsigned int s, void *v, unsigned int l) { (void) s; (void) v; (void) l; return 0; }
static inline void USB_power(unsigned int on) { (void) on; }
static inline void BLE_power(unsigned int on, const char *name) { (void) on; (void) name; }

/* W1 and F1: the driver sees every wipe, and can fail each crypto step after it writes its
 * output, the worst case for leftovers. */
void sm_on_wipe(void *p, size_t n);
extern int g_fail_derive, g_fail_init_key, g_fail_pair, g_fail_sign;
extern unsigned char *g_derive_out;
static inline void explicit_bzero_sm(void *p, size_t n) { memset(p, 0, n); sm_on_wipe(p, n); }
#define explicit_bzero explicit_bzero_sm

typedef uint32_t cx_err_t;
#define CX_OK 0

/* The last derivation: where its path was read and what it was, so a check can compare paths.
 * Static, unlike the switches above, because the Nano X gate builds with these stubs too; each
 * harness is one translation unit, so the driver reads the copy the stub writes. */
#define SM_DERIVED_PATH_MAX 5
static const unsigned int *g_derive_path;
static unsigned int g_derived_path[SM_DERIVED_PATH_MAX];
static unsigned int g_derived_path_len;
/* driver hook: fault the path just before a derivation reads it */
static void (*g_derive_hook)(const unsigned int *path);
/* derivations so far, the driver's included: a refused key request must derive nothing */
static unsigned long g_derivations;

/* Deterministic per path. Each component is folded in, so its top byte, hardened bit included,
 * changes the key like its other bits. gen_corpus.py computes the same function. */
static inline cx_err_t os_derive_bip32_no_throw(unsigned int curve, const unsigned int *path,
                                                unsigned int pathlen, unsigned char *out,
                                                unsigned char *chain) {
    (void) curve; (void) chain;
    if (g_derive_hook) g_derive_hook(path);
    g_derivations++;
    g_derive_path = path;
    g_derived_path_len = pathlen;
    for (unsigned int i = 0; i < pathlen && i < SM_DERIVED_PATH_MAX; i++) g_derived_path[i] = path[i];
    unsigned int x = 0xE1A5;
    for (unsigned int i = 0; i < pathlen; i++) {
        x = x * 31 + path[i];
        x ^= x >> 16;
    }
    for (int i = 0; i < 64; i++) { x = x * 1103515245 + 12345; out[i] = (unsigned char) (x >> 16); }
    g_derive_out = out;
    return g_fail_derive ? 1 : CX_OK;
}

typedef struct { unsigned char plane_mode; } G_io_app_t;
extern G_io_app_t G_io_app;
typedef struct { int dummy; } os_ux_params_t;
#endif
