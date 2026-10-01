/* Host stub for the SDK's os.h, enough for elastos.c and base-encoding.c. THROW maps to longjmp
 * so the app's exception idiom runs on the host. */
#ifndef STUB_OS_H
#define STUB_OS_H
#include <string.h>
#include <strings.h>
#include <setjmp.h>
#include <stdio.h>
#include <stdlib.h>

#define os_memmove memmove
#define os_memcpy memcpy
#define os_memset memset
#define os_memcmp memcmp
#define UNUSED(x) (void) (x)

extern jmp_buf g_ela_jmp;
extern unsigned int g_last_throw;

#define BEGIN_TRY
#define END_TRY
#define TRY if ((g_last_throw = (unsigned int) setjmp(g_ela_jmp)) == 0)
#define CATCH_OTHER(e) else
#define FINALLY
#define THROW(x) longjmp(g_ela_jmp, (int) ((x) == 0 ? 1 : (x)))

#define CHANNEL_APDU 0
#define IO_RETURN_AFTER_TX 0x10
#define IO_ASYNCH_REPLY 0x20

static inline void explicit_bzero_host(void *p, size_t n) { memset(p, 0, n); }
#ifndef explicit_bzero
#define explicit_bzero explicit_bzero_host
#endif
static inline unsigned int os_seph_features(void) { return 0; }
#endif
