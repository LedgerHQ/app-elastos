/* Harness stub: os_io_seproxyhal.h. Nano S buffer sizes (APDU 5 + 255 without U2F, SPI 128 as
 * the Makefile sets), so the sanitizer sees real bounds. */
#ifndef SM_OS_IO_H
#define SM_OS_IO_H

#define IO_APDU_BUFFER_SIZE (5 + 255)
#define IO_SEPROXYHAL_BUFFER_SIZE_B 128

#define SEPROXYHAL_TAG_FINGER_EVENT 0x0B
#define SEPROXYHAL_TAG_BUTTON_PUSH_EVENT 0x0C
#define SEPROXYHAL_TAG_DISPLAY_PROCESSED_EVENT 0x0D
#define SEPROXYHAL_TAG_TICKER_EVENT 0x0E
#define SEPROXYHAL_TAG_SESSION_START_EVENT_FEATURE_SCREEN_BIG 0x01

#define BUTTON_LEFT 0x01
#define BUTTON_RIGHT 0x02
#define BUTTON_EVT_FAST 0x40000000UL
#define BUTTON_EVT_RELEASED 0x80000000UL

extern unsigned char G_io_apdu_buffer[IO_APDU_BUFFER_SIZE];
extern unsigned char G_io_seproxyhal_spi_buffer[IO_SEPROXYHAL_BUFFER_SIZE_B];

/* implemented by the driver */
unsigned short io_exchange(unsigned char channel, unsigned short tx_len);
/* implemented by the driver: the display, which keeps each element it is sent */
void sm_on_display(const void *e);
/* Set once the app answers the current MCU event; the SDK sends one status per event. The
 * driver clears it with each event. */
extern int g_sm_status_sent;

#ifdef HAVE_BOLOS_APP_STACK_CANARY
#include "os.h"
/* The Nano S SDK's stack canary value, which io_seproxyhal_init writes below the stack. Copied
 * from the SDK, not main.c, so a wrong value there shows. */
#define SM_APP_STACK_CANARY_MAGIC 0xDEAD0031u
extern unsigned int app_stack_canary;
/* implemented by the driver: called at each transport start, after the write */
void sm_on_transport_start(void);
static inline void io_seproxyhal_init(void) {
    app_stack_canary = SM_APP_STACK_CANARY_MAGIC;
    sm_on_transport_start();
}
/* resets the device and never returns */
static inline void io_seproxyhal_se_reset(void) { longjmp(g_case_jmp, 4); }
#else
static inline void io_seproxyhal_init(void) {}
#endif
/* Driver hook to skip the call below for one element, as a skipped branch would: nothing is
 * sent, so the drawing loop moves on at once. Static: see g_derive_path in os.h. */
static int (*g_skip_display_send)(const void *e);
static inline void io_seproxyhal_display_default(void *e) {
    if (g_skip_display_send && g_skip_display_send(e)) return;
    if (g_sm_status_sent) return;
    sm_on_display(e);
    g_sm_status_sent = 1;
}
static inline int io_seproxyhal_spi_is_status_sent(void) { return g_sm_status_sent; }
static inline void io_seproxyhal_general_status(void) { g_sm_status_sent = 1; }
static inline void io_seproxyhal_spi_send(const unsigned char *b, unsigned short l) { (void) b; (void) l; }
static inline unsigned short io_seproxyhal_spi_recv(unsigned char *b, unsigned short l, unsigned int f) {
    (void) b; (void) l; (void) f;
    return 0;
}
#endif
