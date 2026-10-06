/* Harness stub: ux.h. The display macros are the Nano S SDK's (lib_ux/include/ux_bagl.h)
 * without the OS calls, so the driver reaches and sees exactly what a user can. Driver hooks can
 * skip one UX_DISPLAY store, a whole screen call, or once the loop's status check. */
#ifndef SM_UX_H
#define SM_UX_H

#include <stdint.h>
#include <string.h>
#include "bagl.h"

/* SDK field names, so the app's display checks read the memory the driver draws from. */
typedef unsigned int (*button_push_callback_t)(unsigned int mask, unsigned int counter);
typedef button_push_callback_t sm_button_handler_t;
typedef const bagl_element_t *(*bagl_element_callback_t)(const bagl_element_t *element);
typedef struct {
    unsigned short element_index;
    struct {
        const bagl_element_t *element_array;
        unsigned char element_array_count;
    } element_arrays[1];
    bagl_element_callback_t screen_before_element_display_callback;
    button_push_callback_t button_push_callback;
} sm_ux_stack_slot_t;
typedef struct {
    sm_ux_stack_slot_t stack[1];
} ux_state_t;
/* as in the Nano S SDK, which names the app's ux G_ux */
#define G_ux ux
extern ux_state_t ux;
#define g_ux_button (G_ux.stack[0].button_push_callback)
#define g_ux_elements (G_ux.stack[0].element_arrays[0].element_array)
#define g_ux_element_count (G_ux.stack[0].element_arrays[0].element_array_count)
extern const char *g_ux_screen;

/* the app's display hook, in main.c */
void io_seproxyhal_display(const bagl_element_t *element);

/* implemented by the driver: the store to skip, the screen asked for, and a redraw start */
#define SM_SKIP_NONE 0
#define SM_SKIP_LAYOUT 1
#define SM_SKIP_HANDLER 2
#define SM_SKIP_INDEX 3
/* the app's whole screen call: nothing is stored and the driver undoes its uiState store */
#define SM_SKIP_CALL 4
unsigned int sm_ux_store_to_skip(void);
void sm_ux_call_skipped(void);
void sm_ux_asked(const char *name, const bagl_element_t *layout, button_push_callback_t handler);
void sm_ux_redraw_started(void);
/* the button event the driver is delivering: BUTTON_EVT_RELEASED and the buttons */
extern unsigned int g_sm_button_event;
/* implemented by the driver, when the loop below finds a status out: 1 skips that check once,
 * so the next element reaches the display hook and is never sent */
int sm_ux_skip_status_check(void);

/* Draws elements while the app may still send a status: one element per event. */
#define UX_DISPLAY_NEXT_ELEMENT()                                                                 \
    while (G_ux.stack[0].element_arrays[0].element_array &&                                       \
           G_ux.stack[0].element_index < G_ux.stack[0].element_arrays[0].element_array_count &&   \
           (!io_seproxyhal_spi_is_status_sent() || sm_ux_skip_status_check())) {                 \
        const bagl_element_t *sm_element_ =                                                       \
            &G_ux.stack[0].element_arrays[0].element_array[G_ux.stack[0].element_index];          \
        const bagl_element_t *sm_drawn_ = sm_element_;                                            \
        if (!G_ux.stack[0].screen_before_element_display_callback ||                              \
            (sm_drawn_ = G_ux.stack[0].screen_before_element_display_callback(sm_element_))) {    \
            /* as in the SDK, 1 from the preprocessor means the element unchanged */              \
            io_seproxyhal_display((uintptr_t) sm_drawn_ == 1 ? sm_element_ : sm_drawn_);          \
        }                                                                                         \
        G_ux.stack[0].element_index++;                                                            \
    }

#define UX_REDISPLAY()                   \
    do {                                 \
        G_ux.stack[0].element_index = 0; \
        sm_ux_redraw_started();          \
        UX_DISPLAY_NEXT_ELEMENT();       \
    } while (0)

#define UX_DISPLAY(elements_array, preprocessor)                                    \
    do {                                                                            \
        unsigned int sm_skip_ = sm_ux_store_to_skip();                              \
        if (sm_skip_ == SM_SKIP_CALL) {                                             \
            sm_ux_call_skipped();                                                   \
            break;                                                                  \
        }                                                                           \
        if (sm_skip_ != SM_SKIP_LAYOUT) {                                           \
            G_ux.stack[0].element_arrays[0].element_array = elements_array;         \
            G_ux.stack[0].element_arrays[0].element_array_count =                   \
                sizeof(elements_array) / sizeof((elements_array)[0]);               \
        }                                                                           \
        if (sm_skip_ != SM_SKIP_HANDLER) {                                          \
            G_ux.stack[0].button_push_callback = elements_array##_button;           \
        }                                                                           \
        G_ux.stack[0].screen_before_element_display_callback = preprocessor;        \
        sm_ux_asked(#elements_array, elements_array, elements_array##_button);      \
        if (sm_skip_ != SM_SKIP_INDEX) {                                            \
            UX_REDISPLAY();                                                         \
        } else {                                                                    \
            /* no store of index 0: drawing resumes at the old index, mid-screen */ \
            UX_DISPLAY_NEXT_ELEMENT();                                              \
        }                                                                           \
    } while (0)

#define UX_INIT() memset(&G_ux, 0, sizeof(G_ux))
#define UX_DISPLAYED() \
    (G_ux.stack[0].element_index >= G_ux.stack[0].element_arrays[0].element_array_count)
#define UX_CONTINUE_DISPLAY_APP(displayed_callback)                  \
    do {                                                             \
        UX_DISPLAY_NEXT_ELEMENT();                                   \
        if (UX_DISPLAYED() && !io_seproxyhal_spi_is_status_sent()) { \
            displayed_callback                                       \
        }                                                            \
    } while (0)
#define UX_DISPLAYED_EVENT(displayed_callback) UX_CONTINUE_DISPLAY_APP(displayed_callback)
#define UX_BUTTON_PUSH_EVENT(seph_packet)                                     \
    do {                                                                      \
        (void) (seph_packet);                                                 \
        if (G_ux.stack[0].button_push_callback) {                             \
            G_ux.stack[0].button_push_callback(g_sm_button_event, 0);         \
        }                                                                     \
        UX_CONTINUE_DISPLAY_APP({});                                          \
    } while (0)
#define UX_DEFAULT_EVENT() UX_CONTINUE_DISPLAY_APP({})
#define UX_TICKER_EVENT(buf, block) do { } while (0)
#define UX_FINGER_EVENT(buf) do { (void) (buf); } while (0)
#define UX_ALLOWED 1
#endif
