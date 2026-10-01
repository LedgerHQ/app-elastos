/*
 * MIT License, see root folder for full license.
 */

#include <string.h>
#include "ui.h"
#include "glyphs.h"
#include "elastos.h"
#include "keys.h"
#include "sw.h"
#include "tx_session.h"

/** default font */
#define DEFAULT_FONT BAGL_FONT_OPEN_SANS_EXTRABOLD_11px | BAGL_FONT_ALIGNMENT_CENTER

#define DEFAULT_FONT_BLUE \
    BAGL_FONT_OPEN_SANS_LIGHT_14px | BAGL_FONT_ALIGNMENT_CENTER | BAGL_FONT_ALIGNMENT_MIDDLE

/** text description font. */
#define TX_DESC_FONT BAGL_FONT_OPEN_SANS_REGULAR_11px | BAGL_FONT_ALIGNMENT_CENTER

/** the timer */
int exit_timer;

/** display for the timer */
char timer_desc[MAX_TIMER_TEXT_WIDTH];

/** UI state enum */
enum UI_STATE uiState;

/** UI state flag */
#if defined(TARGET_NANOX) || defined(TARGET_NANOS2)
ux_state_t G_ux;
bolos_ux_params_t G_ux_params;
#else   // TARGET_NANOX
ux_state_t ux;
#endif  // TARGET_NANOX

/** index of the current screen. */
unsigned int curr_scr_ix;

/** max index for all screens. */
unsigned int max_scr_ix;

/** raw transaction data. */
unsigned char raw_tx[MAX_TX_RAW_LENGTH];

/** current index into raw transaction. */
unsigned int raw_tx_ix;

/** current length of raw transaction. */
unsigned int raw_tx_len;

/** all text descriptions. */
char tx_desc[MAX_TX_TEXT_SCREENS][MAX_TX_TEXT_LINES][MAX_TX_TEXT_WIDTH];

/** currently displayed text description. */
char curr_tx_desc[MAX_TX_TEXT_LINES][MAX_TX_TEXT_WIDTH];

/** currently displayed public key */
char current_public_key[MAX_TX_TEXT_LINES][MAX_TX_TEXT_WIDTH];

/** bold heading of each review screen */
char review_title[MAX_TX_TEXT_SCREENS][MAX_TX_TEXT_WIDTH];

/** heading of the review screen currently displayed on Nano S */
char curr_review_title[MAX_TX_TEXT_WIDTH];

/** Nano S review fully shown; multi-bit so one flipped bit cannot fake it. */
#define REVIEW_COMPLETE 0x5AC3A53Cu
static volatile uint32_t review_complete;

/** Screens shown, one bit each (top and bottom halves on Nano S). Each mask has a complement so
 * one flipped bit cannot mark a half as read. */
static volatile uint32_t review_seen_top;
static volatile uint32_t review_seen_top_check;
static volatile uint32_t review_seen_bottom;
static volatile uint32_t review_seen_bottom_check;

/** Set, with its complement, while Accept (Sign Tx on Nano S) is the last screen drawn in full,
 * so a fault that jumps to it without drawing it cannot sign. */
#define ACCEPT_DRAWN 0xC35A3CA5u
static volatile uint32_t accept_drawn;
static volatile uint32_t accept_drawn_check;

static void set_accept_drawn(bool drawn) {
    accept_drawn = drawn ? ACCEPT_DRAWN : 0;
    accept_drawn_check = drawn ? ~ACCEPT_DRAWN : ~0u;
}

/** 44'/2305'/0'/0/0: the wallet's first receive address, shown by "Display Account". */
static const unsigned int DEFAULT_ACCOUNT_PATH[ELA_PATH_LEN] = {0x8000002C,
                                                                0x80000901,
                                                                0x80000000,
                                                                0,
                                                                0};

/** UI was touched indicating the user wants to deny te signature request */
static const bagl_element_t *io_seproxyhal_touch_deny(const bagl_element_t *e);

/** Path under address check, and whether its reply is still pending. */
static unsigned int address_check_path[ELA_PATH_LEN];
static bool address_check_pending;

/** address check replies: the public key on Approve, 6985 on Reject */
static void address_check_approve(void);
static void address_check_reject(void);

#if defined(TARGET_NANOS)
/** Address check pages, Nano S. Path and address pages reuse review_seen_top bits: no review runs
 * while a check waits. */
#define ADDRESS_CHECK_INTRO_PAGE        0
#define ADDRESS_CHECK_PATH_PAGE         1
#define ADDRESS_CHECK_PATH_REST_PAGE    2
#define ADDRESS_CHECK_ADDRESS_PAGE      3
#define ADDRESS_CHECK_ADDRESS_REST_PAGE 4
#define ADDRESS_CHECK_APPROVE_PAGE      5
#define ADDRESS_CHECK_REJECT_PAGE       6
#define ADDRESS_CHECK_PAGES             7
static void show_address_check_page(unsigned int page);
#else
/** Address check path and address steps. They reuse review_seen_top bits: no review runs while a
 * check waits. */
#define ADDRESS_CHECK_PATH_STEP    0
#define ADDRESS_CHECK_ADDRESS_STEP 1
#define ADDRESS_CHECK_STEPS        2
#endif  // TARGET_NANOS

#if defined(TARGET_NANOS)
/** UI was touched indicating the user wants to exit the app */
static const bagl_element_t *io_seproxyhal_touch_exit(const bagl_element_t *e);

/** display part of the transaction description */
static void ui_display_tx_desc_1(void);
static void ui_display_tx_desc_2(void);

/** display the UI for signing a transaction */
static void ui_sign(void);

/** display the UI for denying a transaction */
static void ui_deny(void);

/** show the public key screen */
static void ui_public_key_1(void);
static void ui_public_key_2(void);

/** move up in the transaction description list */
static const bagl_element_t *tx_desc_up(const bagl_element_t *e);

/** move down in the transaction description list */
static const bagl_element_t *tx_desc_dn(const bagl_element_t *e);

/** show the first half of the review not yet displayed */
static void show_first_unread_half(void);

/** true if the Sign screen is drawn in full and gets the buttons */
static bool sign_screen_on_display(void);
#endif  // TARGET_NANOS

/** Loads the device's own first address for display, never one the computer chose. */
static void load_default_account_address(void) {
    uint8_t pubkey[ELA_PUBKEY_LEN];
    if (keys_get_public_key(DEFAULT_ACCOUNT_PATH, pubkey) != CX_OK) {
        display_no_public_key();
        return;
    }
    display_public_key(pubkey);
}

/** Clears the read marks and the Accept mark. */
static void reset_review_progress(void) {
    review_complete = 0;
    review_seen_top = 0;
    review_seen_top_check = ~0u;
    review_seen_bottom = 0;
    review_seen_bottom_check = ~0u;
    set_accept_drawn(false);
}

#if defined(TARGET_NANOS)
/** True if both halves of every screen are marked shown, masks and complements agreeing. Signing
 * rechecks this rather than trust review_complete. */
static bool review_fully_read(void) {
    if (max_scr_ix == 0 || max_scr_ix > MAX_TX_TEXT_SCREENS) {
        return false;
    }
    uint32_t every_screen = (1u << max_scr_ix) - 1;
    return review_seen_top == every_screen && (review_seen_top_check & every_screen) == 0 &&
           review_seen_bottom == every_screen && (review_seen_bottom_check & every_screen) == 0;
}
#endif  // TARGET_NANOS

#if defined(TARGET_NANOS)
/** Elements drawn so far, in order, and their layout, so a cut-short drawing cannot count for
 * another screen. */
static volatile unsigned int elements_drawn;
static const bagl_element_t *volatile elements_drawn_of;

/** True if the display holds this layout. UX_DISPLAY stores layout and buttons separately, so one
 * skipped store could pair a screen with another's buttons. Volatile so checks are not merged. */
static bool layout_on_display(const bagl_element_t *layout, unsigned int count) {
    const bagl_element_t *drawn =
        *(const bagl_element_t *const volatile *) &G_ux.stack[0].element_arrays[0].element_array;
    unsigned int drawn_count =
        *(const volatile unsigned char *) &G_ux.stack[0].element_arrays[0].element_array_count;
    return drawn == layout && drawn_count == count;
}

/** Marks a fully drawn half as shown, and the review as read once every half is. Reaching the last
 * screen is not enough: going back from Sign reaches it with the rest unread. */
static void mark_review_half_shown(volatile uint32_t *seen, volatile uint32_t *check) {
    if (max_scr_ix == 0 || max_scr_ix > MAX_TX_TEXT_SCREENS || curr_scr_ix >= max_scr_ix) {
        return;
    }
    // mark only what is on display, so a corrupted index cannot mark another screen
    if (memcmp(curr_tx_desc, tx_desc[curr_scr_ix], CURR_TX_DESC_LEN) != 0 ||
        memcmp(curr_review_title, review_title[curr_scr_ix], MAX_TX_TEXT_WIDTH) != 0) {
        return;
    }
    *seen |= 1u << curr_scr_ix;
    *check &= ~(1u << curr_scr_ix);
    if (review_fully_read()) {
        review_complete = REVIEW_COMPLETE;
    }
}
#endif  // TARGET_NANOS

////////////////////////////////////  NANO X //////////////////////////////////////////////////
#if defined(TARGET_NANOX) || defined(TARGET_NANOS2)

/** Marks review step s as drawn, in the mask and its complement. */
static void mark_review_step_shown(unsigned int s) {
    set_accept_drawn(false);
    if (s >= max_scr_ix || s >= MAX_TX_TEXT_SCREENS) {
        return;
    }
    review_seen_top |= 1u << s;
    review_seen_top_check &= ~(1u << s);
}

/** Step being drawn: set just before its layout, out of range after. Address checks reuse it. */
static unsigned int review_step_drawing;

/** Called by review step s before its layout is drawn. */
static void begin_review_step(unsigned int s) {
    set_accept_drawn(false);
    review_step_drawing = s;
}

/** Elements the SDK has drawn since the last clear. */
static volatile unsigned int layout_elements_drawn;

/* -Wl,--wrap in the Makefile routes every SDK element draw through here, so an element counts
 * only once really drawn and a skipped draw shows. */
void __real_io_seph_ux_display_bagl_element(const bagl_element_t *element);
void __wrap_io_seph_ux_display_bagl_element(const bagl_element_t *element) {
    __real_io_seph_ux_display_bagl_element(element);
    layout_elements_drawn++;
}

/** True if the layout was drawn to the end: the SDK leaves element_index at count + 1 and every
 * element was counted. Both are cleared first, so a skipped call cannot pass on old values. */
static bool layout_drawn(unsigned int stack_slot) {
    unsigned int index = *(const volatile unsigned short *) &G_ux.stack[stack_slot].element_index;
    unsigned int count = *(const volatile unsigned char *) &G_ux.stack[stack_slot]
                              .element_arrays[0]
                              .element_array_count;
    return count != 0 && index == count + 1 && layout_elements_drawn == count;
}

static void clear_element_index(unsigned int stack_slot) {
    *(volatile unsigned short *) &G_ux.stack[stack_slot].element_index = 0;
    layout_elements_drawn = 0;
}

/* The SDK's bnnn and pb layouts with a drawn check, for review steps and Accept. Step macros need
 * a params type and an init function per layout name. */
typedef ux_layout_bnnn_params_t ux_layout_review_bnnn_params_t;
typedef ux_layout_pb_params_t ux_layout_accept_pb_params_t;

/** Draws a review step; marks it drawn only if drawn in full. */
static void ux_layout_review_bnnn_init(unsigned int stack_slot) {
    clear_element_index(stack_slot);
    ux_layout_bnnn_init(stack_slot);
    if (layout_drawn(stack_slot)) {
        mark_review_step_shown(review_step_drawing);
    }
    review_step_drawing = MAX_TX_TEXT_SCREENS;
}

/** Draws Accept; marks it on screen only if drawn in full. */
static void ux_layout_accept_pb_init(unsigned int stack_slot) {
    clear_element_index(stack_slot);
    ux_layout_pb_init(stack_slot);
    if (layout_drawn(stack_slot)) {
        set_accept_drawn(true);
    }
}

/** Called by address check step k before its layout is drawn. */
static void begin_address_check_step(unsigned int k) {
    set_accept_drawn(false);
    review_step_drawing = k;
}

/* bnnn with a drawn check for the address check; its Approve uses accept_pb. */
typedef ux_layout_bnnn_params_t ux_layout_check_bnnn_params_t;

/** Draws an address check step; marks it drawn only if drawn in full. */
static void ux_layout_check_bnnn_init(unsigned int stack_slot) {
    unsigned int k = review_step_drawing;
    clear_element_index(stack_slot);
    ux_layout_bnnn_init(stack_slot);
    if (layout_drawn(stack_slot) && k < ADDRESS_CHECK_STEPS) {
        review_seen_top |= 1u << k;
        review_seen_top_check &= ~(1u << k);
    }
    review_step_drawing = MAX_TX_TEXT_SCREENS;
}

UX_STEP_NOCB_INIT(ux_review_intro_step,
                  pnn,
                  set_accept_drawn(false),
                  {&C_icon_eye, "Review", "Transaction"});

/* One step per review screen; the parser fills review_title and tx_desc. */
UX_STEP_NOCB_INIT(ux_review_step_0,
                  review_bnnn,
                  begin_review_step(0),
                  {review_title[0], tx_desc[0][0], tx_desc[0][1], tx_desc[0][2]});
UX_STEP_NOCB_INIT(ux_review_step_1,
                  review_bnnn,
                  begin_review_step(1),
                  {review_title[1], tx_desc[1][0], tx_desc[1][1], tx_desc[1][2]});
UX_STEP_NOCB_INIT(ux_review_step_2,
                  review_bnnn,
                  begin_review_step(2),
                  {review_title[2], tx_desc[2][0], tx_desc[2][1], tx_desc[2][2]});
UX_STEP_NOCB_INIT(ux_review_step_3,
                  review_bnnn,
                  begin_review_step(3),
                  {review_title[3], tx_desc[3][0], tx_desc[3][1], tx_desc[3][2]});
UX_STEP_NOCB_INIT(ux_review_step_4,
                  review_bnnn,
                  begin_review_step(4),
                  {review_title[4], tx_desc[4][0], tx_desc[4][1], tx_desc[4][2]});
UX_STEP_NOCB_INIT(ux_review_step_5,
                  review_bnnn,
                  begin_review_step(5),
                  {review_title[5], tx_desc[5][0], tx_desc[5][1], tx_desc[5][2]});
UX_STEP_NOCB_INIT(ux_review_step_6,
                  review_bnnn,
                  begin_review_step(6),
                  {review_title[6], tx_desc[6][0], tx_desc[6][1], tx_desc[6][2]});
UX_STEP_NOCB_INIT(ux_review_step_7,
                  review_bnnn,
                  begin_review_step(7),
                  {review_title[7], tx_desc[7][0], tx_desc[7][1], tx_desc[7][2]});
UX_STEP_NOCB_INIT(ux_review_step_8,
                  review_bnnn,
                  begin_review_step(8),
                  {review_title[8], tx_desc[8][0], tx_desc[8][1], tx_desc[8][2]});

UX_STEP_CB_INIT(ux_review_accept_step,
                accept_pb,
                set_accept_drawn(false),
                io_seproxyhal_touch_approve(NULL),
                {
                    &C_icon_validate_14,
                    "Accept",
                });
UX_STEP_CB_INIT(ux_review_reject_step,
                pb,
                set_accept_drawn(false),
                io_seproxyhal_touch_deny(NULL),
                {
                    &C_icon_crossmark,
                    "Reject",
                });

/** intro, the review screens, accept, reject, end marker */
static const ux_flow_step_t *ux_review_flow[MAX_TX_TEXT_SCREENS + 4];
_Static_assert(sizeof(ux_review_flow) / sizeof(ux_review_flow[0]) == 1 + MAX_TX_TEXT_SCREENS + 3,
               "the review flow needs a slot for the intro, every review screen, Accept, Reject "
               "and the end marker");

/** Step for review screen s. A switch, not a flash table, so addresses hold wherever the app
 * loads. */
static const ux_flow_step_t *review_step(unsigned int s) {
    switch (s) {
        case 0:
            return &ux_review_step_0;
        case 1:
            return &ux_review_step_1;
        case 2:
            return &ux_review_step_2;
        case 3:
            return &ux_review_step_3;
        case 4:
            return &ux_review_step_4;
        case 5:
            return &ux_review_step_5;
        case 6:
            return &ux_review_step_6;
        case 7:
            return &ux_review_step_7;
        case 8:
            return &ux_review_step_8;
        default:
            return NULL;
    }
}

/** Intro, max_scr_ix screens, Accept, Reject. No loop marker, so Accept is reached only through
 * every screen. */
static void build_review_flow(void) {
    unsigned int n = 0;
    review_step_drawing = MAX_TX_TEXT_SCREENS;
    ux_review_flow[n++] = &ux_review_intro_step;
    for (unsigned int s = 0; s < max_scr_ix && s < MAX_TX_TEXT_SCREENS; s++) {
        ux_review_flow[n++] = review_step(s);
    }
    ux_review_flow[n++] = &ux_review_accept_step;
    ux_review_flow[n++] = &ux_review_reject_step;
    ux_review_flow[n] = FLOW_END_STEP;
}

/** True if the flow holds every review step in order, each was drawn and Accept is on screen. The
 * session checks max_scr_ix; the volatile read keeps the two calls before signing apart. */
static bool review_flow_is_whole(void) {
    unsigned int n = *(volatile unsigned int *) &max_scr_ix;
    if (n == 0 || n > MAX_TX_TEXT_SCREENS || ux_review_flow[0] != &ux_review_intro_step) {
        return false;
    }
    for (unsigned int s = 0; s < n; s++) {
        if (ux_review_flow[1 + s] != review_step(s)) {
            return false;
        }
    }
    bool accept_last = ux_review_flow[1 + n] == &ux_review_accept_step;
    bool reject_after = ux_review_flow[2 + n] == &ux_review_reject_step;
    uint32_t every_step = (1u << n) - 1;
    bool every_step_drawn =
        review_seen_top == every_step && (review_seen_top_check & every_step) == 0;
    bool on_accept = accept_drawn == ACCEPT_DRAWN && (accept_drawn ^ accept_drawn_check) == ~0u;
    return accept_last && reject_after && ux_review_flow[3 + n] == FLOW_END_STEP &&
           every_step_drawn && on_accept;
}

UX_STEP_NOCB(
    ux_display_public_flow_step,
    bnnn,
    {"First address", current_public_key[0], current_public_key[1], current_public_key[2]});
UX_STEP_VALID(ux_display_public_go_back_step,
              pb,
              ui_idle(),
              {
                  &C_icon_back,
                  "Back",
              });

UX_FLOW(ux_display_public_flow, &ux_display_public_flow_step, &ux_display_public_go_back_step);

UX_STEP_NOCB_INIT(ux_address_check_intro_step,
                  pnn,
                  set_accept_drawn(false),
                  {&C_icon_eye, "Verify", "address"});
UX_STEP_NOCB_INIT(ux_address_check_path_step,
                  check_bnnn,
                  begin_address_check_step(ADDRESS_CHECK_PATH_STEP),
                  {"Path",
                   tx_desc[ADDRESS_CHECK_PATH_SCREEN][0],
                   tx_desc[ADDRESS_CHECK_PATH_SCREEN][1],
                   tx_desc[ADDRESS_CHECK_PATH_SCREEN][2]});
UX_STEP_NOCB_INIT(ux_address_check_address_step,
                  check_bnnn,
                  begin_address_check_step(ADDRESS_CHECK_ADDRESS_STEP),
                  {"Address", current_public_key[0], current_public_key[1], current_public_key[2]});
UX_STEP_CB_INIT(ux_address_check_approve_step,
                accept_pb,
                set_accept_drawn(false),
                address_check_approve(),
                {
                    &C_icon_validate_14,
                    "Approve",
                });
UX_STEP_CB_INIT(ux_address_check_reject_step,
                pb,
                set_accept_drawn(false),
                address_check_reject(),
                {
                    &C_icon_crossmark,
                    "Reject",
                });

UX_FLOW(ux_address_check_flow,
        &ux_address_check_intro_step,
        &ux_address_check_path_step,
        &ux_address_check_address_step,
        &ux_address_check_approve_step,
        &ux_address_check_reject_step);

void display_account_address() {
    load_default_account_address();
    if (G_ux.stack_count == 0) {
        ux_stack_push();
    }
    ux_flow_init(0, ux_display_public_flow, NULL);
}

UX_STEP_NOCB(ux_idle_flow_1_step,
             nn,
             {
                 "Application",
                 "is ready",
             });
UX_STEP_VALID(ux_idle_flow_2_step,
              pbb,
              display_account_address(),
              {&C_icon_eye, "Display", "Account"});
UX_STEP_NOCB(ux_idle_flow_3_step,
             bn,
             {
                 "Version",
                 APPVERSION,
             });
UX_STEP_VALID(ux_idle_flow_4_step,
              pb,
              os_sched_exit(-1),
              {
                  &C_icon_dashboard,
                  "Quit",
              });

UX_FLOW(ux_idle_flow,
        &ux_idle_flow_1_step,
        &ux_idle_flow_2_step,
        &ux_idle_flow_3_step,
        &ux_idle_flow_4_step);

#endif
////////////////////////////////////////////////////////////////////////////////////////////////

////////////////////////////////////  NANO S //////////////////////////////////////////////////
#if defined(TARGET_NANOS)

/** UI struct for the idle screen */
static const bagl_element_t bagl_ui_idle_nanos[] = {
    // { {type, userid, x, y, width, height, stroke, radius, fill, fgcolor, bgcolor, font_id,
    // icon_id},
    // text, touch_area_brim, overfgcolor, overbgcolor, tap, out, over,
    // },
    {
        {BAGL_RECTANGLE, 0x00, 0, 0, 128, 32, 0, 0, BAGL_FILL, 0x000000, 0xFFFFFF, 0, 0},
        NULL,
    },
    /* center text */
    {
        {BAGL_LABELINE, 0x02, 0, 20, 128, 11, 0, 0, 0, 0xFFFFFF, 0x000000, DEFAULT_FONT, 0},
        "Elastos",
    },
    /* left icon is a X */
    {
        {BAGL_ICON, 0x00, 3, 12, 7, 7, 0, 0, 0, 0xFFFFFF, 0x000000, 0, BAGL_GLYPH_ICON_CROSS},
        NULL,
    },
    /* right icon is an eye. */
    {
        {BAGL_ICON, 0x00, 115, 13, 7, 7, 0, 0, 0, 0xFFFFFF, 0x000000, 0, BAGL_GLYPH_ICON_EYE_BADGE},
        NULL,
    },

    /* */
};

/** buttons for the idle screen: Right shows the account, Left exits. */
static unsigned int bagl_ui_idle_nanos_button(unsigned int button_mask,
                                              unsigned int button_mask_counter) {
    UNUSED(button_mask_counter);
    switch (button_mask) {
        case BUTTON_EVT_RELEASED | BUTTON_RIGHT:
            load_default_account_address();
            ui_public_key_1();
            break;
        case BUTTON_EVT_RELEASED | BUTTON_LEFT:
            io_seproxyhal_touch_exit(NULL);
            break;
    }

    return 0;
}

/** Account screen, Nano S: address lines 1 and 2. */
static const bagl_element_t bagl_ui_public_key_nanos_1[] = {
    // { {type, userid, x, y, width, height, stroke, radius, fill, fgcolor, bgcolor, font_id,
    // icon_id},
    // text, touch_area_brim, overfgcolor, overbgcolor, tap, out, over,
    // },
    {
        {BAGL_RECTANGLE, 0x00, 0, 0, 128, 32, 0, 0, BAGL_FILL, 0x000000, 0xFFFFFF, 0, 0},
        NULL,
    },
    /* first line of description of current public key */
    {
        {BAGL_LABELINE,
         0x02,
         10,
         12,
         108,
         11,
         0x80 | 10,
         0,
         0,
         0xFFFFFF,
         0x000000,
         TX_DESC_FONT,
         0},
        current_public_key[0],
    },
    /* second line of description of current public key */
    {
        {BAGL_LABELINE,
         0x02,
         10,
         26,
         108,
         11,
         0x80 | 10,
         0,
         0,
         0xFFFFFF,
         0x000000,
         TX_DESC_FONT,
         0},
        current_public_key[1],
    },
    /* left icon is a X */
    {
        {BAGL_ICON, 0x00, 3, 12, 7, 7, 0, 0, 0, 0xFFFFFF, 0x000000, 0, BAGL_GLYPH_ICON_CROSS},
        NULL,
    },
    /* right icon is down arrow */
    {
        {BAGL_ICON, 0x00, 117, 13, 8, 6, 0, 0, 0, 0xFFFFFF, 0x000000, 0, BAGL_GLYPH_ICON_DOWN},
        NULL,
    },
    /* */
};

/** Account screen, Nano S: address lines 2 and 3. */
static const bagl_element_t bagl_ui_public_key_nanos_2[] = {
    // { {type, userid, x, y, width, height, stroke, radius, fill, fgcolor, bgcolor, font_id,
    // icon_id},
    // text, touch_area_brim, overfgcolor, overbgcolor, tap, out, over,
    // },
    {
        {BAGL_RECTANGLE, 0x00, 0, 0, 128, 32, 0, 0, BAGL_FILL, 0x000000, 0xFFFFFF, 0, 0},
        NULL,
    },
    /* second line of description of current public key */
    {
        {BAGL_LABELINE,
         0x02,
         10,
         12,
         108,
         11,
         0x80 | 10,
         0,
         0,
         0xFFFFFF,
         0x000000,
         TX_DESC_FONT,
         0},
        current_public_key[1],
    },
    /* third line of description of current public key  */
    {
        {BAGL_LABELINE,
         0x02,
         10,
         26,
         108,
         11,
         0x80 | 10,
         0,
         0,
         0xFFFFFF,
         0x000000,
         TX_DESC_FONT,
         0},
        current_public_key[2],
    },
    /* right icon is a X */
    {
        {BAGL_ICON, 0x00, 118, 12, 7, 7, 0, 0, 0, 0xFFFFFF, 0x000000, 0, BAGL_GLYPH_ICON_CROSS},
        NULL,
    },
    /* left icon is up arrow  */
    {
        {BAGL_ICON, 0x00, 3, 13, 7, 7, 0, 0, 0, 0xFFFFFF, 0x000000, 0, BAGL_GLYPH_ICON_UP},
        NULL,
    },

    /* */
};

/** buttons for account screen part 1: Right shows the rest, Left leaves. */
static unsigned int bagl_ui_public_key_nanos_1_button(unsigned int button_mask,
                                                      unsigned int button_mask_counter) {
    UNUSED(button_mask_counter);
    switch (button_mask) {
        case BUTTON_EVT_RELEASED | BUTTON_RIGHT:
            ui_public_key_2();
            break;
        case BUTTON_EVT_RELEASED | BUTTON_LEFT:
            ui_idle();
            break;
    }

    return 0;
}

/** buttons for account screen part 2: Left goes back, Right leaves. */
static unsigned int bagl_ui_public_key_nanos_2_button(unsigned int button_mask,
                                                      unsigned int button_mask_counter) {
    UNUSED(button_mask_counter);
    switch (button_mask) {
        case BUTTON_EVT_RELEASED | BUTTON_RIGHT:
            ui_idle();
            break;
        case BUTTON_EVT_RELEASED | BUTTON_LEFT:
            ui_public_key_1();
            break;
    }
    return 0;
}

/** Address check, Nano S: the first screen. */
static const bagl_element_t bagl_ui_address_check_nanos_intro[] = {
    // { {type, userid, x, y, width, height, stroke, radius, fill, fgcolor, bgcolor, font_id,
    // icon_id},
    // text, touch_area_brim, overfgcolor, overbgcolor, tap, out, over,
    // },
    {
        {BAGL_RECTANGLE, 0x00, 0, 0, 128, 32, 0, 0, BAGL_FILL, 0x000000, 0xFFFFFF, 0, 0},
        NULL,
    },
    /* center text */
    {
        {BAGL_LABELINE, 0x02, 0, 20, 128, 11, 0, 0, 0, 0xFFFFFF, 0x000000, DEFAULT_FONT, 0},
        "Verify address",
    },
    /* right icon is down arrow */
    {
        {BAGL_ICON, 0x00, 117, 13, 8, 6, 0, 0, 0, 0xFFFFFF, 0x000000, 0, BAGL_GLYPH_ICON_DOWN},
        NULL,
    },
    /* */
};

/** Address check, Nano S: bold "Path" heading and path line 1. */
static const bagl_element_t bagl_ui_address_check_nanos_path[] = {
    // { {type, userid, x, y, width, height, stroke, radius, fill, fgcolor, bgcolor, font_id,
    // icon_id},
    // text, touch_area_brim, overfgcolor, overbgcolor, tap, out, over,
    // },
    {
        {BAGL_RECTANGLE, 0x00, 0, 0, 128, 32, 0, 0, BAGL_FILL, 0x000000, 0xFFFFFF, 0, 0},
        NULL,
    },
    /* heading */
    {
        {BAGL_LABELINE,
         0x02,
         10,
         12,
         108,
         11,
         0x80 | 10,
         0,
         0,
         0xFFFFFF,
         0x000000,
         DEFAULT_FONT,
         0},
        "Path",
    },
    /* first line of the path */
    {
        {BAGL_LABELINE,
         0x02,
         10,
         26,
         108,
         11,
         0x80 | 10,
         0,
         0,
         0xFFFFFF,
         0x000000,
         TX_DESC_FONT,
         0},
        tx_desc[ADDRESS_CHECK_PATH_SCREEN][0],
    },
    /* left icon is up arrow  */
    {
        {BAGL_ICON, 0x00, 3, 13, 7, 7, 0, 0, 0, 0xFFFFFF, 0x000000, 0, BAGL_GLYPH_ICON_UP},
        NULL,
    },
    /* right icon is down arrow */
    {
        {BAGL_ICON, 0x00, 117, 13, 8, 6, 0, 0, 0, 0xFFFFFF, 0x000000, 0, BAGL_GLYPH_ICON_DOWN},
        NULL,
    },
    /* */
};

/** Address check, Nano S: path lines 2 and 3, when the path wraps. */
static const bagl_element_t bagl_ui_address_check_nanos_path_rest[] = {
    // { {type, userid, x, y, width, height, stroke, radius, fill, fgcolor, bgcolor, font_id,
    // icon_id},
    // text, touch_area_brim, overfgcolor, overbgcolor, tap, out, over,
    // },
    {
        {BAGL_RECTANGLE, 0x00, 0, 0, 128, 32, 0, 0, BAGL_FILL, 0x000000, 0xFFFFFF, 0, 0},
        NULL,
    },
    /* second line of the path */
    {
        {BAGL_LABELINE,
         0x02,
         10,
         12,
         108,
         11,
         0x80 | 10,
         0,
         0,
         0xFFFFFF,
         0x000000,
         TX_DESC_FONT,
         0},
        tx_desc[ADDRESS_CHECK_PATH_SCREEN][1],
    },
    /* third line of the path */
    {
        {BAGL_LABELINE,
         0x02,
         10,
         26,
         108,
         11,
         0x80 | 10,
         0,
         0,
         0xFFFFFF,
         0x000000,
         TX_DESC_FONT,
         0},
        tx_desc[ADDRESS_CHECK_PATH_SCREEN][2],
    },
    /* left icon is up arrow  */
    {
        {BAGL_ICON, 0x00, 3, 13, 7, 7, 0, 0, 0, 0xFFFFFF, 0x000000, 0, BAGL_GLYPH_ICON_UP},
        NULL,
    },
    /* right icon is down arrow */
    {
        {BAGL_ICON, 0x00, 117, 13, 8, 6, 0, 0, 0, 0xFFFFFF, 0x000000, 0, BAGL_GLYPH_ICON_DOWN},
        NULL,
    },
    /* */
};

/** Address check, Nano S: address lines 1 and 2. */
static const bagl_element_t bagl_ui_address_check_nanos_address[] = {
    // { {type, userid, x, y, width, height, stroke, radius, fill, fgcolor, bgcolor, font_id,
    // icon_id},
    // text, touch_area_brim, overfgcolor, overbgcolor, tap, out, over,
    // },
    {
        {BAGL_RECTANGLE, 0x00, 0, 0, 128, 32, 0, 0, BAGL_FILL, 0x000000, 0xFFFFFF, 0, 0},
        NULL,
    },
    /* first line of the address */
    {
        {BAGL_LABELINE,
         0x02,
         10,
         12,
         108,
         11,
         0x80 | 10,
         0,
         0,
         0xFFFFFF,
         0x000000,
         TX_DESC_FONT,
         0},
        current_public_key[0],
    },
    /* second line of the address */
    {
        {BAGL_LABELINE,
         0x02,
         10,
         26,
         108,
         11,
         0x80 | 10,
         0,
         0,
         0xFFFFFF,
         0x000000,
         TX_DESC_FONT,
         0},
        current_public_key[1],
    },
    /* left icon is up arrow  */
    {
        {BAGL_ICON, 0x00, 3, 13, 7, 7, 0, 0, 0, 0xFFFFFF, 0x000000, 0, BAGL_GLYPH_ICON_UP},
        NULL,
    },
    /* right icon is down arrow */
    {
        {BAGL_ICON, 0x00, 117, 13, 8, 6, 0, 0, 0, 0xFFFFFF, 0x000000, 0, BAGL_GLYPH_ICON_DOWN},
        NULL,
    },
    /* */
};

/** Address check, Nano S: address lines 2 and 3. */
static const bagl_element_t bagl_ui_address_check_nanos_address_rest[] = {
    // { {type, userid, x, y, width, height, stroke, radius, fill, fgcolor, bgcolor, font_id,
    // icon_id},
    // text, touch_area_brim, overfgcolor, overbgcolor, tap, out, over,
    // },
    {
        {BAGL_RECTANGLE, 0x00, 0, 0, 128, 32, 0, 0, BAGL_FILL, 0x000000, 0xFFFFFF, 0, 0},
        NULL,
    },
    /* second line of the address */
    {
        {BAGL_LABELINE,
         0x02,
         10,
         12,
         108,
         11,
         0x80 | 10,
         0,
         0,
         0xFFFFFF,
         0x000000,
         TX_DESC_FONT,
         0},
        current_public_key[1],
    },
    /* third line of the address */
    {
        {BAGL_LABELINE,
         0x02,
         10,
         26,
         108,
         11,
         0x80 | 10,
         0,
         0,
         0xFFFFFF,
         0x000000,
         TX_DESC_FONT,
         0},
        current_public_key[2],
    },
    /* left icon is up arrow  */
    {
        {BAGL_ICON, 0x00, 3, 13, 7, 7, 0, 0, 0, 0xFFFFFF, 0x000000, 0, BAGL_GLYPH_ICON_UP},
        NULL,
    },
    /* right icon is down arrow */
    {
        {BAGL_ICON, 0x00, 117, 13, 8, 6, 0, 0, 0, 0xFFFFFF, 0x000000, 0, BAGL_GLYPH_ICON_DOWN},
        NULL,
    },
    /* */
};

/** Address check, Nano S: Approve. */
static const bagl_element_t bagl_ui_address_check_nanos_approve[] = {
    // { {type, userid, x, y, width, height, stroke, radius, fill, fgcolor, bgcolor, font_id,
    // icon_id},
    // text, touch_area_brim, overfgcolor, overbgcolor, tap, out, over,
    // },
    {
        {BAGL_RECTANGLE, 0x00, 0, 0, 128, 32, 0, 0, BAGL_FILL, 0x000000, 0xFFFFFF, 0, 0},
        NULL,
    },
    /* center text */
    {
        {BAGL_LABELINE, 0x02, 0, 20, 128, 11, 0, 0, 0, 0xFFFFFF, 0x000000, DEFAULT_FONT, 0},
        "Approve",
    },
    /* left icon is up arrow  */
    {
        {BAGL_ICON, 0x00, 3, 13, 7, 7, 0, 0, 0, 0xFFFFFF, 0x000000, 0, BAGL_GLYPH_ICON_UP},
        NULL,
    },
    /* right icon is down arrow */
    {
        {BAGL_ICON, 0x00, 117, 13, 8, 6, 0, 0, 0, 0xFFFFFF, 0x000000, 0, BAGL_GLYPH_ICON_DOWN},
        NULL,
    },
    /* */
};

/** Address check, Nano S: Reject. */
static const bagl_element_t bagl_ui_address_check_nanos_reject[] = {
    // { {type, userid, x, y, width, height, stroke, radius, fill, fgcolor, bgcolor, font_id,
    // icon_id},
    // text, touch_area_brim, overfgcolor, overbgcolor, tap, out, over,
    // },
    {
        {BAGL_RECTANGLE, 0x00, 0, 0, 128, 32, 0, 0, BAGL_FILL, 0x000000, 0xFFFFFF, 0, 0},
        NULL,
    },
    /* center text */
    {
        {BAGL_LABELINE, 0x02, 0, 20, 128, 11, 0, 0, 0, 0xFFFFFF, 0x000000, DEFAULT_FONT, 0},
        "Reject",
    },
    /* left icon is up arrow  */
    {
        {BAGL_ICON, 0x00, 3, 13, 7, 7, 0, 0, 0, 0xFFFFFF, 0x000000, 0, BAGL_GLYPH_ICON_UP},
        NULL,
    },
    /* */
};

static bool address_check_path_has_more_lines(void) {
    return tx_desc[ADDRESS_CHECK_PATH_SCREEN][1][0] != '\0';
}

/** Next page, skipping the second path page when the path fits one line. */
static unsigned int address_check_page_after(unsigned int page) {
    unsigned int next = page + 1;
    if (next == ADDRESS_CHECK_PATH_REST_PAGE && !address_check_path_has_more_lines()) {
        next++;
    }
    return next;
}

/** Previous page, skipping the second path page when the path fits one line. */
static unsigned int address_check_page_before(unsigned int page) {
    unsigned int before = page - 1;
    if (before == ADDRESS_CHECK_PATH_REST_PAGE && !address_check_path_has_more_lines()) {
        before--;
    }
    return before;
}

/** Address check buttons, Nano S: both buttons act only on Approve and Reject. */
static unsigned int address_check_button(unsigned int button_mask, unsigned int page) {
    switch (button_mask) {
        case BUTTON_EVT_RELEASED | BUTTON_LEFT:
            if (page > ADDRESS_CHECK_INTRO_PAGE) {
                show_address_check_page(address_check_page_before(page));
            }
            break;
        case BUTTON_EVT_RELEASED | BUTTON_RIGHT:
            if (page < ADDRESS_CHECK_REJECT_PAGE) {
                show_address_check_page(address_check_page_after(page));
            }
            break;
        case BUTTON_EVT_RELEASED | BUTTON_LEFT | BUTTON_RIGHT:
            if (page == ADDRESS_CHECK_APPROVE_PAGE) {
                address_check_approve();
            } else if (page == ADDRESS_CHECK_REJECT_PAGE) {
                address_check_reject();
            }
            break;
    }
    return 0;
}

static unsigned int bagl_ui_address_check_nanos_intro_button(unsigned int button_mask,
                                                             unsigned int button_mask_counter) {
    UNUSED(button_mask_counter);
    return address_check_button(button_mask, ADDRESS_CHECK_INTRO_PAGE);
}

static unsigned int bagl_ui_address_check_nanos_path_button(unsigned int button_mask,
                                                            unsigned int button_mask_counter) {
    UNUSED(button_mask_counter);
    return address_check_button(button_mask, ADDRESS_CHECK_PATH_PAGE);
}

static unsigned int bagl_ui_address_check_nanos_path_rest_button(unsigned int button_mask,
                                                                 unsigned int button_mask_counter) {
    UNUSED(button_mask_counter);
    return address_check_button(button_mask, ADDRESS_CHECK_PATH_REST_PAGE);
}

static unsigned int bagl_ui_address_check_nanos_address_button(unsigned int button_mask,
                                                               unsigned int button_mask_counter) {
    UNUSED(button_mask_counter);
    return address_check_button(button_mask, ADDRESS_CHECK_ADDRESS_PAGE);
}

static unsigned int bagl_ui_address_check_nanos_address_rest_button(
    unsigned int button_mask,
    unsigned int button_mask_counter) {
    UNUSED(button_mask_counter);
    return address_check_button(button_mask, ADDRESS_CHECK_ADDRESS_REST_PAGE);
}

static unsigned int bagl_ui_address_check_nanos_approve_button(unsigned int button_mask,
                                                               unsigned int button_mask_counter) {
    UNUSED(button_mask_counter);
    return address_check_button(button_mask, ADDRESS_CHECK_APPROVE_PAGE);
}

static unsigned int bagl_ui_address_check_nanos_reject_button(unsigned int button_mask,
                                                              unsigned int button_mask_counter) {
    UNUSED(button_mask_counter);
    return address_check_button(button_mask, ADDRESS_CHECK_REJECT_PAGE);
}

static void show_address_check_page(unsigned int page) {
    uiState = UI_ADDRESS_CHECK;
    switch (page) {
        case ADDRESS_CHECK_INTRO_PAGE:
            UX_DISPLAY(bagl_ui_address_check_nanos_intro, NULL);
            break;
        case ADDRESS_CHECK_PATH_PAGE:
            UX_DISPLAY(bagl_ui_address_check_nanos_path, NULL);
            break;
        case ADDRESS_CHECK_PATH_REST_PAGE:
            UX_DISPLAY(bagl_ui_address_check_nanos_path_rest, NULL);
            break;
        case ADDRESS_CHECK_ADDRESS_PAGE:
            UX_DISPLAY(bagl_ui_address_check_nanos_address, NULL);
            break;
        case ADDRESS_CHECK_ADDRESS_REST_PAGE:
            UX_DISPLAY(bagl_ui_address_check_nanos_address_rest, NULL);
            break;
        case ADDRESS_CHECK_APPROVE_PAGE:
            UX_DISPLAY(bagl_ui_address_check_nanos_approve, NULL);
            break;
        default:
            UX_DISPLAY(bagl_ui_address_check_nanos_reject, NULL);
            break;
    }
}

/** Marks a fully drawn path or address page as read, or Approve as drawn. */
static void address_check_page_drawn(const bagl_element_t *layout) {
    unsigned int page = ADDRESS_CHECK_PAGES;
    if (layout == bagl_ui_address_check_nanos_path) {
        page = ADDRESS_CHECK_PATH_PAGE;
    } else if (layout == bagl_ui_address_check_nanos_path_rest) {
        page = ADDRESS_CHECK_PATH_REST_PAGE;
    } else if (layout == bagl_ui_address_check_nanos_address) {
        page = ADDRESS_CHECK_ADDRESS_PAGE;
    } else if (layout == bagl_ui_address_check_nanos_address_rest) {
        page = ADDRESS_CHECK_ADDRESS_REST_PAGE;
    } else if (layout == bagl_ui_address_check_nanos_approve) {
        set_accept_drawn(true);
    }
    if (page == ADDRESS_CHECK_PAGES) {
        return;
    }
    review_seen_top |= 1u << page;
    review_seen_top_check &= ~(1u << page);
}

/** UI struct for the first screen of a review, Nano S. */
static const bagl_element_t bagl_ui_top_sign_nanos[] = {
    // { {type, userid, x, y, width, height, stroke, radius, fill, fgcolor, bgcolor, font_id,
    // icon_id},
    // text, touch_area_brim, overfgcolor, overbgcolor, tap, out, over,
    // },
    {
        {BAGL_RECTANGLE, 0x00, 0, 0, 128, 32, 0, 0, BAGL_FILL, 0x000000, 0xFFFFFF, 0, 0},
        NULL,
    },
    /* top left bar */
    {
        {BAGL_RECTANGLE, 0x00, 3, 1, 12, 2, 0, 0, BAGL_FILL, 0xFFFFFF, 0x000000, 0, 0},
        NULL,
    },
    /* top right bar */
    {
        {BAGL_RECTANGLE, 0x00, 113, 1, 12, 2, 0, 0, BAGL_FILL, 0xFFFFFF, 0x000000, 0, 0},
        NULL,
    },
    /* center text */
    {
        {BAGL_LABELINE, 0x02, 0, 20, 128, 11, 0, 0, 0, 0xFFFFFF, 0x000000, DEFAULT_FONT, 0},
        "Review Tx",
    },
    /* left icon is up arrow  */
    {
        {BAGL_ICON, 0x00, 3, 13, 7, 7, 0, 0, 0, 0xFFFFFF, 0x000000, 0, BAGL_GLYPH_ICON_UP},
        NULL,
    },
    /* right icon is down arrow */
    {
        {BAGL_ICON, 0x00, 117, 13, 8, 6, 0, 0, 0, 0xFFFFFF, 0x000000, 0, BAGL_GLYPH_ICON_DOWN},
        NULL,
    },
    /* */
};

/** buttons for the first review screen: Left up, Right or both down. Nothing signs here. */
static unsigned int bagl_ui_top_sign_nanos_button(unsigned int button_mask,
                                                  unsigned int button_mask_counter) {
    UNUSED(button_mask_counter);
    switch (button_mask) {
        case BUTTON_EVT_RELEASED | BUTTON_LEFT | BUTTON_RIGHT:
            tx_desc_dn(NULL);
            break;

        case BUTTON_EVT_RELEASED | BUTTON_RIGHT:
            tx_desc_dn(NULL);
            break;

        case BUTTON_EVT_RELEASED | BUTTON_LEFT:
            tx_desc_up(NULL);
            break;
    }
    return 0;
}

/** UI struct for the bottom "Sign Transaction" screen, Nano S. */
static const bagl_element_t bagl_ui_sign_nanos[] = {
    // { {type, userid, x, y, width, height, stroke, radius, fill, fgcolor, bgcolor, font_id,
    // icon_id},
    // text, touch_area_brim, overfgcolor, overbgcolor, tap, out, over,
    // },
    {
        {BAGL_RECTANGLE, 0x00, 0, 0, 128, 32, 0, 0, BAGL_FILL, 0x000000, 0xFFFFFF, 0, 0},
        NULL,
    },
    /* top left bar */
    {
        {BAGL_RECTANGLE, 0x00, 3, 1, 12, 2, 0, 0, BAGL_FILL, 0xFFFFFF, 0x000000, 0, 0},
        NULL,
    },
    /* top right bar */
    {
        {BAGL_RECTANGLE, 0x00, 113, 1, 12, 2, 0, 0, BAGL_FILL, 0xFFFFFF, 0x000000, 0, 0},
        NULL,
    },
    /* center text */
    {
        {BAGL_LABELINE, 0x02, 0, 20, 128, 11, 0, 0, 0, 0xFFFFFF, 0x000000, DEFAULT_FONT, 0},
        "Sign Tx",
    },
    /* left icon is up arrow  */
    {
        {BAGL_ICON, 0x00, 3, 13, 7, 7, 0, 0, 0, 0xFFFFFF, 0x000000, 0, BAGL_GLYPH_ICON_UP},
        NULL,
    },
    /* right icon is down arrow */
    {
        {BAGL_ICON, 0x00, 117, 13, 8, 6, 0, 0, 0, 0xFFFFFF, 0x000000, 0, BAGL_GLYPH_ICON_DOWN},
        NULL,
    },
    /* */
};

/** buttons for the Sign screen: Left up, Right down, both sign once every half was shown, else
 * show the first unread half. */
static unsigned int bagl_ui_sign_nanos_button(unsigned int button_mask,
                                              unsigned int button_mask_counter) {
    UNUSED(button_mask_counter);
    switch (button_mask) {
        case BUTTON_EVT_RELEASED | BUTTON_LEFT | BUTTON_RIGHT:
            if (review_complete != REVIEW_COMPLETE || !review_fully_read()) {
                show_first_unread_half();
            } else if (sign_screen_on_display()) {
                io_seproxyhal_touch_approve(NULL);
            }
            // else Sign is not fully drawn yet: ignore the press, the user presses again
            break;

        case BUTTON_EVT_RELEASED | BUTTON_RIGHT:
            tx_desc_dn(NULL);
            break;

        case BUTTON_EVT_RELEASED | BUTTON_LEFT:
            tx_desc_up(NULL);
            break;
    }
    return 0;
}

/** UI struct for the bottom "Deny Transaction" screen, Nano S. */
static const bagl_element_t bagl_ui_deny_nanos[] = {
    // { {type, userid, x, y, width, height, stroke, radius, fill, fgcolor, bgcolor, font_id,
    // icon_id},
    // text, touch_area_brim, overfgcolor, overbgcolor, tap, out, over,
    // },
    {
        {BAGL_RECTANGLE, 0x00, 0, 0, 128, 32, 0, 0, BAGL_FILL, 0x000000, 0xFFFFFF, 0, 0},
        NULL,
    },
    /* top left bar */
    {
        {BAGL_RECTANGLE, 0x00, 3, 1, 12, 2, 0, 0, BAGL_FILL, 0xFFFFFF, 0x000000, 0, 0},
        NULL,
    },
    /* top right bar */
    {
        {BAGL_RECTANGLE, 0x00, 113, 1, 12, 2, 0, 0, BAGL_FILL, 0xFFFFFF, 0x000000, 0, 0},
        NULL,
    },
    /* center text */
    {
        {BAGL_LABELINE, 0x02, 0, 20, 128, 11, 0, 0, 0, 0xFFFFFF, 0x000000, DEFAULT_FONT, 0},
        "Deny Tx",
    },
    /* left icon is up arrow  */
    {
        {BAGL_ICON, 0x00, 3, 13, 7, 7, 0, 0, 0, 0xFFFFFF, 0x000000, 0, BAGL_GLYPH_ICON_UP},
        NULL,
    },
    {
        {BAGL_ICON, 0x00, 117, 13, 8, 6, 0, 0, 0, 0xFFFFFF, 0x000000, 0, BAGL_GLYPH_ICON_DOWN},
        NULL,
    },
    /* */
};

/**
 * buttons for the bottom "Deny Transaction" screen
 *
 * up on Left button, down on right button, deny on both buttons.
 */
static unsigned int bagl_ui_deny_nanos_button(unsigned int button_mask,
                                              unsigned int button_mask_counter) {
    UNUSED(button_mask_counter);
    switch (button_mask) {
        case BUTTON_EVT_RELEASED | BUTTON_LEFT | BUTTON_RIGHT:
            io_seproxyhal_touch_deny(NULL);
            break;

        case BUTTON_EVT_RELEASED | BUTTON_RIGHT:
            tx_desc_dn(NULL);
            break;

        case BUTTON_EVT_RELEASED | BUTTON_LEFT:
            tx_desc_up(NULL);
            break;
    }
    return 0;
}

/** Review screen top half, Nano S: bold heading and line 1. Rows sit 14 px apart, as in the SDK:
 * the font is 12 px tall and a closer row would clip descenders such as j and g. */
static const bagl_element_t bagl_ui_tx_desc_nanos_1[] = {
    // { {type, userid, x, y, width, height, stroke, radius, fill, fgcolor, bgcolor, font_id,
    // icon_id},
    // text, touch_area_brim, overfgcolor, overbgcolor, tap, out, over,
    // },
    {
        {BAGL_RECTANGLE, 0x00, 0, 0, 128, 32, 0, 0, BAGL_FILL, 0x000000, 0xFFFFFF, 0, 0},
        NULL,
    },
    /* heading of the current screen */
    {
        {BAGL_LABELINE,
         0x02,
         10,
         12,
         108,
         11,
         0x80 | 10,
         0,
         0,
         0xFFFFFF,
         0x000000,
         DEFAULT_FONT,
         0},
        curr_review_title,
    },
    /* first line of description of current screen */
    {
        {BAGL_LABELINE,
         0x02,
         10,
         26,
         108,
         11,
         0x80 | 10,
         0,
         0,
         0xFFFFFF,
         0x000000,
         TX_DESC_FONT,
         0},
        curr_tx_desc[0],
    },
    /* left icon is up arrow  */
    {
        {BAGL_ICON, 0x00, 3, 13, 7, 7, 0, 0, 0, 0xFFFFFF, 0x000000, 0, BAGL_GLYPH_ICON_UP},
        NULL,
    },
    /* right icon is down arrow */
    {
        {BAGL_ICON, 0x00, 117, 13, 8, 6, 0, 0, 0, 0xFFFFFF, 0x000000, 0, BAGL_GLYPH_ICON_DOWN},
        NULL,
    },
    /* */
};

/** UI struct for the transaction description screen, Nano S. */
static const bagl_element_t bagl_ui_tx_desc_nanos_2[] = {
    // { {type, userid, x, y, width, height, stroke, radius, fill, fgcolor, bgcolor, font_id,
    // icon_id},
    // text, touch_area_brim, overfgcolor, overbgcolor, tap, out, over,
    // },
    {
        {BAGL_RECTANGLE, 0x00, 0, 0, 128, 32, 0, 0, BAGL_FILL, 0x000000, 0xFFFFFF, 0, 0},
        NULL,
    },
    /* second line of description of current screen */
    {
        {BAGL_LABELINE,
         0x02,
         10,
         12,
         108,
         11,
         0x80 | 10,
         0,
         0,
         0xFFFFFF,
         0x000000,
         TX_DESC_FONT,
         0},
        curr_tx_desc[1],
    },
    /* third line of description of current screen  */
    {
        {BAGL_LABELINE,
         0x02,
         10,
         26,
         108,
         11,
         0x80 | 10,
         0,
         0,
         0xFFFFFF,
         0x000000,
         TX_DESC_FONT,
         0},
        curr_tx_desc[2],
    },
    /* left icon is up arrow  */
    {
        {BAGL_ICON, 0x00, 3, 13, 7, 7, 0, 0, 0, 0xFFFFFF, 0x000000, 0, BAGL_GLYPH_ICON_UP},
        NULL,
    },
    /* right icon is down arrow */
    {
        {BAGL_ICON, 0x00, 117, 13, 8, 6, 0, 0, 0, 0xFFFFFF, 0x000000, 0, BAGL_GLYPH_ICON_DOWN},
        NULL,
    },
    /* */
};

/**
 * buttons for the transaction description screen
 *
 * up on Left button, down on right button.
 */
static unsigned int bagl_ui_tx_desc_nanos_1_button(unsigned int button_mask,
                                                   unsigned int button_mask_counter) {
    UNUSED(button_mask_counter);
    switch (button_mask) {
        case BUTTON_EVT_RELEASED | BUTTON_RIGHT:
            tx_desc_dn(NULL);
            break;

        case BUTTON_EVT_RELEASED | BUTTON_LEFT:
            tx_desc_up(NULL);
            break;
    }
    return 0;
}

/**
 * buttons for the transaction description screen
 *
 * up on Left button, down on right button.
 */
static unsigned int bagl_ui_tx_desc_nanos_2_button(unsigned int button_mask,
                                                   unsigned int button_mask_counter) {
    UNUSED(button_mask_counter);
    switch (button_mask) {
        case BUTTON_EVT_RELEASED | BUTTON_RIGHT:
            tx_desc_dn(NULL);
            break;

        case BUTTON_EVT_RELEASED | BUTTON_LEFT:
            tx_desc_up(NULL);
            break;
    }
    return 0;
}

/** if the user wants to exit go back to the app dashboard. */
static const bagl_element_t *io_seproxyhal_touch_exit(const bagl_element_t *e) {
    UNUSED(e);
    // Go back to the dashboard
    os_sched_exit(0);
    return NULL;  // do not redraw the widget
}

/** copy the current row and its heading for display, clamping the index so no button path reads
 * past tx_desc. */
static void copy_tx_desc(void) {
    if (max_scr_ix == 0 || max_scr_ix > MAX_TX_TEXT_SCREENS) {
        memset(curr_tx_desc, 0, sizeof(curr_tx_desc));
        memset(curr_review_title, 0, sizeof(curr_review_title));
        return;
    }
    if (curr_scr_ix >= max_scr_ix) {
        curr_scr_ix = max_scr_ix - 1;
    }
    // the text changes: restart the count so a half drawn partly with old text never counts
    elements_drawn = 0;
    elements_drawn_of = NULL;
    memmove(curr_tx_desc, tx_desc[curr_scr_ix], CURR_TX_DESC_LEN);
    curr_tx_desc[0][MAX_TX_TEXT_WIDTH - 1] = '\0';
    curr_tx_desc[1][MAX_TX_TEXT_WIDTH - 1] = '\0';
    curr_tx_desc[2][MAX_TX_TEXT_WIDTH - 1] = '\0';
    memmove(curr_review_title, review_title[curr_scr_ix], MAX_TX_TEXT_WIDTH);
    curr_review_title[MAX_TX_TEXT_WIDTH - 1] = '\0';
}

/** Where both buttons on Sign lead until the whole review has been read. */
static void show_first_unread_half(void) {
    for (unsigned int s = 0; s < max_scr_ix && s < MAX_TX_TEXT_SCREENS; s++) {
        uint32_t bit = 1u << s;
        if ((review_seen_top & bit) == 0 || (review_seen_bottom & bit) == 0) {
            curr_scr_ix = s;
            copy_tx_desc();
            if ((review_seen_top & bit) == 0) {
                ui_display_tx_desc_1();
            } else {
                ui_display_tx_desc_2();
            }
            return;
        }
    }
}

/** processes the Up button */
static const bagl_element_t *tx_desc_up(const bagl_element_t *e) {
    UNUSED(e);
    switch (uiState) {
        case UI_TOP_SIGN:
            ui_deny();
            break;

        case UI_TX_DESC_1:
            if (curr_scr_ix == 0) {
                ui_top_sign();
            } else {
                curr_scr_ix--;
                copy_tx_desc();
                ui_display_tx_desc_2();
            }
            break;

        case UI_TX_DESC_2:
            ui_display_tx_desc_1();
            break;

        case UI_SIGN:
            // to the last screen's second half, so reading backwards passes every half
            curr_scr_ix = (max_scr_ix > 0) ? max_scr_ix - 1 : 0;
            copy_tx_desc();
            ui_display_tx_desc_2();
            break;

        case UI_DENY:
            ui_sign();
            break;

        default:
            // outside the review a press is ignored, not an error
            break;
    }
    return NULL;
}

/** processes the Down button */
static const bagl_element_t *tx_desc_dn(const bagl_element_t *e) {
    UNUSED(e);
    switch (uiState) {
        case UI_TOP_SIGN:
            curr_scr_ix = 0;
            copy_tx_desc();
            ui_display_tx_desc_1();
            break;

        case UI_TX_DESC_1:
            ui_display_tx_desc_2();
            break;

        case UI_TX_DESC_2:
            if (curr_scr_ix + 1 >= max_scr_ix) {
                ui_sign();
            } else {
                curr_scr_ix++;
                copy_tx_desc();
                ui_display_tx_desc_1();
            }
            break;

        case UI_SIGN:
            ui_deny();
            break;

        case UI_DENY:
            ui_top_sign();
            break;

        default:
            // outside the review a press is ignored, not an error
            break;
    }
    return NULL;
}

#endif  // TARGET_NANOS

#if defined(TARGET_NANOS)
/** True if Sign is drawn in full and holds the buttons, so no other screen can sign. */
static bool sign_screen_on_display(void) {
    button_push_callback_t buttons =
        *(button_push_callback_t const volatile *) &G_ux.stack[0].button_push_callback;
    bool sign_drawn = accept_drawn == ACCEPT_DRAWN && (accept_drawn ^ accept_drawn_check) == ~0u;
    return *(const volatile enum UI_STATE *) &uiState == UI_SIGN &&
           buttons == bagl_ui_sign_nanos_button &&
           layout_on_display(bagl_ui_sign_nanos,
                             sizeof(bagl_ui_sign_nanos) / sizeof(bagl_ui_sign_nanos[0])) &&
           sign_drawn;
}

/** Called once every element of a layout has been drawn. */
static void screen_drawn(const bagl_element_t *layout) {
    if (layout == bagl_ui_tx_desc_nanos_1 && uiState == UI_TX_DESC_1) {
        mark_review_half_shown(&review_seen_top, &review_seen_top_check);
    } else if (layout == bagl_ui_tx_desc_nanos_2 && uiState == UI_TX_DESC_2) {
        mark_review_half_shown(&review_seen_bottom, &review_seen_bottom_check);
    } else if (layout == bagl_ui_sign_nanos && uiState == UI_SIGN) {
        set_accept_drawn(true);
    } else if (uiState == UI_ADDRESS_CHECK) {
        address_check_page_drawn(layout);
    }
}

/** A screen counts as drawn only when all its elements arrive in order, so a store the SDK skips
 * while drawing leaves it not drawn. */
void ui_element_drawn(const bagl_element_t *element) {
    const bagl_element_t *layout =
        *(const bagl_element_t *const volatile *) &G_ux.stack[0].element_arrays[0].element_array;
    unsigned int count =
        *(const volatile unsigned char *) &G_ux.stack[0].element_arrays[0].element_array_count;
    unsigned int drawn = elements_drawn;

    // any draw means Sign is no longer the whole screen
    set_accept_drawn(false);
    if (layout == NULL || count == 0) {
        elements_drawn = 0;
        return;
    }
    if (element == &layout[0]) {
        drawn = 1;
    } else if (drawn != 0 && drawn < count && elements_drawn_of == layout &&
               element == &layout[drawn]) {
        drawn++;
    } else {
        drawn = 0;
    }
    elements_drawn = drawn;
    elements_drawn_of = layout;
    if (drawn == count) {
        elements_drawn = 0;
        screen_drawn(layout);
    }
}
#endif  // TARGET_NANOS

/** True if the user was shown the whole committed review and the approve screen is up. */
static bool review_shown_whole(void) {
#if defined(TARGET_NANOS)
    return review_complete == REVIEW_COMPLETE && review_fully_read() && sign_screen_on_display();
#else
    return review_flow_is_whole();
#endif
}

/** Signs what the session committed, never bytes from the I/O buffer the computer controls. The
 * reply is the DER signature, then 9000. */
const bagl_element_t *io_seproxyhal_touch_approve(const bagl_element_t *e) {
    UNUSED(e);
    unsigned int tx = 0;
    unsigned short sw = SW_COMMIT_MISMATCH;
    // checked twice, so one skipped check cannot sign
    if (review_shown_whole() && review_shown_whole()) {
        sw = tx_session_sign(G_io_apdu_buffer, sizeof(G_io_apdu_buffer) - 2, &tx);
    }

    tx_session_reset();
    reset_review_progress();
    if (sw != SW_OK) {
        tx = 0;
    }
    G_io_apdu_buffer[tx++] = sw >> 8;
    G_io_apdu_buffer[tx++] = sw & 0xFF;
    // Send back the response, do not restart the event loop
    io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, tx);
    // Display back the original UX
    ui_idle();
    return 0;  // do not redraw the widget
}

/** deny signing. Nano S passes presses on until the host reads the reply; with no review armed
 * they are ignored, so replies cannot nest. */
static const bagl_element_t *io_seproxyhal_touch_deny(const bagl_element_t *e) {
    UNUSED(e);
    if (!tx_session_is_armed()) {
        return 0;
    }
    tx_session_reset();
    reset_review_progress();
    G_io_apdu_buffer[0] = SW_USER_REJECTED >> 8;
    G_io_apdu_buffer[1] = SW_USER_REJECTED & 0xFF;
    // Send back the response, do not restart the event loop
    io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, 2);
    // Display back the original UX
    ui_idle();
    return 0;  // do not redraw the widget
}

#if defined(TARGET_NANOS)
/** show the public key screen */
void ui_public_key_1(void) {
    uiState = UI_PUBLIC_KEY_1;
    if (os_seph_features() & SEPROXYHAL_TAG_SESSION_START_EVENT_FEATURE_SCREEN_BIG) {
    } else {
        UX_DISPLAY(bagl_ui_public_key_nanos_1, NULL);
    }
}

/** show the public key screen */
void ui_public_key_2(void) {
    uiState = UI_PUBLIC_KEY_2;
    if (os_seph_features() & SEPROXYHAL_TAG_SESSION_START_EVENT_FEATURE_SCREEN_BIG) {
    } else {
        UX_DISPLAY(bagl_ui_public_key_nanos_2, NULL);
    }
}
#endif  // TARGET_NANOS

/** Resets the read marks here too, so one skipped reset cannot carry them into this review. */
void ui_start_review(void) {
    reset_review_progress();
    ui_top_sign();
}

/** The only way to read keys outside the range a silent key request answers. It guards privacy,
 * not funds, so it has only the drawn-in-full check of the review's hardening. */
unsigned short ui_start_address_check(const unsigned int *path) {
    uint8_t pubkey[ELA_PUBKEY_LEN];
    if (keys_get_public_key(path, pubkey) != CX_OK) {
        return SW_CRYPTO_FAILED;
    }
    CHECK_SW(display_path_to_check(path));
    CHECK_SW(display_address_to_check(pubkey));
    memcpy(address_check_path, path, sizeof(address_check_path));
    address_check_pending = true;
    // clear marks an earlier screen left
    reset_review_progress();
#if defined(TARGET_NANOS)
    show_address_check_page(ADDRESS_CHECK_INTRO_PAGE);
#elif defined(TARGET_NANOX) || defined(TARGET_NANOS2)
    uiState = UI_ADDRESS_CHECK;
    if (G_ux.stack_count == 0) {
        ux_stack_push();
    }
    review_step_drawing = MAX_TX_TEXT_SCREENS;
    ux_flow_init(0, ux_address_check_flow, NULL);
#endif  // #if TARGET_ID
    return SW_OK;
}

/** True if every path and address screen was drawn in full and Approve is up (on Nano S, also on
 * display with its buttons), so a fault cannot send a key the user was not shown. */
static bool address_check_shown_whole(void) {
    bool approve_drawn = accept_drawn == ACCEPT_DRAWN && (accept_drawn ^ accept_drawn_check) == ~0u;
#if defined(TARGET_NANOS)
    uint32_t every_page = (1u << ADDRESS_CHECK_PATH_PAGE) | (1u << ADDRESS_CHECK_ADDRESS_PAGE) |
                          (1u << ADDRESS_CHECK_ADDRESS_REST_PAGE);
    if (address_check_path_has_more_lines()) {
        every_page |= 1u << ADDRESS_CHECK_PATH_REST_PAGE;
    }
    button_push_callback_t buttons =
        *(button_push_callback_t const volatile *) &G_ux.stack[0].button_push_callback;
    return (review_seen_top & every_page) == every_page &&
           (review_seen_top_check & every_page) == 0 && approve_drawn &&
           *(const volatile enum UI_STATE *) &uiState == UI_ADDRESS_CHECK &&
           buttons == bagl_ui_address_check_nanos_approve_button &&
           layout_on_display(bagl_ui_address_check_nanos_approve,
                             sizeof(bagl_ui_address_check_nanos_approve) /
                                 sizeof(bagl_ui_address_check_nanos_approve[0]));
#else
    uint32_t every_step = (1u << ADDRESS_CHECK_PATH_STEP) | (1u << ADDRESS_CHECK_ADDRESS_STEP);
    return (review_seen_top & every_step) == every_step &&
           (review_seen_top_check & every_step) == 0 && approve_drawn;
#endif
}

/** Sends the public key. A press while the reply is going out finds nothing pending, so replies
 * cannot nest. */
static void address_check_approve(void) {
    unsigned int tx = 0;
    unsigned short sw = SW_OK;
    if (!address_check_pending) {
        return;
    }
    // not all drawn in full yet: ignore the press, as Sign does; the user presses again
    if (!address_check_shown_whole()) {
#if defined(TARGET_NANOX) || defined(TARGET_NANOS2)
        // the SDK ran this step as its own flow: put the check back on Approve to keep the buttons
        ux_flow_init(0, ux_address_check_flow, &ux_address_check_approve_step);
#endif  // TARGET_NANOX || TARGET_NANOS2
        return;
    }
    address_check_pending = false;
    if (keys_get_public_key(address_check_path, G_io_apdu_buffer) == CX_OK) {
        tx = ELA_PUBKEY_LEN;
    } else {
        sw = SW_CRYPTO_FAILED;
    }
    G_io_apdu_buffer[tx++] = sw >> 8;
    G_io_apdu_buffer[tx++] = sw & 0xFF;
    io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, tx);
    ui_idle();
}

/** Answers 6985 and returns to idle. */
static void address_check_reject(void) {
    if (!address_check_pending) {
        return;
    }
    address_check_pending = false;
    G_io_apdu_buffer[0] = SW_USER_REJECTED >> 8;
    G_io_apdu_buffer[1] = SW_USER_REJECTED & 0xFF;
    io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, 2);
    ui_idle();
}

/** Follows the screen, not the session: true even if no review is committed behind it. */
bool ui_review_on_screen(void) {
    switch (uiState) {
        case UI_TOP_SIGN:
        case UI_TX_DESC_1:
        case UI_TX_DESC_2:
        case UI_SIGN:
        case UI_DENY:
        case UI_ADDRESS_CHECK:
            return true;
        default:
            return false;
    }
}

/** show the idle screen. Every review ends here, so its read marks are cleared here. */
void ui_idle(void) {
    uiState = UI_IDLE;
    reset_review_progress();
    address_check_pending = false;

#if defined(TARGET_NANOS)
    UX_DISPLAY(bagl_ui_idle_nanos, NULL);
#elif defined(TARGET_NANOX) || defined(TARGET_NANOS2)
    // reserve a display stack slot if none yet
    if (G_ux.stack_count == 0) {
        ux_stack_push();
    }
    ux_flow_init(0, ux_idle_flow, NULL);
#endif  // #if TARGET_ID
}

#if defined(TARGET_NANOS)
/** show the transaction description screen. */
static void ui_display_tx_desc_1(void) {
    uiState = UI_TX_DESC_1;
    UX_DISPLAY(bagl_ui_tx_desc_nanos_1, NULL);
}

/** show the transaction description screen. */
static void ui_display_tx_desc_2(void) {
    uiState = UI_TX_DESC_2;
    UX_DISPLAY(bagl_ui_tx_desc_nanos_2, NULL);
}

/** show the bottom "Sign Transaction" screen. */
static void ui_sign(void) {
    uiState = UI_SIGN;
    UX_DISPLAY(bagl_ui_sign_nanos, NULL);
}
#endif  // TARGET_NANOS

/** show the top "Sign Transaction" screen. */
void ui_top_sign(void) {
    uiState = UI_TOP_SIGN;

#if defined(TARGET_NANOS)
    UX_DISPLAY(bagl_ui_top_sign_nanos, NULL);
#elif defined(TARGET_NANOX) || defined(TARGET_NANOS2)
    // reserve a display stack slot if none yet
    if (G_ux.stack_count == 0) {
        ux_stack_push();
    }
    build_review_flow();
    ux_flow_init(0, ux_review_flow, NULL);
#endif  // #if TARGET_ID
}

#if defined(TARGET_NANOS)
/** show the "deny" screen */
static void ui_deny(void) {
    uiState = UI_DENY;
    UX_DISPLAY(bagl_ui_deny_nanos, NULL);
}
#endif  // TARGET_NANOS
