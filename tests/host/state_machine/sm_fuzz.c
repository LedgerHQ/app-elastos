/*
 * sm_fuzz.c: state-machine fuzzer for the Elastos app.
 *
 * Compiles the real ui.c, main.c (as main_shim.c), elastos.c, base-encoding.c, keys.c and
 * tx_session.c into one unit, built for the Nano S, which no emulator runs and the wallet cannot
 * reach. Every case starts the app through its real main().
 *
 * Host actions are APDUs and button presses. A press reaches only the handler of the screen
 * showing, as the SDK routes it. Two actions call approve and deny directly, to test what the
 * signing session guarantees if the screens were bypassed. As on the SDK, a command that arrives
 * while a reply waits for the user is dropped.
 *
 * The display is driven as the SDK drives it and the screen checks read what it was sent. Some
 * cases inject one display fault: a skipped UX_DISPLAY store, a cut drawing, a skipped element
 * send or a skipped status check. The display checks then wait until the screen is whole again;
 * the signing checks hold throughout.
 *
 * SHA-256 is real and the stub signer reports the digest and key it got, so the checks compare
 * what was signed with what was shown.
 *
 * On every signature:
 *   B1  a review was on screen
 *   B2  the digest is SHA-256 of exactly that review's body bytes
 *   B3  the key is the key of that review's path
 *   B4  one review gives at most one signature
 *   B5  the screens match a fresh parse of the bytes and did not change before signing
 *   B6  by button: both buttons on Sign, shown in full, after every heading and line was drawn
 *   B7  by any approval, even one forced past the screens: every review screen was drawn
 * After every action:
 *   M1  buffer and screen indexes in bounds
 *   M2  a review is on screen if and only if the session is armed; buttons reach that screen
 *   M3  every screen draws exactly its texts, fonts, colors and rows, inside the screen
 *   M4  every reply is a status word, a 65-byte key or a DER signature; no exchange starts while
 *       a reply is being sent
 *   M5  every press on a review, account or address check screen leads where the model says
 *   P1  a key reply, review or address check follows only a path the spec allows:
 *       44'/2305'/account'/change/index, account hardened, change 0 or 1, index not hardened
 *   A1  a key request gets 6A86 for a bad P1 or P2, 6700 if too long, 6D09 if too short and
 *       6D58 for a refused path; P1 00 gets its key at once inside the silent range (account up
 *       to 100', index up to 50,000), else 6D63 with nothing derived; P1 01 shows the address
 *       check, or gets 6D60 if an address line is too wide; a refused request shows nothing
 *   A2  an address check is answered only by both buttons: on Approve with the key of the path
 *       shown, once every path and address line was drawn in full; on Reject with 6985
 *   A3  an address check is on screen if and only if its reply is pending; after its answer or
 *       an SDK error the app is idle with nothing pending
 *   F1  a failed crypto step (derivation, key setup, public key, program hash or signature) gets
 *       exactly 6D5F, leaves nothing on screen or pending, and signs nothing
 *   L2  reading back from Sign to the top shows every half, and then both buttons on Sign sign
 *   X1  the app leaves only through the OS, never by returning from main
 *   X2  the exit instruction leaves before the next command
 *   X3  only the exit instruction, Quit or the idle timer closes the app
 *   X4  Quit on the home screen closes the app
 *   R1  after a USB reset, or a reply with no command to answer, the transport restarts on the
 *       idle screen with nothing queued, pending or armed
 *   R2  after any other SDK exception the next reply is the spec's status word for it, with
 *       nothing pending, armed or being received
 *   T1  a clock tick never closes the app before the spec's 4098 idle ticks
 * Once per run, before the cases:
 *   G1  one fault (a flipped bit, a skipped check or a skipped display call) in the screen count,
 *       digests, reviewed bytes, path, review text, body length, read marks or screen index
 *       cannot make the app sign what was not reviewed and read
 *   W1  the raw derivation and the private key are wiped on every return path, even when a
 *       crypto step fails after writing its output
 *   T2  idle, or with a review or address check waiting, the app closes on exactly the 4098th
 *       tick after start or the last press, sign or key request; other commands do not restart it
 *   S1  after a USB reset an intact stack canary lets the app carry on; a changed one resets
 *   A1 to A3, F1 and M3 also on scripted address check flows and crypto failures
 * At the end of every case that did not leave the app:
 *   L1  the app still returns a key and signs a normal transfer after a full review; once per
 *       run, a refused command, SDK error or key request mid-transaction ends that transaction
 *
 * AddressSanitizer and UndefinedBehaviorSanitizer stop on any memory or UB fault.
 *
 * usage: ./sm_fuzz [runs] [seed]
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdarg.h>

/* ---- exception context and SDK globals the stubs expect ---------------------------------- */
jmp_buf g_ela_jmp_app;
jmp_buf *g_ela_jmp_ptr = &g_ela_jmp_app;
jmp_buf g_case_jmp;
unsigned int g_last_throw;

/* ---- crypto faults and wipes (W1) ----------------------------------------------------------- */
int g_fail_derive, g_fail_init_key, g_fail_pair, g_fail_sign;
unsigned char *g_derive_out;
#define MAX_WIPES 16
static struct {
    const unsigned char *p;
    size_t n;
} g_wipes[MAX_WIPES];
static unsigned int g_wipe_count;

void sm_on_wipe(void *p, size_t n) {
    if (g_wipe_count < MAX_WIPES) {
        g_wipes[g_wipe_count].p = (const unsigned char *) p;
        g_wipes[g_wipe_count].n = n;
    }
    g_wipe_count++;
}

#include "os.h"
#include "cx.h"
#include "ux.h"
#include "bagl.h"
#include "os_io_seproxyhal.h"

const char *g_ux_screen;
G_io_app_t G_io_app;
unsigned char G_io_apdu_buffer[IO_APDU_BUFFER_SIZE];
cx_ecfp_private_key_t *g_private_key;
void (*g_sha_hook)(void);
const unsigned char *g_sha_hook_input;
/* the canary word the linker places below the stack on the device */
unsigned int app_stack_canary;

const unsigned char C_icon_dashboard[] = {0};
const unsigned char C_icon_validate_14[] = {0};
const unsigned char C_icon_crossmark[] = {0};
const unsigned char C_icon_back[] = {0};

/*
 * Signing compares the digest twice and nothing between can be hooked. So calls of
 * digests_match() in tx_session.c go to digest_compare() below, which can fault either one, and
 * the definition becomes digests_match_real(): its first argument starts with const, a call's
 * with digest. src/ needs no test hook.
 */
#define digests_match(first, ...) digests_match_##first, __VA_ARGS__)
#define digests_match_const       digests_match_real(const
#define digests_match_digest      digest_compare(digest
static bool digest_compare(const uint8_t *a, const uint8_t *b);

/*
 * prepare_review compares raw_tx_ix with the committed body length before and after arming. To
 * fault either one, reads of raw_tx_ix in main.c go through raw_tx_ix_in_main() below; ui.c,
 * elastos.c and tx_session.c read the variable itself.
 */
static unsigned int *raw_tx_ix_in_main(void);

/*
 * A P1 00 key request checks the silent range twice. To fault either check, calls of
 * keys_path_is_silent() in main.c go through silent_check_in_main() below.
 */
static bool silent_check_in_main(const unsigned int *path);

/*
 * No host key has an address with a line too wide for the screen, which the address check must
 * refuse. So keys_program_hash() calls in elastos.c go to sm_program_hash() below, which gives one
 * path such an address, as the Nano X gate does. main.c's call, for the review, is unchanged.
 */
static cx_err_t sm_program_hash(const uint8_t *pubkey, uint8_t *program_hash);

/* ---- the real application ------------------------------------------------------------------ */
#include "ui.c"
#define raw_tx_ix (*raw_tx_ix_in_main())
#define keys_path_is_silent silent_check_in_main
#include "main_shim.c"
#undef keys_path_is_silent
#undef raw_tx_ix
#define keys_program_hash sm_program_hash
#include "elastos.c"
#undef keys_program_hash
#include "base-encoding.c"
#include "keys.c"
#include "tx_session.c"

#include "corpus.h"

#define PATH_BYTES 20
#define DIGEST_LEN 32
#define KEY_LEN 32
#define SIG_REPLY_LEN (36 + 2)
#define PUB_REPLY_LEN (65 + 2)

/* ---- random numbers ------------------------------------------------------------------------- */
static uint64_t rng_state;
/* faults and presses drawn during a case, kept apart so the scripts stay the same */
static uint64_t side_state;
static uint64_t mix_next(uint64_t *state) {
    uint64_t z = (*state += 0x9E3779B97F4A7C15ull);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
    return z ^ (z >> 31);
}
static uint64_t rng_next(void) {
    return mix_next(&rng_state);
}
static unsigned int rnd(unsigned int n) {
    return (unsigned int) (rng_next() % n);
}
static unsigned int side_rnd(unsigned int n) {
    return (unsigned int) (mix_next(&side_state) % n);
}

/* ---- scripted host actions ------------------------------------------------------------------ */
#define MAX_ACTIONS 48
enum {
    ACT_APDU = 1, ACT_LEFT, ACT_RIGHT, ACT_BOTH, ACT_RAW_APPROVE, ACT_RAW_DENY, ACT_WALK_TO_SIGN,
    ACT_WALK_TO_TOP, ACT_READ_BACK, ACT_TICK, ACT_IO_FAULT, ACT_REPLY_FAULT, ACT_ANSWER_PENDING
};
/* the recovery check appended to every case */
enum { TAIL_NONE = 0, TAIL_PUB, TAIL_SIGN, TAIL_WALK, TAIL_APPROVE };
static const char *const ACT_NAME[] = {"?", "APDU", "LEFT", "RIGHT", "BOTH", "RAW_APPROVE", "RAW_DENY", "WALK",
                                       "WALK_BACK", "READ_BACK", "TICK", "IO_FAULT", "REPLY_FAULT",
                                       "ANSWER_PENDING"};

typedef struct {
    unsigned int type;
    unsigned int tail;
    unsigned char bytes[IO_APDU_BUFFER_SIZE];
    unsigned int len;
} action_t;

static action_t g_script[MAX_ACTIONS];
static unsigned int g_script_len;
static unsigned int g_script_ix;
static const action_t *g_cur;

/* how the current approval was triggered */
enum { VIA_NONE = 0, VIA_BUTTON, VIA_RAW };
static int g_via;

/* ---- the review the user was shown ---------------------------------------------------------- */
typedef struct {
    int valid;
    int is_tail;
    unsigned int body_len;
    unsigned char digest[DIGEST_LEN];
    unsigned char key[KEY_LEN];
    char desc[MAX_TX_TEXT_SCREENS][MAX_TX_TEXT_LINES][MAX_TX_TEXT_WIDTH];
    char title[MAX_TX_TEXT_SCREENS][MAX_TX_TEXT_WIDTH];
    unsigned int screens;
    int reparse_ok;
    int content_match;
    unsigned char seen_title[MAX_TX_TEXT_SCREENS];
    unsigned char seen_line[MAX_TX_TEXT_SCREENS][MAX_TX_TEXT_LINES];
    unsigned int sigs;
} review_t;
static review_t g_review;

/* ---- per-case and run state ----------------------------------------------------------------- */
static unsigned long g_case_no;
static uint64_t g_seed;
static int g_exited;
static int g_expect_pub;
static int g_tail_pub_ok;
static int g_tail_sig_ok;
static unsigned char g_tail_digest[DIGEST_LEN];
static unsigned char g_last_signed[DIGEST_LEN];

/* ticks since the last command or press that restarts the exit timer */
static unsigned long g_idle_ticks;
/* Nano S idle timeout from APP_SPECIFICATION.md, not main.c, so a changed timeout shows */
#define SPEC_EXIT_TICKS 4098ul
static volatile int g_in_tick;
static int g_expect_exit;
static int g_quit_pressed;
/* a reply is held for the user, so the SDK drops new commands */
static int g_reply_pending;
static unsigned long g_dropped;
/* an exception the next reply will meet, and what the next exchange must look like after one */
static unsigned int g_throw_on_reply;
enum { AFTER_NONE = 0, AFTER_RESTART, AFTER_STATUS };
static int g_after_fault;
static unsigned int g_after_status_sw;
static unsigned long g_faults;

static unsigned long g_reviews, g_full_reviews, g_sigs_button, g_sigs_raw, g_raw_unreviewed, g_exits, g_tail_ok;
static unsigned long g_violations;
static const char *const CHECKS[] = {"B1", "B2", "B3", "B4", "B5", "B6", "B7", "M1", "M2", "M3", "M4", "M5",
                                     "L1", "L2", "X1", "X2", "X3", "X4", "R1", "R2", "T1", "G1", "W1", "T2",
                                     "P1", "S1", "A1", "A2", "A3", "F1"};
#define CHECK_COUNT (sizeof(CHECKS) / sizeof(CHECKS[0]))
static unsigned long g_check_hits[CHECK_COUNT];

static char g_trace[128][160];
static unsigned int g_trace_len;
static void trace(const char *fmt, ...) {
    if (g_trace_len >= 128) return;
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(g_trace[g_trace_len], 160, fmt, ap);
    va_end(ap);
    g_trace_len++;
}

/* Records a failed check; prints the first three of each with the trace. */
static void fail(const char *check, const char *fmt, ...) {
    unsigned int k = 0;
    while (k < CHECK_COUNT && strcmp(CHECKS[k], check) != 0) k++;
    g_violations++;
    if (k < CHECK_COUNT && g_check_hits[k]++ >= 3) return;
    va_list ap;
    va_start(ap, fmt);
    printf("\n!!! %s seed=%llu case=%lu: ", check, (unsigned long long) g_seed, g_case_no);
    vprintf(fmt, ap);
    va_end(ap);
    printf("\n    uiState=%d screen=%s scr=%u/%u len=%u ix=%u armed=%d\n", uiState,
           g_ux_screen ? g_ux_screen : "-", curr_scr_ix, max_scr_ix, raw_tx_len, raw_tx_ix,
           tx_session_is_armed());
    for (unsigned int i = 0; i < g_trace_len; i++) printf("    %s\n", g_trace[i]);
    fflush(stdout);
}

static int is_review_state(int s) {
    return s == UI_TOP_SIGN || s == UI_TX_DESC_1 || s == UI_TX_DESC_2 || s == UI_SIGN || s == UI_DENY;
}

static sm_button_handler_t address_page_handler(void);

static sm_button_handler_t handler_for_state(int s) {
    switch (s) {
        case UI_IDLE: return bagl_ui_idle_nanos_button;
        case UI_TOP_SIGN: return bagl_ui_top_sign_nanos_button;
        case UI_TX_DESC_1: return bagl_ui_tx_desc_nanos_1_button;
        case UI_TX_DESC_2: return bagl_ui_tx_desc_nanos_2_button;
        case UI_SIGN: return bagl_ui_sign_nanos_button;
        case UI_DENY: return bagl_ui_deny_nanos_button;
        case UI_PUBLIC_KEY_1: return bagl_ui_public_key_nanos_1_button;
        case UI_PUBLIC_KEY_2: return bagl_ui_public_key_nanos_2_button;
        case UI_ADDRESS_CHECK: return address_page_handler();
        default: return NULL;
    }
}

/* ---- the display, as the Nano S SDK drives it ----------------------------------------------- */
int g_sm_status_sent;
unsigned int g_sm_button_event;

/* What the display holds: elements sent since the last redraw from the first, with their text
 * copied, as the SDK sends it with the element. */
#define MAX_FRAME 16
#define FRAME_TEXT 40
static bagl_element_t g_frame[MAX_FRAME];
static char g_frame_text[MAX_FRAME][FRAME_TEXT];
static const bagl_element_t *g_frame_from[MAX_FRAME];
static unsigned int g_frame_len;

void sm_on_display(const void *p) {
    const bagl_element_t *e = (const bagl_element_t *) p;
    if (g_frame_len >= MAX_FRAME) return;
    g_frame[g_frame_len] = *e;
    g_frame_from[g_frame_len] = e;
    if (e->text != NULL) {
        snprintf(g_frame_text[g_frame_len], FRAME_TEXT, "%s", (const char *) e->text);
        g_frame[g_frame_len].text = g_frame_text[g_frame_len];
    }
    g_frame_len++;
}

void sm_ux_redraw_started(void) {
    g_frame_len = 0;
}

static void deliver_event(unsigned char tag) {
    G_io_seproxyhal_spi_buffer[0] = tag;
    g_sm_status_sent = 0;
    io_event(0);
}

/* The MCU answers each element with a display-processed event, on which the app draws the next. */
#define MAX_DISPLAY_EVENTS 32
static unsigned int draw_events_allowed(void);
static void finish_drawing(void) {
    unsigned int allowed = draw_events_allowed();
    for (unsigned int k = 0; k < allowed && !UX_DISPLAYED(); k++) {
        deliver_event(SEPROXYHAL_TAG_DISPLAY_PROCESSED_EVENT);
    }
}

/* Fault: a case may skip one UX_DISPLAY store (layout, button handler or redraw index), so the
 * display and the live buttons can disagree with the app. */
#define SKIP_ODDS 16
static int g_skip_armed;
static unsigned long g_skipped_stores;
/* the screen the app last asked UX_DISPLAY for */
static const bagl_element_t *g_asked_layout;
static button_push_callback_t g_asked_handler;
/* set by any display fault, until the display and the app agree again */
static int g_display_fault;

/* Arms one display fault for half the cases. */
static void plan_display_faults(void) {
    side_state = rng_state ^ 0x5DEECE66Dull;
    g_skip_armed = side_rnd(2) == 0;
}

/* set by a G1 check: the store the next UX_DISPLAY skips */
static unsigned int g_forced_skip;

unsigned int sm_ux_store_to_skip(void) {
    if (g_forced_skip != SM_SKIP_NONE) {
        unsigned int store = g_forced_skip;
        g_forced_skip = SM_SKIP_NONE;
        return store;
    }
    // the recovery check at the end of each case runs without faults
    if (!g_skip_armed || (g_cur != NULL && g_cur->tail != TAIL_NONE) || side_rnd(SKIP_ODDS) != 0) {
        return SM_SKIP_NONE;
    }
    g_skip_armed = 0;
    g_display_fault = 1;
    g_skipped_stores++;
    static const char *const WHAT[] = {"", "layout", "button handler", "index the redraw starts from"};
    unsigned int store = SM_SKIP_LAYOUT + side_rnd(3);
    trace("  UX_DISPLAY skips storing the %s", WHAT[store]);
    return store;
}

/* uiState before a call G1 skips whole: the call's own store of uiState is undone */
static enum UI_STATE g_state_before_skipped_call;

void sm_ux_call_skipped(void) {
    uiState = g_state_before_skipped_call;
}

/* Fault: or cut one screen's drawing short; the next press draws the rest. */
static unsigned long g_cut_draws;
static unsigned int draw_events_allowed(void) {
    if (!g_skip_armed || (g_cur != NULL && g_cur->tail != TAIL_NONE) || side_rnd(SKIP_ODDS) != 0) {
        return MAX_DISPLAY_EVENTS;
    }
    g_skip_armed = 0;
    g_display_fault = 1;
    g_cut_draws++;
    unsigned int allowed = side_rnd(4);
    trace("  the display stops after %u more elements", allowed);
    return allowed;
}

/*
 * Fault: or skip the SDK call that sends one element of a review half, or of an address check
 * path, address or Approve page, which must then not count as drawn. Lower odds, since each
 * element is a chance. A G1 check can name the element.
 */
#define SEND_SKIP_ODDS (4 * SKIP_ODDS)
static unsigned long g_skipped_sends;
static const bagl_element_t *g_forced_send_skip;

static int element_in(const bagl_element_t *e, const bagl_element_t *layout, unsigned int count) {
    for (unsigned int k = 0; k < count; k++) {
        if (e == &layout[k]) return (int) k;
    }
    return -1;
}
#define ELEMENT_IN(e, layout) element_in(e, layout, sizeof(layout) / sizeof((layout)[0]))

static int drawn_element(const bagl_element_t *e) {
    const int k[] = {ELEMENT_IN(e, bagl_ui_tx_desc_nanos_1), ELEMENT_IN(e, bagl_ui_tx_desc_nanos_2),
                     ELEMENT_IN(e, bagl_ui_address_check_nanos_path),
                     ELEMENT_IN(e, bagl_ui_address_check_nanos_path_rest),
                     ELEMENT_IN(e, bagl_ui_address_check_nanos_address),
                     ELEMENT_IN(e, bagl_ui_address_check_nanos_address_rest),
                     ELEMENT_IN(e, bagl_ui_address_check_nanos_approve)};
    for (unsigned int i = 0; i < sizeof(k) / sizeof(k[0]); i++) {
        if (k[i] >= 0) return k[i];
    }
    return -1;
}

/* Called by the stub io_seproxyhal_display_default for every element: 1 skips the call. */
static int skip_display_send(const void *p) {
    const bagl_element_t *e = (const bagl_element_t *) p;
    if (g_forced_send_skip != NULL && e == g_forced_send_skip) {
        g_forced_send_skip = NULL;
        // the display may disagree with the app until a screen is drawn whole
        g_display_fault = 1;
        g_skipped_sends++;
        return 1;
    }
    int k = drawn_element(e);
    if (k < 0 || !g_skip_armed || (g_cur != NULL && g_cur->tail != TAIL_NONE) || side_rnd(SEND_SKIP_ODDS) != 0) {
        return 0;
    }
    g_skip_armed = 0;
    g_display_fault = 1;
    g_skipped_sends++;
    trace("  the display hook skips sending element %d of the screen of state %d", k, uiState);
    return 1;
}

/*
 * Fault: or skip once the drawing loop's check that nothing was sent for this event, so the next
 * element of a review half reaches the display hook with a status out and is never sent. The half
 * must not count as drawn. Own stream, so the other faults stay as they were.
 */
static unsigned long g_skipped_status_checks;
static const bagl_element_t *g_forced_status_skip;
static uint64_t g_status_skip_state;

static void plan_status_check_faults(void) {
    g_status_skip_state = rng_state ^ 0x2545F4914F6CDD1Dull;
}

/* Called by the stub drawing loop when a status is out and elements remain: 1 skips the check. */
int sm_ux_skip_status_check(void) {
    const bagl_element_t *next = &g_ux_elements[G_ux.stack[0].element_index];
    if (g_forced_status_skip != NULL && next == g_forced_status_skip) {
        g_forced_status_skip = NULL;
        return 1;
    }
    int k = drawn_element(next);
    if (k < 0 || !g_skip_armed || (g_cur != NULL && g_cur->tail != TAIL_NONE) ||
        mix_next(&g_status_skip_state) % SEND_SKIP_ODDS != 0) {
        return 0;
    }
    g_skip_armed = 0;
    g_display_fault = 1;
    g_skipped_status_checks++;
    trace("  the drawing loop skips its status check before element %d of the screen of state %d", k, uiState);
    return 1;
}

/*
 * A G1 check can skip one of the two read mark resets between a review ended by an SDK exception
 * and the next: in ui_idle or in ui_start_review. The marks are saved where nothing can change
 * them before that reset, and put back when the app asks for the screen after it.
 */
enum { RESET_NOT_SKIPPED = 0, RESET_IN_UI_IDLE, RESET_IN_START_REVIEW };
enum { SKIP_RESET_OFF = 0, SKIP_RESET_ARMED, SKIP_RESET_THROWN, SKIP_RESET_KEPT, SKIP_RESET_DONE };
/* which reset a check skips, and how far the skip has got */
static int g_reset_to_skip, g_reset_skip_state;
static volatile uint32_t *const READ_MARKS[] = {&review_complete, &review_seen_top, &review_seen_top_check,
                                                &review_seen_bottom, &review_seen_bottom_check,
                                                &accept_drawn, &accept_drawn_check};
#define READ_MARK_COUNT (sizeof(READ_MARKS) / sizeof(READ_MARKS[0]))
static uint32_t g_kept_marks[READ_MARK_COUNT];

static void keep_read_marks(void) {
    for (unsigned int i = 0; i < READ_MARK_COUNT; i++) g_kept_marks[i] = *READ_MARKS[i];
    g_reset_skip_state = SKIP_RESET_KEPT;
    trace("  the next reset of the read marks is skipped");
}

static void skip_reset_on_throw(void) {
    if (g_reset_skip_state != SKIP_RESET_ARMED) return;
    if (g_reset_to_skip == RESET_IN_UI_IDLE) {
        keep_read_marks();
    } else {
        g_reset_skip_state = SKIP_RESET_THROWN;
    }
}

static void skip_reset_on_screen(const bagl_element_t *layout) {
    if (g_reset_skip_state == SKIP_RESET_THROWN && layout == bagl_ui_idle_nanos) {
        keep_read_marks();
        return;
    }
    const bagl_element_t *after_reset =
        g_reset_to_skip == RESET_IN_UI_IDLE ? bagl_ui_idle_nanos : bagl_ui_top_sign_nanos;
    if (g_reset_skip_state != SKIP_RESET_KEPT || layout != after_reset) return;
    for (unsigned int i = 0; i < READ_MARK_COUNT; i++) *READ_MARKS[i] = g_kept_marks[i];
    g_reset_skip_state = SKIP_RESET_DONE;
}

void sm_ux_asked(const char *name, const bagl_element_t *layout, button_push_callback_t handler) {
    skip_reset_on_screen(layout);
    g_ux_screen = name;
    g_asked_layout = layout;
    g_asked_handler = handler;
}

/* True if the display holds layout in full, in order from its first element. */
static int frame_holds(const bagl_element_t *layout, unsigned int count) {
    if (layout == NULL || g_frame_len != count) return 0;
    for (unsigned int i = 0; i < count; i++) {
        if (g_frame_from[i] != &layout[i]) return 0;
    }
    return 1;
}

/* True when the display checks (M2, M3 screens, M5, L2) apply: always, or after a display fault
 * once the display and the app agree again. Signing checks apply whatever the display holds. */
static int display_in_step(void) {
    if (g_display_fault && g_ux_elements == g_asked_layout && g_ux_button == g_asked_handler &&
        frame_holds(g_asked_layout, g_ux_element_count) && g_ux_button == handler_for_state(uiState) &&
        is_review_state(uiState) == tx_session_is_armed() &&
        (uiState == UI_ADDRESS_CHECK) == address_check_pending) {
        g_display_fault = 0;
    }
    return !g_display_fault;
}

/* the last press, and whether the display showed Sign then */
static unsigned long g_press_mask;
static int g_press_saw_sign;

static void reset_display(void) {
    g_sm_status_sent = 0;
    g_sm_button_event = 0;
    g_frame_len = 0;
    G_ux.stack[0].element_index = 0;
    G_ux.stack[0].screen_before_element_display_callback = NULL;
    g_skip_armed = 0;
    g_display_fault = 0;
    g_asked_layout = NULL;
    g_asked_handler = NULL;
    g_press_mask = 0;
    g_press_saw_sign = 0;
}

/* True once every heading and line of every review screen was drawn, empty lines included: the
 * spec requires both halves of every screen before Sign works. */
static int all_screens_seen(const review_t *r) {
    for (unsigned int s = 0; s < r->screens; s++) {
        if (!r->seen_title[s]) return 0;
        for (unsigned int k = 0; k < MAX_TX_TEXT_LINES; k++) {
            if (!r->seen_line[s][k]) return 0;
        }
    }
    return 1;
}

/* bagl_element_t.comp indexes, as in ui.c's positional initializers */
#define EL_X 2
#define EL_Y 3
#define EL_WIDTH 4
#define EL_HEIGHT 5
#define EL_FG 9
#define EL_BG 10
#define EL_FONT 11
#define SCREEN_WIDTH 128
#define SCREEN_HEIGHT 32
/* a label's text starts LABEL_ASCENT rows above its y; the 11 px fonts are GLYPH_ROWS tall */
#define LABEL_ASCENT 9
#define GLYPH_ROWS 12
/* every Nano S text row; ROW_WIDTH is also the parser's line width */
#define ROW_X 10
#define ROW_WIDTH 108

/* Labels on the display, top to bottom. Returns how many; stores at most max. */
static unsigned int drawn_labels(const bagl_element_t *label[], unsigned int max) {
    const bagl_element_t *e = g_frame;
    unsigned int n = 0;
    for (unsigned int i = 0; i < g_frame_len; i++) {
        if (e[i].comp[0] != BAGL_LABELINE) continue;
        if (n < max) {
            unsigned int k = n;
            while (k > 0 && label[k - 1]->comp[EL_Y] > e[i].comp[EL_Y]) {
                label[k] = label[k - 1];
                k--;
            }
            label[k] = &e[i];
        }
        n++;
    }
    return n;
}

/* True if the display shows only this one text. */
static int frame_shows_only(const char *text) {
    const bagl_element_t *label[1];
    return drawn_labels(label, 1) == 1 && label[0]->text != NULL && strcmp(label[0]->text, text) == 0;
}

/* One text row: its text and font, white on black across the full row, inside the screen. */
static int row_ok(const bagl_element_t *l, const char *text, int font, const char *what, unsigned int k) {
    if (l->text == NULL || strcmp(l->text, text) != 0) {
        fail("M3", "row %u of %s draws the wrong text", k, what);
        return 0;
    }
    if ((l->comp[EL_FONT] & BAGL_FONT_ID_MASK) != font) {
        fail("M3", "row %u of %s has the wrong font", k, what);
        return 0;
    }
    if (l->comp[EL_FG] != 0xFFFFFF || l->comp[EL_BG] != 0x000000 || l->comp[EL_X] != ROW_X ||
        l->comp[EL_WIDTH] != ROW_WIDTH || l->comp[EL_Y] < LABEL_ASCENT ||
        l->comp[EL_Y] - LABEL_ASCENT + GLYPH_ROWS > SCREEN_HEIGHT) {
        fail("M3", "row %u of %s is not drawn white on black across the %u px row inside the screen", k,
             what, ROW_WIDTH);
        return 0;
    }
    return 1;
}

/* Black background first, and nothing drawn later covers a text row. A row's outer columns hold
 * no text (the arrows sit there), so they may be covered. */
static int paint_order_ok(const char *what) {
    const bagl_element_t *e = g_frame;
    if (g_frame_len == 0 || e[0].comp[0] != BAGL_RECTANGLE || e[0].comp[EL_X] != 0 ||
        e[0].comp[EL_Y] != 0 || e[0].comp[EL_WIDTH] != SCREEN_WIDTH || e[0].comp[EL_HEIGHT] != SCREEN_HEIGHT ||
        e[0].comp[EL_FG] != 0x000000) {
        fail("M3", "%s does not draw its black background first", what);
        return 0;
    }
    for (unsigned int i = 0; i < g_frame_len; i++) {
        if (e[i].comp[0] != BAGL_LABELINE) continue;
        int top = e[i].comp[EL_Y] - LABEL_ASCENT, bottom = top + GLYPH_ROWS - 1;
        int left = e[i].comp[EL_X] + 1, right = e[i].comp[EL_X] + e[i].comp[EL_WIDTH] - 2;
        for (unsigned int j = i + 1; j < g_frame_len; j++) {
            if (e[j].comp[0] == BAGL_LABELINE) continue;
            int x0 = e[j].comp[EL_X], x1 = x0 + e[j].comp[EL_WIDTH] - 1;
            int y0 = e[j].comp[EL_Y], y1 = y0 + e[j].comp[EL_HEIGHT] - 1;
            if (x0 <= right && x1 >= left && y0 <= bottom && y1 >= top) {
                fail("M3", "%s draws element %u over the text row drawn by element %u", what, j, i);
                return 0;
            }
        }
    }
    return 1;
}

static int two_rows_ok(const char *text0, int font0, const char *text1, int font1, const char *what) {
    const bagl_element_t *label[2];
    if (!paint_order_ok(what)) return 0;
    unsigned int n = drawn_labels(label, 2);
    if (n != 2) {
        fail("M3", "%s draws %u texts, not two", what, n);
        return 0;
    }
    if (!row_ok(label[0], text0, font0, what, 0) || !row_ok(label[1], text1, font1, what, 1)) return 0;
    // closer rows would let the lower row's background erase the bottom of the upper text
    if (label[1]->comp[EL_Y] - label[0]->comp[EL_Y] < GLYPH_ROWS) {
        fail("M3", "the lower row of %s erases the bottom of the upper row", what);
        return 0;
    }
    return 1;
}

/* Marks the shown half of screen s seen if it draws exactly its two texts: the bold heading and
 * line 0, or lines 1 and 2. */
static void mark_drawn(review_t *r, unsigned int s) {
    char what[48];
    int first_half = uiState == UI_TX_DESC_1;
    snprintf(what, sizeof(what), "review half %d of screen %u", uiState, s);
    int ok = first_half ? two_rows_ok(curr_review_title, BAGL_FONT_OPEN_SANS_EXTRABOLD_11px, curr_tx_desc[0],
                                      BAGL_FONT_OPEN_SANS_REGULAR_11px, what)
                        : two_rows_ok(curr_tx_desc[1], BAGL_FONT_OPEN_SANS_REGULAR_11px, curr_tx_desc[2],
                                      BAGL_FONT_OPEN_SANS_REGULAR_11px, what);
    if (!ok) return;
    if (first_half) {
        r->seen_title[s] = 1;
        r->seen_line[s][0] = 1;
    } else {
        r->seen_line[s][1] = 1;
        r->seen_line[s][2] = 1;
    }
}

/* ---- checks run after every action ---------------------------------------------------------- */
/* The device's address at 44'/2305'/0'/0/0, computed without the app's code. */
static char g_account_address[35];

/* The host build's key for path, computed without the app's code. */
static void compute_public_key(const unsigned int path[ELA_PATH_LEN], unsigned char w[ELA_PUBKEY_LEN]) {
    unsigned char raw[64];
    os_derive_bip32_no_throw(CX_CURVE_256R1, path, ELA_PATH_LEN, raw, NULL);
    w[0] = 4;
    for (int i = 1; i < 65; i++) w[i] = (unsigned char) (raw[i % 32] ^ i);
}

/* 44'/2305'/0'/0/1 and the address sm_program_hash() gives it, whose third line is too wide for
 * any screen, written out by hand as in the parser fuzzer. */
static const unsigned int WIDE_PATH[ELA_PATH_LEN] = {0x8000002C, 0x80000901, 0x80000000, 0, 1};
static const uint8_t WIDE_PROGRAM_HASH[ELA_PROGRAM_HASH_LEN] = {0x21, 0x69, 0x77, 0xba, 0x3c, 0xb8, 0xee,
                                                                0xaa, 0x0a, 0xb7, 0xf5, 0x43, 0x00, 0x18,
                                                                0xb1, 0x0e, 0x21, 0x16, 0x1f, 0x70, 0xd3};
static const char WIDE_ADDRESS[] = "ESmZsYAfnQEviw3sEmbGkoWWWWWWMNwWmm";
/* the key of WIDE_PATH, worked out once before the checks */
static unsigned char g_wide_key[ELA_PUBKEY_LEN];

/* The real program hash, but WIDE_ADDRESS's for the key of WIDE_PATH; failures pass through. */
static cx_err_t sm_program_hash(const uint8_t *pubkey, uint8_t *program_hash) {
    cx_err_t err = keys_program_hash(pubkey, program_hash);
    if (err == CX_OK && memcmp(pubkey, g_wide_key, ELA_PUBKEY_LEN) == 0) {
        memcpy(program_hash, WIDE_PROGRAM_HASH, ELA_PROGRAM_HASH_LEN);
    }
    return err;
}

static void compute_address(const unsigned int path[ELA_PATH_LEN], char out[35]) {
    static const char B58[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    unsigned char w[65], script[35], num[25], h1[32], h2[32];
    compute_public_key(path, w);
    script[0] = 33;
    script[1] = (w[64] & 1) ? 0x03 : 0x02;
    memcpy(script + 2, w + 1, 32);
    script[34] = 0xAC;
    sm_sha256(script, sizeof(script), h1);
    sm_sha256(h1, 32, h2);
    num[0] = 0x21;
    for (int i = 0; i < 20; i++) num[1 + i] = (unsigned char) (h2[i] ^ 0x3C);
    // as sm_program_hash() does in the app
    if (memcmp(w, g_wide_key, sizeof(w)) == 0) memcpy(num, WIDE_PROGRAM_HASH, ELA_PROGRAM_HASH_LEN);
    sm_sha256(num, 21, h1);
    sm_sha256(h1, 32, h2);
    memcpy(num + 21, h2, 4);
    char rev[40];
    unsigned int len = 0, nonzero;
    do {
        unsigned int rem = 0;
        nonzero = 0;
        for (int k = 0; k < 25; k++) {
            unsigned int cur = rem * 256 + num[k];
            num[k] = (unsigned char) (cur / 58);
            rem = cur % 58;
            nonzero |= num[k];
        }
        rev[len++] = B58[rem];
    } while (nonzero);
    for (unsigned int k = 0; k < len; k++) out[k] = rev[len - 1 - k];
    out[len] = '\0';
}

static void compute_account_address(void) {
    static const unsigned int path[5] = {0x8000002C, 0x80000901, 0x80000000, 0, 0};
    compute_address(path, g_account_address);
}

static const char *address_page_label(void);

/* M3: Review, Sign, Deny, idle and the one-label address check pages draw one bold label. */
static void check_fixed_screen(void) {
    const char *want = uiState == UI_TOP_SIGN ? "Review Tx"
                       : uiState == UI_SIGN   ? "Sign Tx"
                       : uiState == UI_DENY   ? "Deny Tx"
                       : uiState == UI_IDLE   ? "Elastos"
                                              : NULL;
    if (uiState == UI_ADDRESS_CHECK) want = address_page_label();
    if (want == NULL) return;
    const bagl_element_t *label[1];
    unsigned int n = drawn_labels(label, 1);
    if (n != 1 || label[0]->text == NULL || strcmp(label[0]->text, want) != 0 ||
        (label[0]->comp[EL_FONT] & BAGL_FONT_ID_MASK) != BAGL_FONT_OPEN_SANS_EXTRABOLD_11px ||
        label[0]->comp[EL_FG] != 0xFFFFFF || label[0]->comp[EL_BG] != 0x000000) {
        fail("M3", "screen for state %d does not draw exactly \"%s\" in bold, white on black", uiState, want);
        return;
    }
    // the black background first, and after the label only the arrow and cross icons
    const bagl_element_t *e = g_frame;
    if (e[0].comp[0] != BAGL_RECTANGLE || e[0].comp[EL_X] != 0 || e[0].comp[EL_Y] != 0 ||
        e[0].comp[EL_WIDTH] != SCREEN_WIDTH || e[0].comp[EL_HEIGHT] != SCREEN_HEIGHT || e[0].comp[EL_FG] != 0x000000) {
        fail("M3", "screen for state %d does not draw its black background first", uiState);
        return;
    }
    for (unsigned int j = (unsigned int) (label[0] - e) + 1; j < g_frame_len; j++) {
        if (e[j].comp[0] != BAGL_ICON) {
            fail("M3", "screen for state %d draws element %u over its label", uiState, j);
            return;
        }
    }
}

#define ADDRESS_LINES 3
static const unsigned int ADDRESS_LINE_START[ADDRESS_LINES] = {0, 11, 22};
static const unsigned int ADDRESS_LINE_SIZE[ADDRESS_LINES] = {11, 11, 12};

/* M3: the account screen shows the device's address as lines 1 and 2, then 2 and 3. */
static void check_account_screen(void) {
    if (uiState != UI_PUBLIC_KEY_1 && uiState != UI_PUBLIC_KEY_2) return;
    const unsigned int *starts = ADDRESS_LINE_START, *sizes = ADDRESS_LINE_SIZE;
    for (unsigned int k = 0; k < ADDRESS_LINES; k++) {
        if (strlen(current_public_key[k]) != sizes[k] ||
            memcmp(current_public_key[k], g_account_address + starts[k], sizes[k]) != 0) {
            fail("M3", "account screen line %u is \"%s\", not part of %s", k, current_public_key[k],
                 g_account_address);
            return;
        }
    }
    unsigned int first = uiState == UI_PUBLIC_KEY_1 ? 0 : 1;
    two_rows_ok(current_public_key[first], BAGL_FONT_OPEN_SANS_REGULAR_11px, current_public_key[first + 1],
                BAGL_FONT_OPEN_SANS_REGULAR_11px, "the account screen");
}

static void mark_seen(void) {
    if (!g_review.valid || !tx_session_is_armed()) return;
    if (uiState != UI_TX_DESC_1 && uiState != UI_TX_DESC_2) return;
    // only a half the display holds in full counts: a display fault can leave something else up
    if (uiState == UI_TX_DESC_1 ? !frame_holds(bagl_ui_tx_desc_nanos_1, sizeof(bagl_ui_tx_desc_nanos_1) /
                                                                        sizeof(bagl_ui_tx_desc_nanos_1[0]))
                                : !frame_holds(bagl_ui_tx_desc_nanos_2, sizeof(bagl_ui_tx_desc_nanos_2) /
                                                                        sizeof(bagl_ui_tx_desc_nanos_2[0]))) {
        return;
    }
    if (curr_scr_ix >= g_review.screens) {
        fail("M3", "review screen %u of %u", curr_scr_ix, g_review.screens);
        return;
    }
    if (memcmp(curr_tx_desc, g_review.desc[curr_scr_ix], sizeof(curr_tx_desc)) != 0) {
        fail("M3", "screen %u shows text that is not that screen's text", curr_scr_ix);
        return;
    }
    if (memcmp(curr_review_title, g_review.title[curr_scr_ix], sizeof(curr_review_title)) != 0) {
        fail("M3", "screen %u shows a heading that is not that screen's heading", curr_scr_ix);
        return;
    }
    mark_drawn(&g_review, curr_scr_ix);
}

static void check_address_check(int in_step);

static void after_step(const char *where) {
    if (raw_tx_ix > MAX_TX_RAW_LENGTH || raw_tx_len > MAX_TX_RAW_LENGTH ||
        max_scr_ix > MAX_TX_TEXT_SCREENS ||
        (max_scr_ix == 0 ? curr_scr_ix != 0 : curr_scr_ix >= max_scr_ix)) {
        fail("M1", "at %s: ix=%u len=%u scr=%u/%u", where, raw_tx_ix, raw_tx_len, curr_scr_ix,
             max_scr_ix);
    }
    int in_step = display_in_step();
    if (in_step && is_review_state(uiState) != tx_session_is_armed()) {
        fail("M2", "at %s: review on screen=%d, session armed=%d", where, is_review_state(uiState),
             tx_session_is_armed());
    }
    if (in_step && g_ux_button != handler_for_state(uiState)) {
        fail("M2", "at %s: buttons go to %s but uiState is %d", where, g_ux_screen, uiState);
    }
    if (in_step) {
        check_fixed_screen();
        check_account_screen();
    }
    check_address_check(in_step);
    mark_seen();
}

/* ---- the path rule (P1) --------------------------------------------------------------------- */
/* Not the app's keys_read_path, so a wrong decode there shows as B3 or P1. */
static void decode_path(const unsigned char *b, unsigned int path[ELA_PATH_LEN]) {
    for (int i = 0; i < ELA_PATH_LEN; i++) {
        const unsigned char *p = b + 4 * i;
        path[i] = ((unsigned int) p[0] << 24) | ((unsigned int) p[1] << 16) | ((unsigned int) p[2] << 8) | p[3];
    }
}

/* The path rule from APP_SPECIFICATION.md, not from keys.c. */
#define SPEC_HARDENED 0x80000000u
static int spec_allows_path(const unsigned char *b) {
    unsigned int p[ELA_PATH_LEN];
    decode_path(b, p);
    return p[0] == (SPEC_HARDENED | 44u) && p[1] == (SPEC_HARDENED | 2305u) && (p[2] & SPEC_HARDENED) != 0 &&
           (p[3] == 0 || p[3] == 1) && (p[4] & SPEC_HARDENED) == 0;
}

/* The spec's silent range for P1 00: account 0' to 100', index 0 to 50,000. */
#define SPEC_SILENT_LAST_ACCOUNT 100u
#define SPEC_SILENT_LAST_INDEX 50000u
static int spec_silent_path(const unsigned char *b) {
    unsigned int p[ELA_PATH_LEN];
    decode_path(b, p);
    return spec_allows_path(b) && p[2] - SPEC_HARDENED <= SPEC_SILENT_LAST_ACCOUNT && p[4] <= SPEC_SILENT_LAST_INDEX;
}

static void check_path_allowed(const char *what, const unsigned char *b) {
    unsigned int p[ELA_PATH_LEN];
    if (spec_allows_path(b)) return;
    decode_path(b, p);
    fail("P1", "%s follows the path %08x/%08x/%08x/%08x/%08x, which the specification refuses", what, p[0], p[1],
         p[2], p[3], p[4]);
}

/* the last command, if a five-part key request, and its path, for P1 */
static int g_key_request;
static unsigned char g_key_request_path[PATH_BYTES];

/* Called for every command that reaches the app. */
static void note_key_request(const unsigned char *apdu, unsigned int len) {
    g_key_request = len == 5 + PATH_BYTES && apdu[0] == 0x80 && apdu[1] == 0x04;
    if (g_key_request) memcpy(g_key_request_path, apdu + 5, PATH_BYTES);
}

/* ---- the address check (A1, A2, A3) -------------------------------------------------------- */
/* Key request rules from the spec, not from main.c or ui.c; see A1 and A2 above. */
#define KEY_P1_SILENT 0x00
#define KEY_P1_SHOW 0x01
#define SPEC_SW_OK 0x9000
#define SPEC_SW_WRONG_LENGTH 0x6700
#define SPEC_SW_REJECTED 0x6985
#define SPEC_SW_WRONG_P1P2 0x6A86
#define SPEC_SW_PATH_TOO_SHORT 0x6D09
#define SPEC_SW_BAD_PATH 0x6D58
#define SPEC_SW_TOO_WIDE 0x6D60
#define SPEC_SW_PATH_NEEDS_CHECK 0x6D63

/* The seven Nano S address check pages in order. PAGE_PATH_REST shows only for a path of more
 * than one line; label is the one label of a page that shows neither path nor address. */
#define ADDRESS_PAGES 7
#define PAGE_PATH 1
#define PAGE_PATH_REST 2
#define PAGE_LINES_1_2 3
#define PAGE_LINES_2_3 4
#define PAGE_APPROVE 5
#define PAGE_REJECT 6
#define PAGE_NONE (-1)
#define ADDRESS_PAGE_ENTRY(layout, label) {layout, sizeof(layout) / sizeof(bagl_element_t), layout##_button, label}
static const struct {
    const bagl_element_t *layout;
    unsigned int count;
    sm_button_handler_t handler;
    const char *label;
} ADDRESS_PAGE[ADDRESS_PAGES] = {
    ADDRESS_PAGE_ENTRY(bagl_ui_address_check_nanos_intro, "Verify address"),
    ADDRESS_PAGE_ENTRY(bagl_ui_address_check_nanos_path, NULL),
    ADDRESS_PAGE_ENTRY(bagl_ui_address_check_nanos_path_rest, NULL),
    ADDRESS_PAGE_ENTRY(bagl_ui_address_check_nanos_address, NULL),
    ADDRESS_PAGE_ENTRY(bagl_ui_address_check_nanos_address_rest, NULL),
    ADDRESS_PAGE_ENTRY(bagl_ui_address_check_nanos_approve, "Approve"),
    ADDRESS_PAGE_ENTRY(bagl_ui_address_check_nanos_reject, "Reject"),
};

/*
 * The path lines an address check shows, per the spec: decimal parts, ' when hardened, / between,
 * broken after the last / that fits so no number is cut. Packed part by part, not character by
 * character as in elastos.c. Returns the line count, or PATH_SHOWN_LINES + 1 if it does not fit.
 */
#define PATH_SHOWN_LINES 3
static unsigned int spec_path_lines(const unsigned char *b, char lines[PATH_SHOWN_LINES][MAX_TX_TEXT_WIDTH]) {
    unsigned int p[ELA_PATH_LEN], line = 0;
    decode_path(b, p);
    memset(lines, 0, PATH_SHOWN_LINES * MAX_TX_TEXT_WIDTH);
    for (int i = 0; i < ELA_PATH_LEN; i++) {
        char part[16], joined[2 * MAX_TX_TEXT_WIDTH];
        snprintf(part, sizeof(part), "%u%s%s", p[i] & ~SPEC_HARDENED, (p[i] & SPEC_HARDENED) ? "'" : "",
                 i + 1 < ELA_PATH_LEN ? "/" : "");
        snprintf(joined, sizeof(joined), "%s%s", lines[line], part);
        if (lines[line][0] != '\0' && (strlen(joined) > MAX_TX_TEXT_WIDTH - 1 || !line_fits(joined))) {
            if (++line == PATH_SHOWN_LINES) return PATH_SHOWN_LINES + 1;
            snprintf(joined, sizeof(joined), "%s", part);
        }
        snprintf(lines[line], MAX_TX_TEXT_WIDTH, "%s", joined);
    }
    return line + 1;
}

/* The last key request and the address check shown for it. */
static struct {
    int request;                        /* the last command was a key request */
    int replied;                        /* its reply was seen, at once or held */
    unsigned char p1, p2;
    unsigned int len;
    unsigned char path[PATH_BYTES];
    int state_before;                   /* uiState when it arrived */
    unsigned long faults_at_request;    /* display faults when it arrived */
    unsigned long derivations_at_request;  /* derivations when it arrived */
    int shown;                          /* its address check waits for the user */
    char address[sizeof(g_account_address)];  /* computed here */
    unsigned char key[ELA_PUBKEY_LEN];  /* computed here */
    char path_line[PATH_SHOWN_LINES][MAX_TX_TEXT_WIDTH];  /* computed here */
    unsigned int path_lines;            /* how many lines its path takes */
    unsigned char path_drawn[PATH_SHOWN_LINES];  /* path lines the display held in full */
    unsigned char line_drawn[ADDRESS_LINES];  /* address lines the display held in full */
    int answer_forced;                  /* answered by ACT_ANSWER_PENDING */
    int expect_idle;                    /* answered: the app must be idle */
    unsigned int shows, approved, rejected, unasked;  /* per case, for the checks run once */
} g_addr;
static unsigned long g_address_shown, g_address_approved, g_address_rejected, g_silent_refused;
/* Approve presses refused for undrawn lines, and approvals after a display fault */
static unsigned long g_approve_refused_undrawn, g_approved_after_fault;

static void reset_address_check(void) {
    address_check_pending = false;
    memset(address_check_path, 0, sizeof(address_check_path));
    memset(&g_addr, 0, sizeof(g_addr));
}

static int asked_address_page(void) {
    for (int p = 0; p < ADDRESS_PAGES; p++) {
        if (g_asked_layout == ADDRESS_PAGE[p].layout) return p;
    }
    return PAGE_NONE;
}

static sm_button_handler_t address_page_handler(void) {
    int p = asked_address_page();
    return p == PAGE_NONE ? NULL : ADDRESS_PAGE[p].handler;
}

static const char *address_page_label(void) {
    int p = asked_address_page();
    return p == PAGE_NONE ? NULL : ADDRESS_PAGE[p].label;
}

static int address_page_on_display(int p) {
    return frame_holds(ADDRESS_PAGE[p].layout, ADDRESS_PAGE[p].count);
}

static int held_address_page(void) {
    for (int p = 0; p < ADDRESS_PAGES; p++) {
        if (address_page_on_display(p)) return p;
    }
    return PAGE_NONE;
}

/* The spec's condition for Approve: every path and address line was drawn in full. */
static int check_lines_all_drawn(void) {
    for (unsigned int k = 0; k < g_addr.path_lines && k < PATH_SHOWN_LINES; k++) {
        if (!g_addr.path_drawn[k]) return 0;
    }
    return g_addr.line_drawn[0] && g_addr.line_drawn[1] && g_addr.line_drawn[2];
}

static unsigned int reply_status(unsigned short tx_len) {
    return tx_len >= 2 ? ((unsigned int) G_io_apdu_buffer[tx_len - 2] << 8) | G_io_apdu_buffer[tx_len - 1] : 0;
}

static void address_line(const char *address, unsigned int k, char line[MAX_TX_TEXT_WIDTH]) {
    memset(line, 0, MAX_TX_TEXT_WIDTH);
    memcpy(line, address + ADDRESS_LINE_START[k], ADDRESS_LINE_SIZE[k]);
}

/* Uses the app's width table, which the parser fuzzer checks. */
static int address_too_wide(const char *address) {
    char line[MAX_TX_TEXT_WIDTH];
    for (unsigned int k = 0; k < ADDRESS_LINES; k++) {
        address_line(address, k, line);
        if (!line_fits(line)) return 1;
    }
    return 0;
}

static unsigned long display_faults(void) {
    return g_skipped_stores + g_cut_draws + g_skipped_sends + g_skipped_status_checks;
}

/* A display fault since the request. Only Approve is hardened against them, so the other
 * address check display rules are skipped then. */
static int address_check_faulted(void) {
    return display_faults() != g_addr.faults_at_request;
}

/* A P1 00 request for an allowed path outside the silent range, which the spec refuses. */
static int key_request_needs_check(unsigned char p1, unsigned char p2, unsigned int len, const unsigned char *path) {
    return p1 == KEY_P1_SILENT && p2 == 0 && len == 5 + PATH_BYTES && spec_allows_path(path) && !spec_silent_path(path);
}

/* True if the spec refuses this key request. */
static int key_request_refused(unsigned char p1, unsigned char p2, unsigned int len, const unsigned char *path) {
    return (p1 != KEY_P1_SILENT && p1 != KEY_P1_SHOW) || p2 != 0 || len != 5 + PATH_BYTES || !spec_allows_path(path) ||
           key_request_needs_check(p1, p2, len, path);
}

/* Called for every command that reaches the app. */
static void note_address_request(const unsigned char *apdu, unsigned int len) {
    g_addr.request = len >= 5 && apdu[0] == 0x80 && apdu[1] == 0x04;
    g_addr.replied = 0;
    if (!g_addr.request) return;
    g_addr.p1 = apdu[2];
    g_addr.p2 = apdu[3];
    g_addr.len = len;
    memset(g_addr.path, 0, sizeof(g_addr.path));
    if (len == 5 + PATH_BYTES) memcpy(g_addr.path, apdu + 5, PATH_BYTES);
    g_addr.state_before = uiState;
    g_addr.faults_at_request = display_faults();
    g_addr.derivations_at_request = g_derivations;
}

/* A refused command shows nothing: nothing waits, and the screen is as before, or idle if it was
 * a review or address check page with nothing waiting, which a command closes. */
static void expect_nothing_shown(const char *check, int state_before, const char *what) {
    int closed = is_review_state(state_before) || state_before == UI_ADDRESS_CHECK;
    int want = closed ? UI_IDLE : state_before;
    if (uiState != want || tx_session_is_armed() || address_check_pending) {
        fail(check, "%s left uiState %d, not %d, with a review %s and an address check %s", what, uiState, want,
             tx_session_is_armed() ? "armed" : "not armed", address_check_pending ? "pending" : "not pending");
    }
}

/* A1: the reply a key request gets at once. */
static void check_key_reply_at_once(unsigned short tx_len) {
    unsigned int sw = reply_status(tx_len);
    unsigned int path[ELA_PATH_LEN];
    g_addr.replied = 1;
    if (uiState == UI_ADDRESS_CHECK) {
        fail("A1", "a key request with P1 %02x was answered at once with an address check on screen", g_addr.p1);
    }
    if (tx_session_is_receiving()) {
        fail("A1", "a key request with P1 %02x was answered with a transaction still being received", g_addr.p1);
    }
    if ((g_addr.p1 != KEY_P1_SILENT && g_addr.p1 != KEY_P1_SHOW) || g_addr.p2 != 0) {
        if (tx_len != 2 || sw != SPEC_SW_WRONG_P1P2) {
            fail("A1", "a key request with P1 %02x and P2 %02x got %u bytes, status %04X, not 6A86", g_addr.p1,
                 g_addr.p2, tx_len, sw);
        }
        return;
    }
    // the length is the bytes received, not Lc, which the wallet sends as 00
    if (g_addr.len > 5 + PATH_BYTES && (tx_len != 2 || sw != SPEC_SW_WRONG_LENGTH)) {
        fail("A1", "a key request of %u bytes, more than its 20 path bytes, got %u bytes, status %04X, not 6700",
             g_addr.len, tx_len, sw);
    }
    if (g_addr.len < 5 + PATH_BYTES && (tx_len != 2 || sw != SPEC_SW_PATH_TOO_SHORT)) {
        fail("A1", "a key request of %u bytes, fewer than its 20 path bytes, got %u bytes, status %04X, not 6D09",
             g_addr.len, tx_len, sw);
    }
    // the order is 6A86, then 6D09 or 6700, then 6D58, then 6D63
    if (g_addr.len == 5 + PATH_BYTES && !spec_allows_path(g_addr.path) &&
        (tx_len != 2 || sw != SPEC_SW_BAD_PATH)) {
        decode_path(g_addr.path, path);
        fail("A1", "a P1 %02x request for %08x/%08x/%08x/%08x/%08x, which the path rule refuses, got %u bytes, "
                   "status %04X, not 6D58", g_addr.p1, path[0], path[1], path[2], path[3], path[4], tx_len, sw);
    }
    // outside the silent range a key is read only through the address check; derive nothing
    if (key_request_needs_check(g_addr.p1, g_addr.p2, g_addr.len, g_addr.path)) {
        g_silent_refused++;
        decode_path(g_addr.path, path);
        if (tx_len != 2 || sw != SPEC_SW_PATH_NEEDS_CHECK) {
            fail("A1", "a P1 00 request for %08x/%08x/%08x/%08x/%08x, outside the silent range, got %u bytes, status "
                       "%04X, not 6D63", path[0], path[1], path[2], path[3], path[4], tx_len, sw);
        }
        if (g_derivations != g_addr.derivations_at_request) {
            fail("A1", "a P1 00 request outside the silent range derived %lu keys; it must derive none",
                 g_derivations - g_addr.derivations_at_request);
        }
        expect_nothing_shown("A1", g_addr.state_before, "a P1 00 request outside the silent range");
        return;
    }
    if (key_request_refused(g_addr.p1, g_addr.p2, g_addr.len, g_addr.path)) {
        if (tx_len != 2 || sw == SPEC_SW_OK) {
            fail("A1", "a key request of %u bytes, or on a path the specification refuses, got %u bytes, status %04X",
                 g_addr.len, tx_len, sw);
        }
        return;
    }
    decode_path(g_addr.path, path);
    if (g_addr.p1 == KEY_P1_SHOW) {
        char address[sizeof(g_account_address)];
        compute_address(path, address);
        if (tx_len != 2 || sw != SPEC_SW_TOO_WIDE || !address_too_wide(address)) {
            fail("A1", "a P1 01 request for %s got %u bytes, status %04X, at once instead of showing the address",
                 address, tx_len, sw);
        }
        expect_nothing_shown("A1", g_addr.state_before, "a P1 01 request refused at once");
        return;
    }
    unsigned char key[ELA_PUBKEY_LEN];
    compute_public_key(path, key);
    if (tx_len != PUB_REPLY_LEN || sw != SPEC_SW_OK || memcmp(G_io_apdu_buffer, key, ELA_PUBKEY_LEN) != 0) {
        fail("A1", "a P1 00 request got %u bytes, status %04X, not the key of exactly its path", tx_len, sw);
    }
    // it closes a review or address check page a display fault left; other screens stay
    int dead = is_review_state(g_addr.state_before) || g_addr.state_before == UI_ADDRESS_CHECK;
    if (uiState != (dead ? UI_IDLE : g_addr.state_before)) {
        fail("A1", "a P1 00 request changed the screen from state %d to %d", g_addr.state_before, uiState);
    }
}

/* Called when the app holds its reply to a key request: an address check must be on screen. */
static void take_address_snapshot(void) {
    unsigned int path[ELA_PATH_LEN];
    g_addr.replied = 1;
    if (g_addr.p1 != KEY_P1_SHOW || g_addr.p2 != 0 || g_addr.len != 5 + PATH_BYTES) {
        fail("A1", "a key request with P1 %02x, P2 %02x and %u bytes waits for the user; only P1 01 on a five-part "
                   "path shows its address", g_addr.p1, g_addr.p2, g_addr.len);
    }
    check_path_allowed("an address check", g_addr.path);
    decode_path(g_addr.path, path);
    compute_address(path, g_addr.address);
    compute_public_key(path, g_addr.key);
    g_addr.path_lines = spec_path_lines(g_addr.path, g_addr.path_line);
    if (g_addr.path_lines > PATH_SHOWN_LINES) {
        fail("A1", "an address check is shown for a path whose lines do not fit the screen");
    }
    if (address_too_wide(g_addr.address)) {
        fail("A1", "the address %s, with a line too wide for the screen, is shown rather than refused with 6D60",
             g_addr.address);
    }
    if (uiState != UI_ADDRESS_CHECK || !address_check_pending) {
        fail("A3", "a key request waits for the user with uiState %d and an address check %s", uiState,
             address_check_pending ? "pending" : "not pending");
    }
    memset(g_addr.line_drawn, 0, sizeof(g_addr.line_drawn));
    memset(g_addr.path_drawn, 0, sizeof(g_addr.path_drawn));
    g_addr.shown = 1;
    g_addr.shows++;
    g_address_shown++;
    trace("  address check shown: %s", g_addr.address);
}

/* A2: a reply sent with IO_RETURN_AFTER_TX, answering a command held for the user. */
static void check_address_answer(unsigned short tx_len) {
    unsigned int sw = reply_status(tx_len);
    int is_key = tx_len == PUB_REPLY_LEN && G_io_apdu_buffer[0] == 0x04 && sw == SPEC_SW_OK;
    int forced = g_addr.answer_forced;
    g_addr.answer_forced = 0;
    if (!g_addr.shown) {
        // a review is never answered with a key, and 6985 with nothing waiting is a stray Reject
        g_addr.unasked++;
        if (is_key || (sw == SPEC_SW_REJECTED && !g_reply_pending)) {
            fail("A2", "an answer of %u bytes, status %04X, with no address check waiting and %s", tx_len, sw,
                 g_reply_pending ? "a review waiting" : "no command waiting");
        }
        return;
    }
    // after a display fault the app may be off the check, so it need not return to idle
    int faulted = address_check_faulted() || !display_in_step();
    g_addr.shown = 0;
    g_addr.expect_idle = !faulted;
    // its key request ended any transaction, and none can start while it waits
    if (tx_session_is_receiving()) {
        fail("A3", "the address check was answered with a transaction still being received");
    }
    if (forced) {
        if (tx_len != 2 || sw != SPEC_SW_REJECTED) {
            fail("A2", "Reject called on the address check sent %u bytes, status %04X, not 6985", tx_len, sw);
        }
        return;
    }
    if (g_via == VIA_RAW) {
        // the review's approval, called whatever is on screen, may end the check, never with a key
        if (is_key) fail("A2", "the review's approval answered the address check with a key");
        return;
    }
    if (g_via != VIA_BUTTON || g_press_mask != (BUTTON_LEFT | BUTTON_RIGHT)) {
        fail("A2", "the address check was answered by button %lu, not by both", g_press_mask);
        return;
    }
    if (is_key) {
        g_addr.approved++;
        g_address_approved++;
        if (memcmp(G_io_apdu_buffer, g_addr.key, ELA_PUBKEY_LEN) != 0) {
            fail("A2", "Approve sent a key other than the key of the path whose address %s was shown", g_addr.address);
        }
        // the app's own rule, so it holds after a display fault too
        if (faulted) g_approved_after_fault++;
        if (!address_page_on_display(PAGE_APPROVE)) {
            fail("A2", "both buttons approved the address check while the display did not hold Approve");
        } else if (!check_lines_all_drawn()) {
            fail("A2", "Approve before the whole path and address were drawn: path lines drawn %d %d %d of %u, "
                       "address lines drawn %d %d %d", g_addr.path_drawn[0], g_addr.path_drawn[1],
                 g_addr.path_drawn[2], g_addr.path_lines, g_addr.line_drawn[0], g_addr.line_drawn[1],
                 g_addr.line_drawn[2]);
        }
        if (faulted) return;
        if (g_ux_button != ADDRESS_PAGE[PAGE_APPROVE].handler) {
            fail("A2", "both buttons approved the address check while another page's buttons were live");
        }
    } else if (tx_len == 2 && sw == SPEC_SW_REJECTED) {
        g_addr.rejected++;
        g_address_rejected++;
        if (!faulted && (!address_page_on_display(PAGE_REJECT) || g_ux_button != ADDRESS_PAGE[PAGE_REJECT].handler)) {
            fail("A2", "both buttons rejected the address check while the display did not hold Reject");
        }
    } else {
        fail("A2", "the address check was answered with %u bytes, status %04X, neither its key nor 6985", tx_len, sw);
    }
}

/* Called at the start of every exchange: A3 after an SDK exception, then A1 or A2. */
static void check_address_exchange(unsigned char channel, unsigned short tx_len) {
    if (g_after_fault != AFTER_NONE) {
        // the exception ended the request and its check; exempt after a display fault
        int faulted = g_addr.shown && address_check_faulted();
        g_addr.request = 0;
        g_addr.shown = 0;
        if (!faulted && (address_check_pending || uiState == UI_ADDRESS_CHECK)) {
            fail("A3", "after an SDK error an address check is still %s",
                 address_check_pending ? "pending" : "on screen");
        }
    }
    if (tx_len == 0) return;
    if (channel & IO_RETURN_AFTER_TX) {
        check_address_answer(tx_len);
    } else if (g_addr.request && !g_addr.replied) {
        check_key_reply_at_once(tx_len);
    }
}

/* After every action: A3, and M3 for the path and address pages. */
static void check_address_check(int in_step) {
    if (g_addr.expect_idle && !g_exited) {
        g_addr.expect_idle = 0;
        if (uiState != UI_IDLE || address_check_pending) {
            fail("A3", "after its answer the address check left uiState %d with a check %s", uiState,
                 address_check_pending ? "pending" : "not pending");
        }
    }
    // a display fault can move the app off a pending check, or back onto an answered one
    if (in_step && address_check_pending != (uiState == UI_ADDRESS_CHECK)) {
        fail("A3", "uiState %d with an address check %s", uiState, address_check_pending ? "pending" : "not pending");
    }
    if (in_step && g_addr.shown && !address_check_faulted() && uiState != UI_ADDRESS_CHECK) {
        fail("A3", "the address check left the screen without an answer, for uiState %d", uiState);
    }
    // a page counts as drawn once the display holds it in full, whatever the app asked for, so the
    // Approve rule holds after a display fault too
    int p = g_addr.shown ? held_address_page() : PAGE_NONE;
    if (p == PAGE_PATH) {
        if (two_rows_ok("Path", BAGL_FONT_OPEN_SANS_EXTRABOLD_11px, g_addr.path_line[0],
                        BAGL_FONT_OPEN_SANS_REGULAR_11px, "the first page of the path of an address check")) {
            g_addr.path_drawn[0] = 1;
        }
    } else if (p == PAGE_PATH_REST) {
        if (two_rows_ok(g_addr.path_line[1], BAGL_FONT_OPEN_SANS_REGULAR_11px, g_addr.path_line[2],
                        BAGL_FONT_OPEN_SANS_REGULAR_11px, "the second page of the path of an address check")) {
            g_addr.path_drawn[1] = g_addr.path_drawn[2] = 1;
        }
    } else if (p == PAGE_LINES_1_2 || p == PAGE_LINES_2_3) {
        unsigned int first = p == PAGE_LINES_1_2 ? 0 : 1;
        char top[MAX_TX_TEXT_WIDTH], bottom[MAX_TX_TEXT_WIDTH];
        address_line(g_addr.address, first, top);
        address_line(g_addr.address, first + 1, bottom);
        if (two_rows_ok(top, BAGL_FONT_OPEN_SANS_REGULAR_11px, bottom, BAGL_FONT_OPEN_SANS_REGULAR_11px,
                        "an address check page")) {
            g_addr.line_drawn[first] = g_addr.line_drawn[first + 1] = 1;
        }
    }
}

/* ---- failed key derivations and signatures (F1) --------------------------------------------- */
/*
 * Now and then one crypto step fails for one command or press, after writing its output, the
 * worst case. The spec answers 6D5F with no data, nothing on screen or pending, nothing signed.
 * Written from the spec, not from main.c, ui.c or tx_session.c.
 */
#define SPEC_SW_CRYPTO_FAILED 0x6D5F
enum {
    FAIL_NONE = 0, FAIL_KEY_SILENT, FAIL_KEY_SHOW, FAIL_SIGN_REQUEST, FAIL_ADDRESS_APPROVE, FAIL_REVIEW_ACCEPT,
    FAIL_KINDS
};
static const char *const FAIL_KIND[FAIL_KINDS] = {"", "a P1 00 key request", "a P1 01 key request",
                                                  "the last part of a sign request", "Approve on an address check",
                                                  "Accept on a review"};
enum { SWITCH_DERIVE, SWITCH_INIT_KEY, SWITCH_PAIR, SWITCH_PROGRAM_HASH, SWITCH_SIGN, SWITCHES };
static int *const FAIL_SWITCH[SWITCHES] = {&g_fail_derive, &g_fail_init_key, &g_fail_pair, &g_fail_ripemd,
                                           &g_fail_sign};
static const char *const SWITCH_NAME[SWITCHES] = {"the derivation", "the private key's setup", "the public key",
                                                  "the program hash", "the signature"};
/* The steps each reaches: all derive a key; Accept signs where the others make the public key;
 * P1 01 and sign requests also hash the key's address. */
#define KEY_SWITCHES ((1u << SWITCH_DERIVE) | (1u << SWITCH_INIT_KEY) | (1u << SWITCH_PAIR))
static const unsigned int FAIL_REACHES[FAIL_KINDS] = {
    0, KEY_SWITCHES, KEY_SWITCHES | (1u << SWITCH_PROGRAM_HASH), KEY_SWITCHES | (1u << SWITCH_PROGRAM_HASH),
    KEY_SWITCHES, (1u << SWITCH_DERIVE) | (1u << SWITCH_INIT_KEY) | (1u << SWITCH_SIGN)};
/* One in this many of each fails: each fails often enough without starving the other checks. */
static const unsigned int FAIL_ODDS[FAIL_KINDS] = {0, 4, 16, 32, 8, 16};

static struct {
    int kind;                    /* what the switch on is for, or FAIL_NONE */
    int sw;                      /* the switch on */
    int state_before;            /* uiState when it went on */
    unsigned long sigs;          /* signatures when it went on */
    int forced_kind, forced_sw;  /* set by check_crypto_failures */
    int random;                  /* the case may fail one now and then */
    uint64_t state;              /* own stream, so scripts and display faults stay the same */
} g_crypto;
static unsigned long g_crypto_faults[FAIL_KINDS], g_crypto_answers;

static void reset_crypto_faults(void) {
    for (int k = 0; k < SWITCHES; k++) *FAIL_SWITCH[k] = 0;
    memset(&g_crypto, 0, sizeof(g_crypto));
}

static void plan_crypto_faults(void) {
    g_crypto.state = rng_state ^ 0xC3A5C85C97CB3127ull;
    g_crypto.random = 1;
}

/* Turns one failure on for what is about to reach the app; never in the recovery tail. */
static void arm_crypto_fault(int kind) {
    int sw;
    if (kind == FAIL_NONE || (g_cur != NULL && g_cur->tail != TAIL_NONE)) return;
    if (g_crypto.forced_kind == kind) {
        sw = g_crypto.forced_sw;
        g_crypto.forced_kind = FAIL_NONE;
    } else if (g_crypto.random && mix_next(&g_crypto.state) % FAIL_ODDS[kind] == 0) {
        do {
            sw = (int) (mix_next(&g_crypto.state) % SWITCHES);
        } while ((FAIL_REACHES[kind] & (1u << sw)) == 0);
    } else {
        return;
    }
    g_crypto.kind = kind;
    g_crypto.sw = sw;
    g_crypto.state_before = uiState;
    g_crypto.sigs = g_sigs_button + g_sigs_raw;
    *FAIL_SWITCH[sw] = 1;
    g_crypto_faults[kind]++;
    trace("  %s fails for %s", SWITCH_NAME[sw], FAIL_KIND[kind]);
}

/* The F1 kind of a command: an allowed key request, or the exact last part of a corpus transfer
 * with nothing being received, whose key is derived before anything can refuse it. */
static int command_fail_kind(const unsigned char *apdu, unsigned int len) {
    if (len >= 5 && apdu[0] == 0x80 && apdu[1] == 0x04) {
        if (key_request_refused(apdu[2], apdu[3], len, apdu + 5)) return FAIL_NONE;
        return apdu[2] == KEY_P1_SILENT ? FAIL_KEY_SILENT : FAIL_KEY_SHOW;
    }
    if (tx_session_is_receiving()) return FAIL_NONE;
    for (unsigned int k = 0; k < LEGIT_COUNT; k++) {
        const corpus_apdu_t *last = &CORPUS[LEGIT_FIRST[k] + LEGIT_PARTS[k] - 1];
        if (len == last->n && len > 5 + PATH_BYTES && memcmp(apdu, last->p, len) == 0) return FAIL_SIGN_REQUEST;
    }
    return FAIL_NONE;
}

/* True if both buttons now must approve the address check shown. */
static int address_approve_ready(void) {
    return g_addr.shown && address_check_pending && !address_check_faulted() && display_in_step() &&
           uiState == UI_ADDRESS_CHECK && asked_address_page() == PAGE_APPROVE &&
           address_page_on_display(PAGE_APPROVE) && check_lines_all_drawn();
}

static int press_fail_kind(int review_ready) {
    if (review_ready) return FAIL_REVIEW_ACCEPT;
    if (address_approve_ready()) return FAIL_ADDRESS_APPROVE;
    return FAIL_NONE;
}

/* Before a both-buttons press: returns the kind now failing, or FAIL_NONE. */
static int arm_crypto_fault_for_press(int review_ready) {
    arm_crypto_fault(press_fail_kind(review_ready));
    return g_crypto.kind;
}

/* F1, at the start of every exchange: with a failure on, this is its answer. Returns 1 then, so
 * A1 and A2 leave it to F1. */
static int check_crypto_fault_answer(unsigned char channel, unsigned short tx_len) {
    int kind = g_crypto.kind, press = kind == FAIL_ADDRESS_APPROVE || kind == FAIL_REVIEW_ACCEPT;
    unsigned int sw = reply_status(tx_len);
    if (kind == FAIL_NONE) return 0;
    *FAIL_SWITCH[g_crypto.sw] = 0;
    g_crypto.kind = FAIL_NONE;
    g_crypto_answers++;
    if (tx_len != 2 || sw != SPEC_SW_CRYPTO_FAILED || (channel & IO_ASYNCH_REPLY) ||
        press != ((channel & IO_RETURN_AFTER_TX) != 0)) {
        fail("F1", "%s with %s failing got %u bytes, status %04X%s, not 6D5F alone", FAIL_KIND[kind],
             SWITCH_NAME[g_crypto.sw], tx_len, sw, (channel & IO_ASYNCH_REPLY) ? ", and waits for the user" : "");
    }
    if (g_sigs_button + g_sigs_raw != g_crypto.sigs) {
        fail("F1", "%s with %s failing signed", FAIL_KIND[kind], SWITCH_NAME[g_crypto.sw]);
    }
    if (kind == FAIL_ADDRESS_APPROVE) {
        // the answer ends the check, as A2's would
        g_addr.shown = 0;
        g_addr.expect_idle = 1;
    } else if (!press) {
        g_addr.replied = 1;
        expect_nothing_shown("F1", g_crypto.state_before, FAIL_KIND[kind]);
    }
    return 1;
}

/* F1 after a failing press: an answer was sent and the app is idle with nothing left. */
static void check_crypto_fault_press(int kind) {
    if (kind == FAIL_NONE) return;
    if (g_crypto.kind != FAIL_NONE) {
        fail("F1", "%s with %s failing sent no answer", FAIL_KIND[kind], SWITCH_NAME[g_crypto.sw]);
        *FAIL_SWITCH[g_crypto.sw] = 0;
        g_crypto.kind = FAIL_NONE;
        return;
    }
    if (uiState != UI_IDLE || tx_session_is_armed() || address_check_pending) {
        fail("F1", "after %s failed, uiState %d, with a review %s and an address check %s", FAIL_KIND[kind], uiState,
             tx_session_is_armed() ? "armed" : "not armed", address_check_pending ? "pending" : "not pending");
    }
}

/* ---- the reply stream ----------------------------------------------------------------------- */
static void record_response(unsigned short tx_len) {
    unsigned int sw = tx_len >= 2 ? (G_io_apdu_buffer[tx_len - 2] << 8) | G_io_apdu_buffer[tx_len - 1] : 0;
    int is_sig = tx_len == SIG_REPLY_LEN && G_io_apdu_buffer[0] == 0x30 && G_io_apdu_buffer[1] == 0x22 &&
                 sw == 0x9000;
    int is_pub = tx_len == PUB_REPLY_LEN && G_io_apdu_buffer[0] == 0x04 && sw == 0x9000;
    trace("  reply len=%u sw=%04X%s%s", tx_len, sw, is_sig ? " SIGNATURE" : "", is_pub ? " KEY" : "");

    if (tx_len != 2 && !is_sig && !is_pub) {
        fail("M4", "reply of %u bytes is neither a status word, a key nor a signature", tx_len);
    }
    if (is_sig && memcmp(G_io_apdu_buffer + 4, g_last_signed, DIGEST_LEN) != 0) {
        fail("M4", "signature reply does not carry the digest that was just signed");
    }
    if (is_pub && !g_key_request) fail("P1", "a key reply answers a command that is not a five-part key request");
    if (is_pub && g_key_request) check_path_allowed("a key reply", g_key_request_path);
    if (g_expect_pub) {
        g_expect_pub = 0;
        g_tail_pub_ok = is_pub;
    }
}

/* ---- capture what the user is about to review ----------------------------------------------- */
static void derive_key_for(const unsigned char *path_bytes, unsigned char key[KEY_LEN]) {
    unsigned int path[ELA_PATH_LEN];
    unsigned char raw[64];
    decode_path(path_bytes, path);
    os_derive_bip32_no_throw(CX_CURVE_256R1, path, ELA_PATH_LEN, raw, NULL);
    memcpy(key, raw, KEY_LEN);
}

/* B5: parses the committed bytes afresh and compares with the review. */
static void reparse(review_t *r) {
    unsigned int sav_ix = raw_tx_ix, sav_len = raw_tx_len, sav_max = max_scr_ix, sav_curr = curr_scr_ix;
    char sav_desc[MAX_TX_TEXT_SCREENS][MAX_TX_TEXT_LINES][MAX_TX_TEXT_WIDTH];
    char sav_title[MAX_TX_TEXT_SCREENS][MAX_TX_TEXT_WIDTH];
    memcpy(sav_desc, tx_desc, sizeof(tx_desc));
    memcpy(sav_title, review_title, sizeof(review_title));

    unsigned int path[ELA_PATH_LEN];
    uint8_t pub[ELA_PUBKEY_LEN], ph[ELA_PROGRAM_HASH_LEN];
    keys_read_path(raw_tx + r->body_len, path);
    keys_get_public_key(path, pub);
    keys_program_hash(pub, ph);

    memset(tx_desc, 0, sizeof(tx_desc));
    memset(review_title, 0, sizeof(review_title));
    max_scr_ix = 0;
    raw_tx_len = r->body_len + PATH_BYTES;
    if (tx_parse_and_render(ph) == SW_OK) {
        r->reparse_ok = 1;
        r->content_match = max_scr_ix == r->screens && memcmp(tx_desc, r->desc, sizeof(tx_desc)) == 0 &&
                           memcmp(review_title, r->title, sizeof(review_title)) == 0;
    } else {
        r->reparse_ok = 0;
    }

    memcpy(tx_desc, sav_desc, sizeof(tx_desc));
    memcpy(review_title, sav_title, sizeof(review_title));
    raw_tx_ix = sav_ix;
    raw_tx_len = sav_len;
    max_scr_ix = sav_max;
    curr_scr_ix = sav_curr;
}

/* Called when the app holds its reply for a review. */
static void take_snapshot(void) {
    review_t *r = &g_review;
    g_reviews++;
    memset(r, 0, sizeof(*r));
    trace("  review armed: %u screens", max_scr_ix);
    if (max_scr_ix == MAX_TX_TEXT_SCREENS) g_full_reviews++;
    if (!tx_session_is_armed() || uiState != UI_TOP_SIGN) {
        fail("M2", "review-pending reply without an armed review on screen");
        return;
    }
    if (raw_tx_len <= PATH_BYTES || raw_tx_len > MAX_TX_RAW_LENGTH) {
        fail("M1", "armed with raw_tx_len=%u", raw_tx_len);
        return;
    }
    r->valid = 1;
    r->is_tail = g_cur != NULL && g_cur->tail == TAIL_SIGN;
    r->body_len = raw_tx_len - PATH_BYTES;
    sm_sha256(raw_tx, r->body_len, r->digest);
    derive_key_for(raw_tx + r->body_len, r->key);
    check_path_allowed("a review", raw_tx + r->body_len);
    memcpy(r->desc, tx_desc, sizeof(tx_desc));
    memcpy(r->title, review_title, sizeof(review_title));
    r->screens = max_scr_ix;
    for (unsigned int s = 0; s < r->screens; s++) {
        if (r->title[s][0] == '\0' || r->desc[s][0][0] == '\0') {
            fail("M3", "review screen %u has no heading or no text", s);
        }
    }
    reparse(r);
}

/* Set while G1 calls the signing session directly; a signature then only counts for G1. */
static int g_probe;
static int g_probe_signed;

/* Called by the stub signer for every signature the app computes. */
void sm_on_sign(const unsigned char *digest, const unsigned char *key_d) {
    review_t *r = &g_review;
    if (g_probe) {
        g_probe_signed = 1;
        return;
    }
    memcpy(g_last_signed, digest, DIGEST_LEN);
    trace("  SIGN via=%s", g_via == VIA_BUTTON ? "button" : g_via == VIA_RAW ? "raw" : "none");
    if (g_via == VIA_BUTTON) g_sigs_button++;
    if (g_via == VIA_RAW) g_sigs_raw++;
    if (g_via == VIA_NONE) fail("B1", "signature outside any approval");

    if (!r->valid) {
        fail("B1", "signature with no review shown");
        return;
    }
    if (memcmp(digest, r->digest, DIGEST_LEN) != 0) fail("B2", "signed digest is not SHA-256 of the reviewed bytes");
    if (memcmp(key_d, r->key, KEY_LEN) != 0) fail("B3", "signing key is not the key of the reviewed path");
    if (r->sigs++ > 0) fail("B4", "second signature from one review");
    if (!r->reparse_ok || !r->content_match) fail("B5", "screens differ from a fresh parse of the signed bytes");
    if (max_scr_ix != r->screens || memcmp(tx_desc, r->desc, sizeof(tx_desc)) != 0 ||
        memcmp(review_title, r->title, sizeof(review_title)) != 0) {
        fail("B5", "screens changed between review and signing");
    }
    int seen = all_screens_seen(r);
    if (g_via == VIA_BUTTON) {
        if (uiState != UI_SIGN) fail("B6", "button signature while uiState=%d", uiState);
        if (!g_press_saw_sign || g_press_mask != (BUTTON_LEFT | BUTTON_RIGHT)) {
            fail("B6", "button signature from button %lu while the display %s the Sign screen", g_press_mask,
                 g_press_saw_sign ? "showed" : "did not show");
        }
        if (!seen) fail("B6", "button signature before every review screen was shown");
    } else if (g_via == VIA_RAW && !seen) {
        g_raw_unreviewed++;
        fail("B7", "approval signed before every review screen was shown");
    }
    if (g_cur != NULL && g_cur->tail == TAIL_APPROVE && r->is_tail && seen &&
        memcmp(digest, g_tail_digest, DIGEST_LEN) == 0) {
        g_tail_sig_ok = 1;
    }
}

/* ---- delivering actions --------------------------------------------------------------------- */
#define NAV_LEAVES (-1)

/* M5: Nano S review navigation from its description, not ui.c. Returns the next state, setting
 * *next_s for a review half, or NAV_LEAVES when the press ends the review. */
static int nav_model(int state, unsigned int s, unsigned int last, unsigned long mask, const review_t *r,
                     unsigned int *next_s) {
    int left = mask == BUTTON_LEFT, right = mask == BUTTON_RIGHT;
    *next_s = s;
    switch (state) {
        case UI_TOP_SIGN:
            if (left) return UI_DENY;
            *next_s = 0;
            return UI_TX_DESC_1;
        case UI_TX_DESC_1:
            if (right) return UI_TX_DESC_2;
            if (!left) return UI_TX_DESC_1;
            if (s == 0) return UI_TOP_SIGN;
            *next_s = s - 1;
            return UI_TX_DESC_2;
        case UI_TX_DESC_2:
            if (left) return UI_TX_DESC_1;
            if (!right) return UI_TX_DESC_2;
            if (s == last) return UI_SIGN;
            *next_s = s + 1;
            return UI_TX_DESC_1;
        case UI_SIGN:
            if (right) return UI_DENY;
            if (left) {
                *next_s = last;
                return UI_TX_DESC_2;
            }
            if (all_screens_seen(r)) return NAV_LEAVES;
            // both buttons before the whole review was read: the first half not yet shown
            for (unsigned int k = 0; k <= last; k++) {
                *next_s = k;
                if (!r->seen_title[k]) return UI_TX_DESC_1;
                if (!r->seen_line[k][1]) return UI_TX_DESC_2;
            }
            *next_s = s;
            return UI_SIGN;
        case UI_DENY:
            if (left) return UI_SIGN;
            if (right) return UI_TOP_SIGN;
            return NAV_LEAVES;
        default:
            return state;
    }
}

#define NAV_NONE (-2)

/* M5: the account screen, from its description; NAV_NONE for presses it does not cover. */
static int account_nav_model(int state, unsigned long mask) {
    int left = mask == BUTTON_LEFT, right = mask == BUTTON_RIGHT;
    switch (state) {
        case UI_IDLE:
            return right ? UI_PUBLIC_KEY_1 : NAV_NONE;
        case UI_PUBLIC_KEY_1:
            return right ? UI_PUBLIC_KEY_2 : left ? UI_IDLE : NAV_NONE;
        case UI_PUBLIC_KEY_2:
            return right ? UI_IDLE : left ? UI_PUBLIC_KEY_1 : NAV_NONE;
        default:
            return NAV_NONE;
    }
}

/* M5: the address check, from its description. Returns the page a press leads to, NAV_LEAVES
 * when it answers, or NAV_NONE when no page of the check shown is up. */
static int address_nav_model(unsigned long mask) {
    int p = asked_address_page();
    if (uiState != UI_ADDRESS_CHECK || p == PAGE_NONE || !g_addr.shown) return NAV_NONE;
    int one_line = g_addr.path_lines < 2;
    if (mask == BUTTON_RIGHT) {
        int next = p + 1 < ADDRESS_PAGES ? p + 1 : p;
        return next == PAGE_PATH_REST && one_line ? next + 1 : next;
    }
    if (mask == BUTTON_LEFT) {
        int before = p > 0 ? p - 1 : p;
        return before == PAGE_PATH_REST && one_line ? before - 1 : before;
    }
    // both buttons answer on Approve only once the path and the address were drawn in full
    if (p == PAGE_APPROVE && !check_lines_all_drawn()) return p;
    return p == PAGE_APPROVE || p == PAGE_REJECT ? NAV_LEAVES : p;
}

/* M5: a press on an address page led where the model says. */
static void check_address_nav(int want, unsigned long mask) {
    if (want == NAV_NONE) return;
    if (want == NAV_LEAVES ? uiState != UI_IDLE : uiState != UI_ADDRESS_CHECK || asked_address_page() != want) {
        fail("M5", "button %lu on the address check led to state %d page %d, the model says page %d (%d for idle)",
             mask, uiState, asked_address_page(), want, NAV_LEAVES);
    }
}

/* Presses through the live handler and checks where it leads. */
static void do_press(unsigned long mask) {
    // the models apply only while the display and the app agree
    int in_step = display_in_step();
    int review =
        in_step && is_review_state(uiState) && tx_session_is_armed() && g_review.valid && max_scr_ix > 0;
    int from = uiState;
    unsigned int from_s = curr_scr_ix, want_s = 0;
    int want = review ? nav_model(uiState, curr_scr_ix, max_scr_ix - 1, mask, &g_review, &want_s) : 0;
    int want_account = in_step ? account_nav_model(uiState, mask) : NAV_NONE;
    int want_page = in_step ? address_nav_model(mask) : NAV_NONE;
    int quit = g_ux_button == bagl_ui_idle_nanos_button && mask == BUTTON_LEFT;
    if (quit) g_quit_pressed = 1;
    g_press_mask = mask;
    g_press_saw_sign = frame_shows_only("Sign Tx");
    // io_event restarts the exit timer and passes the press to the stored handler
    g_idle_ticks = 0;
    g_via = VIA_BUTTON;
    g_sm_button_event = (unsigned int) (BUTTON_EVT_RELEASED | mask);
    deliver_event(SEPROXYHAL_TAG_BUTTON_PUSH_EVENT);
    g_sm_button_event = 0;
    g_via = VIA_NONE;
    finish_drawing();
    // Quit leaves through the OS, which does not return here
    if (quit) fail("X4", "Quit on the home screen did not close the app");
    if (want_account != NAV_NONE && uiState != want_account) {
        fail("M5", "button %lu on account state %d led to state %d, the model says %d", mask, from, uiState,
             want_account);
    }
    check_address_nav(want_page, mask);
    if (!review) return;
    int got_review_half = uiState == UI_TX_DESC_1 || uiState == UI_TX_DESC_2;
    if (want == NAV_LEAVES ? uiState != UI_IDLE
                           : uiState != want || (got_review_half && curr_scr_ix != want_s)) {
        fail("M5", "button %lu on state %d screen %u led to state %d screen %u, the model says %d screen %u",
             mask, from, from_s, uiState, curr_scr_ix, want, want_s);
    }
}

static void press(unsigned long mask) {
    if (g_ux_button == NULL) return;
    // leaving the app ends the case; keep it rare so cases reach deeper states
    if (g_ux_button == bagl_ui_idle_nanos_button && mask == BUTTON_LEFT && rnd(8) != 0) return;
    do_press(mask);
}

static void walk(unsigned long mask, int until) {
    for (unsigned int i = 0; i < 64 && uiState != until && is_review_state(uiState); i++) {
        do_press(mask);
        after_step("walk");
    }
}

static void deliver_tick(void) {
    g_in_tick = 1;
    deliver_event(SEPROXYHAL_TAG_TICKER_EVENT);
    g_in_tick = 0;
    g_idle_ticks++;
    finish_drawing();
}

/* The SDK passes on presses while an IO_RETURN_AFTER_TX reply is sent, so sometimes press then.
 * A reply sent from inside another fails M4. */
static int g_reply_in_flight;
static unsigned long g_presses_in_flight;
static void press_while_sending(void) {
    static const unsigned long MASKS[] = {BUTTON_LEFT, BUTTON_RIGHT, BUTTON_LEFT | BUTTON_RIGHT};
    if (g_reply_in_flight || side_rnd(2) != 0) return;
    unsigned long mask = MASKS[side_rnd(3)];
    if (g_ux_button == NULL) return;
    // keep Quit rare, as press does
    if (g_ux_button == bagl_ui_idle_nanos_button && mask == BUTTON_LEFT && side_rnd(8) != 0) return;
    int via = g_via;
    g_reply_in_flight = 1;
    g_presses_in_flight++;
    trace("  button %lu pressed while the reply is sent (uiState=%d armed=%d)", mask, uiState,
          tx_session_is_armed());
    do_press(mask);
    g_reply_in_flight = 0;
    g_via = via;
}

/* The spec's status word for an SDK error, written from the spec, not from main.c. */
static unsigned int spec_status_for_error(unsigned int code) {
    if ((code >= 0x6000 && code <= 0x6FFF) || (code >= 0x9000 && code <= 0x9FFF)) return code;
    return 0x6800 + code % 0x800;
}

/* Two errors that are status words already and two with bits above the low byte, taken in turn
 * rather than drawn so the random scripts stay the same. */
static const unsigned int STATUS_ERRORS[] = {0x6700, 0x9001, 0x0785, 0x0107};
static unsigned int g_status_errors_thrown;
static unsigned int next_status_error(void) {
    return STATUS_ERRORS[g_status_errors_thrown++ % (sizeof(STATUS_ERRORS) / sizeof(STATUS_ERRORS[0]))];
}

/* R1 or R2: what the next exchange must look like after the SDK throws code. */
static void expect_after_fault(unsigned int code) {
    g_after_fault = code == EXCEPTION_IO_RESET || code == INVALID_STATE ? AFTER_RESTART : AFTER_STATUS;
    g_after_status_sw = spec_status_for_error(code);
    g_faults++;
    skip_reset_on_throw();
}

/* The user rejects a waiting address check. If a display fault made the app forget it, nothing
 * can answer it, so the host resets USB, as a user would unplug the device. */
static void answer_address_check(void) {
    if (!g_addr.shown) return;
    if (address_check_pending) {
        g_addr.answer_forced = 1;
        address_check_reject();
        g_addr.answer_forced = 0;
    } else if (address_check_faulted()) {
        trace("  the address check can no longer be answered: USB reset");
        expect_after_fault(EXCEPTION_IO_RESET);
        THROW(EXCEPTION_IO_RESET);
    }
}

static void run_action(const action_t *a) {
    trace("%s%s (uiState=%d scr=%u/%u armed=%d)", a->tail ? "tail " : "", ACT_NAME[a->type], uiState,
          curr_scr_ix, max_scr_ix, tx_session_is_armed());
    switch (a->type) {
        case ACT_LEFT: press(BUTTON_LEFT); break;
        case ACT_RIGHT: press(BUTTON_RIGHT); break;
        case ACT_BOTH: {
            int ready = uiState == UI_SIGN && tx_session_is_armed() && g_review.valid &&
                        all_screens_seen(&g_review) && display_in_step();
            int check_ready = address_approve_ready();
            int check_undrawn = g_addr.shown && address_check_pending && address_page_on_display(PAGE_APPROVE) &&
                                !check_lines_all_drawn();
            unsigned int before = g_review.sigs, approved_before = g_addr.approved;
            int failing = arm_crypto_fault_for_press(ready);
            press(BUTTON_LEFT | BUTTON_RIGHT);
            check_crypto_fault_press(failing);
            if (check_undrawn && g_addr.approved == approved_before) g_approve_refused_undrawn++;
            if (ready && !failing && g_review.sigs == before) {
                fail("L2", "Sign refused although every screen was shown");
            }
            if (check_ready && !failing && g_addr.approved == approved_before) {
                fail("A2", "Approve did not answer although the path and the address were drawn in full");
            }
            break;
        }
        case ACT_RAW_APPROVE:
            // no address check page leads to Sign; called now it would answer the check's command
            if (g_addr.shown) break;
            g_via = VIA_RAW;
            io_seproxyhal_touch_approve(NULL);
            g_via = VIA_NONE;
            break;
        case ACT_RAW_DENY: io_seproxyhal_touch_deny(NULL); break;
        case ACT_WALK_TO_SIGN:
            walk(BUTTON_RIGHT, UI_SIGN);
            break;
        case ACT_WALK_TO_TOP:
            walk(BUTTON_LEFT, UI_TOP_SIGN);
            break;
        case ACT_TICK:
            for (unsigned int k = a->len; k > 0; k--) deliver_tick();
            break;
        case ACT_IO_FAULT: {
            // a USB reset, a reply with no command to answer, or an error that gets a status word
            static const unsigned int RESTARTS[] = {EXCEPTION_IO_RESET, INVALID_STATE};
            unsigned int code = a->len % 3 < 2 ? RESTARTS[a->len % 3] : next_status_error();
            expect_after_fault(code);
            THROW(code);
            break;
        }
        case ACT_REPLY_FAULT:
            // the next reply finds no command to answer, or fails with another error
            g_throw_on_reply = a->len == 2 ? next_status_error() : INVALID_STATE;
            break;
        case ACT_ANSWER_PENDING:
            // the user answers anything waiting, so the next command reaches the app
            if (tx_session_is_armed()) io_seproxyhal_touch_deny(NULL);
            answer_address_check();
            break;
        case ACT_READ_BACK: {
            if (uiState != UI_SIGN) break;
            unsigned long skipped = g_skipped_stores + g_cut_draws + g_skipped_sends + g_skipped_status_checks;
            walk(BUTTON_LEFT, UI_TOP_SIGN);
            // a display fault on the way can keep a half off the display
            if (g_skipped_stores + g_cut_draws + g_skipped_sends + g_skipped_status_checks != skipped) break;
            if (uiState != UI_TOP_SIGN) {
                fail("L2", "reading back from Sign did not reach the top");
            } else if (g_review.valid && !all_screens_seen(&g_review)) {
                fail("L2", "reading back from Sign to the top did not show every screen");
            }
            break;
        }
    }
}

/* The SDK contract: tx_len > 0 sends a reply; IO_RETURN_AFTER_TX returns at once; otherwise
 * wait for the next host event, which here is the next scripted action. */
unsigned short io_exchange(unsigned char channel, unsigned short tx_len) {
    if (!check_crypto_fault_answer(channel, tx_len)) {
        check_address_exchange(channel, tx_len);
    }
    if (g_reply_in_flight) {
        fail("M4", "an exchange of %u bytes started while a reply was still being sent", tx_len);
    }
    if (g_after_fault == AFTER_RESTART) {
        if (tx_len != 0 || (channel & (IO_ASYNCH_REPLY | IO_RETURN_AFTER_TX)) || uiState != UI_IDLE ||
            tx_session_is_armed()) {
            fail("R1", "after a transport fault: reply %u bytes, channel %02x, uiState %d, armed %d", tx_len, channel,
                 uiState, tx_session_is_armed());
        }
        g_after_fault = AFTER_NONE;
    } else if (g_after_fault == AFTER_STATUS) {
        unsigned int sw = tx_len == 2 ? ((unsigned int) G_io_apdu_buffer[0] << 8) | G_io_apdu_buffer[1] : 0;
        if (tx_len != 2 || sw != g_after_status_sw || (channel & IO_ASYNCH_REPLY) || tx_session_is_armed() ||
            tx_session_is_receiving() || is_review_state(uiState)) {
            fail("R2", "after an exception: reply %u bytes, status %04X, channel %02x, armed %d, receiving %d, "
                       "uiState %d", tx_len, sw, channel, tx_session_is_armed(), tx_session_is_receiving(), uiState);
        }
        g_after_fault = AFTER_NONE;
    }
    if ((channel & IO_RETURN_AFTER_TX) && tx_len > 0 && g_throw_on_reply != 0) {
        unsigned int code = g_throw_on_reply;
        g_throw_on_reply = 0;
        expect_after_fault(code);
        THROW(code);
    }
    if (tx_len > 0) record_response(tx_len);
    if (channel & IO_RETURN_AFTER_TX) {
        g_reply_pending = 0;
        press_while_sending();
        // the SDK returns once the reply is out, with no status sent yet
        g_sm_status_sent = 0;
        return 0;
    }
    g_reply_pending = (channel & IO_ASYNCH_REPLY) != 0;
    if ((channel & IO_ASYNCH_REPLY) && g_addr.request) {
        take_address_snapshot();
    } else if (channel & IO_ASYNCH_REPLY) {
        take_snapshot();
    }
    finish_drawing();
    after_step("await");
    if (g_expect_exit) {
        fail("X2", "the exit instruction did not leave the app");
        g_expect_exit = 0;
    }

    for (;;) {
        if (g_script_ix >= g_script_len) longjmp(g_case_jmp, 1);
        const action_t *a = &g_script[g_script_ix++];
        g_cur = a;
        if (a->type == ACT_APDU && g_reply_pending) {
            // the Nano S SDK drops a command while a reply is held for the one before it
            trace("%sAPDU dropped: a review is waiting", a->tail ? "tail " : "");
            g_dropped++;
            continue;
        }
        if (a->type == ACT_APDU) {
            memcpy(G_io_apdu_buffer, a->bytes, a->len);
            trace("%sAPDU %02x %02x p1=%02x p2=%02x lc=%02x len=%u", a->tail ? "tail " : "",
                  a->len > 0 ? a->bytes[0] : 0, a->len > 1 ? a->bytes[1] : 0, a->len > 2 ? a->bytes[2] : 0,
                  a->len > 3 ? a->bytes[3] : 0, a->len > 4 ? a->bytes[4] : 0, a->len);
            g_expect_pub = a->tail == TAIL_PUB;
            note_key_request(a->bytes, a->len);
            note_address_request(a->bytes, a->len);
            arm_crypto_fault(command_fail_kind(a->bytes, a->len));
            // a sign or key request restarts the exit timer
            if (a->len >= 5 && a->bytes[0] == 0x80 && (a->bytes[1] == 0x02 || a->bytes[1] == 0x04)) g_idle_ticks = 0;
            g_expect_exit = a->len >= 5 && a->bytes[0] == 0x80 && a->bytes[1] == 0xFF;
            // the command arrived as an event, which the app has not answered yet
            g_sm_status_sent = 0;
            return (unsigned short) a->len;
        }
        run_action(a);
        finish_drawing();
        after_step(ACT_NAME[a->type]);
    }
}

/* ---- case generation ------------------------------------------------------------------------ */
static action_t *push(unsigned int type) {
    if (g_script_len >= MAX_ACTIONS) {
        fprintf(stderr, "harness bug: script longer than %d actions\n", MAX_ACTIONS);
        abort();
    }
    action_t *a = &g_script[g_script_len++];
    memset(a, 0, sizeof(*a));
    a->type = type;
    return a;
}

static void push_corpus(unsigned int ix) {
    action_t *a = push(ACT_APDU);
    memcpy(a->bytes, CORPUS[ix].p, CORPUS[ix].n);
    a->len = CORPUS[ix].n;
}

static void push_legit(unsigned int k) {
    for (unsigned int i = 0; i < LEGIT_PARTS[k]; i++) push_corpus(LEGIT_FIRST[k] + i);
}

/* An allowed key request with 1 to 4 extra bytes, Lc counting them or not: only the app's byte
 * count can refuse it, with 6700. */
static void push_long_key_request(void) {
    action_t *a = push(ACT_APDU);
    const corpus_apdu_t *c = &CORPUS[KEY_ALLOWED[rnd(KEY_ALLOWED_COUNT)]];
    unsigned int extra = 1 + rnd(4);
    memcpy(a->bytes, c->p, c->n);
    for (unsigned int i = 0; i < extra; i++) a->bytes[c->n + i] = (unsigned char) rnd(256);
    a->len = c->n + extra;
    if (rnd(2)) a->bytes[4] = (unsigned char) (a->len - 5);
}

/* A corpus APDU, mutated or not, or random bytes. */
static void push_random_apdu(void) {
    // the only source of key requests too long for an allowed path
    if (rnd(32) == 0) {
        push_long_key_request();
        return;
    }
    action_t *a = push(ACT_APDU);
    unsigned int r = rnd(100);
    if (r < 60) {
        const corpus_apdu_t *c = &CORPUS[rnd(CORPUS_COUNT)];
        memcpy(a->bytes, c->p, c->n);
        a->len = c->n;
        unsigned int m = rnd(100);
        if (m < 30) {
            unsigned int flips = 1 + rnd(4);
            for (unsigned int i = 0; i < flips; i++) {
                a->bytes[5 + rnd(a->len - 5)] ^= (unsigned char) (1 << rnd(8));
            }
        } else if (m < 40) {
            a->len = rnd(a->len);
        } else if (m < 50) {
            a->bytes[4] = (unsigned char) rnd(256);
        } else if (m < 58) {
            a->bytes[2] = (unsigned char) rnd(256);
        } else if (m < 62) {
            a->bytes[3] = (unsigned char) rnd(256);
        } else if (m < 66) {
            a->bytes[1] = (unsigned char) rnd(256);
        }
    } else {
        a->len = rnd(66);
        a->bytes[0] = rnd(4) == 0 ? (unsigned char) rnd(256) : 0x80;
        for (unsigned int i = 1; i < a->len; i++) a->bytes[i] = (unsigned char) rnd(256);
        if (a->len > 3 && rnd(2)) a->bytes[3] = 0;
        if (a->len > 4 && rnd(2)) a->bytes[4] = (unsigned char) (a->len - 5);
    }
}

static void push_presses(unsigned int n) {
    for (unsigned int i = 0; i < n && g_script_len < MAX_ACTIONS - 8; i++) {
        unsigned int r = rnd(100);
        push(r < 60 ? ACT_RIGHT : r < 85 ? ACT_LEFT : ACT_BOTH);
    }
}

static void push_presses_right(unsigned int n) {
    for (unsigned int i = 0; i < n && g_script_len < MAX_ACTIONS - 12; i++) push(ACT_RIGHT);
}

static void put_wide_path(action_t *a) {
    for (unsigned int i = 0; i < PATH_BYTES; i++) {
        a->bytes[5 + i] = (unsigned char) (WIDE_PATH[i / 4] >> (24 - 8 * (i % 4)));
    }
}

/* An address check request, maybe mutated: half from those that must show, half from all. */
static void push_address_request(void) {
    action_t *a = push(ACT_APDU);
    const corpus_apdu_t *c = &CORPUS[ADDR_FIRST + rnd(rnd(2) ? ADDR_SHOWN : ADDR_COUNT)];
    memcpy(a->bytes, c->p, c->n);
    a->len = c->n;
    switch (rnd(8)) {
        case 0:  // a path one bit away
            a->bytes[5 + rnd(PATH_BYTES)] ^= (unsigned char) (1 << rnd(8));
            break;
        case 1:  // P1 00 to 03
            a->bytes[2] = (unsigned char) rnd(4);
            break;
        case 2:  // a P2 other than 00
            a->bytes[3] = (unsigned char) (1 + rnd(255));
            break;
        case 3:  // the path whose address is too wide for the screen
            put_wide_path(a);
            break;
        default:
            break;
    }
}

/* Right presses from the first page to page, for the request pushed last: one fewer past the
 * path when its second page is not shown. */
static unsigned int presses_to(int page) {
    const action_t *request = &g_script[g_script_len - 1];
    char lines[PATH_SHOWN_LINES][MAX_TX_TEXT_WIDTH];
    int one_line = request->len == 5 + PATH_BYTES && spec_path_lines(request->bytes + 5, lines) == 1;
    return (unsigned int) page - (one_line && page > PAGE_PATH_REST ? 1u : 0u);
}

static void push_address_check(void) {
    push_address_request();
    unsigned int to_approve = presses_to(PAGE_APPROVE), to_reject = presses_to(PAGE_REJECT);
    switch (rnd(5)) {
        case 0:  // read the path and the address and approve
            push_presses_right(to_approve);
            push(ACT_BOTH);
            break;
        case 1:  // read on to Reject and reject
            push_presses_right(to_reject);
            push(ACT_BOTH);
            break;
        case 2:  // both buttons before the whole path and address were read
            push_presses_right(rnd(to_approve));
            push(ACT_BOTH);
            break;
        case 3:  // on to Reject, back to Approve, approve
            push_presses_right(to_reject);
            push(ACT_LEFT);
            push(ACT_BOTH);
            break;
        default:  // wander
            push_presses(rnd(12));
            break;
    }
}

static void gen_case(void) {
    g_script_len = 0;
    g_script_ix = 0;
    plan_display_faults();
    plan_crypto_faults();
    plan_status_check_faults();

    if (rnd(100) < 50) {
        push_legit(rnd(LEGIT_COUNT));
        switch (rnd(10)) {
            case 0:  // wander through the review
                push_presses(rnd(24));
                break;
            case 1:  // read everything, then a new request arrives, then try the short way to Sign
                push(ACT_WALK_TO_SIGN);
                if (rnd(100) < 70) {
                    if (rnd(2)) {
                        push_legit(rnd(LEGIT_COUNT));
                    } else {
                        push_random_apdu();
                    }
                }
                push(ACT_LEFT);
                push(ACT_LEFT);
                push(ACT_BOTH);
                break;
            case 2:  // go round the wrong way to Sign without reading
                push(ACT_LEFT);
                push(ACT_LEFT);
                push(ACT_BOTH);
                break;
            case 3:  // approve honestly, then try for a second signature
                push(ACT_WALK_TO_SIGN);
                push(ACT_BOTH);
                push(rnd(2) ? ACT_RAW_APPROVE : ACT_BOTH);
                break;
            case 4: {  // swap in a changed last part, then approve
                push_presses(rnd(12));
                action_t *a = push(ACT_APDU);
                const corpus_apdu_t *c = &CORPUS[LEGIT_FIRST[rnd(LEGIT_COUNT)]];
                memcpy(a->bytes, c->p, c->n);
                a->len = c->n;
                a->bytes[2] = 0x80;
                for (unsigned int f = 1 + rnd(6); f > 0; f--) {
                    a->bytes[5 + rnd(a->len - 5)] ^= (unsigned char) (1 << rnd(8));
                }
                push(rnd(2) ? ACT_RAW_APPROVE : ACT_BOTH);
                break;
            }
            case 5:  // read part of it, go back to the top, then the wrong way round to Sign
                push_presses_right(rnd(18));
                push(ACT_WALK_TO_TOP);
                push(ACT_LEFT);
                push(ACT_LEFT);
                push(ACT_BOTH);
                break;
            case 6:  // go round to Sign, read part of it backwards, then forward to Sign
                push(ACT_LEFT);
                push(ACT_LEFT);
                for (unsigned int i = rnd(18); i > 0; i--) push(ACT_LEFT);
                push(ACT_WALK_TO_SIGN);
                push(ACT_BOTH);
                break;
            case 7:  // go round to Sign, read everything backwards, go round again and sign
                push(ACT_LEFT);
                push(ACT_LEFT);
                push(ACT_READ_BACK);
                push(ACT_LEFT);
                push(ACT_LEFT);
                push(ACT_BOTH);
                break;
            case 8:  // read the start, go round to Sign, read the end backwards, skip the middle
                push_presses_right(1 + rnd(8));
                push(ACT_WALK_TO_TOP);
                push(ACT_LEFT);
                push(ACT_LEFT);
                for (unsigned int i = 1 + rnd(8); i > 0; i--) push(ACT_LEFT);
                push(ACT_WALK_TO_SIGN);
                push(ACT_BOTH);
                push(ACT_BOTH);
                break;
            default:  // flood the buffer with "more to come" parts
                // answer the review above first, or the SDK drops every part
                push(ACT_ANSWER_PENDING);
                for (unsigned int i = 2 + rnd(8); i > 0 && g_script_len < MAX_ACTIONS - 12; i--) {
                    push_corpus(LEGIT_FIRST[LEGIT_COUNT - 1]);
                }
                break;
        }
    } else if (rnd(100) < 40) {
        push_address_check();
    }
    unsigned int target = g_script_len + rnd(20);
    while (g_script_len < target && g_script_len < MAX_ACTIONS - 8) {
        unsigned int r = rnd(100);
        if (r < 55) {
            push_random_apdu();
        } else if (r < 67) {
            push(ACT_RIGHT);
        } else if (r < 75) {
            push(ACT_LEFT);
        } else if (r < 81) {
            push(ACT_BOTH);
        } else if (r < 85) {
            push(ACT_RAW_APPROVE);
        } else if (r < 88) {
            push(ACT_RAW_DENY);
        } else if (r < 91) {
            push(ACT_WALK_TO_SIGN);
        } else if (r < 93) {
            push(ACT_WALK_TO_TOP);
        } else if (r < 95) {
            push(ACT_TICK)->len = 1 + rnd(40);
        } else if (r < 96) {
            push(rnd(2) ? ACT_IO_FAULT : ACT_REPLY_FAULT)->len = rnd(3);
        } else {
            push_legit(rnd(LEGIT_COUNT));
        }
    }
    // recovery check (L1): a key request and a fully reviewed signature must still work
    push(ACT_ANSWER_PENDING);
    push_corpus(GETPUB_IX);
    g_script[g_script_len - 1].tail = TAIL_PUB;
    push_corpus(TAIL_SIGN_IX);
    g_script[g_script_len - 1].tail = TAIL_SIGN;
    push(ACT_WALK_TO_SIGN)->tail = TAIL_WALK;
    push(ACT_BOTH)->tail = TAIL_APPROVE;
}

/* ---- per-case reset, mirroring main() at boot ----------------------------------------------- */
/* The app's memory as the OS hands it over: every variable zero. main() does the rest. */
static void reset_app(void) {
    memset(raw_tx, 0, sizeof(raw_tx));
    memset(G_io_apdu_buffer, 0, sizeof(G_io_apdu_buffer));
    memset(G_io_seproxyhal_spi_buffer, 0, sizeof(G_io_seproxyhal_spi_buffer));
    memset(current_public_key, 0, sizeof(current_public_key));
    memset(tx_desc, 0, sizeof(tx_desc));
    memset(curr_tx_desc, 0, sizeof(curr_tx_desc));
    memset(review_title, 0, sizeof(review_title));
    memset(curr_review_title, 0, sizeof(curr_review_title));
    memset(timer_desc, 0, sizeof(timer_desc));
    uiState = UI_INIT;
    exit_timer = 0;
    curr_scr_ix = max_scr_ix = raw_tx_ix = raw_tx_len = 0;
    session_state = 0;
    committed_body_len = committed_screens = committed_screens_check = 0;
    memset(committed_path, 0, sizeof(committed_path));
    memset(committed_digest, 0, sizeof(committed_digest));
    memset(committed_text_digest, 0, sizeof(committed_text_digest));
    transport_started = false;
    app_stack_canary = 0;
    review_complete = review_seen_top = review_seen_bottom = 0;
    g_ux_button = NULL;
    g_ux_screen = NULL;
    g_ux_elements = NULL;
    g_ux_element_count = 0;
    reset_display();
    reset_address_check();
    reset_crypto_faults();

    memset(&g_review, 0, sizeof(g_review));
    g_trace_len = 0;
    g_cur = NULL;
    g_via = VIA_NONE;
    g_exited = 0;
    g_expect_pub = 0;
    g_tail_pub_ok = 0;
    g_tail_sig_ok = 0;
    g_idle_ticks = 0;
    g_in_tick = 0;
    g_expect_exit = 0;
    g_quit_pressed = 0;
    g_reply_pending = 0;
    g_throw_on_reply = 0;
    g_after_fault = AFTER_NONE;
    g_key_request = 0;
    g_reply_in_flight = 0;
}

/* Runs the real main(). Returns 1 when the script ran out, 2 when the app left through the OS,
 * 3 on reset(), 4 when the app reset the device through the SDK. */
static int run_app(void) {
    int rc = setjmp(g_case_jmp);
    if (rc == 0) {
        elastos_device_main();
        fail("X1", "main returned instead of leaving through the OS");
        rc = 2;
    }
    g_ela_jmp_ptr = &g_ela_jmp_app;
    return rc;
}

/* Commits the tail transaction as its sign request would. */
static unsigned short commit_tail_review(void) {
    const corpus_apdu_t *t = &CORPUS[TAIL_SIGN_IX];
    tx_session_begin();
    memcpy(raw_tx, t->p + APDU_HEADER_LENGTH, t->n - APDU_HEADER_LENGTH);
    raw_tx_ix = raw_tx_len = t->n - APDU_HEADER_LENGTH;
    return prepare_review();
}

/* Signs directly; returns whether a signature was computed. */
static int probe_sign(unsigned short *sw) {
    unsigned char out[80];
    unsigned int len = 0;
    g_probe = 1;
    g_probe_signed = 0;
    *sw = tx_session_sign(out, sizeof(out), &len);
    g_probe = 0;
    return g_probe_signed;
}

/* G1: one flipped bit in byte i of buf after the commit must make signing refuse with 6D5E. */
static void expect_flip_refused(uint8_t *buf, size_t i, const char *name) {
    unsigned short sw;
    reset_app();
    if (commit_tail_review() != SW_OK) {
        fail("G1", "the tail transaction was refused");
        return;
    }
    buf[i] ^= (uint8_t) (1u << (i % 8));
    if (probe_sign(&sw) || sw != SW_COMMIT_MISMATCH) {
        fail("G1", "one flipped bit in byte %zu of the %s, signing returned %04x", i, name, sw);
    }
}

/* G1: one flipped bit in the screen count, reviewed bytes, path or committed digest is refused. */
static void check_signing_faults(void) {
    unsigned short sw;
    reset_app();
    if (commit_tail_review() != SW_OK || !probe_sign(&sw) || sw != SW_OK) {
        fail("G1", "the tail transaction does not sign when nothing is changed");
    }
    for (unsigned int bit = 0; bit < 8; bit++) {
        for (unsigned int what = 0; what < 3; what++) {
            reset_app();
            if (commit_tail_review() != SW_OK) {
                fail("G1", "the tail transaction was refused");
                return;
            }
            const char *name = what == 0 ? "screen count" : what == 1 ? "reviewed bytes" : "committed path";
            if (what == 0) {
                max_scr_ix ^= 1u << bit;
            } else if (what == 1) {
                raw_tx[bit * 7] ^= (uint8_t) (1u << bit);
            } else {
                committed_path[bit % ELA_PATH_LEN] ^= 1u << (bit * 3);
            }
            if (probe_sign(&sw) || sw != SW_COMMIT_MISMATCH) {
                fail("G1", "one flipped bit in the %s, signing returned %04x", name, sw);
            }
        }
    }
    // every byte of the committed digest, so a comparison that stops short of the end shows
    for (size_t i = 0; i < sizeof(committed_digest); i++) {
        expect_flip_refused(committed_digest, i, "committed digest");
    }
    reset_app();
}

/* Counts hashes during a commit, notes the last before arming (between the two renders), and at
 * g_render_fault_call flips a bit of the first render's text. */
static unsigned int g_sha_calls, g_last_unarmed_call, g_render_fault_call;
static uint8_t *g_render_fault_byte;
static uint8_t g_render_fault_mask;
static void render_fault_hook(void) {
    g_sha_calls++;
    if (!tx_session_is_armed()) g_last_unarmed_call = g_sha_calls;
    if (g_sha_calls == g_render_fault_call) *g_render_fault_byte ^= g_render_fault_mask;
}

/* G1: the review text is bound to the commit. A flipped bit in a heading, a line or their digest
 * stops signing; one during the first render stops the commit, as the second render differs. */
static void check_text_binding(void) {
    for (size_t i = 0; i < sizeof(committed_text_digest); i++) {
        expect_flip_refused(committed_text_digest, i, "committed text digest");
    }
    for (size_t i = 0; i < sizeof(review_title); i++) {
        expect_flip_refused((uint8_t *) review_title, i, "review headings");
    }
    for (size_t i = 0; i < sizeof(tx_desc); i++) {
        expect_flip_refused((uint8_t *) tx_desc, i, "review lines");
    }

    // count a clean commit's hashes to find the one between the renders
    reset_app();
    g_sha_calls = g_last_unarmed_call = g_render_fault_call = 0;
    g_sha_hook = render_fault_hook;
    unsigned short clean = commit_tail_review();
    g_sha_hook = NULL;
    unsigned int between = g_last_unarmed_call;
    if (clean != SW_OK || between < 2) {
        fail("G1", "no hash between the two renders of the tail review (commit %04x)", clean);
        return;
    }
    for (size_t i = 0; i < sizeof(review_title) + sizeof(tx_desc); i++) {
        const char *name = i < sizeof(review_title) ? "review headings" : "review lines";
        size_t at = i < sizeof(review_title) ? i : i - sizeof(review_title);
        unsigned short sw, probe_sw;
        reset_app();
        g_sha_calls = 0;
        g_render_fault_call = between;
        g_render_fault_byte = (i < sizeof(review_title) ? (uint8_t *) review_title : (uint8_t *) tx_desc) + at;
        g_render_fault_mask = (uint8_t) (1u << (at % 8));
        g_sha_hook = render_fault_hook;
        sw = commit_tail_review();
        g_sha_hook = NULL;
        g_render_fault_call = 0;
        if (sw != SW_COMMIT_MISMATCH || probe_sign(&probe_sw)) {
            fail("G1", "one flipped bit in byte %zu of the %s while the review was first rendered, commit %04x", at,
                 name, sw);
        }
    }
    reset_app();
}

static void show_and_draw(void (*show)(void)) {
    show();
    finish_drawing();
}

/* With the index flipped past the last screen, Up must bring it back in range, show that
 * screen's text, and mark read nothing but screen shown's first half and the half now up. */
static void expect_index_brought_back(unsigned int shown) {
    unsigned int flipped = curr_scr_ix;
    do_press(BUTTON_LEFT);
    if (curr_scr_ix >= max_scr_ix) {
        fail("G1", "a screen index flipped to %u, past the last of %u screens, was not brought back", flipped,
             max_scr_ix);
        return;
    }
    if (memcmp(curr_tx_desc, tx_desc[curr_scr_ix], sizeof(curr_tx_desc)) != 0 ||
        memcmp(curr_review_title, review_title[curr_scr_ix], sizeof(curr_review_title)) != 0 ||
        review_seen_top != 1u << shown || (review_seen_bottom & ~(1u << curr_scr_ix)) != 0) {
        fail("G1", "after the screen index was flipped to %u, the display or the read marks do not follow screen %u",
             flipped, curr_scr_ix);
    }
}

/* G1: one flipped bit in a read mask or its complement cannot mark an unread half as read. */
static void check_read_mask_faults(void) {
    for (unsigned int bit = 0; bit < 8; bit++) {
        unsigned int top_half = bit & 1;  // which half is left unread
        volatile uint32_t *seen = top_half ? &review_seen_top : &review_seen_bottom;
        volatile uint32_t *check = top_half ? &review_seen_top_check : &review_seen_bottom_check;
        reset_app();
        if (commit_tail_review() != SW_OK) {
            fail("G1", "the tail transaction was refused");
            return;
        }
        reset_review_progress();
        unsigned int unread = (bit / 2) % max_scr_ix;
        for (unsigned int s = 0; s < max_scr_ix; s++) {
            curr_scr_ix = s;
            copy_tx_desc();
            if (s != unread || !top_half) show_and_draw(ui_display_tx_desc_1);
            if (s != unread || top_half) show_and_draw(ui_display_tx_desc_2);
        }
        show_and_draw(ui_sign);
        if (review_shown_whole()) {
            fail("G1", "the review counts as read with a half unread");
        }
        *seen ^= 1u << unread;
        review_complete = REVIEW_COMPLETE;
        if (review_shown_whole()) {
            fail("G1", "one flipped read bit lets the review count as read with a half unread");
        }
        *seen ^= 1u << unread;
        // now clear the half's bit in the complement instead
        *check &= ~(1u << unread);
        if (review_shown_whole()) {
            fail("G1", "one cleared complement bit lets the review count as read with a half unread");
        }
        *check |= 1u << unread;
        curr_scr_ix = unread;
        copy_tx_desc();
        show_and_draw(top_half ? ui_display_tx_desc_1 : ui_display_tx_desc_2);
        show_and_draw(ui_sign);
        if (!review_shown_whole()) {
            fail("G1", "the review does not count as read after every half was shown");
        }
    }
    // a flipped index must not mark the screen it now names; bit 3 lands past the last screen but
    // inside tx_desc, so a missing bound shows as a bad index, not an out-of-bounds read
    for (unsigned int bit = 0; bit < 4; bit++) {
        reset_app();
        if (commit_tail_review() != SW_OK) return;
        reset_review_progress();
        curr_scr_ix = 0;
        copy_tx_desc();
        show_and_draw(ui_display_tx_desc_1);
        curr_scr_ix ^= 1u << bit;
        if (curr_scr_ix >= max_scr_ix) {
            expect_index_brought_back(0);
            continue;
        }
        show_and_draw(ui_display_tx_desc_2);
        if (review_seen_bottom != 0) {
            fail("G1", "a flipped screen index marked a screen that was never drawn as read");
        }
    }
    reset_app();
}

/* Draws every review half but one (none if unread is past the last screen). */
static void draw_halves_but(unsigned int unread, int top_half) {
    for (unsigned int s = 0; s < max_scr_ix; s++) {
        curr_scr_ix = s;
        copy_tx_desc();
        if (s != unread || !top_half) show_and_draw(ui_display_tx_desc_1);
        if (s != unread || top_half) show_and_draw(ui_display_tx_desc_2);
    }
}

/* The three-output transfer with its last output paid to a stranger: recipient screens 2, 4 and
 * 6, all headed "Recipient"; 6 is one bit from 2 and from 4. */
#define THREE_OUTPUTS_LEGIT 3
static const unsigned int RECIPIENT_SCREENS[] = {2, 4, 6};
#define RECIPIENT_COUNT (sizeof(RECIPIENT_SCREENS) / sizeof(RECIPIENT_SCREENS[0]))

/* Copies corpus transfer k into a new session's buffer; returns its length. */
static unsigned int load_legit(unsigned int k) {
    unsigned int n = 0;
    tx_session_begin();
    for (unsigned int i = 0; i < LEGIT_PARTS[k]; i++) {
        const corpus_apdu_t *part = &CORPUS[LEGIT_FIRST[k] + i];
        memcpy(raw_tx + n, part->p + APDU_HEADER_LENGTH, part->n - APDU_HEADER_LENGTH);
        n += part->n - APDU_HEADER_LENGTH;
    }
    return n;
}

static unsigned short commit_three_recipients(void) {
    unsigned int n = load_legit(THREE_OUTPUTS_LEGIT);
    // the last output's program hash comes just before the lock time and the path
    uint8_t *last_payee = raw_tx + n - PATH_BYTES - 4 - ELA_PROGRAM_HASH_LEN;
    last_payee[0] = 0x21;
    memset(last_payee + 1, 0xDE, ELA_PROGRAM_HASH_LEN - 1);
    raw_tx_ix = raw_tx_len = n;
    return prepare_review();
}

/* True if the recipient screens share their heading and no two show the same lines. */
static int recipients_share_heading(void) {
    if (max_scr_ix <= RECIPIENT_SCREENS[RECIPIENT_COUNT - 1]) return 0;
    for (unsigned int i = 0; i < RECIPIENT_COUNT; i++) {
        for (unsigned int j = i + 1; j < RECIPIENT_COUNT; j++) {
            unsigned int a = RECIPIENT_SCREENS[i], b = RECIPIENT_SCREENS[j];
            if (memcmp(review_title[a], review_title[b], sizeof(review_title[a])) != 0 ||
                memcmp(tx_desc[a], tx_desc[b], sizeof(tx_desc[a])) == 0) {
                return 0;
            }
        }
    }
    return 1;
}

/* Leaves one half of recipient screen to unread, then flips the index from from to to while that
 * half of from is drawn. The half must stay unread until drawn itself. */
static void expect_same_heading_flip_unread(unsigned int from, unsigned int to, int top_half) {
    void (*half)(void) = top_half ? ui_display_tx_desc_1 : ui_display_tx_desc_2;
    volatile uint32_t *seen = top_half ? &review_seen_top : &review_seen_bottom;
    const char *which = top_half ? "top" : "bottom";
    reset_app();
    if (commit_three_recipients() != SW_OK || !recipients_share_heading()) {
        fail("G1", "the transfer to three recipients was refused, or its recipient screens are not as expected");
        return;
    }
    reset_review_progress();
    draw_halves_but(to, top_half);
    curr_scr_ix = from;
    copy_tx_desc();
    half();
    curr_scr_ix ^= from ^ to;
    finish_drawing();
    show_and_draw(ui_sign);
    if ((*seen & (1u << to)) != 0 || review_shown_whole()) {
        fail("G1", "the screen index flipped from recipient screen %u to %u while its %s half was drawn marked screen "
             "%u's %s half read", from, to, which, to, which);
    }
    curr_scr_ix = to;
    copy_tx_desc();
    show_and_draw(half);
    show_and_draw(ui_sign);
    if (!review_shown_whole()) {
        fail("G1", "the transfer to three recipients does not count as read after every half was shown");
    }
}

/* G1: a half counts as read only if the display holds that screen's lines, not just its heading:
 * an index flip between recipient screens keeps the heading but changes the address. */
static void check_same_heading_flips(void) {
    for (unsigned int i = 0; i < RECIPIENT_COUNT; i++) {
        for (unsigned int j = 0; j < RECIPIENT_COUNT; j++) {
            unsigned int from = RECIPIENT_SCREENS[i], to = RECIPIENT_SCREENS[j], flip = from ^ to;
            // one bit apart: screens 2 and 6, and 4 and 6
            if (flip == 0 || (flip & (flip - 1)) != 0) continue;
            expect_same_heading_flip_unread(from, to, 1);
            expect_same_heading_flip_unread(from, to, 0);
        }
    }
    reset_app();
}

/* the poll vote fills all nine review screens; the tail review has seven */
#define POLL_VOTE_LEGIT 8
#define TAIL_SCREENS 7

static unsigned short commit_poll_vote(void) {
    raw_tx_ix = raw_tx_len = load_legit(POLL_VOTE_LEGIT);
    return prepare_review();
}

/* G1: an index flipped past the last screen is brought back even when Up leaves it equal to the
 * screen count, which an off-by-one bound would let through. Tried on 7 and 9 screens. */
static void check_index_flip_boundary(void) {
    for (unsigned int vote = 0; vote < 2; vote++) {
        unsigned int screens = vote ? MAX_TX_TEXT_SCREENS : TAIL_SCREENS;
        for (unsigned int shown = 0; shown < screens; shown++) {
            for (unsigned int bit = 0; bit < 4; bit++) {
                if ((shown ^ (1u << bit)) < screens) continue;
                reset_app();
                unsigned short sw = vote ? commit_poll_vote() : commit_tail_review();
                if (sw != SW_OK || max_scr_ix != screens) {
                    fail("G1", "the %s review was refused or does not have %u screens", vote ? "poll vote" : "tail",
                         screens);
                    return;
                }
                reset_review_progress();
                curr_scr_ix = shown;
                copy_tx_desc();
                show_and_draw(ui_display_tx_desc_1);
                curr_scr_ix ^= 1u << bit;
                expect_index_brought_back(shown);
            }
        }
    }
    reset_app();
}

/* two wallet transfers with the same number of review screens */
#define SEND_CHANGE_LEGIT 1
#define ZERO_CHANGE_LEGIT 2

/*
 * G1: a new review starts unread. A review read to Sign is ended by an SDK exception; then, with
 * no reset of the read marks skipped or one of the two skipped, a second review of as many screens
 * taken the short way to Sign must not count as read: both buttons show its first half instead.
 */
static void check_read_marks_per_review(void) {
    static const char *const FAULT[] = {"a USB reset", "a reply with no command to answer", "an SDK error"};
    static const char *const SKIPPED[] = {"", " and a skipped reset in ui_idle",
                                          " and a skipped reset in ui_start_review"};
    unsigned long reviews = g_reviews, faults = g_faults;
    for (int site = RESET_NOT_SKIPPED; site <= RESET_IN_START_REVIEW; site++) {
        for (unsigned int code = 0; code < 3; code++) {
            reset_app();
            g_script_len = 0;
            g_script_ix = 0;
            push_legit(SEND_CHANGE_LEGIT);
            push(ACT_WALK_TO_SIGN);
            push(ACT_IO_FAULT)->len = code;
            push_legit(ZERO_CHANGE_LEGIT);
            push(ACT_LEFT);
            push(ACT_LEFT);
            g_reset_to_skip = site;
            g_reset_skip_state = site == RESET_NOT_SKIPPED ? SKIP_RESET_OFF : SKIP_RESET_ARMED;
            int rc = run_app();
            int skipped = g_reset_skip_state == SKIP_RESET_DONE;
            g_reset_skip_state = SKIP_RESET_OFF;
            if (rc != 1 || !tx_session_is_armed() || !sign_screen_on_display()) {
                fail("G1", "after %s%s, the second review did not wait on Sign (run ended %d)", FAULT[code],
                     SKIPPED[site], rc);
                continue;
            }
            // the kept marks must be a full read: review_complete, every screen in review_seen_top
            if ((site != RESET_NOT_SKIPPED && !skipped) ||
                (site == RESET_IN_UI_IDLE &&
                 (g_kept_marks[0] != REVIEW_COMPLETE || g_kept_marks[1] != (1u << max_scr_ix) - 1))) {
                fail("G1", "after %s%s, the reset was not skipped as planned", FAULT[code], SKIPPED[site]);
                continue;
            }
            if (review_shown_whole()) {
                fail("G1", "after %s%s, a new review counts as read before any of it was shown", FAULT[code],
                     SKIPPED[site]);
            }
            do_press(BUTTON_LEFT | BUTTON_RIGHT);
            if (g_review.sigs != 0 || !tx_session_is_armed() || uiState != UI_TX_DESC_1) {
                fail("G1", "after %s%s, both buttons on Sign did not lead to the new review's first half", FAULT[code],
                     SKIPPED[site]);
            }
        }
    }
    g_reset_to_skip = RESET_NOT_SKIPPED;
    g_reviews = reviews;
    g_faults = faults;
    reset_app();
}

#define LAYOUT_ELEMENTS(layout) (sizeof(layout) / sizeof((layout)[0]))

/* Ticks until the app's periodic redraw starts and lets it draw only its first drawn elements,
 * so the next press lands mid-redraw. Returns 0 if no redraw started. */
static int redraw_under_way(unsigned int drawn) {
    Timer_Set();
    for (unsigned int t = 0; t <= EXIT_TIMER_REFRESH_INTERVAL; t++) {
        deliver_event(SEPROXYHAL_TAG_TICKER_EVENT);
        if (g_frame_len != 1) continue;
        for (unsigned int e = 1; e < drawn; e++) deliver_event(SEPROXYHAL_TAG_DISPLAY_PROCESSED_EVENT);
        return g_frame_len == drawn;
    }
    return 0;
}

/* G1: both buttons on Sign mid-redraw are ignored, and the review signs once Sign is whole again.
 * Approval checks the screen too, so it refuses mid-redraw even if the button check is skipped. */
static void check_sign_press_during_redraw(void) {
    for (unsigned int drawn = 1; drawn < LAYOUT_ELEMENTS(bagl_ui_sign_nanos); drawn++) {
        unsigned short sw;
        reset_app();
        if (commit_tail_review() != SW_OK) {
            fail("G1", "the tail transaction was refused");
            return;
        }
        reset_review_progress();
        draw_halves_but(max_scr_ix, 0);
        show_and_draw(ui_sign);
        if (!redraw_under_way(drawn)) {
            fail("G1", "the app did not draw the Sign screen again");
            return;
        }
        if (review_shown_whole()) {
            fail("G1", "with %u of Sign's %zu elements drawn again, approval counts Sign as on display", drawn,
                 LAYOUT_ELEMENTS(bagl_ui_sign_nanos));
        }
        g_probe = 1;
        g_probe_signed = 0;
        do_press(BUTTON_LEFT | BUTTON_RIGHT);
        g_probe = 0;
        if (g_probe_signed || !tx_session_is_armed() || uiState != UI_SIGN) {
            fail("G1", "both buttons on Sign, with %u of its %zu elements drawn again, signed or ended the review",
                 drawn, LAYOUT_ELEMENTS(bagl_ui_sign_nanos));
            continue;
        }
        if (!review_shown_whole() || !probe_sign(&sw) || sw != SW_OK) {
            fail("G1", "the review does not sign once Sign is drawn again in full");
        }
    }
    reset_app();
}

/* G1: with the redraw index store skipped, a press mid-redraw draws the next screen over the old
 * one, which must not count as drawn: the last half (Left from Sign) or Sign (Left from Deny). */
static void check_stale_index_after_redraw(void) {
    for (unsigned int from_deny = 0; from_deny < 2; from_deny++) {
        unsigned int count = from_deny ? LAYOUT_ELEMENTS(bagl_ui_deny_nanos) : LAYOUT_ELEMENTS(bagl_ui_sign_nanos);
        const char *next = from_deny ? "Sign" : "the last review half";
        for (unsigned int drawn = 1; drawn < count; drawn++) {
            reset_app();
            if (commit_tail_review() != SW_OK) {
                fail("G1", "the tail transaction was refused");
                return;
            }
            reset_review_progress();
            unsigned int last = max_scr_ix - 1;
            // Left from Sign puts up the last screen's second half, so leave that half unread
            draw_halves_but(from_deny ? max_scr_ix : last, 0);
            show_and_draw(from_deny ? ui_deny : ui_sign);
            if (!redraw_under_way(drawn)) {
                fail("G1", "the app did not draw its screen again");
                return;
            }
            g_forced_skip = SM_SKIP_INDEX;
            do_press(BUTTON_LEFT);
            if (g_forced_skip != SM_SKIP_NONE) {
                g_forced_skip = SM_SKIP_NONE;
                fail("G1", "Left put up no screen, so no store was skipped");
                return;
            }
            if (from_deny ? sign_screen_on_display() : (review_seen_bottom & (1u << last)) != 0) {
                fail("G1", "%s, drawn on from element %u where the redraw of %s stopped, counts as drawn", next, drawn,
                     from_deny ? "Deny Tx" : "Sign");
            }
        }
    }
    reset_app();
}

/* True if the display holds that half of screen s in full, with its own two texts. */
static int display_holds_half(unsigned int s, int top_half) {
    const bagl_element_t *label[2];
    const bagl_element_t *layout = top_half ? bagl_ui_tx_desc_nanos_1 : bagl_ui_tx_desc_nanos_2;
    unsigned int count = top_half ? LAYOUT_ELEMENTS(bagl_ui_tx_desc_nanos_1) : LAYOUT_ELEMENTS(bagl_ui_tx_desc_nanos_2);
    if (!frame_holds(layout, count) || drawn_labels(label, 2) != 2 || label[0]->text == NULL ||
        label[1]->text == NULL) {
        return 0;
    }
    const char *upper = top_half ? review_title[s] : tx_desc[s][1];
    const char *lower = top_half ? tx_desc[s][0] : tx_desc[s][2];
    return strcmp(label[0]->text, upper) == 0 && strcmp(label[1]->text, lower) == 0;
}

/* G1: every half newly marked read since top and bottom must be on the display in full. */
static void expect_marked_halves_on_display(uint32_t top, uint32_t bottom, const char *what) {
    for (unsigned int s = 0; s < max_scr_ix; s++) {
        for (int top_half = 0; top_half < 2; top_half++) {
            uint32_t before = top_half ? top : bottom, now = top_half ? review_seen_top : review_seen_bottom;
            if ((now & ~before & (1u << s)) != 0 && !display_holds_half(s, top_half)) {
                fail("G1", "%s: the %s half of screen %u counts as read, but the display does not hold it", what,
                     top_half ? "top" : "bottom", s);
            }
        }
    }
}

/* G1: one half is unread and its neighbour is mid-redraw when the user presses towards it, and the
 * call that puts the unread half up is skipped whole. The redraw then ends with the new text over
 * the old, which must not count as the unread half. */
static void check_skipped_display_call(void) {
    for (int top_half = 0; top_half < 2; top_half++) {
        for (unsigned int drawn = 1; drawn < LAYOUT_ELEMENTS(bagl_ui_tx_desc_nanos_1); drawn++) {
            for (unsigned int unread = 0; unread < TAIL_SCREENS; unread++) {
                // Left from the next screen, or Right from the one before, reaches this half
                if (top_half ? unread + 1 >= TAIL_SCREENS : unread == 0) continue;
                char what[96];
                snprintf(what, sizeof(what), "%s with %u elements drawn again and the display call skipped",
                         top_half ? "Left" : "Right", drawn);
                reset_app();
                if (commit_tail_review() != SW_OK || max_scr_ix != TAIL_SCREENS) {
                    fail("G1", "the tail transaction was refused or does not have %u screens", TAIL_SCREENS);
                    return;
                }
                reset_review_progress();
                draw_halves_but(unread, top_half);
                curr_scr_ix = top_half ? unread + 1 : unread - 1;
                copy_tx_desc();
                show_and_draw(top_half ? ui_display_tx_desc_1 : ui_display_tx_desc_2);
                if (!redraw_under_way(drawn)) {
                    fail("G1", "the app did not draw its screen again");
                    return;
                }
                uint32_t top = review_seen_top, bottom = review_seen_bottom;
                g_state_before_skipped_call = uiState;
                g_forced_skip = SM_SKIP_CALL;
                // the app and the display now disagree, so the navigation model does not apply
                g_display_fault = 1;
                do_press(top_half ? BUTTON_LEFT : BUTTON_RIGHT);
                if (g_forced_skip != SM_SKIP_NONE) {
                    g_forced_skip = SM_SKIP_NONE;
                    fail("G1", "%s: the press put up no screen, so no call was skipped", what);
                    return;
                }
                expect_marked_halves_on_display(top, bottom, what);
            }
        }
    }
    reset_app();
}

/* G1: an element counts towards a half only if the SDK sent it. Each element of each half of the
 * tail review is skipped once; the half must not count as read until drawn again in full. */
static void check_skipped_element_send(void) {
    for (int top_half = 0; top_half < 2; top_half++) {
        const bagl_element_t *layout = top_half ? bagl_ui_tx_desc_nanos_1 : bagl_ui_tx_desc_nanos_2;
        void (*half)(void) = top_half ? ui_display_tx_desc_1 : ui_display_tx_desc_2;
        volatile uint32_t *seen = top_half ? &review_seen_top : &review_seen_bottom;
        for (unsigned int k = 0; k < LAYOUT_ELEMENTS(bagl_ui_tx_desc_nanos_1); k++) {
            for (unsigned int s = 0; s < TAIL_SCREENS; s++) {
                char what[80];
                snprintf(what, sizeof(what), "element %u of the %s half of screen %u not sent", k,
                         top_half ? "top" : "bottom", s);
                reset_app();
                if (commit_tail_review() != SW_OK || max_scr_ix != TAIL_SCREENS) {
                    fail("G1", "the tail transaction was refused or does not have %u screens", TAIL_SCREENS);
                    return;
                }
                reset_review_progress();
                curr_scr_ix = s;
                copy_tx_desc();
                uint32_t top = review_seen_top, bottom = review_seen_bottom;
                g_forced_send_skip = &layout[k];
                show_and_draw(half);
                if (g_forced_send_skip != NULL) {
                    g_forced_send_skip = NULL;
                    fail("G1", "%s: the element was never handed to the SDK", what);
                    return;
                }
                expect_marked_halves_on_display(top, bottom, what);
                show_and_draw(half);
                if ((*seen & (1u << s)) == 0) {
                    fail("G1", "%s: drawn again in full, the half does not count as read", what);
                }
            }
        }
    }
    reset_app();
}

/* G1: likewise with the drawing loop's status check skipped before each element but the first,
 * so the element is handed over with a status out and never sent. */
static void check_skipped_status_check(void) {
    for (int top_half = 0; top_half < 2; top_half++) {
        const bagl_element_t *layout = top_half ? bagl_ui_tx_desc_nanos_1 : bagl_ui_tx_desc_nanos_2;
        void (*half)(void) = top_half ? ui_display_tx_desc_1 : ui_display_tx_desc_2;
        volatile uint32_t *seen = top_half ? &review_seen_top : &review_seen_bottom;
        for (unsigned int k = 1; k < LAYOUT_ELEMENTS(bagl_ui_tx_desc_nanos_1); k++) {
            for (unsigned int s = 0; s < TAIL_SCREENS; s++) {
                char what[96];
                snprintf(what, sizeof(what), "element %u of the %s half of screen %u drawn with a status out", k,
                         top_half ? "top" : "bottom", s);
                reset_app();
                if (commit_tail_review() != SW_OK || max_scr_ix != TAIL_SCREENS) {
                    fail("G1", "the tail transaction was refused or does not have %u screens", TAIL_SCREENS);
                    return;
                }
                reset_review_progress();
                curr_scr_ix = s;
                copy_tx_desc();
                uint32_t top = review_seen_top, bottom = review_seen_bottom;
                g_forced_status_skip = &layout[k];
                show_and_draw(half);
                if (g_forced_status_skip != NULL) {
                    g_forced_status_skip = NULL;
                    fail("G1", "%s: the drawing loop never checked the status before the element", what);
                    return;
                }
                expect_marked_halves_on_display(top, bottom, what);
                show_and_draw(half);
                if ((*seen & (1u << s)) == 0) {
                    fail("G1", "%s: drawn again in full, the half does not count as read", what);
                }
            }
        }
    }
    reset_app();
}

/* What g_sha_hook does inside the one hash of a signing call: undo a fault set before the call,
 * so only the first check can see it, or make one, so only the second check can. */
static int g_hook_action;
static unsigned int g_hook_saved;
/* flips the 'h' of the tail memo's "hello" (screen 1, line 1) to '`' */
#define TEXT_FAULT_BIT 8
static void signing_hook(void) {
    switch (g_hook_action) {
        case 1: max_scr_ix = g_hook_saved; break;
        case 2: max_scr_ix ^= 1u; break;
        case 3: committed_path[4] = g_hook_saved; break;
        case 4: committed_path[4] ^= 1u; break;
        case 5: tx_desc[1][1][0] = (char) g_hook_saved; break;
        case 6: tx_desc[1][1][0] ^= TEXT_FAULT_BIT; break;
    }
}

/* G1: each check at signing is made twice; a fault that one of them misses, the other catches. */
static void check_double_checks(void) {
    static const char *const WHAT[] = {"", "screen count, before the first check", "screen count, after the first check",
                                       "path, before the first check", "path, after the first check",
                                       "review text, before the first check", "review text, after the first check"};
    for (int action = 1; action <= 6; action++) {
        unsigned short sw;
        reset_app();
        if (commit_tail_review() != SW_OK) return;
        if (action == 1) {
            g_hook_saved = max_scr_ix;
            max_scr_ix ^= 1u;
        } else if (action == 3) {
            g_hook_saved = committed_path[4];
            committed_path[4] ^= 1u;
        } else if (action == 5) {
            g_hook_saved = (unsigned char) tx_desc[1][1][0];
            tx_desc[1][1][0] ^= TEXT_FAULT_BIT;
        }
        g_hook_action = action;
        g_sha_hook = signing_hook;
        g_sha_hook_input = raw_tx;  // the one hash of the transaction bytes between the checks
        int signed_it = probe_sign(&sw);
        g_sha_hook = NULL;
        g_sha_hook_input = NULL;
        g_hook_action = 0;
        if (signed_it || sw != SW_COMMIT_MISMATCH) {
            fail("G1", "a changed %s was not caught, signing returned %04x", WHAT[action], sw);
        }
    }
    reset_app();
}

/* ---- G1: the second checks, the text hash and the signing path ------------------------------ */
/* Make the first or second comparison with the committed digest pass; only signing makes them. */
static int g_first_digest_compare_faulted, g_second_digest_compare_faulted;
static unsigned int g_digest_compares;

static bool digest_compare(const uint8_t *a, const uint8_t *b) {
    if (b == committed_digest) {
        unsigned int compare = g_digest_compares++;
        if ((compare == 0 && g_first_digest_compare_faulted) || (compare == 1 && g_second_digest_compare_faulted)) {
            return true;
        }
    }
    return digests_match_real(a, b);
}

/* Flips one bit of the session state inside signing's hash, after its first check. */
static void session_state_fault_hook(void) {
    session_state ^= 1u;
}

/* G1: a state or digest fault the first check misses is refused by the second alone. */
static void check_second_checks(void) {
    unsigned short sw;
    reset_app();
    if (commit_tail_review() != SW_OK) {
        fail("G1", "the tail transaction was refused");
        return;
    }
    g_sha_hook = session_state_fault_hook;
    g_sha_hook_input = raw_tx;  // the transaction hash, after the first state check
    int signed_it = probe_sign(&sw);
    g_sha_hook = NULL;
    g_sha_hook_input = NULL;
    if (signed_it || sw != SW_NOT_ARMED) {
        fail("G1", "one flipped bit in the session state after its first check, signing returned %04x", sw);
    }
    // first prove the fault reaches that comparison and nothing else
    reset_app();
    if (commit_tail_review() != SW_OK) return;
    g_digest_compares = 0;
    g_first_digest_compare_faulted = 1;
    signed_it = probe_sign(&sw);
    g_first_digest_compare_faulted = 0;
    if (!signed_it || sw != SW_OK || g_digest_compares == 0) {
        fail("G1", "with the first digest comparison skipped and nothing changed, signing returned %04x", sw);
    }
    for (size_t i = 0; i < sizeof(committed_digest); i++) {
        reset_app();
        if (commit_tail_review() != SW_OK) return;
        committed_digest[i] ^= (uint8_t) (1u << (i % 8));
        g_digest_compares = 0;
        g_first_digest_compare_faulted = 1;
        signed_it = probe_sign(&sw);
        g_first_digest_compare_faulted = 0;
        if (signed_it || sw != SW_COMMIT_MISMATCH) {
            fail("G1", "one flipped bit in byte %zu of the committed digest, the first comparison skipped, "
                       "signing returned %04x", i, sw);
        }
    }
    reset_app();
}

/* G1: likewise with the second comparison passing, so a first result thrown away shows. */
static void check_first_digest_comparison(void) {
    unsigned short sw;
    // first prove the fault reaches that comparison and nothing else
    reset_app();
    if (commit_tail_review() != SW_OK) return;
    g_digest_compares = 0;
    g_second_digest_compare_faulted = 1;
    int signed_it = probe_sign(&sw);
    g_second_digest_compare_faulted = 0;
    if (!signed_it || sw != SW_OK || g_digest_compares != 2) {
        fail("G1", "with the second digest comparison skipped and nothing changed, signing returned %04x after %u "
                   "comparisons", sw, g_digest_compares);
    }
    for (size_t i = 0; i < sizeof(committed_digest); i++) {
        reset_app();
        if (commit_tail_review() != SW_OK) return;
        committed_digest[i] ^= (uint8_t) (1u << (i % 8));
        g_digest_compares = 0;
        g_second_digest_compare_faulted = 1;
        signed_it = probe_sign(&sw);
        g_second_digest_compare_faulted = 0;
        if (signed_it || sw != SW_COMMIT_MISMATCH) {
            fail("G1", "one flipped bit in byte %zu of the committed digest, the second comparison skipped, "
                       "signing returned %04x", i, sw);
        }
    }
    reset_app();
}

/* G1: a failed text hash, at signing or at commit, signs nothing. */
static void check_text_hash_failure(void) {
    unsigned short sw;
    reset_app();
    if (commit_tail_review() != SW_OK) {
        fail("G1", "the tail transaction was refused");
        return;
    }
    g_fail_sha256_parts = 1;
    int signed_it = probe_sign(&sw);
    g_fail_sha256_parts = 0;
    if (signed_it || sw != SW_COMMIT_MISMATCH) {
        fail("G1", "the hash of the review text failed at signing, signing returned %04x", sw);
    }
    reset_app();
    g_fail_sha256_parts = 1;
    unsigned short commit_sw = commit_tail_review();
    g_fail_sha256_parts = 0;
    if (commit_sw != SW_COMMIT_MISMATCH || probe_sign(&sw)) {
        fail("G1", "the hash of the review text failed while the review was committed, commit %04x",
             commit_sw);
    }
    reset_app();
}

static void tail_review_path(unsigned int path[ELA_PATH_LEN]) {
    const corpus_apdu_t *t = &CORPUS[TAIL_SIGN_IX];
    decode_path(t->p + t->n - PATH_BYTES, path);
}

static int derived_from(const unsigned int path[ELA_PATH_LEN]) {
    return g_derived_path_len == ELA_PATH_LEN &&
           memcmp(g_derived_path, path, ELA_PATH_LEN * sizeof(path[0])) == 0;
}

static int spec_allows_components(const unsigned int path[ELA_PATH_LEN]) {
    unsigned char b[PATH_BYTES];
    for (unsigned int i = 0; i < PATH_BYTES; i++) b[i] = (unsigned char) (path[i / 4] >> (24 - 8 * (i % 4)));
    return spec_allows_path(b);
}

/* G1: signing uses the committed path, not the path bytes left in the buffer: a flipped bit
 * there signs only with the reviewed path. */
static void check_buffered_path_faults(void) {
    const corpus_apdu_t *t = &CORPUS[TAIL_SIGN_IX];
    unsigned int body_len = t->n - APDU_HEADER_LENGTH - PATH_BYTES, reviewed[ELA_PATH_LEN];
    tail_review_path(reviewed);
    for (unsigned int bit = 0; bit < 8 * PATH_BYTES; bit++) {
        unsigned short sw;
        reset_app();
        if (commit_tail_review() != SW_OK) {
            fail("G1", "the tail transaction was refused");
            return;
        }
        raw_tx[body_len + bit / 8] ^= (uint8_t) (1u << (bit % 8));
        g_derived_path_len = 0;
        if (probe_sign(&sw) && !derived_from(reviewed)) {
            fail("G1", "one flipped bit in byte %u of the path left in the buffer signed with "
                       "%08x/%08x/%08x/%08x/%08x, not the reviewed path", bit / 8, g_derived_path[0],
                 g_derived_path[1], g_derived_path[2], g_derived_path[3], g_derived_path[4]);
        }
    }
    reset_app();
}

/* For check_path_while_built: count commit hashes, note the last before arming, and flip bit
 * g_path_fault_bit of the derived path at hash g_path_fault_call, or at the derivation if 0. */
static unsigned int g_path_hashes, g_path_last_unarmed, g_path_fault_call, g_path_fault_bit;
static int g_path_fault_armed;
static void flip_path_bit(const unsigned int *path) {
    ((unsigned int *) path)[g_path_fault_bit / 32] ^= 1u << (g_path_fault_bit % 32);
}
static void path_fault_hook(void) {
    g_path_hashes++;
    if (!tx_session_is_armed()) g_path_last_unarmed = g_path_hashes;
    if (g_path_fault_armed && g_path_hashes == g_path_fault_call && g_derive_path != NULL) {
        flip_path_bit(g_derive_path);
    }
}
static void path_derive_hook(const unsigned int *path) {
    if (g_path_fault_armed && g_path_fault_call == 0) flip_path_bit(path);
}

/* G1: a flipped path bit while the review is built, at the derivation or any hash up to the
 * transaction's, is refused, or signs with the path the shown key came from if it is allowed. */
static void check_path_while_built(void) {
    // count a clean commit's hashes up to the transaction's, the last before arming
    reset_app();
    g_derive_path = NULL;
    g_path_hashes = g_path_last_unarmed = 0;
    g_sha_hook = path_fault_hook;
    unsigned short clean = commit_tail_review();
    g_sha_hook = NULL;
    unsigned int window = g_path_last_unarmed;
    if (clean != SW_OK || window == 0) {
        fail("G1", "no hash while the tail review is built (commit %04x)", clean);
        return;
    }
    for (unsigned int call = 0; call <= window; call++) {
        for (unsigned int bit = 0; bit < 32 * ELA_PATH_LEN; bit++) {
            unsigned int shown[ELA_PATH_LEN];
            unsigned short sw;
            reset_app();
            g_derive_path = NULL;
            g_path_hashes = 0;
            g_path_fault_call = call;
            g_path_fault_bit = bit;
            g_path_fault_armed = 1;
            g_sha_hook = path_fault_hook;
            g_derive_hook = path_derive_hook;
            unsigned short commit_sw = commit_tail_review();
            g_sha_hook = NULL;
            g_derive_hook = NULL;
            g_path_fault_armed = 0;
            // the app ends the session on any refusal
            if (commit_sw != SW_OK) continue;
            memcpy(shown, g_derived_path, sizeof(shown));
            g_derived_path_len = 0;
            if (probe_sign(&sw) && (!derived_from(shown) || !spec_allows_components(g_derived_path))) {
                fail("G1", "bit %u of the path flipped at point %u of the commit (0 the derivation, then "
                           "each hash): the key shown came from %08x/%08x/%08x/%08x/%08x, the key that "
                           "signed from %08x/%08x/%08x/%08x/%08x", bit, call, shown[0], shown[1], shown[2],
                     shown[3], shown[4], g_derived_path[0], g_derived_path[1], g_derived_path[2],
                     g_derived_path[3], g_derived_path[4]);
            }
        }
    }
    g_derive_path = NULL;
    reset_app();
}

/* Flips the path once, before the first derivation of the commit, and leaves it flipped. */
static void path_once_derive_hook(const unsigned int *path) {
    if (!g_path_fault_armed) return;
    flip_path_bit(path);
    g_path_fault_armed = 0;
}

/* G1: likewise with the flip before the first derivation, left in place so both renders agree
 * and the fault reaches signing. */
static void check_path_flipped_before_key(void) {
    for (unsigned int bit = 0; bit < 32 * ELA_PATH_LEN; bit++) {
        unsigned int shown[ELA_PATH_LEN];
        unsigned short sw;
        reset_app();
        g_derive_path = NULL;
        g_path_fault_bit = bit;
        g_path_fault_armed = 1;
        g_derive_hook = path_once_derive_hook;
        unsigned short commit_sw = commit_tail_review();
        g_derive_hook = NULL;
        g_path_fault_armed = 0;
        // the app ends the session on any refusal
        if (commit_sw != SW_OK) continue;
        memcpy(shown, g_derived_path, sizeof(shown));
        g_derived_path_len = 0;
        if (probe_sign(&sw) && (!derived_from(shown) || !spec_allows_components(g_derived_path))) {
            fail("G1", "bit %u of the path flipped before the key shown was derived: the key shown came from "
                       "%08x/%08x/%08x/%08x/%08x, the key that signed from %08x/%08x/%08x/%08x/%08x", bit, shown[0],
                 shown[1], shown[2], shown[3], shown[4], g_derived_path[0], g_derived_path[1], g_derived_path[2],
                 g_derived_path[3], g_derived_path[4]);
        }
    }
    g_derive_path = NULL;
    reset_app();
}

/* G1: signing applies the path rule again: a refused path committed with its complement, as if
 * the check at review were skipped, does not sign. */
static void check_refused_path_committed(void) {
    unsigned int reviewed[ELA_PATH_LEN];
    tail_review_path(reviewed);
    for (unsigned int bit = 0; bit < 32 * ELA_PATH_LEN; bit++) {
        unsigned int path[ELA_PATH_LEN];
        unsigned short sw;
        memcpy(path, reviewed, sizeof(path));
        path[bit / 32] ^= 1u << (bit % 32);
        if (spec_allows_components(path)) continue;
        reset_app();
        if (commit_tail_review() != SW_OK) {
            fail("G1", "the tail transaction was refused");
            return;
        }
        for (unsigned int i = 0; i < ELA_PATH_LEN; i++) {
            committed_path[i] = path[i];
            committed_path_check[i] = ~path[i];
        }
        if (probe_sign(&sw) || sw != SW_COMMIT_MISMATCH) {
            fail("G1", "the path %08x/%08x/%08x/%08x/%08x, which the specification refuses, committed with "
                       "its complement, signing returned %04x",
                 path[0], path[1], path[2], path[3], path[4], sw);
        }
    }
    reset_app();
}

/* Where check_key_while_built flips one bit during the commit: the path only while the first
 * derivation reads it, the key it gives, or that key's address. */
enum { KEY_FAULT_PATH_READ = 0, KEY_FAULT_KEY, KEY_FAULT_ADDRESS, KEY_FAULTS };
static int g_key_fault, g_key_fault_armed;
static unsigned int g_key_fault_bit;
static unsigned int *g_key_fault_path;

static void flip_key_fault_path_bit(void) {
    g_key_fault_path[g_key_fault_bit / 32] ^= 1u << (g_key_fault_bit % 32);
}
static void key_fault_derive_hook(const unsigned int *path) {
    if (!g_key_fault_armed || g_key_fault != KEY_FAULT_PATH_READ || g_key_fault_path != NULL) return;
    g_key_fault_path = (unsigned int *) path;
    flip_key_fault_path_bit();
}
static void key_fault_hash_hook(const unsigned char *in, size_t inlen) {
    if (!g_key_fault_armed || g_key_fault == KEY_FAULT_ADDRESS) return;
    if (g_key_fault == KEY_FAULT_PATH_READ && g_key_fault_path != NULL) {
        flip_key_fault_path_bit();
    } else if (g_key_fault == KEY_FAULT_KEY && g_key_fault_bit < 8 * inlen) {
        ((unsigned char *) in)[g_key_fault_bit / 8] ^= (unsigned char) (1u << (g_key_fault_bit % 8));
    }
    g_key_fault_armed = 0;
}
static void key_fault_ripemd_hook(unsigned char *out, size_t outlen) {
    if (!g_key_fault_armed || g_key_fault != KEY_FAULT_ADDRESS) return;
    if (g_key_fault_bit < 8 * outlen) out[g_key_fault_bit / 8] ^= (unsigned char) (1u << (g_key_fault_bit % 8));
    g_key_fault_armed = 0;
}

/* G1: one fault while the review is built cannot make "Signing with" name another key than the
 * one that signs: the commit refuses, or it signs with the reviewed path and clean text. */
static void check_key_while_built(void) {
    static const char *const WHERE[] = {"the path while the key shown was derived", "the key shown",
                                        "the address shown"};
    static const unsigned int BITS[] = {32 * ELA_PATH_LEN, 8 * (COMPRESSED_PUBKEY_LEN + 2),
                                        8 * (ELA_PROGRAM_HASH_LEN - 1)};
    static char clean_desc[MAX_TX_TEXT_SCREENS][MAX_TX_TEXT_LINES][MAX_TX_TEXT_WIDTH];
    static char clean_title[MAX_TX_TEXT_SCREENS][MAX_TX_TEXT_WIDTH];
    unsigned int reviewed[ELA_PATH_LEN];
    tail_review_path(reviewed);
    reset_app();
    if (commit_tail_review() != SW_OK) {
        fail("G1", "the tail transaction was refused");
        return;
    }
    memcpy(clean_desc, tx_desc, sizeof(clean_desc));
    memcpy(clean_title, review_title, sizeof(clean_title));
    for (int fault = 0; fault < KEY_FAULTS; fault++) {
        for (unsigned int bit = 0; bit < BITS[fault]; bit++) {
            unsigned short sw;
            reset_app();
            g_key_fault = fault;
            g_key_fault_bit = bit;
            g_key_fault_path = NULL;
            g_key_fault_armed = 1;
            g_derive_hook = key_fault_derive_hook;
            g_hash_input_hook = key_fault_hash_hook;
            g_ripemd_output_hook = key_fault_ripemd_hook;
            unsigned short commit_sw = commit_tail_review();
            g_derive_hook = NULL;
            g_hash_input_hook = NULL;
            g_ripemd_output_hook = NULL;
            g_key_fault_armed = 0;
            // the app ends the session on any refusal
            if (commit_sw != SW_OK) continue;
            int clean_text = memcmp(tx_desc, clean_desc, sizeof(clean_desc)) == 0 &&
                             memcmp(review_title, clean_title, sizeof(clean_title)) == 0;
            g_derived_path_len = 0;
            if (probe_sign(&sw) && (!derived_from(reviewed) || !clean_text)) {
                fail("G1", "bit %u of %s flipped before the first render: the review %s, and the key of "
                           "%08x/%08x/%08x/%08x/%08x signed", bit, WHERE[fault],
                     clean_text ? "was the reviewed path's" : "showed another address", g_derived_path[0],
                     g_derived_path[1], g_derived_path[2], g_derived_path[3], g_derived_path[4]);
            }
        }
    }
    reset_app();
}

/* Counts the review text parts hashed at signing, and flips a committed path bit at one. */
static unsigned int g_text_parts, g_text_fault_part, g_text_fault_bit;
static void text_path_fault_hook(const unsigned char *in, size_t inlen) {
    (void) inlen;
    if (in != (const unsigned char *) review_title && in != (const unsigned char *) tx_desc) return;
    if (++g_text_parts == g_text_fault_part) committed_path[g_text_fault_bit / 32] ^= 1u << (g_text_fault_bit % 32);
}

/* G1: the path is checked last, just before the derivation, so a flipped path bit during the text
 * hash signs nothing or signs with the reviewed path. */
static void check_path_during_text_hash(void) {
    unsigned int reviewed[ELA_PATH_LEN];
    unsigned short sw;
    tail_review_path(reviewed);
    // count the text parts a clean signing hashes
    reset_app();
    int signed_clean = commit_tail_review() == SW_OK;
    g_text_parts = g_text_fault_part = 0;
    g_hash_input_hook = text_path_fault_hook;
    signed_clean = signed_clean && probe_sign(&sw);
    g_hash_input_hook = NULL;
    unsigned int parts = g_text_parts;
    if (!signed_clean || parts == 0) {
        fail("G1", "the tail review did not sign, or signing hashed no review text");
        return;
    }
    for (unsigned int part = 1; part <= parts; part++) {
        for (unsigned int bit = 0; bit < 32 * ELA_PATH_LEN; bit++) {
            reset_app();
            if (commit_tail_review() != SW_OK) {
                fail("G1", "the tail transaction was refused");
                return;
            }
            g_text_parts = 0;
            g_text_fault_part = part;
            g_text_fault_bit = bit;
            g_derived_path_len = 0;
            g_hash_input_hook = text_path_fault_hook;
            int signed_it = probe_sign(&sw);
            g_hash_input_hook = NULL;
            if (signed_it && !derived_from(reviewed)) {
                fail("G1", "bit %u of the committed path flipped while part %u of %u of the review text was hashed "
                           "at signing: signed with %08x/%08x/%08x/%08x/%08x", bit, part, parts, g_derived_path[0],
                     g_derived_path[1], g_derived_path[2], g_derived_path[3], g_derived_path[4]);
            }
        }
    }
    reset_app();
}

/* Reports a hash reading past raw_tx before it runs, which the sanitizer might stop. */
static int g_read_past_buffer;
static void buffer_end_hook(const unsigned char *in, size_t inlen) {
    uintptr_t start = (uintptr_t) raw_tx, end = start + sizeof(raw_tx), at = (uintptr_t) in;
    if (at < start || at >= end || inlen <= end - at) return;
    g_read_past_buffer = 1;
    fail("G1", "signing hashes %zu bytes from byte %zu of the %zu-byte transaction buffer, past its end", inlen,
         (size_t) (at - start), sizeof(raw_tx));
}

/* G1: a flipped bit in the committed body length signs nothing and reads nothing past raw_tx,
 * which on the device could run past the app's memory before the digest check refuses. */
static void check_body_len_faults(void) {
    for (unsigned int bit = 0; bit < 32; bit++) {
        unsigned short sw;
        reset_app();
        if (commit_tail_review() != SW_OK) {
            fail("G1", "the tail transaction was refused");
            return;
        }
        committed_body_len ^= 1u << bit;
        g_read_past_buffer = 0;
        g_hash_input_hook = buffer_end_hook;
        int signed_it = probe_sign(&sw);
        g_hash_input_hook = NULL;
        // a higher bit would read further past the buffer
        if (g_read_past_buffer) break;
        if (signed_it || (sw != SW_NOT_ARMED && sw != SW_COMMIT_MISMATCH)) {
            fail("G1", "bit %u of the committed body length flipped, signing returned %04x", bit, sw);
        }
    }
    reset_app();
}

/* Set by check_parsed_length_faults to make prepare_review's first (before arming) or second
 * comparison of raw_tx_ix with the body length pass. */
enum { BODY_CHECK_NONE = 0, BODY_CHECK_FIRST, BODY_CHECK_SECOND };
static int g_body_check_passing;
static unsigned int g_body_len_taken;

static unsigned int *raw_tx_ix_in_main(void) {
    static unsigned int passing;
    int check = tx_session_is_armed() ? BODY_CHECK_SECOND : BODY_CHECK_FIRST;
    if (g_body_check_passing != check) return &raw_tx_ix;
    g_body_check_passing = BODY_CHECK_NONE;
    passing = g_body_len_taken;
    return &passing;
}

/* For check_parsed_length_faults: flip bit g_len_fault_bit of raw_tx_len once, at hash
 * g_len_fault_call, or at the key derivation if 0, after prepare_review read it. */
static unsigned int g_len_hashes, g_len_fault_call, g_len_fault_bit;
static int g_len_fault_armed;
static void flip_len_bit(void) {
    raw_tx_len ^= 1u << g_len_fault_bit;
    g_len_fault_armed = 0;
}
static void len_fault_hook(void) {
    g_len_hashes++;
    if (g_len_fault_armed && g_len_hashes == g_len_fault_call) flip_len_bit();
}
static void len_derive_hook(const unsigned int *path) {
    (void) path;
    if (g_len_fault_armed && g_len_fault_call == 0) flip_len_bit();
}

/* The tail transaction with extra bytes before its path, which the parser refuses as trailing. */
static unsigned short commit_tail_with_extra(unsigned int extra) {
    const corpus_apdu_t *t = &CORPUS[TAIL_SIGN_IX];
    unsigned int body = t->n - APDU_HEADER_LENGTH - PATH_BYTES;
    tx_session_begin();
    memcpy(raw_tx, t->p + APDU_HEADER_LENGTH, body);
    memset(raw_tx + body, 0xEE, extra);
    memcpy(raw_tx + body + extra, t->p + APDU_HEADER_LENGTH + body, PATH_BYTES);
    raw_tx_ix = raw_tx_len = body + extra + PATH_BYTES;
    return prepare_review();
}

/* G1: the committed bytes are exactly those the parser read. With extra bytes after the body, a
 * flipped raw_tx_len bit after prepare_review read it can hide them from the parser; nothing may
 * sign, even with one of the two length comparisons passing. */
static void check_parsed_length_faults(void) {
    static const char *const PASSING[] = {"", ", with the first length check passing",
                                          ", with the second length check passing"};
    const corpus_apdu_t *t = &CORPUS[TAIL_SIGN_IX];
    unsigned int clean = t->n - APDU_HEADER_LENGTH;
    for (unsigned int bit = 0; clean + (1u << bit) <= MAX_TX_RAW_LENGTH; bit++) {
        unsigned int extra = 1u << bit;
        if ((clean & extra) != 0) continue;
        // count the hashes of the refused commit
        reset_app();
        g_len_hashes = 0;
        g_len_fault_armed = 0;
        g_sha_hook = len_fault_hook;
        unsigned short sw = commit_tail_with_extra(extra);
        g_sha_hook = NULL;
        unsigned int window = g_len_hashes;
        if (sw != SW_TX_TRAILING_BYTES) {
            fail("G1", "the tail transaction with %u bytes after its body returned %04x, not %04x", extra, sw,
                 SW_TX_TRAILING_BYTES);
            continue;
        }
        for (unsigned int call = 0; call <= window; call++) {
            for (int passing = BODY_CHECK_NONE; passing <= BODY_CHECK_SECOND; passing++) {
                unsigned short sign_sw;
                reset_app();
                g_len_hashes = 0;
                g_len_fault_call = call;
                g_len_fault_bit = bit;
                g_len_fault_armed = 1;
                g_body_check_passing = passing;
                g_body_len_taken = clean + extra - PATH_BYTES;
                g_sha_hook = len_fault_hook;
                g_derive_hook = len_derive_hook;
                sw = commit_tail_with_extra(extra);
                g_sha_hook = NULL;
                g_derive_hook = NULL;
                g_len_fault_armed = 0;
                g_body_check_passing = BODY_CHECK_NONE;
                if (sw == SW_OK && probe_sign(&sign_sw)) {
                    fail("G1", "raw_tx_len flipped from %u to %u at point %u of the commit (0 the key derivation, "
                               "then each hash)%s: a body %u longer than the parser read was signed", clean + extra,
                         clean, call, PASSING[passing], extra);
                }
            }
        }
    }
    reset_app();
}

/* G1: the checks of this group, each on the tail review committed afresh. */
static void check_session_faults(void) {
    check_second_checks();
    check_first_digest_comparison();
    check_text_hash_failure();
    check_buffered_path_faults();
    check_path_while_built();
    check_path_flipped_before_key();
    check_refused_path_committed();
    check_key_while_built();
    check_path_during_text_hash();
    check_body_len_faults();
    check_parsed_length_faults();
}

/* True if some wipe the app made covers the whole range. */
static int was_wiped(const void *p, size_t n) {
    const unsigned char *q = (const unsigned char *) p;
    for (unsigned int k = 0; k < g_wipe_count && k < MAX_WIPES; k++) {
        if (g_wipes[k].p <= q && q + n <= g_wipes[k].p + g_wipes[k].n) return 1;
    }
    return 0;
}

/* W1: the raw derivation and private key are wiped on return, whichever step fails. */
static void check_key_wipes(void) {
    static const unsigned int path[ELA_PATH_LEN] = {0x8000002C, 0x80000901, 0x80000000, 0, 0};
    static const char *const FAULT[] = {"no fault", "the derivation fails", "the key setup fails",
                                        "the public key or the signature fails"};
    uint8_t digest[ELA_DIGEST_LEN] = {0};
    for (int fault = 0; fault < 4; fault++) {
        for (int op = 0; op < 2; op++) {
            uint8_t out[80];
            size_t len = sizeof(out);
            g_wipe_count = 0;
            g_derive_out = NULL;
            g_private_key = NULL;
            g_fail_derive = fault == 1;
            g_fail_init_key = fault == 2;
            g_fail_pair = g_fail_sign = fault == 3;
            g_probe = 1;
            if (op == 0) {
                keys_get_public_key(path, out);
            } else {
                keys_sign_digest(path, digest, out, &len);
            }
            g_probe = 0;
            g_fail_derive = g_fail_init_key = g_fail_pair = g_fail_sign = 0;
            const char *call = op == 0 ? "key request" : "signature";
            if (g_derive_out == NULL || !was_wiped(g_derive_out, 64)) {
                fail("W1", "%s when %s: the raw derivation output was not wiped", call, FAULT[fault]);
            }
            if (g_private_key != NULL && !was_wiped(g_private_key, sizeof(*g_private_key))) {
                fail("W1", "%s when %s: the private key was not wiped", call, FAULT[fault]);
            }
        }
    }
}

/* What check_idle_timer does at tick 3000. Sign and key requests restart the count, accepted or
 * refused; other commands do not. */
enum {
    IDLE_NOTHING, IDLE_BUTTON, IDLE_KEY, IDLE_SIGN_PART, IDLE_ADDRESS_CHECK,
    // the commands from here on are refused
    IDLE_KEY_REFUSED, IDLE_SIGN_PART_REFUSED, IDLE_UNKNOWN_INS, IDLE_EVENTS
};
static const char *const IDLE_EVENT[IDLE_EVENTS] = {
    "left alone", "a button press", "a key request answered at once", "the first part of a sign request",
    "a key request that shows its address", "a key request on a path the specification refuses",
    "a sign part with an unknown P1", "an unknown instruction"};

static void send_idle_command(unsigned int k) {
    static const unsigned char SIGN_PART[] = {0x80, 0x02, 0x00, 0x00, 0x01, 0x02};
    static const unsigned char UNKNOWN_INS[] = {0x80, 0x03, 0x00, 0x00, 0x00};
    const corpus_apdu_t *key = &CORPUS[k == IDLE_ADDRESS_CHECK ? ADDR_FIRST : GETPUB_IX];
    const unsigned char *apdu = key->p;
    unsigned int len = key->n;
    if (k == IDLE_SIGN_PART || k == IDLE_SIGN_PART_REFUSED) {
        apdu = SIGN_PART;
        len = sizeof(SIGN_PART);
    } else if (k == IDLE_UNKNOWN_INS) {
        apdu = UNKNOWN_INS;
        len = sizeof(UNKNOWN_INS);
    }
    memcpy(G_io_apdu_buffer, apdu, len);
    if (k == IDLE_KEY_REFUSED) G_io_apdu_buffer[5 + 8] &= 0x7F;  // an account that is not hardened
    if (k == IDLE_SIGN_PART_REFUSED) G_io_apdu_buffer[2] = 0x55;
    int refused = k >= IDLE_KEY_REFUSED;
    unsigned int data_len = 0, reply_flags = 0;
    bool exit_now = false;
    if ((handle_apdu(len, &data_len, &reply_flags, &exit_now) != SW_OK) != refused) {
        fail("T2", "%s was %s", IDLE_EVENT[k], refused ? "accepted" : "refused");
    }
    // the transaction a sign part opened is dropped; an address check stays up, waiting
    tx_session_reset();
}

/* T2: the app closes on exactly tick 4098 after start or the last press, sign or key request. */
static void check_idle_timer(void) {
    for (unsigned int variant = 0; variant < IDLE_EVENTS; variant++) {
        unsigned long press_tick = variant == IDLE_NOTHING ? 0 : 3000;
        // an unknown instruction does not restart the count
        unsigned long restart_tick = variant == IDLE_UNKNOWN_INS ? 0 : press_tick;
        reset_app();
        g_script_len = 0;
        g_script_ix = 0;
        if (run_app() != 1) {
            fail("T2", "the app did not start");
            continue;
        }
        volatile unsigned long delivered = 0;
        if (setjmp(g_case_jmp) == 0) {
            for (;;) {
                if (press_tick != 0 && delivered == press_tick) {
                    if (variant == IDLE_BUTTON) {
                        G_io_seproxyhal_spi_buffer[0] = SEPROXYHAL_TAG_BUTTON_PUSH_EVENT;
                        io_event(0);
                    } else {
                        send_idle_command(variant);
                    }
                }
                deliver_tick();
                delivered++;
                if (delivered > 3 * SPEC_EXIT_TICKS) {
                    fail("T2", "%s: the app never closes", IDLE_EVENT[variant]);
                    break;
                }
            }
        } else if (delivered + 1 != restart_tick + SPEC_EXIT_TICKS) {
            fail("T2", "%s: the app closed on tick %lu, not %lu", IDLE_EVENT[variant], delivered + 1,
                 restart_tick + SPEC_EXIT_TICKS);
        }
        g_ela_jmp_ptr = &g_ela_jmp_app;
        g_in_tick = 0;
    }
}

static int timer_wait_is_up(int address) {
    if (address) return uiState == UI_ADDRESS_CHECK && address_check_pending;
    return uiState == UI_TOP_SIGN && tx_session_is_armed();
}

/* T2: a waiting review or address check closes on exactly tick 4098 after it, or after a press. */
static void check_review_timer(void) {
    static const char *const WAIT[] = {"review", "address check"};
    unsigned long reviews = g_reviews, shown = g_address_shown;
    for (unsigned int variant = 0; variant < 4; variant++) {
        int address = variant >= 2;
        unsigned long press_tick = variant % 2 == 0 ? 0 : 3000;
        reset_app();
        g_script_len = 0;
        g_script_ix = 0;
        push_corpus(address ? ADDR_FIRST : TAIL_SIGN_IX);
        if (run_app() != 1 || !timer_wait_is_up(address)) {
            fail("T2", "the request did not put the %s up", WAIT[address]);
            continue;
        }
        volatile unsigned long delivered = 0;
        if (setjmp(g_case_jmp) == 0) {
            for (;;) {
                if (press_tick != 0 && delivered == press_tick) do_press(BUTTON_RIGHT);
                deliver_tick();
                delivered++;
                if (delivered > 3 * SPEC_EXIT_TICKS) {
                    fail("T2", "a waiting %s never closes", WAIT[address]);
                    break;
                }
            }
        } else if (delivered + 1 != press_tick + SPEC_EXIT_TICKS) {
            fail("T2", "a waiting %s closed on tick %lu, not %lu", WAIT[address], delivered + 1,
                 press_tick + SPEC_EXIT_TICKS);
        }
        g_ela_jmp_ptr = &g_ela_jmp_app;
        g_in_tick = 0;
    }
    g_reviews = reviews;
    g_address_shown = shown;
    reset_app();
}

/* transport starts, and the canary bits S1 flips at each, as a stack overflow would */
static unsigned int g_transport_starts;
static unsigned int g_canary_flip;

/* Called by the stub io_seproxyhal_init right after it writes the canary. */
void sm_on_transport_start(void) {
    g_transport_starts++;
    app_stack_canary ^= g_canary_flip;
}

/* S1: after a USB reset an intact canary lets the app carry on; a changed one resets. */
static void check_stack_canary(void) {
    unsigned long faults = g_faults;
    for (unsigned int changed = 0; changed < 2; changed++) {
        reset_app();
        g_script_len = 0;
        g_script_ix = 0;
        push(ACT_IO_FAULT);  // code 0: a USB reset, so the transport starts again
        push_corpus(GETPUB_IX);
        g_script[g_script_len - 1].tail = TAIL_PUB;
        g_transport_starts = 0;
        g_canary_flip = changed ? 0x100u : 0;
        int rc = run_app();
        g_canary_flip = 0;
        if (changed && (rc != 4 || g_transport_starts != 1)) {
            fail("S1", "a restart with the canary changed did not reset the device: run ended %d after %u starts", rc,
                 g_transport_starts);
        } else if (!changed && (rc != 1 || g_transport_starts != 2 || !g_tail_pub_ok)) {
            fail("S1", "a restart with the canary intact did not carry on: run ended %d after %u starts, key reply %d",
                 rc, g_transport_starts, g_tail_pub_ok);
        }
    }
    g_faults = faults;
    reset_app();
}

/* Address check flows run once, on the second account's path, and the refused key requests. */
enum {
    FLOW_APPROVE, FLOW_REJECT, FLOW_BOTH_EARLY, FLOW_READ_BACK, FLOW_USB_RESET, FLOW_NO_COMMAND, FLOW_SDK_ERROR,
    FLOW_REFUSED, FLOWS
};

static void push_address_flow(int flow) {
    if (flow == FLOW_REFUSED) {
        for (unsigned int i = ADDR_FIRST; i < ADDR_FIRST + ADDR_COUNT; i++) {
            const unsigned char *c = CORPUS[i].p;
            if (key_request_refused(c[2], c[3], CORPUS[i].n, c + 5)) push_corpus(i);
        }
        return;
    }
    push_corpus(ADDR_FIRST);
    unsigned int to_approve = presses_to(PAGE_APPROVE), to_reject = presses_to(PAGE_REJECT);
    switch (flow) {
        case FLOW_APPROVE:
            push_presses_right(to_approve);
            push(ACT_BOTH);
            break;
        case FLOW_REJECT:
            push_presses_right(to_reject);
            push(ACT_BOTH);
            break;
        case FLOW_BOTH_EARLY:
            for (unsigned int p = 0; p < to_approve; p++) {
                push(ACT_BOTH);
                push(ACT_RIGHT);
            }
            push(ACT_BOTH);
            break;
        case FLOW_READ_BACK:
            // one press past each end, which must stay there
            push_presses_right(ADDRESS_PAGES);
            for (unsigned int p = 0; p < ADDRESS_PAGES; p++) push(ACT_LEFT);
            push_presses_right(to_approve);
            push(ACT_BOTH);
            break;
        default:  // an SDK error while the check waits, then a second check, approved
            push(ACT_RIGHT);
            push(ACT_IO_FAULT)->len = (unsigned int) (flow - FLOW_USB_RESET);
            push_corpus(ADDR_FIRST);
            push_presses_right(presses_to(PAGE_APPROVE));
            push(ACT_BOTH);
            break;
    }
}

/* A1 to A3 on scripted address check flows, each followed by a key request; then Approve and
 * Reject with no check waiting must send nothing. */
static void check_address_flows(void) {
    static const char *const FLOW[] = {"approved", "rejected", "with both buttons on each page before Approve",
                                       "read back from Reject", "ended by a USB reset",
                                       "ended by a reply with no command to answer", "ended by an SDK error",
                                       "refused"};
    unsigned long faults = g_faults, shown = g_address_shown, approved_all = g_address_approved,
                  rejected_all = g_address_rejected;
    for (int flow = 0; flow < FLOWS; flow++) {
        unsigned int shows = flow == FLOW_REFUSED ? 0 : flow >= FLOW_USB_RESET ? 2 : 1;
        unsigned int approved = flow == FLOW_REJECT || flow == FLOW_REFUSED ? 0 : 1;
        unsigned int rejected = flow == FLOW_REJECT;
        reset_app();
        g_script_len = 0;
        g_script_ix = 0;
        push_address_flow(flow);
        push_corpus(GETPUB_IX);
        g_script[g_script_len - 1].tail = TAIL_PUB;
        int rc = run_app();
        if (g_addr.shows != shows) {
            fail("A1", "address check %s: shown %u times, not %u", FLOW[flow], g_addr.shows, shows);
        }
        if (g_addr.approved != approved || g_addr.rejected != rejected) {
            fail("A2", "address check %s: approved %u and rejected %u times, not %u and %u", FLOW[flow],
                 g_addr.approved, g_addr.rejected, approved, rejected);
        }
        if (rc != 1 || !g_tail_pub_ok || uiState != UI_IDLE || address_check_pending) {
            fail("A3", "address check %s: run ended %d, next key reply %d, uiState %d, check pending %d", FLOW[flow],
                 rc, g_tail_pub_ok, uiState, address_check_pending);
        }
    }
    for (int answered = 0; answered < 2; answered++) {
        reset_app();
        g_script_len = 0;
        g_script_ix = 0;
        if (answered) {
            push_address_flow(FLOW_APPROVE);
            run_app();
        }
        unsigned int unasked = g_addr.unasked;
        address_check_approve();
        address_check_reject();
        if (g_addr.unasked != unasked) {
            fail("A2", "Approve or Reject with no address check waiting%s sent a reply",
                 answered ? ", after one was approved," : "");
        }
    }
    g_faults = faults;
    g_address_shown = shown;
    g_address_approved = approved_all;
    g_address_rejected = rejected_all;
}

/* A1: a P1 01 request for WIDE_PATH, from home or the account screen, gets 6D60 and shows
 * nothing; the next key request still works. */
static void check_wide_address_refused(void) {
    char address[sizeof(g_account_address)];
    compute_address(WIDE_PATH, address);
    if (strcmp(address, WIDE_ADDRESS) != 0 || !address_too_wide(address)) {
        fail("A1", "the address worked out for the wide path is %s, not %s with a line too wide", address,
             WIDE_ADDRESS);
        return;
    }
    for (int from_account = 0; from_account < 2; from_account++) {
        reset_app();
        g_script_len = 0;
        g_script_ix = 0;
        if (from_account) push(ACT_RIGHT);
        push_corpus(ADDR_FIRST);
        put_wide_path(&g_script[g_script_len - 1]);
        push_corpus(GETPUB_IX);
        g_script[g_script_len - 1].tail = TAIL_PUB;
        int rc = run_app();
        int want = from_account ? UI_PUBLIC_KEY_1 : UI_IDLE;
        if (rc != 1 || g_addr.shows != 0 || !g_tail_pub_ok || uiState != want || address_check_pending) {
            fail("A1", "a P1 01 request for the wide address from the %s: run ended %d, shown %u times, next key "
                       "reply %d, uiState %d, check pending %d", from_account ? "account screen" : "home screen", rc,
                 g_addr.shows, g_tail_pub_ok, uiState, address_check_pending);
        }
    }
    reset_app();
}

/* A2: on the longest path, three lines, with one element of a path, address or Approve page not
 * sent, Approve must not answer until that page is drawn again in full. */
static void check_address_pages_drawn_in_full(void) {
    static const unsigned int LONGEST[ELA_PATH_LEN] = {0x8000002C, 0x80000901, 0xFFFFFFFF, 1, 0x7FFFFFFF};
    static const int PAGES[] = {PAGE_PATH, PAGE_PATH_REST, PAGE_LINES_1_2, PAGE_LINES_2_3, PAGE_APPROVE};
    unsigned long faults = g_faults, shown = g_address_shown, approved_all = g_address_approved,
                  refused_all = g_approve_refused_undrawn, after_fault = g_approved_after_fault;
    unsigned long refused_here = 0;
    for (size_t t = 0; t < sizeof(PAGES) / sizeof(PAGES[0]); t++) {
        int page = PAGES[t];
        for (unsigned int k = 0; k < ADDRESS_PAGE[page].count; k++) {
            reset_app();
            g_script_len = 0;
            g_script_ix = 0;
            push_corpus(ADDR_FIRST);
            action_t *request = &g_script[g_script_len - 1];
            for (unsigned int i = 0; i < PATH_BYTES; i++) {
                request->bytes[5 + i] = (unsigned char) (LONGEST[i / 4] >> (24 - 8 * (i % 4)));
            }
            unsigned int to_approve = presses_to(PAGE_APPROVE), to_page = presses_to(page);
            unsigned int back = to_approve > to_page ? to_approve - to_page : 1;
            push_presses_right(to_approve);
            push(ACT_BOTH);
            for (unsigned int i = 0; i < back; i++) push(ACT_LEFT);
            push_presses_right(back);
            push(ACT_BOTH);
            push_corpus(GETPUB_IX);
            g_script[g_script_len - 1].tail = TAIL_PUB;
            unsigned long refused = g_approve_refused_undrawn;
            g_forced_send_skip = &ADDRESS_PAGE[page].layout[k];
            int rc = run_app();
            refused_here += g_approve_refused_undrawn - refused;
            if (g_forced_send_skip != NULL) {
                g_forced_send_skip = NULL;
                fail("A2", "element %u of address check page %d was never handed to the SDK", k, page);
            } else if (rc != 1 || g_addr.shows != 1 || g_addr.approved != 1 || !g_tail_pub_ok) {
                fail("A2", "with element %u of address check page %d not sent, then the page drawn again: run "
                           "ended %d, shown %u times, approved %u times, next key reply %d", k, page, rc,
                     g_addr.shows, g_addr.approved, g_tail_pub_ok);
            }
        }
    }
    if (refused_here == 0) {
        fail("A2", "no press on Approve was refused for a page of the path or the address not drawn in full");
    }
    g_faults = faults;
    g_address_shown = shown;
    g_address_approved = approved_all;
    g_approve_refused_undrawn = refused_all;
    g_approved_after_fault = after_fault;
    reset_app();
}

/* Set by check_silent_range_faults to make the first or second silent range check pass. */
enum { SILENT_CHECK_NONE = 0, SILENT_CHECK_FIRST, SILENT_CHECK_SECOND };
static int g_silent_check_passing;
static unsigned int g_silent_checks_made, g_silent_checks_passed;

static bool silent_check_in_main(const unsigned int *path) {
    unsigned int check = ++g_silent_checks_made;
    if (g_silent_check_passing != SILENT_CHECK_NONE && check == (unsigned int) g_silent_check_passing) {
        g_silent_checks_passed++;
        return true;
    }
    return keys_path_is_silent(path);
}

static void put_silent_request(const unsigned int path[ELA_PATH_LEN],
                               unsigned char apdu[APDU_HEADER_LENGTH + PATH_BYTES]) {
    static const unsigned char HEADER[APDU_HEADER_LENGTH] = {0x80, 0x04, KEY_P1_SILENT, 0x00, PATH_BYTES};
    memcpy(apdu, HEADER, sizeof(HEADER));
    for (unsigned int i = 0; i < PATH_BYTES; i++) {
        apdu[APDU_HEADER_LENGTH + i] = (unsigned char) (path[i / 4] >> (24 - 8 * (i % 4)));
    }
}

/* Sends apdu to handle_apdu with one silent range check passing; returns the status word. */
static unsigned short silent_request(const unsigned char apdu[APDU_HEADER_LENGTH + PATH_BYTES], int passing,
                                     unsigned int *data_len) {
    unsigned int flags = 0;
    bool exit_now = false;
    memset(G_io_apdu_buffer, 0, sizeof(G_io_apdu_buffer));
    memcpy(G_io_apdu_buffer, apdu, APDU_HEADER_LENGTH + PATH_BYTES);
    *data_len = 0;
    g_silent_checks_made = 0;
    g_silent_checks_passed = 0;
    g_silent_check_passing = passing;
    unsigned short sw = handle_apdu(APDU_HEADER_LENGTH + PATH_BYTES, data_len, &flags, &exit_now);
    g_silent_check_passing = SILENT_CHECK_NONE;
    if (flags != 0 || exit_now) {
        fail("G1", "a P1 00 request left reply flags %02x and exit %d", flags, exit_now);
    }
    return sw;
}

/* G1: with either silent range check made to pass, a path outside the range still gets 6D63
 * from the other, derives nothing and leaves the buffer as it was. */
static void check_silent_range_faults(void) {
    static const unsigned int OUTSIDE[][ELA_PATH_LEN] = {
        {0x8000002C, 0x80000901, 0x80000065, 0, 0},           // account 101', the first outside
        {0x8000002C, 0x80000901, 0x80000000, 0, 50001},       // index 50,001, the first outside
        {0x8000002C, 0x80000901, 0xFFFFFFFF, 1, 0x7FFFFFFF},  // the last account and index of all
    };
    static const unsigned int INSIDE[ELA_PATH_LEN] = {0x8000002C, 0x80000901, 0x80000064, 1, 50000};
    unsigned char apdu[APDU_HEADER_LENGTH + PATH_BYTES];
    unsigned char key[ELA_PUBKEY_LEN];
    unsigned int data_len;
    for (int passing = SILENT_CHECK_FIRST; passing <= SILENT_CHECK_SECOND; passing++) {
        for (size_t k = 0; k < sizeof(OUTSIDE) / sizeof(OUTSIDE[0]); k++) {
            reset_app();
            put_silent_request(OUTSIDE[k], apdu);
            unsigned long derivations = g_derivations;
            unsigned short sw = silent_request(apdu, passing, &data_len);
            int buffer_kept = memcmp(G_io_apdu_buffer, apdu, sizeof(apdu)) == 0;
            if (sw != SPEC_SW_PATH_NEEDS_CHECK || data_len != 0 || g_derivations != derivations || !buffer_kept) {
                fail("G1", "with the %s check of the silent range made to pass, a P1 00 request for account %08x "
                           "and index %u got %04X with %u bytes, after %lu derivations, buffer %s",
                     passing == SILENT_CHECK_FIRST ? "first" : "second", OUTSIDE[k][2], OUTSIDE[k][4], sw, data_len,
                     g_derivations - derivations, buffer_kept ? "as the request left it" : "changed");
            }
            if (passing == SILENT_CHECK_FIRST && g_silent_checks_passed != 1) {
                fail("G1", "the fault meant for the first check of the silent range made %u checks pass",
                     g_silent_checks_passed);
            }
        }
    }
    reset_app();
    put_silent_request(INSIDE, apdu);
    unsigned short sw = silent_request(apdu, SILENT_CHECK_FIRST, &data_len);
    unsigned int passed = g_silent_checks_passed;
    compute_public_key(INSIDE, key);
    if (sw != SW_OK || data_len != ELA_PUBKEY_LEN || memcmp(G_io_apdu_buffer, key, ELA_PUBKEY_LEN) != 0 ||
        passed != 1) {
        fail("G1", "with the first check of the silent range made to pass, a P1 00 request inside the range got "
                   "%04X with %u bytes, %u checks made to pass", sw, data_len, passed);
    }
    reset_app();
}

/* One crypto failure scenario, then the recovery tail. */
static void push_crypto_failure(int kind) {
    switch (kind) {
        case FAIL_KEY_SILENT:
            push_corpus(GETPUB_IX);
            break;
        case FAIL_KEY_SHOW:
            push_corpus(ADDR_FIRST);
            break;
        case FAIL_SIGN_REQUEST:
            push_legit(SEND_CHANGE_LEGIT);
            break;
        case FAIL_ADDRESS_APPROVE:
            push_corpus(ADDR_FIRST);
            push_presses_right(presses_to(PAGE_APPROVE));
            push(ACT_BOTH);
            break;
        default:  // Accept on a review read in full
            push_legit(SEND_CHANGE_LEGIT);
            push(ACT_WALK_TO_SIGN);
            push(ACT_BOTH);
            break;
    }
    push(ACT_ANSWER_PENDING);
    push_corpus(GETPUB_IX);
    g_script[g_script_len - 1].tail = TAIL_PUB;
    push_corpus(TAIL_SIGN_IX);
    g_script[g_script_len - 1].tail = TAIL_SIGN;
    push(ACT_WALK_TO_SIGN)->tail = TAIL_WALK;
    push(ACT_BOTH)->tail = TAIL_APPROVE;
}

/* F1: each of the five fails once at every step it reaches; the app must then still give a key
 * and sign. */
static void check_crypto_failures(void) {
    unsigned long reviews = g_reviews, shown = g_address_shown, answers = g_crypto_answers, faults[FAIL_KINDS];
    memcpy(faults, g_crypto_faults, sizeof(faults));
    for (int kind = FAIL_KEY_SILENT; kind < FAIL_KINDS; kind++) {
        for (int sw = 0; sw < SWITCHES; sw++) {
            if ((FAIL_REACHES[kind] & (1u << sw)) == 0) continue;
            unsigned long answered = g_crypto_answers;
            reset_app();
            g_script_len = 0;
            g_script_ix = 0;
            push_crypto_failure(kind);
            g_crypto.forced_kind = kind;
            g_crypto.forced_sw = sw;
            int rc = run_app();
            if (g_crypto.forced_kind != FAIL_NONE || g_crypto_answers != answered + 1) {
                fail("F1", "%s with %s failing: the failure %s", FAIL_KIND[kind], SWITCH_NAME[sw],
                     g_crypto.forced_kind != FAIL_NONE ? "was never reached" : "got no answer");
            }
            if (rc != 1 || !g_tail_pub_ok || !g_tail_sig_ok) {
                fail("F1", "after %s with %s failing, the app no longer returns a key and signs (run ended %d, key "
                           "reply %d, signature %d)", FAIL_KIND[kind], SWITCH_NAME[sw], rc, g_tail_pub_ok,
                     g_tail_sig_ok);
            }
        }
    }
    g_reviews = reviews;
    g_address_shown = shown;
    memcpy(g_crypto_faults, faults, sizeof(faults));
    g_crypto_answers = answers;
    reset_app();
}

/* the steps the account screen reaches: the key, then its address hash */
#define ACCOUNT_SWITCHES (KEY_SWITCHES | (1u << SWITCH_PROGRAM_HASH))

/* M3: the account screen part for state is up in full and shows exactly upper and lower. */
static void expect_account_lines(int state, const char *upper, const char *lower, const char *what) {
    const bagl_element_t *layout = state == UI_PUBLIC_KEY_1 ? bagl_ui_public_key_nanos_1 : bagl_ui_public_key_nanos_2;
    unsigned int count = state == UI_PUBLIC_KEY_1 ? LAYOUT_ELEMENTS(bagl_ui_public_key_nanos_1)
                                                 : LAYOUT_ELEMENTS(bagl_ui_public_key_nanos_2);
    const bagl_element_t *label[2];
    if (uiState != state || !frame_holds(layout, count) || drawn_labels(label, 2) != 2 || label[0]->text == NULL ||
        label[1]->text == NULL) {
        fail("M3", "%s: uiState %d, not %d, or the display does not hold that part of the account screen", what,
             uiState, state);
        return;
    }
    if (strcmp(label[0]->text, upper) != 0 || strcmp(label[1]->text, lower) != 0) {
        fail("M3", "%s: the account screen shows \"%s\" \"%s\", not \"%s\" \"%s\"", what, label[0]->text,
             label[1]->text, upper, lower);
        return;
    }
    two_rows_ok(upper, BAGL_FONT_OPEN_SANS_REGULAR_11px, lower, BAGL_FONT_OPEN_SANS_REGULAR_11px, what);
}

/* M3: after an address check of another path is approved, each failing step of the account
 * screen must show the placeholder, never the address just checked. */
static void check_account_screen_failures(void) {
    static const char PLACEHOLDER_0[] = "Could not get", PLACEHOLDER_1[] = "the address";
    unsigned long shown = g_address_shown, approved = g_address_approved;
    for (int sw = 0; sw < SWITCHES; sw++) {
        if ((ACCOUNT_SWITCHES & (1u << sw)) == 0) continue;
        char what[80];
        snprintf(what, sizeof(what), "the account screen with %s failing", SWITCH_NAME[sw]);
        reset_app();
        g_script_len = 0;
        g_script_ix = 0;
        push_address_flow(FLOW_APPROVE);
        if (run_app() != 1 || g_addr.approved != 1 || uiState != UI_IDLE) {
            fail("M3", "%s: the address check before it was not approved", what);
            continue;
        }
        *FAIL_SWITCH[sw] = 1;
        do_press(BUTTON_RIGHT);
        *FAIL_SWITCH[sw] = 0;
        expect_account_lines(UI_PUBLIC_KEY_1, PLACEHOLDER_0, PLACEHOLDER_1, what);
        do_press(BUTTON_RIGHT);
        expect_account_lines(UI_PUBLIC_KEY_2, PLACEHOLDER_1, "", what);
    }
    g_address_shown = shown;
    g_address_approved = approved;
    reset_app();
}

/* L1: a refused command or SDK error mid-transaction ends it, so the next transfer is reviewed
 * and signs on its own. */
static void check_refusal_mid_stream(void) {
    static const char *const REFUSED[] = {"a length byte that does not match the data", "an unknown P1",
                                          "a P2 other than 00", "an unknown instruction", "an unknown class",
                                          "a command shorter than its header", "an empty command",
                                          "a part past the end of the buffer", "an SDK error"};
    const unsigned int first = LEGIT_FIRST[LEGIT_COUNT - 1];
    const corpus_apdu_t *part = &CORPUS[first];
    unsigned long reviews = g_reviews, faults = g_faults;
    unsigned int status_errors = g_status_errors_thrown;
    for (unsigned int v = 0; v < sizeof(REFUSED) / sizeof(REFUSED[0]); v++) {
        reset_app();
        g_script_len = 0;
        g_script_ix = 0;
        push_corpus(first);  // with more to come, answered 9000
        if (v == 7) {
            // five parts of 255 bytes: the fifth no longer fits the 1024-byte buffer
            for (unsigned int i = 0; i < 4; i++) push_corpus(first);
        } else if (v == 8) {
            push(ACT_IO_FAULT)->len = 2;  // an error that gets a status word
        } else {
            action_t *a = push(ACT_APDU);
            memcpy(a->bytes, part->p, part->n);
            a->len = part->n;
            switch (v) {
                case 0: a->bytes[4]--; break;
                case 1: a->bytes[2] = 0x01; break;
                case 2: a->bytes[3] = 0x01; break;
                case 3: a->bytes[1] = 0x03; break;
                case 4: a->bytes[0] = 0xE0; break;
                case 5: a->len = 3; break;
                default: a->len = 0; break;
            }
        }
        push_corpus(TAIL_SIGN_IX);
        g_script[g_script_len - 1].tail = TAIL_SIGN;
        push(ACT_WALK_TO_SIGN)->tail = TAIL_WALK;
        push(ACT_BOTH)->tail = TAIL_APPROVE;
        int rc = run_app();
        if (rc != 1 || !g_tail_sig_ok) {
            fail("L1", "after %s while a transaction was being received, the wallet's next transfer was not "
                       "reviewed and signed (run ended %d)", REFUSED[v], rc);
        }
    }
    // the random cases meet the same SDK errors in turn as before
    g_status_errors_thrown = status_errors;
    g_reviews = reviews;
    g_faults = faults;
    reset_app();
}

/* L1: likewise for a key request, answered at once or through an approved or rejected check. */
static void check_key_request_mid_stream(void) {
    static const char *const REQUEST[] = {"a key request answered at once", "an address check approved",
                                          "an address check rejected"};
    const unsigned int first = LEGIT_FIRST[LEGIT_COUNT - 1];
    unsigned long reviews = g_reviews, shown = g_address_shown, approved_all = g_address_approved,
                  rejected_all = g_address_rejected;
    for (unsigned int v = 0; v < sizeof(REQUEST) / sizeof(REQUEST[0]); v++) {
        unsigned int approved = v == 1, rejected = v == 2;
        reset_app();
        g_script_len = 0;
        g_script_ix = 0;
        push_corpus(first);  // with more to come, answered 9000
        if (v == 0) {
            push_corpus(GETPUB_IX);
        } else {
            push_corpus(ADDR_FIRST);
            push_presses_right(presses_to(approved ? PAGE_APPROVE : PAGE_REJECT));
            push(ACT_BOTH);
        }
        push_corpus(TAIL_SIGN_IX);
        g_script[g_script_len - 1].tail = TAIL_SIGN;
        push(ACT_WALK_TO_SIGN)->tail = TAIL_WALK;
        push(ACT_BOTH)->tail = TAIL_APPROVE;
        int rc = run_app();
        if (g_addr.approved != approved || g_addr.rejected != rejected) {
            fail("A2", "%s while a transaction was being received: approved %u and rejected %u times, not %u and %u",
                 REQUEST[v], g_addr.approved, g_addr.rejected, approved, rejected);
        }
        if (rc != 1 || !g_tail_sig_ok) {
            fail("L1", "after %s while a transaction was being received, the wallet's next transfer was not "
                       "reviewed and signed (run ended %d)", REQUEST[v], rc);
        }
    }
    g_reviews = reviews;
    g_address_shown = shown;
    g_address_approved = approved_all;
    g_address_rejected = rejected_all;
    reset_app();
}

int main(int argc, char **argv) {
    unsigned long runs = argc > 1 ? strtoul(argv[1], NULL, 0) : 200000;
    g_seed = argc > 2 ? strtoull(argv[2], NULL, 0) : 0xF1C5001ull;
    rng_state = g_seed;

    const corpus_apdu_t *t = &CORPUS[TAIL_SIGN_IX];
    sm_sha256(t->p + 5, t->n - 5 - PATH_BYTES, g_tail_digest);

    printf("sm_fuzz (patched app, Nano S): runs=%lu seed=%llu\n", runs, (unsigned long long) g_seed);
    compute_public_key(WIDE_PATH, g_wide_key);
    compute_account_address();
    g_skip_display_send = skip_display_send;
    check_address_flows();
    check_address_pages_drawn_in_full();
    check_wide_address_refused();
    check_silent_range_faults();
    check_crypto_failures();
    check_account_screen_failures();
    check_signing_faults();
    check_text_binding();
    check_read_mask_faults();
    check_index_flip_boundary();
    check_double_checks();
    check_session_faults();
    check_key_wipes();
    check_idle_timer();
    check_review_timer();
    check_stack_canary();
    check_refusal_mid_stream();
    check_key_request_mid_stream();
    check_same_heading_flips();
    check_read_marks_per_review();
    check_sign_press_during_redraw();
    check_skipped_display_call();
    check_stale_index_after_redraw();
    check_skipped_element_send();
    check_skipped_status_check();
    for (g_case_no = 0; g_case_no < runs; g_case_no++) {
        if ((g_case_no & 0x7FFF) == 0) {
            fprintf(stderr, "...case %lu reviews=%lu sigs=%lu/%lu violations=%lu\n", g_case_no, g_reviews,
                    g_sigs_button, g_sigs_raw, g_violations);
        }
        rng_state = g_seed ^ (0xD1B54A32D192ED03ull * (g_case_no + 1));
        reset_app();
        gen_case();
        if (run_app() != 1) {
            g_exited = 1;  // left through the OS, or reset
            if (g_in_tick && g_idle_ticks + 1 < SPEC_EXIT_TICKS) {
                fail("T1", "a clock tick closed the app after %lu idle ticks", g_idle_ticks + 1);
            } else if (!g_in_tick && !g_expect_exit && !g_quit_pressed) {
                fail("X3", "the app closed without the exit instruction, Quit or the idle timer");
            }
            g_in_tick = 0;
            g_expect_exit = 0;
        }
        after_step("case-end");
        if (g_exited) {
            g_exits++;
        } else if (g_tail_pub_ok && g_tail_sig_ok) {
            g_tail_ok++;
        } else {
            fail("L1", "app no longer usable: key reply ok=%d, reviewed signature ok=%d", g_tail_pub_ok,
                 g_tail_sig_ok);
        }
    }
    printf("done: cases=%lu reviews=%lu (%lu with every screen used) button_signatures=%lu raw_signatures=%lu "
           "raw_unreviewed=%lu exits=%lu recovered=%lu sdk_faults=%lu dropped_commands=%lu violations=%lu\n",
           g_case_no, g_reviews, g_full_reviews, g_sigs_button, g_sigs_raw, g_raw_unreviewed, g_exits, g_tail_ok,
           g_faults, g_dropped, g_violations);
    printf("display faults: skipped_stores=%lu cut_draws=%lu skipped_sends=%lu skipped_status_checks=%lu "
           "presses_while_sending=%lu\n",
           g_skipped_stores, g_cut_draws, g_skipped_sends, g_skipped_status_checks, g_presses_in_flight);
    printf("address checks: shown=%lu approved=%lu rejected=%lu approved_after_a_display_fault=%lu "
           "approve_refused_before_drawn=%lu; P1 00 requests outside the silent range: %lu\n",
           g_address_shown, g_address_approved, g_address_rejected, g_approved_after_fault,
           g_approve_refused_undrawn, g_silent_refused);
    printf("failed crypto steps: key P1 00=%lu key P1 01=%lu sign request=%lu Approve=%lu Accept=%lu, answered %lu\n",
           g_crypto_faults[FAIL_KEY_SILENT], g_crypto_faults[FAIL_KEY_SHOW], g_crypto_faults[FAIL_SIGN_REQUEST],
           g_crypto_faults[FAIL_ADDRESS_APPROVE], g_crypto_faults[FAIL_REVIEW_ACCEPT], g_crypto_answers);
    printf("by check:");
    for (unsigned int k = 0; k < CHECK_COUNT; k++) printf(" %s=%lu", CHECKS[k], g_check_hits[k]);
    printf("\n");
    return g_violations ? 1 : 0;
}
