/*
 * Host check of the Nano X and Nano S Plus approval gate.
 *
 * Builds the real ui.c for Nano X with the real parser, session and key code, and a stand-in flow
 * engine (stubs/ux.h) in which this driver walks the flow itself. It moves the flow position, or
 * corrupts the flow or the gate's marks, as a fault would, and checks that Accept signs only after
 * every review step was drawn and only while Accept is on screen. Review checks run on a six-screen
 * transfer and on a nine-screen poll vote, which fills the flow so the sanitizers see it at its
 * largest.
 *
 *   G2  honest walks sign, also one that draws a step again
 *   G3  a jump to Accept past undrawn steps is refused with 6D5E, also with a gate check faulted
 *   G4  the position moved from Reject to Accept is refused
 *   G5  a review step duplicated in the flow is refused
 *   G6  a one-bit forward move past an undrawn step is refused
 *   G7  a skipped step marked drawn by one bit in the mask or its complement is refused
 *   G8  a stale or flipped Accept flag, or Accept drawn then left, is refused
 *   G9  the Reject slot or end marker overwritten is refused
 *   G10 a skipped layout call of a review step or Accept is refused
 *   G11 a flow with two review steps swapped is refused
 *   G12 the intro replaced by another step is refused
 *   G13 the Accept slot replaced, then a jump past the end marker onto a stale Accept (two faults,
 *       transfer only), is refused
 *   G14 the account screen shows its own address whole, never a cut or just-checked one
 *   G15 ui_review_on_screen() is true exactly while a review or address check is up
 *   G16 a drawing cut short at any element is refused
 *   G17 one element's draw skipped is refused
 *   G18 the address check's flow and path lines; Approve answers only once every step was drawn
 *       whole, and a refused press puts the flow back on Approve
 *
 * G11 to G13 set every mark, so only the checks of the flow's slots can refuse.
 *
 * usage: ./gate
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <setjmp.h>
#include <stdbool.h>
#include <stdint.h>

jmp_buf g_ela_jmp_app;
jmp_buf *g_ela_jmp_ptr = &g_ela_jmp_app;
jmp_buf g_case_jmp;
unsigned int g_last_throw;
int g_fail_derive, g_fail_init_key, g_fail_pair, g_fail_sign;
unsigned char *g_derive_out;

#include "os.h"
#include "cx.h"
#include "ux.h"
#include "bagl.h"
#include "os_io_seproxyhal.h"

G_io_app_t G_io_app;
unsigned char G_io_apdu_buffer[IO_APDU_BUFFER_SIZE];
unsigned char G_io_seproxyhal_spi_buffer[IO_SEPROXYHAL_BUFFER_SIZE_B];
cx_ecfp_private_key_t *g_private_key;
void (*g_sha_hook)(void);
const unsigned char *g_sha_hook_input;

/*
 * Approval checks the gate twice, and ui.c calls nothing between the checks a stub could hook. So
 * each review_shown_whole() call goes to gate_check(), which can fault the first or the second,
 * and the definition becomes review_shown_whole_void(). src/ needs no test hook.
 */
#define review_shown_whole(...) review_shown_whole_##__VA_ARGS__(__VA_ARGS__)
#define review_shown_whole_     gate_check
static bool gate_check(void);

/*
 * A real key's address is too wide for the screen about once in 7 trillion on Nano X, too rare to
 * grind. So the account screen's keys_program_hash() call goes to gate_program_hash(), which can
 * return such an address; keys.c still defines the real one. src/ needs no test hook.
 */
#define keys_program_hash gate_program_hash
static cx_err_t gate_program_hash(const uint8_t *pubkey, uint8_t *program_hash);

#include "ui.c"
#include "elastos.c"
#include "base-encoding.c"
#undef keys_program_hash
#include "keys.c"
#include "tx_session.c"

static unsigned long g_failures;
static unsigned int g_signatures;
static unsigned int g_last_sw;
static const ux_flow_step_t *const *g_flow;
static unsigned int g_index;
/* 0: the six-screen transfer; 1: the nine-screen poll vote */
static int g_vote;
/* set while the address check runs, so failures name it */
static int g_address_check;
/* one fault: the first gate check of each approval passes */
static int g_first_check_faulted;
/* one fault: the second gate check passes, so only acting on the first check's result refuses */
static int g_second_check_faulted;
static unsigned int g_gate_checks;

static bool gate_check(void) {
    g_gate_checks++;
    if (g_first_check_faulted && g_gate_checks == 1) {
        return true;
    }
    if (g_second_check_faulted && g_gate_checks == 2) {
        return true;
    }
    return review_shown_whole_void();
}

/* set by G14: replaces the program hash of the account screen's key */
static const uint8_t *g_account_program_hash;

static cx_err_t gate_program_hash(const uint8_t *pubkey, uint8_t *program_hash) {
    if (g_account_program_hash) {
        memcpy(program_hash, g_account_program_hash, ELA_PROGRAM_HASH_LEN);
        return CX_OK;
    }
    return keys_program_hash(pubkey, program_hash);
}

/* icons named by the step parameters the stub keeps */
const unsigned char C_icon_eye[] = {0};
const unsigned char C_icon_validate_14[] = {0};
const unsigned char C_icon_crossmark[] = {0};

void sm_on_wipe(void *p, size_t n) {
    (void) p;
    (void) n;
}

void sm_on_sign(const unsigned char *digest, const unsigned char *key_d) {
    (void) digest;
    (void) key_d;
    g_signatures++;
}

unsigned short io_exchange(unsigned char channel, unsigned short tx_len) {
    (void) channel;
    if (tx_len >= 2) g_last_sw = ((unsigned int) G_io_apdu_buffer[tx_len - 2] << 8) | G_io_apdu_buffer[tx_len - 1];
    return 0;
}

void ux_stack_push(void) {
    G_ux.stack_count++;
}

/* the next layout call is skipped, as by one skipped call instruction */
static int g_skip_layout;

/* nonzero: the next drawing stops at this element, as one fault in the SDK's loop would */
static unsigned int g_cut_draw_at;

/* nonzero: the next drawing skips this element and runs on, as one skipped call would */
static unsigned int g_skip_draw_of;

/* the SDK's element draw, which the app wraps to count elements drawn */
void __real_io_seph_ux_display_bagl_element(const bagl_element_t *element) {
    (void) element;
}

/* Draws a layout as the SDK does: the element index rises before each element and goes one past
 * the last only after the screen update, so a cut drawing leaves it where it stopped. */
void gate_draw_layout(unsigned int stack_slot, unsigned int count) {
    if (g_skip_layout) {
        g_skip_layout = 0;
        return;
    }
    memset(&G_ux.stack[stack_slot], 0, sizeof(G_ux.stack[stack_slot]));
    G_ux.stack[stack_slot].element_arrays[0].element_array_count = (unsigned char) count;
    unsigned int drawn = g_cut_draw_at ? g_cut_draw_at : count;
    for (unsigned int k = 1; k <= drawn; k++) {
        if (k != g_skip_draw_of) {
            __wrap_io_seph_ux_display_bagl_element(NULL);  // a skipped draw does not stop the loop
        }
    }
    G_ux.stack[stack_slot].element_index = (unsigned short) (g_cut_draw_at ? g_cut_draw_at : count + 1);
    g_cut_draw_at = 0;
    g_skip_draw_of = 0;
}

/* The flow engine runs a step's init when it shows it. */
static void draw(void) {
    if (g_flow[g_index]->init) g_flow[g_index]->init(0);
}

/* Shows the flow at start, or at its first step if start is not in it, as the SDK does. */
void ux_flow_init(unsigned int stack_slot, const ux_flow_step_t *const *steps, const ux_flow_step_t *start) {
    (void) stack_slot;
    g_flow = steps;
    g_index = 0;
    while (start != NULL && g_flow[g_index] != start && g_flow[g_index] != FLOW_END_STEP) {
        g_index++;
    }
    if (g_flow[g_index] == FLOW_END_STEP) {
        g_index = 0;
    }
    draw();
}

static const char *review_name(void) {
    if (g_address_check) {
        return "address check";
    }
    return g_vote ? "nine-screen vote" : "six-screen transfer";
}

static void fail(const char *check, const char *what) {
    g_failures++;
    printf("!!! %s on the %s: %s\n", check, review_name(), what);
}

/* Presses right up to index, drawing each step. */
static void walk_to(unsigned int index) {
    while (g_index < index) {
        g_index++;
        draw();
    }
}

/* Presses left down to index, drawing each step. */
static void walk_back_to(unsigned int index) {
    while (g_index > index) {
        g_index--;
        draw();
    }
}

/* ux_flow_validate runs a step's action as a one-step flow of its own, so the step's flow is gone
 * unless the action puts one back. */
static const ux_flow_step_t g_action_step = {0, 0, "a step's action, run as a flow of its own"};
static const ux_flow_step_t *const g_action_flow[] = {&g_action_step, FLOW_END_STEP};

/* Both buttons on the current step, as the SDK handles them. */
static void press_both(void) {
    const ux_flow_step_t *step = g_flow[g_index];
    if (step->validate) {
        g_flow = g_action_flow;
        g_index = 0;
        step->validate();
    }
}

static unsigned int review_screens(void) {
    return g_vote ? MAX_TX_TEXT_SCREENS : 6;
}

/* No attributes for the transfer; for the vote, a poll vote memo in the wallet's layout. */
static unsigned int put_attributes(unsigned int n) {
    static const char AMOUNT[] = "1234.5";
    if (!g_vote) {
        raw_tx[n++] = 0x00;  // no attributes
        return n;
    }
    raw_tx[n++] = 0x01;  // one attribute
    raw_tx[n++] = 0x81;  // a memo
    raw_tx[n++] = 8 + 32 + 4 + 1 + (sizeof(AMOUNT) - 1);
    memcpy(raw_tx + n, "pollvote", 8);
    n += 8;
    memset(raw_tx + n, 0xC7, 32);  // poll id
    n += 32;
    raw_tx[n++] = 0x01;  // choice index 1, shown as choice 2
    memset(raw_tx + n, 0, 3);
    n += 3;
    raw_tx[n++] = sizeof(AMOUNT) - 1;
    memcpy(raw_tx + n, AMOUNT, sizeof(AMOUNT) - 1);
    return n + sizeof(AMOUNT) - 1;
}

/* Commits a payment with change (and a vote memo for the vote) as a sign request's last part
 * would, and shows the review flow. */
static void commit_review(void) {
    static const unsigned int path[ELA_PATH_LEN] = {0x8000002C, 0x80000901, 0x80000000, 0, 0};
    static const uint8_t ELA_ID[32] = {0xb0, 0x37, 0xdb, 0x96, 0x4a, 0x23, 0x14, 0x58, 0xd2, 0xd6, 0xff,
                                       0xd5, 0xea, 0x18, 0x94, 0x4c, 0x4f, 0x90, 0xe6, 0x3d, 0x54, 0x7c,
                                       0x5d, 0x3b, 0x98, 0x74, 0xdf, 0x66, 0xa4, 0xea, 0xd0, 0xa3};
    uint8_t pub[ELA_PUBKEY_LEN], ph[ELA_PROGRAM_HASH_LEN], digest[32];
    unsigned int n = 0;

    tx_session_begin();
    keys_get_public_key(tx_session_commit_path(path), pub);
    keys_program_hash(pub, ph);
    raw_tx[n++] = 0x02;  // transfer
    raw_tx[n++] = 0x00;  // payload version
    n = put_attributes(n);
    raw_tx[n++] = 0x01;  // one input
    memset(raw_tx + n, 0x5A, 38);
    n += 38;
    raw_tx[n++] = 0x02;  // two outputs: a payment and change
    for (int k = 0; k < 2; k++) {
        memcpy(raw_tx + n, ELA_ID, 32);
        n += 32;
        uint64_t sela = k == 0 ? 150000000ULL : 4849000000ULL;
        for (int j = 0; j < 8; j++) raw_tx[n++] = (uint8_t) (sela >> (8 * j));
        memset(raw_tx + n, 0, 4);
        n += 4;
        if (k == 0) {
            raw_tx[n] = 0x21;
            memset(raw_tx + n + 1, 0x11, 20);
        } else {
            memcpy(raw_tx + n, ph, 21);
        }
        n += 21;
    }
    memset(raw_tx + n, 0, 4);  // lock time
    n += 4;
    for (int i = 0; i < ELA_PATH_LEN; i++) {
        raw_tx[n + 4 * i] = (uint8_t) (path[i] >> 24);
        raw_tx[n + 4 * i + 1] = (uint8_t) (path[i] >> 16);
        raw_tx[n + 4 * i + 2] = (uint8_t) (path[i] >> 8);
        raw_tx[n + 4 * i + 3] = (uint8_t) path[i];
    }
    raw_tx_len = raw_tx_ix = n + ELA_PATH_BYTES;
    if (tx_parse_and_render(ph) != SW_OK || max_scr_ix != review_screens()) {
        fail("G2", "the test transaction was refused, or its review has the wrong number of screens");
        exit(1);
    }
    cx_hash_sha256(raw_tx, n, digest, sizeof(digest));
    tx_session_arm(digest, n, max_scr_ix);
    curr_scr_ix = 0;
    ui_start_review();  // as the sign request does: clears the marks of the case before
    g_signatures = 0;
    g_last_sw = 0;
    g_gate_checks = 0;
}

static unsigned int accept_index(void) {
    return 1 + max_scr_ix;
}

/* Expects 6D5E and no signature. */
static void expect_refused(const char *check, const char *what) {
    if (g_signatures != 0 || g_last_sw != SW_COMMIT_MISMATCH) {
        char msg[200];
        snprintf(msg, sizeof(msg), "%s: %u signatures, reply %04X", what, g_signatures, g_last_sw);
        fail(check, msg);
    }
}

/* G2: honest walks sign. */
static void check_honest_walks(void) {
    commit_review();
    walk_to(accept_index());
    press_both();
    if (g_signatures != 1 || g_last_sw != SW_OK) fail("G2", "an honest walk to Accept did not sign");

    commit_review();
    walk_to(accept_index());
    g_index = 2;  // back to a review step, drawn again, then on to Accept
    draw();
    walk_to(accept_index());
    press_both();
    if (g_signatures != 1 || g_last_sw != SW_OK) fail("G2", "a walk that drew a step twice did not sign");
}

/* G3 and G4: the position moved to Accept from the intro, the second last step or Reject. */
static void check_moves_to_accept(void) {
    commit_review();
    g_index = accept_index();  // the position jumps from the intro to Accept
    draw();
    press_both();
    expect_refused("G3", "Accept signed with no review step drawn");

    commit_review();
    g_first_check_faulted = 1;  // one more fault: the first of the two gate checks passes
    g_index = accept_index();
    draw();
    press_both();
    g_first_check_faulted = 0;
    expect_refused("G3", "Accept signed with no review step drawn and the first gate check faulted");

    commit_review();
    g_second_check_faulted = 1;  // one more fault: the second of the two gate checks passes
    g_index = accept_index();
    draw();
    press_both();
    g_second_check_faulted = 0;
    expect_refused("G3", "Accept signed with no review step drawn and the second gate check faulted");

    commit_review();
    walk_to(accept_index() - 2);  // up to the second last review step
    g_index = accept_index();     // the last review step skipped
    draw();
    press_both();
    expect_refused("G3", "Accept signed with the last review step never drawn");

    commit_review();
    walk_to(accept_index() + 1);  // Reject on screen
    g_index = accept_index();     // the position moves to Accept without drawing it
    press_both();
    expect_refused("G4", "both buttons on Reject signed after the position moved to Accept");
}

/* G6: one flipped bit moves the position past an undrawn step; the user walks on to Accept. */
static void check_forward_moves(void) {
    for (unsigned int from = 0; from < review_screens(); from++) {
        for (unsigned int bit = 1; bit <= review_screens(); bit <<= 1) {
            unsigned int to = from ^ bit;
            if (to <= from + 1 || to > review_screens()) {
                continue;  // backwards, skips nothing, or lands on Accept or past it
            }
            char what[120];
            commit_review();
            walk_to(from);
            g_index = to;  // one bit flipped in the flow position
            draw();
            walk_to(accept_index());
            press_both();
            snprintf(what, sizeof(what), "Accept signed after the flow position jumped from %u to %u",
                     from, to);
            expect_refused("G6", what);
        }
    }
}

/* G7: step s skipped, then marked drawn by one bit set in the mask or cleared in its complement. */
static void check_drawn_step_mask(void) {
    for (unsigned int s = 0; s < review_screens(); s++) {
        for (int in_complement = 0; in_complement <= 1; in_complement++) {
            char what[120];
            commit_review();
            walk_to(s);       // the intro, or the review step before step s
            g_index = s + 2;  // step s skipped
            draw();
            walk_to(accept_index());
            if (in_complement) {
                review_seen_top_check &= ~(1u << s);
            } else {
                review_seen_top |= 1u << s;
            }
            press_both();
            snprintf(what, sizeof(what), "Accept signed with review step %u never drawn and one bit %s", s,
                     in_complement ? "cleared in the complement" : "set in the mask");
            expect_refused("G7", what);
        }
    }
}

/* G8: the Accept flag or its complement faulted with Reject on screen and the position moved to
 * Accept; then Accept drawn, a step back, and the position moved to Accept. */
static void check_accept_flag(void) {
    for (unsigned int fault = 0; fault < 2 + 2 * 32; fault++) {
        char flag[60], what[160];
        commit_review();
        walk_to(accept_index() + 1);  // Accept drawn, then Reject
        if (fault == 0) {
            accept_drawn = ACCEPT_DRAWN;  // Reject's store to the flag skipped
            snprintf(flag, sizeof(flag), "the Accept flag left set");
        } else if (fault == 1) {
            accept_drawn_check = ~ACCEPT_DRAWN;  // Reject's store to the complement skipped
            snprintf(flag, sizeof(flag), "the Accept flag's complement left set");
        } else if (fault < 2 + 32) {
            accept_drawn ^= 1u << (fault - 2);
            snprintf(flag, sizeof(flag), "bit %u of the Accept flag flipped", fault - 2);
        } else {
            accept_drawn_check ^= 1u << (fault - 2 - 32);
            snprintf(flag, sizeof(flag), "bit %u of the Accept flag's complement flipped", fault - 2 - 32);
        }
        g_index = accept_index();  // the position moves from Reject to Accept without drawing it
        press_both();
        snprintf(what, sizeof(what), "%s, Reject on screen and the position moved to Accept, signed", flag);
        expect_refused("G8", what);
    }

    commit_review();
    walk_to(accept_index());
    g_index--;  // one step back: the last review step drawn again
    draw();
    g_index = accept_index();  // the position moves to Accept without drawing it
    press_both();
    expect_refused("G8", "Accept drawn, a step back, then the position moved to Accept, signed");
}

/* G5 and G9: the flow corrupted after it was built. */
static void check_flow_slots(void) {
    commit_review();
    ux_review_flow[2] = ux_review_flow[1];  // a review step duplicated in place of the next
    walk_to(accept_index());
    press_both();
    expect_refused("G5", "a flow with a review step duplicated signed");

    commit_review();
    ux_review_flow[accept_index() + 1] = &ux_review_accept_step;  // Accept in the Reject slot
    walk_to(accept_index());
    press_both();
    expect_refused("G9", "a flow with Accept in the Reject slot signed");

    commit_review();
    ux_review_flow[accept_index() + 2] = &ux_review_accept_step;  // the end marker overwritten
    walk_to(accept_index());
    press_both();
    expect_refused("G9", "a flow with its end marker overwritten signed");
}

/* G10: one layout call skipped: the position moves and init runs, but the screen is unchanged. */
static void check_skipped_layouts(void) {
    char what[160];
    for (unsigned int s = 0; s < review_screens(); s++) {
        commit_review();
        walk_to(1 + s - 1);  // up to the step before review step s
        g_skip_layout = 1;
        walk_to(1 + s);  // review step s, its layout call skipped
        walk_to(accept_index());
        press_both();
        snprintf(what, sizeof(what), "review step %u never drawn (its layout call skipped), Accept signed", s);
        expect_refused("G10", what);
    }

    commit_review();
    walk_to(accept_index() - 1);
    g_skip_layout = 1;
    walk_to(accept_index());  // Accept, its layout call skipped: the last review step still shows
    press_both();
    expect_refused("G10", "Accept's layout call skipped with the last review step on screen, signed");

    commit_review();
    walk_to(accept_index() + 1);  // Reject drawn
    g_index = accept_index();     // left to Accept, its layout call skipped: Reject still shows
    g_skip_layout = 1;
    draw();
    press_both();
    expect_refused("G10", "Accept's layout call skipped with Reject on screen, signed");
    g_skip_layout = 0;
}

/* G16: a drawing cut short at each element, so the screen is never updated. */
static void check_cut_draws(void) {
    char what[160];
    for (unsigned int s = 0; s < review_screens(); s++) {
        for (unsigned int k = 1; k <= GATE_BNNN_ELEMENTS; k++) {
            commit_review();
            walk_to(1 + s - 1);  // up to the step before review step s
            g_cut_draw_at = k;
            walk_to(1 + s);  // review step s, its drawing cut short at element k
            walk_to(accept_index());
            press_both();
            snprintf(what, sizeof(what), "review step %u drawn only to element %u of %u, Accept signed", s, k,
                     GATE_BNNN_ELEMENTS);
            expect_refused("G16", what);
        }
    }

    for (unsigned int k = 1; k <= GATE_PB_ELEMENTS; k++) {
        commit_review();
        walk_to(accept_index() - 1);
        g_cut_draw_at = k;
        walk_to(accept_index());  // Accept drawn only in part after the last review step
        press_both();
        snprintf(what, sizeof(what), "Accept drawn only to element %u of %u after the last review step, signed",
                 k, GATE_PB_ELEMENTS);
        expect_refused("G16", what);

        commit_review();
        walk_to(accept_index() + 1);  // Reject drawn
        g_cut_draw_at = k;
        walk_back_to(accept_index());  // Accept drawn only in part after Reject
        press_both();
        snprintf(what, sizeof(what), "Accept drawn only to element %u of %u after Reject, signed", k,
                 GATE_PB_ELEMENTS);
        expect_refused("G16", what);
    }
}

/* G17: one element's draw skipped while the loop runs on: the screen updates and the index ends as
 * after a whole drawing, so only the count of elements drawn shows it. */
static void check_skipped_element_draws(void) {
    char what[160];
    for (unsigned int s = 0; s < review_screens(); s++) {
        for (unsigned int k = 1; k <= GATE_BNNN_ELEMENTS; k++) {
            commit_review();
            walk_to(1 + s - 1);  // up to the step before review step s
            g_skip_draw_of = k;
            walk_to(1 + s);  // review step s, its element k never drawn
            walk_to(accept_index());
            press_both();
            snprintf(what, sizeof(what), "review step %u drawn without its element %u of %u, Accept signed", s,
                     k, GATE_BNNN_ELEMENTS);
            expect_refused("G17", what);
        }
    }

    for (unsigned int k = 1; k <= GATE_PB_ELEMENTS; k++) {
        commit_review();
        walk_to(accept_index() - 1);
        g_skip_draw_of = k;
        walk_to(accept_index());  // Accept drawn without element k after the last review step
        press_both();
        snprintf(what, sizeof(what), "Accept drawn without its element %u of %u after the last review step, "
                 "signed", k, GATE_PB_ELEMENTS);
        expect_refused("G17", what);

        commit_review();
        walk_to(accept_index() + 1);  // Reject drawn
        g_skip_draw_of = k;
        walk_back_to(accept_index());  // Accept drawn without element k after Reject
        press_both();
        snprintf(what, sizeof(what), "Accept drawn without its element %u of %u after Reject, signed", k,
                 GATE_PB_ELEMENTS);
        expect_refused("G17", what);
    }
}

/* True if the marks say every step was drawn and Accept is on screen, so only the checks of the
 * flow's slots can refuse. */
static bool every_mark_set(void) {
    uint32_t every_step = (1u << max_scr_ix) - 1;
    return review_seen_top == every_step && (review_seen_top_check & every_step) == 0 &&
           accept_drawn == ACCEPT_DRAWN && (accept_drawn ^ accept_drawn_check) == ~0u;
}

/* Both buttons on a misshapen flow walked in full; expects 6D5E. */
static void expect_shape_refused(const char *check, const char *what) {
    if (!every_mark_set()) {
        char msg[200];
        snprintf(msg, sizeof(msg), "%s: a mark was left unset, so the case does not test the flow", what);
        fail(check, msg);
        return;
    }
    press_both();
    expect_refused(check, what);
}

/* G11: two review steps swapped; every step drawn, in the wrong order. */
static void check_steps_in_order(void) {
    for (unsigned int a = 0; a < review_screens(); a++) {
        for (unsigned int b = a + 1; b < review_screens(); b++) {
            char what[120];
            commit_review();
            const ux_flow_step_t *step = ux_review_flow[1 + a];
            ux_review_flow[1 + a] = ux_review_flow[1 + b];
            ux_review_flow[1 + b] = step;
            walk_to(accept_index());
            snprintf(what, sizeof(what), "a flow with review steps %u and %u swapped signed", a, b);
            expect_shape_refused("G11", what);
        }
    }
}

/* G12: the intro replaced; the flow starts on the step put in its place. */
static void check_intro(void) {
    const ux_flow_step_t *const in_place[] = {review_step(0), review_step(review_screens() - 1),
                                              &ux_review_accept_step, &ux_review_reject_step};
    const char *const names[] = {"the first review step", "the last review step", "Accept", "Reject"};
    for (unsigned int r = 0; r < sizeof(in_place) / sizeof(in_place[0]); r++) {
        char what[120];
        commit_review();
        ux_review_flow[0] = in_place[r];
        g_index = 0;
        draw();
        walk_to(accept_index());
        snprintf(what, sizeof(what), "a flow starting on %s in place of the intro signed", names[r]);
        expect_shape_refused("G12", what);
    }

    commit_review();
    ux_review_flow[0] = &ux_review_accept_step;
    g_index = 0;
    draw();
    walk_to(accept_index() - 1);  // every review step
    walk_back_to(0);              // then back to the start, where Accept is
    expect_shape_refused("G12", "both buttons on Accept in the intro's place, after every step, signed");
}

/* G13: the Accept slot replaced, then the flow position moved past the end marker onto the Accept
 * that the nine-screen vote, committed first, left there. */
static void check_accept_slot(void) {
    if (review_screens() == MAX_TX_TEXT_SCREENS) {
        return;  // the flow is full: nothing lies past its end marker
    }
    const ux_flow_step_t *const in_place[] = {review_step(review_screens() - 1), &ux_review_reject_step};
    const char *const names[] = {"the last review step", "Reject"};
    for (unsigned int r = 0; r < sizeof(in_place) / sizeof(in_place[0]); r++) {
        char what[160];
        g_vote = 1;
        commit_review();  // leaves Accept, Reject and an end marker past the transfer's end marker
        g_vote = 0;
        commit_review();
        ux_review_flow[accept_index()] = in_place[r];
        walk_to(accept_index() + 1);        // every review step, the step in Accept's place, Reject
        g_index = 1 + MAX_TX_TEXT_SCREENS;  // one bit flipped, from Reject at 8 to 10: the vote's Accept
        draw();
        snprintf(what, sizeof(what), "%s in the Accept slot, then the Accept a longer review left, signed",
                 names[r]);
        expect_shape_refused("G13", what);
    }
}

/* G14 failures name the account screen. */
static void fail_account(const char *what) {
    g_failures++;
    printf("!!! G14 on the account screen: %s\n", what);
}

/* G14: the account screen, as Display Account on the home screen opens it. */
static void check_account_screen(void) {
    /* ESmZsYAfnQEviw3sEmbGkoWWWWWWMNwWmm, whose third line is 117 px, too wide for any screen */
    static const uint8_t WIDE[ELA_PROGRAM_HASH_LEN] = {0x21, 0x69, 0x77, 0xba, 0x3c, 0xb8, 0xee,
                                                       0xaa, 0x0a, 0xb7, 0xf5, 0x43, 0x00, 0x18,
                                                       0xb1, 0x0e, 0x21, 0x16, 0x1f, 0x70, 0xd3};
    uint8_t pub[ELA_PUBKEY_LEN], ph[ELA_PROGRAM_HASH_LEN];
    char address[ADDRESS_BASE58_LEN + 1], shown[sizeof(current_public_key) + 1] = "";

    keys_get_public_key(DEFAULT_ACCOUNT_PATH, pub);
    keys_program_hash(pub, ph);
    to_address(ph, address);
    display_account_address();
    for (int k = 0; k < MAX_TX_TEXT_LINES; k++) {
        strcat(shown, current_public_key[k]);
        if (!line_fits(current_public_key[k])) fail_account("a line of the device's own address is cut");
    }
    if (strcmp(shown, address) != 0) fail_account("the device's own address is not shown whole");

    g_account_program_hash = WIDE;
    display_account_address();
    g_account_program_hash = NULL;
    if (strcmp(current_public_key[0], "Address too wide") != 0 ||
        strcmp(current_public_key[1], "to show here") != 0 || current_public_key[2][0] != '\0') {
        char msg[200];
        snprintf(msg, sizeof(msg), "an address too wide for the screen shows \"%s\" \"%s\" \"%s\"",
                 current_public_key[0], current_public_key[1], current_public_key[2]);
        fail_account(msg);
    }

    /* a refused check of a too-wide address must leave the account screen's lines as they were */
    display_account_address();
    g_account_program_hash = WIDE;
    unsigned short sw = ui_start_address_check(DEFAULT_ACCOUNT_PATH);
    g_account_program_hash = NULL;
    shown[0] = '\0';
    for (int k = 0; k < MAX_TX_TEXT_LINES; k++) strcat(shown, current_public_key[k]);
    if (sw != SW_TX_ADDRESS_TOO_WIDE || address_check_pending) {
        char msg[120];
        snprintf(msg, sizeof(msg), "a check of an address too wide gave %04X, pending %d", sw, address_check_pending);
        fail_account(msg);
    }
    if (strcmp(shown, address) != 0) {
        char msg[200];
        snprintf(msg, sizeof(msg), "a refused check of a wide address left \"%s\" on the account screen", shown);
        fail_account(msg);
    }
}

/* Starts an address check of path and presses both buttons on Approve; returns the reply. */
static unsigned int approve_address_check(const unsigned int *path) {
    g_last_sw = 0;
    unsigned short sw = ui_start_address_check(path);
    if (sw != SW_OK) {
        return sw;
    }
    while (g_flow[g_index] != &ux_address_check_approve_step && g_flow[g_index + 1] != FLOW_END_STEP) {
        walk_to(g_index + 1);
    }
    press_both();
    return g_last_sw;
}

/* G14: an approved check leaves its address in the account screen's lines, so a failed derivation
 * or program hash of the account key must show the placeholder, not that address. */
static void check_account_screen_failures(void) {
    static const unsigned int CHECKED_PATH[ELA_PATH_LEN] = {0x8000002C, 0x80000901, 0x80000001, 0, 7};
    int *const failures[] = {&g_fail_derive, &g_fail_ripemd};
    const char *const names[] = {"derivation", "program hash"};
    uint8_t pub[ELA_PUBKEY_LEN], ph[ELA_PROGRAM_HASH_LEN];
    char checked[ADDRESS_BASE58_LEN + 1];

    keys_get_public_key(CHECKED_PATH, pub);
    keys_program_hash(pub, ph);
    to_address(ph, checked);
    for (unsigned int f = 0; f < sizeof(failures) / sizeof(failures[0]); f++) {
        char shown[sizeof(current_public_key) + 1] = "", msg[240];
        unsigned int sw = approve_address_check(CHECKED_PATH);
        for (int k = 0; k < MAX_TX_TEXT_LINES; k++) strcat(shown, current_public_key[k]);
        if (sw != SW_OK || strcmp(shown, checked) != 0) {
            snprintf(msg, sizeof(msg), "the check of 44'/2305'/1'/0/7 gave %04X and left \"%s\", not its "
                     "address, so the case does not test the account screen", sw, shown);
            fail_account(msg);
            continue;
        }

        *failures[f] = 1;
        display_account_address();
        *failures[f] = 0;
        shown[0] = '\0';
        for (int k = 0; k < MAX_TX_TEXT_LINES; k++) strcat(shown, current_public_key[k]);
        if (strcmp(shown, checked) == 0) {
            snprintf(msg, sizeof(msg), "a failed %s of its own key shows the address just checked, \"%s\"",
                     names[f], shown);
            fail_account(msg);
        } else if (strcmp(current_public_key[0], "Could not get") != 0 ||
                   strcmp(current_public_key[1], "the address") != 0 || current_public_key[2][0] != '\0') {
            snprintf(msg, sizeof(msg), "a failed %s of its own key, after a check was approved, shows "
                     "\"%s\" \"%s\" \"%s\"", names[f], current_public_key[0], current_public_key[1],
                     current_public_key[2]);
            fail_account(msg);
        }
    }
}

/* Expects ui_review_on_screen() to equal on_screen. */
static void expect_review_on_screen(bool on_screen, const char *what) {
    if (ui_review_on_screen() != on_screen) {
        char msg[200];
        snprintf(msg, sizeof(msg), "%s, but ui_review_on_screen() is %s", what, on_screen ? "false" : "true");
        fail("G15", msg);
    }
}

/* G15: ui_review_on_screen() is all main.c reads of the display here. An SDK error returns to idle
 * only if it is true, also one thrown while Accept or Reject sends its reply. */
static void check_review_on_screen(void) {
    char what[120];
    commit_review();
    for (unsigned int i = 0; i <= accept_index() + 1; i++) {  // the intro, every review step, Accept, Reject
        walk_to(i);
        snprintf(what, sizeof(what), "step %u of the review flow is up", i);
        expect_review_on_screen(true, what);
    }
    walk_back_to(accept_index());
    press_both();
    if (g_signatures != 1 || g_last_sw != SW_OK) fail("G15", "an honest walk to Accept did not sign");
    expect_review_on_screen(false, "Accept signed and returned to idle");

    commit_review();
    walk_to(accept_index() + 1);
    press_both();
    if (g_signatures != 0 || g_last_sw != SW_USER_REJECTED) fail("G15", "Reject did not answer 6985");
    expect_review_on_screen(false, "Reject answered and returned to idle");

    commit_review();
    walk_to(1);
    ui_idle();
    expect_review_on_screen(false, "the review was closed by a return to idle");
}

/* Starts a check of the default account and presses right to step, expecting it on screen. */
static void walk_address_check_to(const ux_flow_step_t *step) {
    char what[120];
    g_last_sw = 0;
    if (ui_start_address_check(DEFAULT_ACCOUNT_PATH) != SW_OK) {
        fail("G15", "the address check of the default account was refused");
        exit(1);
    }
    expect_review_on_screen(true, "the address check flow is up");
    while (g_flow[g_index] != step) {
        if (g_flow[g_index + 1] == FLOW_END_STEP) {
            fail("G15", "a step of the address check flow is missing");
            exit(1);
        }
        walk_to(g_index + 1);
        snprintf(what, sizeof(what), "the address check flow is up on %s", g_flow[g_index]->name);
        expect_review_on_screen(true, what);
    }
}

/* G15 on the address check: Approve, Reject or idle must leave nothing main.c takes for it. */
static void check_address_check_on_screen(void) {
    g_address_check = 1;
    walk_address_check_to(&ux_address_check_approve_step);
    press_both();
    if (g_last_sw != SW_OK) fail("G15", "Approve did not answer with the public key");
    expect_review_on_screen(false, "Approve answered and returned to idle");

    walk_address_check_to(&ux_address_check_reject_step);
    press_both();
    if (g_last_sw != SW_USER_REJECTED) fail("G15", "Reject did not answer 6985");
    expect_review_on_screen(false, "Reject answered and returned to idle");

    walk_address_check_to(&ux_address_check_address_step);
    ui_idle();
    expect_review_on_screen(false, "the address check was closed by a return to idle");
    g_address_check = 0;
}

/* G18 failures name the address check. */
static void fail_check(const char *what) {
    g_failures++;
    printf("!!! G18 on the address check: %s\n", what);
}

/* The address check flow, in order. */
static const ux_flow_step_t *const CHECK_STEPS[] = {&ux_address_check_intro_step, &ux_address_check_path_step,
                                                    &ux_address_check_address_step,
                                                    &ux_address_check_approve_step, &ux_address_check_reject_step};
#define CHECK_INTRO   0
#define CHECK_PATH    1
#define CHECK_ADDRESS 2
#define CHECK_APPROVE 3
#define CHECK_REJECT  4

/* G18's paths, lines written out by hand: one line, two, and three (the longest path allowed). */
static const struct {
    unsigned int path[ELA_PATH_LEN];
    const char *lines[3];
} CHECK_PATHS[] = {
    {{0x8000002C, 0x80000901, 0x80000000, 0, 0}, {"44'/2305'/0'/0/0", "", ""}},
    {{0x8000002C, 0x80000901, 0x80000065, 0, 0}, {"44'/2305'/101'/0/", "0", ""}},
    {{0x8000002C, 0x80000901, 0xFFFFFFFF, 1, 0x7FFFFFFF}, {"44'/2305'/", "2147483647'/1/", "2147483647"}},
};
static unsigned int g_check_path;

/* Starts an address check of the path under test, with the intro drawn. */
static void start_check(void) {
    g_last_sw = 0;
    if (ui_start_address_check(CHECK_PATHS[g_check_path].path) != SW_OK) {
        fail_check("an address check was refused");
        exit(1);
    }
}

/* Expects the last Approve to have sent nothing, with the check still waiting. */
static void expect_check_refused(const char *what) {
    if (g_last_sw != 0 || !address_check_pending) {
        char msg[240];
        snprintf(msg, sizeof(msg), "%s, on %s: reply %04X, check %s", what, CHECK_PATHS[g_check_path].lines[0],
                 g_last_sw, address_check_pending ? "waiting" : "answered");
        fail_check(msg);
    }
    // Approve's action runs as its own flow, so the check must put its flow back on Approve
    if (g_flow != ux_address_check_flow || g_flow[g_index] != &ux_address_check_approve_step) {
        char msg[240];
        snprintf(msg, sizeof(msg), "%s, on %s: the check's flow was not put back on Approve", what,
                 CHECK_PATHS[g_check_path].lines[0]);
        fail_check(msg);
    }
}

/* G18: the flow and the path's text. Returns false if the flow is wrong, since the other G18
 * checks walk it by step position. */
static bool check_address_check_shape(void) {
    char msg[240];
    start_check();
    unsigned int k = 0;
    for (; k < sizeof(CHECK_STEPS) / sizeof(CHECK_STEPS[0]) && g_flow[k] != FLOW_END_STEP; k++) {
        if (g_flow[k] != CHECK_STEPS[k]) {
            snprintf(msg, sizeof(msg), "step %u of the flow is not %s", k, CHECK_STEPS[k]->name);
            fail_check(msg);
        }
    }
    if (k != sizeof(CHECK_STEPS) / sizeof(CHECK_STEPS[0]) || g_flow[k] != FLOW_END_STEP) {
        snprintf(msg, sizeof(msg), "the flow does not end right after Reject, its fifth step");
        fail_check(msg);
        ui_idle();
        return false;
    }
    const char *const *shown = ux_address_check_path_step_val.lines;
    if (strcmp(shown[0], "Path") != 0) fail_check("the path step is not headed \"Path\"");
    for (unsigned int k = 0; k < 3; k++) {
        if (strcmp(shown[1 + k], CHECK_PATHS[g_check_path].lines[k]) != 0 || !line_fits(shown[1 + k])) {
            snprintf(msg, sizeof(msg), "line %u of the path shows \"%s\", not \"%s\"", k + 1, shown[1 + k],
                     CHECK_PATHS[g_check_path].lines[k]);
            fail_check(msg);
        }
    }
    const char *const *address = ux_address_check_address_step_val.lines;
    if (strcmp(address[0], "Address") != 0 || address[1] != current_public_key[0] ||
        address[2] != current_public_key[1] || address[3] != current_public_key[2]) {
        fail_check("the address step does not show \"Address\" and the address's three lines");
    }
    ui_idle();
    return true;
}

/* G18: an honest walk approves, and so does one that draws a step again; Reject rejects. */
static void check_address_check_honest(void) {
    start_check();
    walk_to(CHECK_APPROVE);
    press_both();
    if (g_last_sw != SW_OK || address_check_pending) fail_check("an honest walk to Approve did not answer");

    start_check();
    walk_to(CHECK_APPROVE);
    walk_back_to(CHECK_PATH);  // back to the path, drawn again, then on to Approve
    walk_to(CHECK_APPROVE);
    press_both();
    if (g_last_sw != SW_OK || address_check_pending) fail_check("a walk that drew the path twice did not answer");

    start_check();
    walk_to(CHECK_REJECT);
    press_both();
    if (g_last_sw != SW_USER_REJECTED || address_check_pending) fail_check("Reject did not answer 6985");
}

/* G18: the flow position moved past the path or the address, or onto Approve without drawing it. */
static void check_address_check_moves(void) {
    char what[120];
    for (unsigned int skipped = CHECK_PATH; skipped <= CHECK_ADDRESS; skipped++) {
        start_check();
        walk_to(skipped - 1);
        g_index = skipped + 1;  // the position jumps over the step
        draw();
        walk_to(CHECK_APPROVE);
        press_both();
        snprintf(what, sizeof(what), "Approve answered with the %s never drawn",
                 skipped == CHECK_PATH ? "path" : "address");
        expect_check_refused(what);
    }

    start_check();
    g_index = CHECK_APPROVE;  // from the intro straight to Approve
    draw();
    press_both();
    expect_check_refused("Approve answered with neither the path nor the address drawn");

    start_check();
    walk_to(CHECK_REJECT);  // Approve drawn, then Reject
    g_index = CHECK_APPROVE;  // the position moves back to Approve without drawing it
    press_both();
    expect_check_refused("Approve answered from a position moved off Reject without drawing Approve");

    start_check();
    walk_to(CHECK_APPROVE);        // Approve drawn
    walk_back_to(CHECK_ADDRESS);   // back on the address, drawn again
    g_index = CHECK_APPROVE;       // the position moves on to Approve without drawing it
    press_both();
    expect_check_refused("Approve answered from a position moved off the address without drawing Approve");
}

/* G18: the path, address or Approve with its layout call skipped, its drawing cut at each element,
 * or each element's draw skipped. */
static void check_address_check_draws(void) {
    char what[160];
    for (unsigned int step = CHECK_PATH; step <= CHECK_APPROVE; step++) {
        unsigned int count = step == CHECK_APPROVE ? GATE_PB_ELEMENTS : GATE_BNNN_ELEMENTS;
        static const char *const NAMES[] = {"", "the path", "the address", "Approve"};
        const char *name = NAMES[step];
        for (unsigned int fault = 0; fault <= 2 * count; fault++) {
            start_check();
            walk_to(step - 1);
            if (fault == 0) {
                g_skip_layout = 1;
                snprintf(what, sizeof(what), "Approve answered with the layout call of %s skipped", name);
            } else if (fault <= count) {
                g_cut_draw_at = fault;
                snprintf(what, sizeof(what), "Approve answered with %s drawn only to element %u of %u", name,
                         fault, count);
            } else {
                g_skip_draw_of = fault - count;
                snprintf(what, sizeof(what), "Approve answered with %s drawn without its element %u of %u", name,
                         fault - count, count);
            }
            walk_to(step);
            walk_to(CHECK_APPROVE);
            press_both();
            expect_check_refused(what);
            g_skip_layout = 0;
        }
    }
}

/* G18: Approve answers only once the path, address and Approve were each drawn in full. */
static void check_address_check_gate(void) {
    g_address_check = 1;
    for (g_check_path = 0; g_check_path < sizeof(CHECK_PATHS) / sizeof(CHECK_PATHS[0]); g_check_path++) {
        if (!check_address_check_shape()) {
            break;
        }
        check_address_check_honest();
        check_address_check_moves();
        check_address_check_draws();
    }
    ui_idle();
    g_address_check = 0;
}

int main(void) {
    uiState = UI_IDLE;
    tx_session_reset();
    ui_idle();

    for (g_vote = 0; g_vote <= 1; g_vote++) {
        check_honest_walks();
        check_moves_to_accept();
        check_flow_slots();
        check_forward_moves();
        check_drawn_step_mask();
        check_accept_flag();
        check_skipped_layouts();
        check_cut_draws();
        check_skipped_element_draws();
        check_steps_in_order();
        check_intro();
        check_accept_slot();
        check_review_on_screen();
    }
    check_account_screen();
    check_account_screen_failures();
    check_address_check_on_screen();
    check_address_check_gate();

    printf("nanox gate: %s, %lu failures\n", g_failures ? "FAIL" : "ok", g_failures);
    return g_failures ? 1 : 0;
}
