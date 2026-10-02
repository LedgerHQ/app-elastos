/*
 * MIT License, see root folder for full license.
 */
#ifndef UI_H
#define UI_H

#include "os.h"
#include "cx.h"
#include "ux.h"
#include <stdbool.h>
#include "os_io_seproxyhal.h"
#include "bagl.h"
#include "sha256_hash_len.h"

/** no info */
#define NO_INFO "Info not available"

/** the timer */
extern int exit_timer;

/** max with of timer display */
#define MAX_TIMER_TEXT_WIDTH 4

/** display for the timer */
extern char timer_desc[MAX_TIMER_TEXT_WIDTH];

/** length of the APDU (application protocol data unit) header. */
#define APDU_HEADER_LENGTH 5

/** offset in the APDU header which says the length of the body. */
#define APDU_BODY_LENGTH_OFFSET 4

/** for signing, indicates this is the last part of the transaction. */
#define P1_LAST 0x80

/** for signing, indicates this is not the last part of the transaction, there are more parts
 * coming. */
#define P1_MORE 0x00

/** Key request P1: reply without asking the user. */
#define P1_KEY_SILENT 0x00

/** Key request P1: reply once the user approves the path and address shown. */
#define P1_KEY_SHOW 0x01

/** length of BIP44 path */
#define BIP44_PATH_LEN 5

/** length of BIP44 path, in bytes */
#define BIP44_BYTE_LENGTH (BIP44_PATH_LEN * sizeof(unsigned int))

/** Largest transaction plus its 20-byte path. Nano S leaves an app about 4.5 KB of RAM, so this
 * cannot grow much. */
#define MAX_TX_RAW_LENGTH 1024

/** max width of a single line of text. */
#define MAX_TX_TEXT_WIDTH 18

/** Review line width in pixels. On Nano X and Nano S Plus the SDK replaces the middle of wider
 * text with "...", so 14444444.44444444 could read as 144444...4444444. */
#if defined(TARGET_NANOS)
#define REVIEW_LINE_WIDTH_PX 108
#else
#define REVIEW_LINE_WIDTH_PX 116
#endif

/** max lines of text to display. */
#define MAX_TX_TEXT_LINES 3

/** Review screen the address check draws the path on; a key request ends any review first. */
#define ADDRESS_CHECK_PATH_SCREEN 0

/** Signer, poll vote (3) or memo text (up to 5), two per output, fee notice. */
#define MAX_TX_TEXT_SCREENS 9

/** max number of hex bytes that can be displayed (2 hex characters for 1 byte of data) */
#define MAX_HEX_BUFFER_LEN (MAX_TX_TEXT_WIDTH / 2)

/** max number of bytes for one line of text. */
#define CURR_TX_DESC_LEN (MAX_TX_TEXT_LINES * MAX_TX_TEXT_WIDTH)

/** max number of bytes for all text screens. */
#define MAX_TX_DESC_LEN (MAX_TX_TEXT_SCREENS * CURR_TX_DESC_LEN)

/** UI currently displayed */
enum UI_STATE {
    UI_INIT,
    UI_IDLE,
    UI_TOP_SIGN,
    UI_TX_DESC_1,
    UI_TX_DESC_2,
    UI_SIGN,
    UI_DENY,
    UI_PUBLIC_KEY_1,
    UI_PUBLIC_KEY_2,
    UI_ADDRESS_CHECK
};

/** UI state enum */
extern enum UI_STATE uiState;

/** UI state flag */
extern ux_state_t ux;

/** index of the current screen. */
extern unsigned int curr_scr_ix;

/** max index for all screens. */
extern unsigned int max_scr_ix;

/** raw transaction data. */
extern unsigned char raw_tx[MAX_TX_RAW_LENGTH];

/** current index into raw transaction. */
extern unsigned int raw_tx_ix;

/** current length of raw transaction. */
extern unsigned int raw_tx_len;

/** all text descriptions. */
extern char tx_desc[MAX_TX_TEXT_SCREENS][MAX_TX_TEXT_LINES][MAX_TX_TEXT_WIDTH];

/** currently displayed text description. */
extern char curr_tx_desc[MAX_TX_TEXT_LINES][MAX_TX_TEXT_WIDTH];

/** currently displayed public key */
extern char current_public_key[MAX_TX_TEXT_LINES][MAX_TX_TEXT_WIDTH];

/** bold heading of each review screen */
extern char review_title[MAX_TX_TEXT_SCREENS][MAX_TX_TEXT_WIDTH];

/** heading of the review screen currently displayed on Nano S */
extern char curr_review_title[MAX_TX_TEXT_WIDTH];

/** true while a review or address check waits for the user */
bool ui_review_on_screen(void);

/** shows a newly committed review, no screen of it yet counted as read */
void ui_start_review(void);

/** shows a path and its address for the user to check; the reply waits for the answer */
unsigned short ui_start_address_check(const unsigned int *path);

#if defined(TARGET_NANOS)
/** records each element as it is handed to the display */
void ui_element_drawn(const bagl_element_t *element);
#endif  // TARGET_NANOS

/** signs the committed transaction once the user approves it */
const bagl_element_t *io_seproxyhal_touch_approve(const bagl_element_t *e);

/** show the idle UI */
void ui_idle(void);

/** show the "Sign TX" ui, starting at the top of the Tx display */
void ui_top_sign(void);

#endif  // UI_H
