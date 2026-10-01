/*******************************************************************************
 *   Ledger Blue
 *   (c) 2016 Ledger
 *   Modified by the contributors to the Elastos Ledger app, 2018 to 2026
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 ********************************************************************************/

#include <string.h>
#include "os.h"
#include "cx.h"
#include <stdbool.h>
#include "os_io_seproxyhal.h"
#include "ui.h"
#include "elastos.h"
#include "bagl.h"
#include "base-encoding.h"
#include "keys.h"
#include "sw.h"
#include "tx_session.h"
// #include "btchip_base58.h"

#define DEBUG_OUT_ENABLED false

#define MAX_EXIT_TIMER 4098

#define EXIT_TIMER_REFRESH_INTERVAL 512

#if defined(TARGET_NANOS) && defined(HAVE_BOLOS_APP_STACK_CANARY)
/** Canary the Nano S SDK keeps below the stack; any other value means the stack overran it. */
#define APP_STACK_CANARY 0xDEAD0031u
extern unsigned int app_stack_canary;

/** Set once io_seproxyhal_init has written the canary. */
static volatile bool transport_started;
#endif

static void Timer_UpdateDescription() {
    snprintf(timer_desc, MAX_TIMER_TEXT_WIDTH, "%d", exit_timer / EXIT_TIMER_REFRESH_INTERVAL);
}

#if defined(TARGET_NANOS)
static void Timer_UpdateDisplay() {
    if ((exit_timer % EXIT_TIMER_REFRESH_INTERVAL) == (EXIT_TIMER_REFRESH_INTERVAL / 2)) {
        UX_REDISPLAY();
    }
}

static void Timer_Tick() {
    if (exit_timer > 0) {
        exit_timer--;
        Timer_UpdateDescription();
    }
}
#endif  // TARGET_NANOS

static void Timer_Set() {
    exit_timer = MAX_EXIT_TIMER;
    Timer_UpdateDescription();
}

static void Timer_Restart() {
    if (exit_timer != MAX_EXIT_TIMER) {
        Timer_Set();
    }
}

#if defined(TARGET_NANOS)
static bool Timer_Expired() {
    return exit_timer <= 0;
}
#endif  // TARGET_NANOS

/** IO buffer to communicate with the outside world. */
unsigned char G_io_seproxyhal_spi_buffer[IO_SEPROXYHAL_BUFFER_SIZE_B];

/** start of the buffer, reject any transmission that doesn't start with this, as it's invalid. */
#define CLA 0x80

/** #### instructions start #### **/
/** instruction to sign transaction and send back the signature. */
#define INS_SIGN 0x02

/** instruction to send back the public key. */
#define INS_GET_PUBLIC_KEY 0x04

/** instruction to return to the dashboard. */
#define INS_EXIT 0xFF

/** #### instructions end #### */

/** offsets in the APDU header */
#define OFFSET_CLA 0
#define OFFSET_INS 1
#define OFFSET_P1  2
#define OFFSET_P2  3
#define OFFSET_LC  4

/** some kind of event loop */
unsigned short io_exchange_al(unsigned char channel, unsigned short tx_len) {
    switch (channel & ~(IO_FLAGS)) {
        case CHANNEL_KEYBOARD:
            break;

        // multiplexed io exchange over a SPI channel and TLV encapsulated protocol
        case CHANNEL_SPI:
            if (tx_len) {
                io_seproxyhal_spi_send(G_io_apdu_buffer, tx_len);

                if (channel & IO_RESET_AFTER_REPLIED) {
                    reset();
                }
                // nothing received from the master so far
                //(it's a tx transaction)
                return 0;
            } else {
                return io_seproxyhal_spi_recv(G_io_apdu_buffer, sizeof(G_io_apdu_buffer), 0);
            }

        default:
            THROW(INVALID_PARAMETER);
    }
    return 0;
}

/** Ends any signing session and takes a dead review off screen. The SDK blocks new commands while
 * a review waits, so only an SDK exception can end one here. */
static void abandon_signing_session(void) {
    bool review_on_screen = tx_session_is_armed() || ui_review_on_screen();
    tx_session_reset();
    if (review_on_screen) {
        ui_idle();
    }
}

/** Program hash of the signing key: shown as "Signing with", matched for "Back to you". */
static unsigned short signer_address(const unsigned int *signing_path,
                                     uint8_t program_hash[ELA_PROGRAM_HASH_LEN]) {
    uint8_t pubkey[ELA_PUBKEY_LEN];
    if (keys_get_public_key(signing_path, pubkey) != CX_OK ||
        keys_program_hash(pubkey, program_hash) != CX_OK) {
        return SW_CRYPTO_FAILED;
    }
    return SW_OK;
}

/** Renders the transaction and commits the digest of exactly the rendered bytes and of the text
 * shown, so approval can sign only what was shown. */
static unsigned short prepare_review(void) {
    unsigned int path[ELA_PATH_LEN];
    uint8_t signer_program_hash[ELA_PROGRAM_HASH_LEN];
    uint8_t digest[ELA_DIGEST_LEN];

    if (raw_tx_len <= ELA_PATH_BYTES) {
        return SW_TX_TOO_SHORT;
    }
    unsigned int body_len = raw_tx_len - ELA_PATH_BYTES;

    keys_read_path(raw_tx + body_len, path);
    if (!keys_path_is_valid(path)) {
        return SW_BAD_PATH;
    }
    // derive the shown key from the committed copy, the one signing uses
    const unsigned int *signing_path = tx_session_commit_path(path);
    CHECK_SW(signer_address(signing_path, signer_program_hash));

    CHECK_SW(tx_parse_and_render(signer_program_hash));
    // the bytes hashed and signed must be exactly those the parser read to its end
    if (raw_tx_ix != body_len) {
        return SW_COMMIT_MISMATCH;
    }

    cx_hash_sha256(raw_tx, body_len, digest, sizeof(digest));
    tx_session_arm(digest, body_len, max_scr_ix);
    // derive and render again and compare the text, so one fault cannot show something the bytes
    // and key do not say
    CHECK_SW(signer_address(signing_path, signer_program_hash));
    CHECK_SW(tx_parse_and_render(signer_program_hash));
    if (raw_tx_ix != body_len || !tx_session_text_matches()) {
        return SW_COMMIT_MISMATCH;
    }
    curr_scr_ix = 0;
    return SW_OK;
}

/** Appends one part of a transaction; the last part starts the review and defers the reply. */
static unsigned short handle_sign(unsigned int rx, unsigned int *flags) {
    unsigned char p1 = G_io_apdu_buffer[OFFSET_P1];
    unsigned int lc = G_io_apdu_buffer[OFFSET_LC];

    if (p1 != P1_MORE && p1 != P1_LAST) {
        return SW_WRONG_P1P2;
    }
    if (G_io_apdu_buffer[OFFSET_P2] != 0) {
        return SW_WRONG_P1P2;
    }
    // Lc must match what arrived, or stale buffer bytes would be copied in and signed
    if (rx != APDU_HEADER_LENGTH + lc) {
        return SW_WRONG_LENGTH;
    }

    if (!tx_session_is_receiving()) {
        abandon_signing_session();
        tx_session_begin();
    }
    if (lc > MAX_TX_RAW_LENGTH - raw_tx_ix) {
        return SW_TX_TOO_LARGE;
    }
    memmove(raw_tx + raw_tx_ix, G_io_apdu_buffer + APDU_HEADER_LENGTH, lc);
    raw_tx_ix += lc;

    if (p1 == P1_MORE) {
        return SW_OK;
    }

    raw_tx_len = raw_tx_ix;
    CHECK_SW(prepare_review());
    ui_start_review();
    *flags |= IO_ASYNCH_REPLY;
    return SW_OK;
}

/**
 * Essentials sends Lc 0, so the received size is checked. P1 00 answers silently, for pairing,
 * within Ledger's Bitcoin app limits; P1 01 shows the path and address first, for any valid path.
 */
static unsigned short handle_get_public_key(unsigned int rx,
                                            unsigned int *tx,
                                            unsigned int *flags) {
    unsigned char p1 = G_io_apdu_buffer[OFFSET_P1];
    unsigned int path[ELA_PATH_LEN];
    uint8_t pubkey[ELA_PUBKEY_LEN];

    if ((p1 != P1_KEY_SILENT && p1 != P1_KEY_SHOW) || G_io_apdu_buffer[OFFSET_P2] != 0) {
        return SW_WRONG_P1P2;
    }
    if (rx < APDU_HEADER_LENGTH + ELA_PATH_BYTES) {
        return SW_PUBKEY_PATH_TOO_SHORT;
    }
    // exactly five components: a longer path must not be answered with the key for its start
    if (rx > APDU_HEADER_LENGTH + ELA_PATH_BYTES) {
        return SW_WRONG_LENGTH;
    }
    keys_read_path(G_io_apdu_buffer + APDU_HEADER_LENGTH, path);
    if (!keys_path_is_valid(path)) {
        return SW_BAD_PATH;
    }
    if (p1 == P1_KEY_SHOW) {
        CHECK_SW(ui_start_address_check(path));
        *flags |= IO_ASYNCH_REPLY;
        return SW_OK;
    }
    // checked twice before deriving, so one skipped check cannot release a key outside the range
    if (!keys_path_is_silent(path) || !keys_path_is_silent(path)) {
        return SW_PATH_NEEDS_CHECK;
    }
    if (keys_get_public_key(path, pubkey) != CX_OK) {
        return SW_CRYPTO_FAILED;
    }
    memmove(G_io_apdu_buffer, pubkey, ELA_PUBKEY_LEN);
    *tx = ELA_PUBKEY_LEN;
    return SW_OK;
}

/** Runs one command and returns its status word; any reply data is in G_io_apdu_buffer. */
static unsigned short handle_apdu(unsigned int rx,
                                  unsigned int *tx,
                                  unsigned int *flags,
                                  bool *exit_requested) {
    if (rx == 0) {
        return SW_NO_COMMAND;
    }
    if (rx < APDU_HEADER_LENGTH) {
        return SW_WRONG_LENGTH;
    }
    // if the buffer doesn't start with the magic byte, return an error.
    if (G_io_apdu_buffer[OFFSET_CLA] != CLA) {
        return SW_CLA_NOT_SUPPORTED;
    }

    switch (G_io_apdu_buffer[OFFSET_INS]) {
        case INS_SIGN:
            Timer_Restart();
            return handle_sign(rx, flags);

        case INS_GET_PUBLIC_KEY:
            Timer_Restart();
            abandon_signing_session();
            return handle_get_public_key(rx, tx, flags);

        case INS_EXIT:
            abandon_signing_session();
            *exit_requested = true;
            return SW_OK;

        default:
            return SW_INS_NOT_SUPPORTED;
    }
}

/** Appends sw after tx bytes of reply data; returns the reply length. */
static unsigned int append_status_word(unsigned int tx, unsigned short sw) {
    G_io_apdu_buffer[tx] = sw >> 8;
    G_io_apdu_buffer[tx + 1] = sw & 0xFF;
    return tx + 2;
}

/** Maps an SDK exception to a status word. */
static unsigned short exception_status_word(unsigned int e) {
    switch (e & 0xF000) {
        case 0x6000:
        case 0x9000:
            return e;
        default:
            return 0x6800 | (e & 0x7FF);
    }
}

/** Main loop. Returns true if the transport must be restarted, false on the exit instruction. */
static bool elastos_main(void) {
    volatile unsigned int tx = 0;
    volatile unsigned int flags = 0;
    volatile bool exit_requested = false;
    volatile bool transport_reset = false;

    // DESIGN NOTE: the bootloader ignores the way APDU are fetched. The only
    // goal is to retrieve APDU.
    // When APDU are to be fetched from multiple IOs, like NFC+USB+BLE, make
    // sure the io_event is called with a
    // switch event, before the apdu is replied to the bootloader. This avoid
    // APDU injection faults.
    while (!exit_requested) {
        BEGIN_TRY {
            TRY {
                unsigned int reply_len = tx;
                // so the exception handler sends no stale reply if io_exchange throws
                tx = 0;
                unsigned int rx = io_exchange(CHANNEL_APDU | flags, reply_len);
                flags = 0;

                unsigned int data_len = 0;
                unsigned int reply_flags = 0;
                bool exit_now = false;
                unsigned short sw = handle_apdu(rx, &data_len, &reply_flags, &exit_now);
                // any failure ends the session, so no state carries over to the next one
                if (sw != SW_OK) {
                    abandon_signing_session();
                    data_len = 0;
                    reply_flags = 0;
                }
                exit_requested = exit_now;
                flags = reply_flags;
                if ((reply_flags & IO_ASYNCH_REPLY) == 0) {
                    tx = append_status_word(data_len, sw);
                }
            }
            CATCH(EXCEPTION_IO_RESET) {
                // the transport must be started again; main() does that
                transport_reset = true;
                exit_requested = true;
            }
            CATCH(INVALID_STATE) {
                // Nano S: a reply found no command to answer, so no status word can be sent
                // either; start the transport again rather than queue one more reply
                transport_reset = true;
                exit_requested = true;
            }
            CATCH_OTHER(e) {
                // no reply is pending any more, so the next exchange must not wait as if one were
                flags = 0;
                abandon_signing_session();
                tx = append_status_word(0, exception_status_word(e));
            }
            FINALLY {
            }
        }
        END_TRY;
    }
    return transport_reset;
}

/** display function */
void io_seproxyhal_display(const bagl_element_t *element) {
#if defined(TARGET_NANOS)
    bool sent_before = io_seproxyhal_spi_is_status_sent();
#endif  // TARGET_NANOS
    io_seproxyhal_display_default((bagl_element_t *) element);
#if defined(TARGET_NANOS)
    // drawn only if this call sent the event's one status: a skipped send, or a draw after the
    // status was already out, does not count
    ui_element_drawn(!sent_before && io_seproxyhal_spi_is_status_sent() ? element : NULL);
#endif  // TARGET_NANOS
}

/* io event loop */
unsigned char io_event(unsigned char channel) {
    UNUSED(channel);
    // nothing done with the event, throw an error on the transport layer if
    // needed

    // can't have more than one tag in the reply, not supported yet.
    switch (G_io_seproxyhal_spi_buffer[0]) {
        case SEPROXYHAL_TAG_FINGER_EVENT:
            Timer_Restart();
            UX_FINGER_EVENT(G_io_seproxyhal_spi_buffer);
            break;

        case SEPROXYHAL_TAG_BUTTON_PUSH_EVENT:  // for Nano S
            Timer_Restart();
            UX_BUTTON_PUSH_EVENT(G_io_seproxyhal_spi_buffer);
            break;

        case SEPROXYHAL_TAG_DISPLAY_PROCESSED_EVENT:
            // Timer_Restart();
            if (UX_DISPLAYED()) {
                // perform actions after all screen elements have been displayed
            } else {
                UX_DISPLAYED_EVENT();
            }
            break;

        case SEPROXYHAL_TAG_TICKER_EVENT:
#if defined(TARGET_NANOX) || defined(TARGET_NANOS2)
            UX_TICKER_EVENT(G_io_seproxyhal_spi_buffer, {
                // don't redisplay if UX not allowed (pin locked in the common bolos
                // ux ?)
                if (UX_ALLOWED) {
                    // redisplay screen
                    UX_REDISPLAY();
                }
            });
#else
            Timer_Tick();
            if (Timer_Expired()) {
                os_sched_exit(0);
            } else {
                Timer_UpdateDisplay();
            }
#endif
            break;

        // unknown events are acknowledged
        default:
            UX_DEFAULT_EVENT();
            break;
    }

    // close the event if not done previously (by a display or whatever)
    if (!io_seproxyhal_spi_is_status_sent()) {
        io_seproxyhal_general_status();
    }

    // command has been processed, DO NOT reset the current APDU transport
    return 1;
}

/** boot up the app and intialize it */
__attribute__((section(".boot"))) int main(void) {
    // exit critical section
    __asm volatile("cpsie i");

    // ensure exception will work as planned
    os_boot();

    // on Nano S a USB reset or an undeliverable reply ends the main loop; start everything again
    for (;;) {
        volatile bool restart = true;

#if defined(TARGET_NANOS) && defined(HAVE_BOLOS_APP_STACK_CANARY)
        // io_seproxyhal_init writes the stack canary again, so check it before a restart does
        if (transport_started && app_stack_canary != APP_STACK_CANARY) {
            io_seproxyhal_se_reset();
        }
#endif

        uiState = UI_IDLE;
        tx_session_reset();
        UX_INIT();

        BEGIN_TRY {
            TRY {
                io_seproxyhal_init();
#if defined(TARGET_NANOS) && defined(HAVE_BOLOS_APP_STACK_CANARY)
                transport_started = true;
#endif

#ifdef TARGET_NANOX
                // grab the current plane mode setting
                G_io_app.plane_mode = os_setting_get(OS_SETTING_PLANEMODE, NULL, 0);
#endif  // TARGET_NANOX

                USB_power(0);
                USB_power(1);

                // init the public key display to "no public key".
                display_no_public_key();

                // show idle screen.
                ui_idle();

                // set timer
                Timer_Set();

#ifdef HAVE_BLE
                BLE_power(0, NULL);
                BLE_power(1, "Nano X");
#endif  // HAVE_BLE

                // run main event loop.
                restart = elastos_main();
            }
            CATCH(EXCEPTION_IO_RESET) {
                CLOSE_TRY;
                continue;
            }
            CATCH_OTHER(e) {
                UNUSED(e);
                CLOSE_TRY;
                break;
            }
            FINALLY {
            }
        }
        END_TRY;
        if (!restart) {
            break;
        }
    }
    // Leave through the OS rather than returning from main.
    os_sched_exit(-1);
    return 0;
}
