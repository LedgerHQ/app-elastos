#!/usr/bin/env python3
"""Plant one known bug in a copy of the source, to prove the fuzzer it targets catches it.

usage: plant.py <variant> <source-copy-dir>

Each replacement must match exactly once, so a plant cannot silently do nothing. "clean" changes
nothing.
"""
import os
import sys

PLANTS = {
    "p1": ("Nano S Sign screen signs without the review having been read", [
        ("ui.c",
         "            if (review_complete != REVIEW_COMPLETE || !review_fully_read()) {\n"
         "                show_first_unread_half();\n"
         "            } else if (sign_screen_on_display()) {",
         "            if (0) {\n"
         "            } else if (1) {"),
        ("ui.c",
         "    return review_complete == REVIEW_COMPLETE && review_fully_read() && sign_screen_on_display();",
         "    return true;"),
    ]),
    "p2": ("off by one: the read check leaves out the last screen", [
        ("ui.c",
         "    uint32_t every_screen = (1u << max_scr_ix) - 1;\n"
         "    return review_seen_top == every_screen && (review_seen_top_check & every_screen) == 0 &&\n"
         "           review_seen_bottom == every_screen && (review_seen_bottom_check & every_screen) == 0;",
         "    uint32_t every_screen = (1u << (max_scr_ix - 1)) - 1;\n"
         "    return (review_seen_top & every_screen) == every_screen &&\n"
         "           (review_seen_bottom & every_screen) == every_screen;"),
    ]),
    "p3": ("returning to idle keeps the read flag, so it carries over to the next transaction", [
        ("ui.c",
         "void ui_idle(void) {\n    uiState = UI_IDLE;\n    reset_review_progress();\n",
         "void ui_idle(void) {\n    uiState = UI_IDLE;\n"),
    ]),
    "p4": ("the committed digest covers the path bytes as well as the transaction", [
        ("main.c",
         "cx_hash_sha256(raw_tx, body_len, digest, sizeof(digest));\n"
         "    tx_session_arm(digest, body_len, max_scr_ix);",
         "cx_hash_sha256(raw_tx, raw_tx_len, digest, sizeof(digest));\n"
         "    tx_session_arm(digest, raw_tx_len, max_scr_ix);"),
    ]),
    "p5": ("approval does not end the session, so it can sign again", [
        ("tx_session.c",
         "    session_state = SESSION_IDLE;\n\n    if (keys_sign_digest(",
         "    if (keys_sign_digest("),
        ("ui.c",
         "    tx_session_reset();\n    reset_review_progress();\n    if (sw != SW_OK) {",
         "    reset_review_progress();\n    if (sw != SW_OK) {"),
    ]),
    "p6": ("going back from Sign lands one past the last screen, and the index clamp is gone", [
        ("ui.c",
         "            curr_scr_ix = (max_scr_ix > 0) ? max_scr_ix - 1 : 0;",
         "            curr_scr_ix = max_scr_ix;"),
        ("ui.c",
         "    if (curr_scr_ix >= max_scr_ix) {\n        curr_scr_ix = max_scr_ix - 1;\n    }\n",
         ""),
    ]),
    "p7": ("the size check on incoming parts is gone, so a long stream overruns the buffer", [
        ("main.c",
         "    if (lc > MAX_TX_RAW_LENGTH - raw_tx_ix) {\n        return SW_TX_TOO_LARGE;\n    }\n",
         ""),
    ]),
    "p8": ("an earlier version of the Nano S gate: passing the last screen counts as reading all", [
        ("ui.c",
         "            if (curr_scr_ix + 1 >= max_scr_ix) {\n                ui_sign();",
         "            if (curr_scr_ix + 1 >= max_scr_ix) {\n"
         "                review_seen_top = review_seen_bottom = (1u << max_scr_ix) - 1;\n"
         "                review_seen_top_check = review_seen_bottom_check = 0;\n"
         "                review_complete = REVIEW_COMPLETE;\n                ui_sign();"),
    ]),
    "p9": ("the Nano S first half shows a text line where the heading belongs", [
        ("ui.c",
         "        curr_review_title,\n    },\n",
         "        curr_tx_desc[1],\n    },\n"),
    ]),
    "p10": ("the heading is not copied to the Nano S display buffer", [
        ("ui.c",
         "    memmove(curr_review_title, review_title[curr_scr_ix], MAX_TX_TEXT_WIDTH);\n",
         ""),
    ]),
    "p11": ("the Nano S second half draws its two lines in the wrong order", [
        ("ui.c", "        curr_tx_desc[1],\n", "        SWAP_PLACEHOLDER,\n"),
        ("ui.c", "        curr_tx_desc[2],\n", "        curr_tx_desc[1],\n"),
        ("ui.c", "        SWAP_PLACEHOLDER,\n", "        curr_tx_desc[2],\n"),
    ]),
    "p12": ("the Nano S heading is drawn in the regular font, like any other line", [
        ("ui.c",
         "         DEFAULT_FONT,\n         0},\n        curr_review_title,",
         "         TX_DESC_FONT,\n         0},\n        curr_review_title,"),
    ]),
    "p13": ("amounts are checked in characters only, so a wide amount is cut short on screen", [
        ("elastos.c", "    if (!line_fits(out)) {\n        return SW_TX_AMOUNT;\n    }\n", ""),
    ]),
    "p15": ("address lines are not measured, so a wide address is cut short on screen", [
        ("elastos.c",
         "        if (!line_fits(lines[k])) {\n            return SW_TX_ADDRESS_TOO_WIDE;\n        }\n",
         ""),
    ]),
    "p100": ("the signer's own address lines are not measured, so a wide one is cut short on screen", [
        ("elastos.c",
         "    return render_reviewed_address(signer_program_hash, tx_desc[screen]);",
         "    return render_address(signer_program_hash, tx_desc[screen]) ? SW_OK : SW_TX_ADDRESS_TYPE;"),
    ]),
    "p14": ("going back from Sign lands on the first half of the last screen, as in v1.1.5", [
        ("ui.c",
         "            copy_tx_desc();\n            ui_display_tx_desc_2();\n            break;\n",
         "            copy_tx_desc();\n            ui_display_tx_desc_1();\n            break;\n"),
    ]),
    "p17": ("signing no longer compares the screen count with the one committed", [
        ("tx_session.c",
         "    return screens != 0 && (screens ^ committed_screens_check) == ~0u && max_scr_ix == screens;",
         "    return screens != 0;"),
    ]),
    "p18": ("the Nano S review heading sits 11 px above the line below it, which erases its last row", [
        ("ui.c",
         "    /* heading of the current screen */\n    {\n        {BAGL_LABELINE,\n         0x02,\n         10,\n         12,",
         "    /* heading of the current screen */\n    {\n        {BAGL_LABELINE,\n         0x02,\n         10,\n         15,"),
    ]),
    "p19": ("the right button leaves the first part of the account screen", [
        ("ui.c",
         "        case BUTTON_EVT_RELEASED | BUTTON_RIGHT:\n            ui_public_key_2();",
         "        case BUTTON_EVT_RELEASED | BUTTON_RIGHT:\n            ui_idle();"),
    ]),
    "p20": ("the first review screen still says Sign Tx Now", [
        ("ui.c", "        \"Review Tx\",", "        \"Sign Tx Now\","),
    ]),
    "p21": ("both buttons on an unread Sign screen do nothing", [
        ("ui.c",
         "            if (review_complete != REVIEW_COMPLETE || !review_fully_read()) {\n"
         "                show_first_unread_half();\n",
         "            if (review_complete != REVIEW_COMPLETE || !review_fully_read()) {\n"),
    ]),
    "p22": ("the read check forgets the third review screen", [
        ("ui.c",
         "    uint32_t every_screen = (1u << max_scr_ix) - 1;\n    return review_seen_top",
         "    uint32_t every_screen = ((1u << max_scr_ix) - 1) & ~4u;\n    return review_seen_top"),
    ]),
    "p23": ("the second part of the account screen draws its first line twice", [
        ("ui.c",
         "    /* third line of description of current public key  */\n    {\n        {BAGL_LABELINE,\n"
         "         0x02,\n         10,\n         26,\n         108,\n         11,\n         0x80 | 10,\n"
         "         0,\n         0,\n         0xFFFFFF,\n         0x000000,\n         TX_DESC_FONT,\n"
         "         0},\n        current_public_key[2],",
         "    /* third line of description of current public key  */\n    {\n        {BAGL_LABELINE,\n"
         "         0x02,\n         10,\n         26,\n         108,\n         11,\n         0x80 | 10,\n"
         "         0,\n         0,\n         0xFFFFFF,\n         0x000000,\n         TX_DESC_FONT,\n"
         "         0},\n        current_public_key[1],"),
    ]),
    "p24": ("one letter of the width table is a pixel too wide", [
        ("elastos.c", '"$*+012356789<=>EFLSYZ^`aegkvxy|~" DIFFERING_6_PX,',
         '"$*+012356789<=>EFLSYZ^`aegvxy|~" DIFFERING_6_PX,'),
        ("elastos.c", '"#ABCKPRTVbdhnopqu" DIFFERING_7_PX,', '"#ABCKPRTVbdhknopqu" DIFFERING_7_PX,'),
    ]),
    "p25": ("a count above 252 is read as its first byte instead of being refused", [
        ("elastos.c", "    if (*out > MAX_SINGLE_BYTE_COUNT) {\n        return SW_TX_VARINT_TOO_LARGE;\n    }\n", ""),
    ]),
    "p26": ("change is recognised from the 20-byte hash alone, without the address type", [
        ("elastos.c",
         "memcmp(program_hash, signer_program_hash, ELA_PROGRAM_HASH_LEN) == 0",
         "memcmp(program_hash + 1, signer_program_hash + 1, ELA_PROGRAM_HASH_LEN - 1) == 0"),
    ]),
    "p27": ("two letters of the base58 alphabet are swapped", [
        ("base-encoding.c", "'g', 'h', 'i', 'j'", "'g', 'i', 'h', 'j'"),
    ]),
    "p28": ("a payment may spend at most 16 coins", [
        ("elastos.c", "    if (inputs == 0) {", "    if (inputs == 0 || inputs > 16) {"),
    ]),
    "p29": ("signing no longer compares the bytes with the digest committed for them", [
        ("tx_session.c", "        diff |= a[i] ^ b[i];\n    }\n    return diff == 0;",
         "        diff |= a[i] ^ b[i];\n    }\n    return true;"),
    ]),
    "p30": ("the raw key derivation is left on the stack", [
        ("keys.c", "    explicit_bzero(raw, sizeof(raw));\n", ""),
    ]),
    "p31": ("signing leaves the private key on the stack", [
        ("keys.c",
         "                                     &info);\n    }\n    explicit_bzero(&private_key, sizeof(private_key));\n",
         "                                     &info);\n    }\n"),
    ]),
    "p32": ("main never starts the exit timer, so the app closes on the first tick", [
        ("main.c", "                // set timer\n                Timer_Set();\n", ""),
    ]),
    "p33": ("main returns instead of leaving through the OS", [
        ("main.c", "    // Leave through the OS rather than returning from main.\n    os_sched_exit(-1);\n", ""),
    ]),
    "p34": ("the exit instruction is answered but ignored", [
        ("main.c", "            *exit_requested = true;\n", ""),
    ]),
    "p35": ("a button press no longer restarts the exit timer", [
        ("main.c", "    if (exit_timer != MAX_EXIT_TIMER) {", "    if (exit_timer == MAX_EXIT_TIMER) {"),
    ]),
    "p36": ("a key request leaves the private key on the stack", [
        ("keys.c",
         "        memcpy(pubkey, public_key.W, ELA_PUBKEY_LEN);\n    }\n    explicit_bzero(&private_key, sizeof(private_key));\n",
         "        memcpy(pubkey, public_key.W, ELA_PUBKEY_LEN);\n    }\n"),
    ]),
    "p37": ("a poll vote in the memo is read as memo text, not as a vote", [
        ("elastos.c",
         "    if (data_len < POLL_VOTE_FLAG_LEN ||\n        memcmp(raw_tx + raw_tx_ix, POLL_VOTE_FLAG, POLL_VOTE_FLAG_LEN) != 0) {",
         "    if (1) {"),
    ]),
    "p38": ("a vote memo longer than its declared amount is accepted", [
        ("elastos.c",
         "    if (data_len != POLL_VOTE_FIXED_LEN + amount_len || amount_len >= sizeof(amount)) {",
         "    if (data_len < POLL_VOTE_FIXED_LEN + amount_len || amount_len >= sizeof(amount)) {"),
    ]),
    "p39": ("the vote screen numbers choices from 0 while the wallet lists them from the first", [
        ("elastos.c", '"Choice %d", (int) (choice + 1)', '"Choice %d", (int) choice'),
    ]),
    "p40": ("a vote amount with a NUL inside is shown only up to the NUL", [
        ("elastos.c", " strlen(amount) != amount_len ||", ""),
    ]),
    "p53": ("the second half of a Nano S review screen draws its black background last, over the text", [
        ("ui.c",
         "static const bagl_element_t bagl_ui_tx_desc_nanos_2[] = {\n"
         "    // { {type, userid, x, y, width, height, stroke, radius, fill, fgcolor, bgcolor, font_id,\n"
         "    // icon_id},\n"
         "    // text, touch_area_brim, overfgcolor, overbgcolor, tap, out, over,\n"
         "    // },\n"
         "    {\n"
         "        {BAGL_RECTANGLE, 0x00, 0, 0, 128, 32, 0, 0, BAGL_FILL, 0x000000, 0xFFFFFF, 0, 0},\n"
         "        NULL,\n"
         "    },\n",
         "static const bagl_element_t bagl_ui_tx_desc_nanos_2[] = {\n"),
        ("ui.c",
         "        curr_tx_desc[2],\n    },\n",
         "        curr_tx_desc[2],\n    },\n"
         "    {\n"
         "        {BAGL_RECTANGLE, 0x00, 0, 0, 128, 32, 0, 0, BAGL_FILL, 0x000000, 0xFFFFFF, 0, 0},\n"
         "        NULL,\n"
         "    },\n"),
    ]),
    "p54": ("a separator line under the Nano S heading erases the bottom of its letters", [
        ("ui.c",
         "        curr_tx_desc[0],\n    },\n",
         "        curr_tx_desc[0],\n    },\n"
         "    {\n"
         "        {BAGL_RECTANGLE, 0x00, 10, 14, 108, 1, 0, 0, BAGL_FILL, 0x000000, 0x000000, 0, 0},\n"
         "        NULL,\n"
         "    },\n"),
    ]),
    "p41": ("a poll vote may come with a second memo, which readers of the chain may take instead", [
        ("elastos.c", "        if (nonces > MAX_NONCES || memos > MAX_MEMOS) {",
         "        if (nonces > MAX_NONCES || (memos > MAX_MEMOS && !memo_is_vote)) {"),
    ]),
    "p42": ("a memo of 253 bytes or more is taken for a nonce, so it is never read as a vote or as text", [
        ("elastos.c", "        if (usage == ATTRIBUTE_MEMO) {\n            CHECK_SW(parse_memo(",
         "        if (usage == ATTRIBUTE_MEMO && data_len <= MAX_SINGLE_BYTE_COUNT) {\n            CHECK_SW(parse_memo("),
    ]),
    "p43": ("a memo after the first attribute, where the wallet puts it after its nonce, is taken for a nonce", [
        ("elastos.c", "        if (usage == ATTRIBUTE_MEMO) {\n            CHECK_SW(parse_memo(",
         "        if (usage == ATTRIBUTE_MEMO && i < 1) {\n            CHECK_SW(parse_memo("),
    ]),
    "p210": ("memo text is skipped and signed unseen, as in version 1.1.5", [
        ("elastos.c", "        return render_memo_text(data_len, screens);", "        return skip_bytes(data_len);"),
    ]),
    "p211": ("memo lines are measured in characters only, so a wide line is cut short on screen", [
        ("elastos.c", "    return wrap->chars < WRAP_LINE_CHARS && wrap->width + c_width <= REVIEW_LINE_WIDTH_PX;",
         "    return wrap->chars < WRAP_LINE_CHARS;"),
    ]),
    "p212": ("memo text may hold any byte, so a control character or one the font lacks is signed undrawn", [
        ("elastos.c", "        if (!is_memo_char(c) || !wrap_char(&wrap, (char) c, MEMO_BREAKS)) {",
         "        if (!wrap_char(&wrap, (char) c, MEMO_BREAKS)) {"),
    ]),
    "p213": ("a second memo is accepted, and the review shows the second over the first", [
        ("elastos.c", "#define MAX_MEMOS       1", "#define MAX_MEMOS       2"),
    ]),
    "p214": ("a second nonce is accepted, so more data is signed unseen", [
        ("elastos.c", "        if (nonces > MAX_NONCES || memos > MAX_MEMOS) {", "        if (memos > MAX_MEMOS) {"),
    ]),
    "p215": ("a nonce of nine bytes is accepted, one more than is signed unseen", [
        ("elastos.c", "#define MAX_NONCE_LEN 8", "#define MAX_NONCE_LEN 9"),
    ]),
    "p216": ("memo text that leaves no room for every output is accepted, and the review runs past its end", [
        ("elastos.c",
         "    if (MEMO_FIRST_SCREEN + memo_screens + SCREENS_PER_OUTPUT * outputs + FEE_NOTICE_SCREENS >",
         "    if (memo_is_vote && MEMO_FIRST_SCREEN + memo_screens + SCREENS_PER_OUTPUT * outputs + FEE_NOTICE_SCREENS >"),
    ]),
    "p217": ("a line of memo text takes 18 characters, leaving no terminator, so the screen shows 17", [
        ("elastos.c", "#define WRAP_LINE_CHARS (MAX_TX_TEXT_WIDTH - 1)", "#define WRAP_LINE_CHARS MAX_TX_TEXT_WIDTH"),
    ]),
    "p218": ("a line of memo text ends after its first space, comma or colon, not its last that fits", [
        ("elastos.c", "    if (c != '\\0' && strchr(breaks, c) != NULL) {",
         "    if (c != '\\0' && strchr(breaks, c) != NULL && wrap->break_chars == 0) {"),
    ]),
    "p219": ("a word moved to the next line takes the next character too, though it no longer fits", [
        ("elastos.c",
         "        if (!wrap_fits(wrap, c_width) && !wrap_next_line(wrap)) {\n            return false;\n        }\n",
         ""),
    ]),
    "p44": ("signing no longer checks the committed path against its complement", [
        ("tx_session.c", "        if ((committed_path[i] ^ committed_path_check[i]) != ~0u) {", "        if (0) {"),
    ]),
    "p45": ("the Nano S read check trusts the masks without their complements", [
        ("ui.c",
         "    return review_seen_top == every_screen && (review_seen_top_check & every_screen) == 0 &&\n"
         "           review_seen_bottom == every_screen && (review_seen_bottom_check & every_screen) == 0;",
         "    return review_seen_top == every_screen && review_seen_bottom == every_screen;"),
    ]),
    "p46": ("approval no longer checks that the whole review was shown", [
        ("ui.c", "    if (review_shown_whole() && review_shown_whole()) {", "    if (1) {"),
    ]),
    "p47": ("a reply that finds no command to answer is answered again, forever", [
        ("main.c",
         "            CATCH(INVALID_STATE) {\n"
         "                // Nano S: a reply found no command to answer, so no status word can be sent\n"
         "                // either; start the transport again rather than queue one more reply\n"
         "                transport_reset = true;\n"
         "                exit_requested = true;\n"
         "            }\n",
         ""),
    ]),
    "p48": ("a USB reset is answered like any other exception instead of restarting the transport", [
        ("main.c",
         "            CATCH(EXCEPTION_IO_RESET) {\n"
         "                // the transport must be started again; main() does that\n"
         "                transport_reset = true;\n"
         "                exit_requested = true;\n"
         "            }\n",
         ""),
    ]),
    "p49": ("a USB reset closes the app", [
        ("main.c",
         "                // the transport must be started again; main() does that\n"
         "                transport_reset = true;\n",
         "                // the transport must be started again; main() does that\n"),
    ]),
    "p50": ("after an exception the next exchange still waits for a reply as if a review were pending", [
        ("main.c", "                flags = 0;\n                abandon_signing_session();", "                abandon_signing_session();"),
    ]),
    "p51": ("an exception in main closes the app instead of starting the transport again", [
        ("main.c", "                restart = elastos_main();", "                elastos_main();\n                restart = false;"),
    ]),
    "p52": ("the account screen shows the last key the computer asked for, as v1.1.5 did", [
        ("main.c", "    memmove(G_io_apdu_buffer, pubkey, ELA_PUBKEY_LEN);",
         "    display_public_key(pubkey);\n    memmove(G_io_apdu_buffer, pubkey, ELA_PUBKEY_LEN);"),
        ("ui.c", "            load_default_account_address();\n            ui_public_key_1();", "            ui_public_key_1();"),
    ]),
    "p59": ("Nano X and Nano S Plus: approval trusts the flow without checking it", [
        ("ui.c",
         "    return accept_last && reject_after && ux_review_flow[3 + n] == FLOW_END_STEP &&\n"
         "           every_step_drawn && on_accept;",
         "    return true;"),
    ]),
    "p60": ("Nano X and Nano S Plus: approval does not check that Accept is the step on screen", [
        ("ui.c", "           every_step_drawn && on_accept;", "           every_step_drawn;"),
    ]),
    "p61": ("Nano X and Nano S Plus: approval does not check that every review step was drawn", [
        ("ui.c", "           every_step_drawn && on_accept;", "           on_accept;"),
    ]),
    "p70": ("Nano X and Nano S Plus: drawing a review step marks every earlier step as drawn too", [
        ("ui.c",
         "    review_seen_top |= 1u << s;\n    review_seen_top_check &= ~(1u << s);\n",
         "    review_seen_top |= (1u << (s + 1)) - 1;\n    review_seen_top_check &= ~((1u << (s + 1)) - 1);\n"),
    ]),
    "p71": ("Nano X and Nano S Plus: approval checks only that the last review step was drawn", [
        ("ui.c",
         "    bool every_step_drawn =\n"
         "        review_seen_top == every_step && (review_seen_top_check & every_step) == 0;",
         "    bool every_step_drawn = (review_seen_top & (1u << (n - 1))) != 0 && every_step != 0;"),
    ]),
    "p72": ("Nano X and Nano S Plus: approval trusts the drawn-step mask without its complement", [
        ("ui.c",
         "    bool every_step_drawn =\n"
         "        review_seen_top == every_step && (review_seen_top_check & every_step) == 0;",
         "    bool every_step_drawn = review_seen_top == every_step;"),
    ]),
    "p73": ("Nano X and Nano S Plus: approval trusts the complement of the drawn-step mask alone", [
        ("ui.c",
         "    bool every_step_drawn =\n"
         "        review_seen_top == every_step && (review_seen_top_check & every_step) == 0;",
         "    bool every_step_drawn = (review_seen_top_check & every_step) == 0;"),
    ]),
    "p74": ("Nano X and Nano S Plus: approval trusts the Accept flag without its complement", [
        ("ui.c",
         "    bool on_accept = accept_drawn == ACCEPT_DRAWN && (accept_drawn ^ accept_drawn_check) == ~0u;",
         "    bool on_accept = accept_drawn == ACCEPT_DRAWN;"),
    ]),
    "p75": ("Nano X and Nano S Plus: approval does not check that Reject follows Accept", [
        ("ui.c",
         "    bool reject_after = ux_review_flow[2 + n] == &ux_review_reject_step;",
         "    bool reject_after = true;"),
    ]),
    "p76": ("Nano X and Nano S Plus: approval does not check the end marker of the flow", [
        ("ui.c",
         "    return accept_last && reject_after && ux_review_flow[3 + n] == FLOW_END_STEP &&\n",
         "    return accept_last && reject_after &&\n"),
    ]),
    "p77": ("Nano X and Nano S Plus: showing a review step leaves the Accept flag set", [
        ("ui.c",
         "static void mark_review_step_shown(unsigned int s) {\n    set_accept_drawn(false);\n",
         "static void mark_review_step_shown(unsigned int s) {\n"),
        ("ui.c",
         "static void begin_review_step(unsigned int s) {\n    set_accept_drawn(false);\n",
         "static void begin_review_step(unsigned int s) {\n"),
    ]),
    "p78": ("approval checks the whole review once instead of twice", [
        ("ui.c",
         "    if (review_shown_whole() && review_shown_whole()) {",
         "    if (review_shown_whole()) {"),
    ]),
    "p79": ("Nano X and Nano S Plus: the review flow is one slot short, and its size check agrees", [
        ("ui.c",
         "static const ux_flow_step_t *ux_review_flow[MAX_TX_TEXT_SCREENS + 4];",
         "static const ux_flow_step_t *ux_review_flow[MAX_TX_TEXT_SCREENS + 3];"),
        ("ui.c",
         "_Static_assert(sizeof(ux_review_flow) / sizeof(ux_review_flow[0]) == 1 + MAX_TX_TEXT_SCREENS + 3,",
         "_Static_assert(sizeof(ux_review_flow) / sizeof(ux_review_flow[0]) == 1 + MAX_TX_TEXT_SCREENS + 2,"),
    ]),
    "p62": ("the first-half read mask loses its complement", [
        ("ui.c", "    review_seen_top_check = ~0u;\n    review_seen_bottom = 0;",
         "    review_seen_top_check = 0;\n    review_seen_bottom = 0;"),
    ]),
    "p63": ("the Nano S Sign screen draws its black background last, over the label", [
        ("ui.c", "static const bagl_element_t bagl_ui_sign_nanos[] = {\n    // { {type, userid, x, y, width, height, stroke, radius, fill, fgcolor, bgcolor, font_id,\n    // icon_id},\n    // text, touch_area_brim, overfgcolor, overbgcolor, tap, out, over,\n    // },\n    {\n        {BAGL_RECTANGLE, 0x00, 0, 0, 128, 32, 0, 0, BAGL_FILL, 0x000000, 0xFFFFFF, 0, 0},\n        NULL,\n    },\n",
         "static const bagl_element_t bagl_ui_sign_nanos[] = {\n    // { {type, userid, x, y, width, height, stroke, radius, fill, fgcolor, bgcolor, font_id,\n    // icon_id},\n    // text, touch_area_brim, overfgcolor, overbgcolor, tap, out, over,\n    // },\n"),
        ("ui.c", "        \"Sign Tx\",\n    },\n", "        \"Sign Tx\",\n    },\n    {\n        {BAGL_RECTANGLE, 0x00, 0, 0, 128, 32, 0, 0, BAGL_FILL, 0x000000, 0xFFFFFF, 0, 0},\n        NULL,\n    },\n"),
    ]),
    "p64": ("the Nano S Deny screen draws its black background last, over the label", [
        ("ui.c", "static const bagl_element_t bagl_ui_deny_nanos[] = {\n    // { {type, userid, x, y, width, height, stroke, radius, fill, fgcolor, bgcolor, font_id,\n    // icon_id},\n    // text, touch_area_brim, overfgcolor, overbgcolor, tap, out, over,\n    // },\n    {\n        {BAGL_RECTANGLE, 0x00, 0, 0, 128, 32, 0, 0, BAGL_FILL, 0x000000, 0xFFFFFF, 0, 0},\n        NULL,\n    },\n",
         "static const bagl_element_t bagl_ui_deny_nanos[] = {\n    // { {type, userid, x, y, width, height, stroke, radius, fill, fgcolor, bgcolor, font_id,\n    // icon_id},\n    // text, touch_area_brim, overfgcolor, overbgcolor, tap, out, over,\n    // },\n"),
        ("ui.c", "        \"Deny Tx\",\n    },\n", "        \"Deny Tx\",\n    },\n    {\n        {BAGL_RECTANGLE, 0x00, 0, 0, 128, 32, 0, 0, BAGL_FILL, 0x000000, 0xFFFFFF, 0, 0},\n        NULL,\n    },\n"),
    ]),
    "p65": ("an exception from the SDK is answered as a success", [
        ("main.c", "            return 0x6800 | (e & 0x7FF);", "            return SW_OK;"),
    ]),
    "p66": ("a Nano S half is marked read from the screen index, whatever the display holds", [
        ("ui.c",
         "    if (memcmp(curr_tx_desc, tx_desc[curr_scr_ix], CURR_TX_DESC_LEN) != 0 ||\n"
         "        memcmp(curr_review_title, review_title[curr_scr_ix], MAX_TX_TEXT_WIDTH) != 0) {\n"
         "        return;\n    }\n",
         ""),
    ]),
    "p67": ("Quit on the Nano S home screen no longer closes the app", [
        ("ui.c", "    // Go back to the dashboard\n    os_sched_exit(0);\n", "    // Go back to the dashboard\n"),
    ]),
    "p68": ("signing checks the screen count and path only after the hash", [
        ("tx_session.c",
         "    if (!screen_count_matches() || !path_matches() || !tx_session_text_matches()) {\n"
         "        return SW_COMMIT_MISMATCH;\n    }\n"
         "    cx_hash_sha256(",
         "    cx_hash_sha256("),
    ]),
    "p69": ('signing checks the screen count and path only before the hash', [
        ('tx_session.c',
         '    // the path last, just before the key is derived from it, so no long step lies between them\n    if (!screen_count_matches() || !tx_session_text_matches() || !path_matches()) {\n        return SW_COMMIT_MISMATCH;\n    }\n    session_state = SESSION_IDLE;',
         '    session_state = SESSION_IDLE;'),
    ]),
    "p16": ("Up on the top review screen goes straight to Sign instead of Deny", [
        ("ui.c", "        case UI_TOP_SIGN:\n            ui_deny();\n", "        case UI_TOP_SIGN:\n            ui_sign();\n"),
    ]),
    "p90": ('the review is rendered once, so a fault while rendering is committed as the text', [
        ('main.c',
         '    CHECK_SW(signer_address(signing_path, signer_program_hash));\n    CHECK_SW(tx_parse_and_render(signer_program_hash));\n    if (raw_tx_ix != body_len || !tx_session_text_matches()) {\n        return SW_COMMIT_MISMATCH;\n    }\n',
         ''),
    ]),
    "p91": ('signing never checks the review text', [
        ('tx_session.c',
         '    if (!screen_count_matches() || !path_matches() || !tx_session_text_matches()) {\n        return SW_COMMIT_MISMATCH;\n    }\n    cx_hash_sha256(',
         '    if (!screen_count_matches() || !path_matches()) {\n        return SW_COMMIT_MISMATCH;\n    }\n    cx_hash_sha256('),
        ('tx_session.c',
         '    // the path last, just before the key is derived from it, so no long step lies between them\n    if (!screen_count_matches() || !tx_session_text_matches() || !path_matches()) {\n        return SW_COMMIT_MISMATCH;\n    }\n    session_state = SESSION_IDLE;',
         '    // the path last, just before the key is derived from it, so no long step lies between them\n    if (!screen_count_matches() || !path_matches()) {\n        return SW_COMMIT_MISMATCH;\n    }\n    session_state = SESSION_IDLE;'),
    ]),
    "p92": ("signing checks the review text only after the hash", [
        ("tx_session.c",
         "    if (!screen_count_matches() || !path_matches() || !tx_session_text_matches()) {\n"
         "        return SW_COMMIT_MISMATCH;\n    }\n    cx_hash_sha256(",
         "    if (!screen_count_matches() || !path_matches()) {\n"
         "        return SW_COMMIT_MISMATCH;\n    }\n    cx_hash_sha256("),
    ]),
    "p93": ('signing checks the review text only before the hash', [
        ('tx_session.c',
         '    // the path last, just before the key is derived from it, so no long step lies between them\n    if (!screen_count_matches() || !tx_session_text_matches() || !path_matches()) {\n        return SW_COMMIT_MISMATCH;\n    }\n    session_state = SESSION_IDLE;',
         '    // the path last, just before the key is derived from it, so no long step lies between them\n    if (!screen_count_matches() || !path_matches()) {\n        return SW_COMMIT_MISMATCH;\n    }\n    session_state = SESSION_IDLE;'),
    ]),
    "p94": ("the path rule ignores the hardened bit of the change", [
        ("keys.c",
         "           path[3] <= 1 && (path[4] & HARDENED) == 0;",
         "           (path[3] & ~HARDENED) <= 1 && (path[4] & HARDENED) == 0;"),
    ]),
    "p95": ("main() checks the stack canary against a wrong value", [
        ("main.c", "#define APP_STACK_CANARY 0xDEAD0031u", "#define APP_STACK_CANARY 0xDEAD0030u"),
    ]),
    "p96": ("the digest comparison leaves out the last byte", [
        ("tx_session.c",
         "    for (unsigned int i = 0; i < ELA_DIGEST_LEN; i++) {\n        diff |= a[i] ^ b[i];",
         "    for (unsigned int i = 0; i + 1 < ELA_DIGEST_LEN; i++) {\n        diff |= a[i] ^ b[i];"),
    ]),
    "p97": ("the text digest leaves out the review headings", [
        ("tx_session.c",
         "                         (const uint8_t *) review_title,\n"
         "                         sizeof(review_title),\n",
         "                         (const uint8_t *) review_title,\n"
         "                         0,\n"),
    ]),
    "p98": ("a sign request is reviewed without checking its path", [
        ("main.c",
         "    keys_read_path(raw_tx + body_len, path);\n"
         "    if (!keys_path_is_valid(path)) {\n        return SW_BAD_PATH;\n    }\n",
         "    keys_read_path(raw_tx + body_len, path);\n"),
    ]),
    "p99": ("main() no longer checks the stack canary before the transport starts again", [
        ("main.c",
         "        if (transport_started && app_stack_canary != APP_STACK_CANARY) {\n"
         "            io_seproxyhal_se_reset();\n        }\n",
         ""),
    ]),
    "p80": ("Nano S approval does not check that the Sign screen is on the display", [
        ("ui.c",
         "    return review_complete == REVIEW_COMPLETE && review_fully_read() && sign_screen_on_display();",
         "    return review_complete == REVIEW_COMPLETE && review_fully_read();"),
    ]),
    "p81": ("a Nano S half is marked read when it is asked for, not once it has been drawn", [
        ("ui.c",
         "    uiState = UI_TX_DESC_1;\n    UX_DISPLAY(bagl_ui_tx_desc_nanos_1, NULL);\n",
         "    uiState = UI_TX_DESC_1;\n    UX_DISPLAY(bagl_ui_tx_desc_nanos_1, NULL);\n"
         "    mark_review_half_shown(&review_seen_top, &review_seen_top_check);\n"),
        ("ui.c",
         "    uiState = UI_TX_DESC_2;\n    UX_DISPLAY(bagl_ui_tx_desc_nanos_2, NULL);\n",
         "    uiState = UI_TX_DESC_2;\n    UX_DISPLAY(bagl_ui_tx_desc_nanos_2, NULL);\n"
         "    mark_review_half_shown(&review_seen_bottom, &review_seen_bottom_check);\n"),
    ]),
    "p82": ("Nano S io_seproxyhal_display sends nothing to the display", [
        ("main.c", "    io_seproxyhal_display_default((bagl_element_t *) element);", "    UNUSED(element);"),
    ]),
    "p83": ("Nano S io_event ignores the display-processed event, so a screen stops after one element", [
        ("main.c",
         "            if (UX_DISPLAYED()) {\n"
         "                // perform actions after all screen elements have been displayed\n"
         "            } else {\n"
         "                UX_DISPLAYED_EVENT();\n"
         "            }\n",
         ""),
    ]),
    "p84": ("Deny sends its reply even when no review is armed, so presses during the reply nest replies", [
        ("ui.c",
         "    if (!tx_session_is_armed()) {\n        return 0;\n    }\n"
         "    tx_session_reset();\n    reset_review_progress();\n"
         "    G_io_apdu_buffer[0] = SW_USER_REJECTED >> 8;",
         "    tx_session_reset();\n    reset_review_progress();\n"
         "    G_io_apdu_buffer[0] = SW_USER_REJECTED >> 8;"),
    ]),
    "p85": ("Deny forgets the review only after its reply is sent", [
        ("ui.c",
         "    tx_session_reset();\n    reset_review_progress();\n"
         "    G_io_apdu_buffer[0] = SW_USER_REJECTED >> 8;\n"
         "    G_io_apdu_buffer[1] = SW_USER_REJECTED & 0xFF;\n"
         "    // Send back the response, do not restart the event loop\n"
         "    io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, 2);\n",
         "    G_io_apdu_buffer[0] = SW_USER_REJECTED >> 8;\n"
         "    G_io_apdu_buffer[1] = SW_USER_REJECTED & 0xFF;\n"
         "    // Send back the response, do not restart the event loop\n"
         "    io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, 2);\n"
         "    tx_session_reset();\n    reset_review_progress();\n"),
    ]),
    "p86": ("an SDK error while Accept or Reject replies leaves the review on screen", [
        ("main.c",
         "    bool review_on_screen = tx_session_is_armed() || ui_review_on_screen();",
         "    bool review_on_screen = tx_session_is_armed();"),
    ]),
    "p101": ("a Nano S screen counts as drawn once its first element reaches the display", [
        ("ui.c",
         "    if (drawn == count) {\n        elements_drawn = 0;\n        screen_drawn(layout);\n    }\n",
         "    if (drawn != 0) {\n        screen_drawn(layout);\n    }\n"),
    ]),
    "p102": ("Nano S signs without checking that the Sign screen was drawn in full", [
        ("ui.c",
         "                             sizeof(bagl_ui_sign_nanos) / sizeof(bagl_ui_sign_nanos[0])) &&\n"
         "           sign_drawn;",
         "                             sizeof(bagl_ui_sign_nanos) / sizeof(bagl_ui_sign_nanos[0])) &&\n"
         "           (sign_drawn || true);"),
    ]),
    "p103": ("the Nano S display hook no longer tells the review what was drawn", [
        ("main.c", "    ui_element_drawn(!sent_before && io_seproxyhal_spi_is_status_sent() ? element : NULL);\n",
         "    (void) sent_before;\n"),
    ]),
    "p104": ("Nano X: a layout counts as drawn whatever the SDK did", [
        ("ui.c", "    return count != 0 && index == count + 1 && layout_elements_drawn == count;", "    return true;"),
    ]),
    "p105": ("Nano X: neither the element index nor the count of elements drawn is cleared before a layout", [
        ("ui.c",
         "    *(volatile unsigned short *) &G_ux.stack[stack_slot].element_index = 0;\n"
         "    layout_elements_drawn = 0;\n",
         "    (void) stack_slot;\n"),
    ]),
    "p106": ("Nano X: Accept counts as on screen as soon as its step starts, before it is drawn", [
        ("ui.c",
         "UX_STEP_CB_INIT(ux_review_accept_step,\n                accept_pb,\n                set_accept_drawn(false),",
         "UX_STEP_CB_INIT(ux_review_accept_step,\n                pb,\n                set_accept_drawn(true),"),
    ]),
    "p130": ("Nano X and Nano S Plus: approval does not check that each review slot holds its own step", [
        ("ui.c",
         "    for (unsigned int s = 0; s < n; s++) {\n"
         "        if (ux_review_flow[1 + s] != review_step(s)) {\n"
         "            return false;\n"
         "        }\n"
         "    }\n",
         ""),
    ]),
    "p131": ("Nano X and Nano S Plus: approval does not check that the flow starts on the intro", [
        ("ui.c",
         "    if (n == 0 || n > MAX_TX_TEXT_SCREENS || ux_review_flow[0] != &ux_review_intro_step) {",
         "    if (n == 0 || n > MAX_TX_TEXT_SCREENS) {"),
    ]),
    "p132": ("Nano X and Nano S Plus: approval does not check that Accept follows the last review step", [
        ("ui.c",
         "    bool accept_last = ux_review_flow[1 + n] == &ux_review_accept_step;",
         "    bool accept_last = true;"),
    ]),
    "p133": ("the account screen shows an address too wide for the screen cut, not refused", [
        ("elastos.c",
         "    unsigned short sw = render_reviewed_address(program_hash, current_public_key);",
         "    unsigned short sw = render_address(program_hash, current_public_key) ? SW_OK : SW_TX_ADDRESS_TYPE;"),
    ]),
    "p160": ("Nano X and Nano S Plus: the review does not count as on screen, so an SDK error leaves it there", [
        ("ui.c",
         "    uiState = UI_TOP_SIGN;\n\n#if defined(TARGET_NANOS)\n    UX_DISPLAY(bagl_ui_top_sign_nanos, NULL);",
         "#if defined(TARGET_NANOS)\n    uiState = UI_TOP_SIGN;\n    UX_DISPLAY(bagl_ui_top_sign_nanos, NULL);"),
    ]),
    "p161": ("Nano X: a layout counts as drawn as soon as its drawing starts", [
        ("ui.c", "    return count != 0 && index == count + 1 && layout_elements_drawn == count;", "    return count != 0 && index != 0;"),
    ]),
    "p162": ("Nano X: a layout counts as drawn once its last element is, before the screen is updated", [
        ("ui.c", "    return count != 0 && index == count + 1 && layout_elements_drawn == count;", "    return count != 0 && index >= count;"),
    ]),
    "p163": ("an address check does not count as on screen, so an SDK error leaves it there", [
        ("ui.c", "        case UI_DENY:\n        case UI_ADDRESS_CHECK:\n", "        case UI_DENY:\n"),
    ]),
    "p164": ("Nano X and Nano S Plus: the address check does not count as on screen", [
        ("ui.c",
         "    uiState = UI_ADDRESS_CHECK;\n    if (G_ux.stack_count == 0) {",
         "    if (G_ux.stack_count == 0) {"),
    ]),
    "p165": ("returning to idle keeps the screen state, so a closed review still counts as on screen", [
        ("ui.c", "void ui_idle(void) {\n    uiState = UI_IDLE;\n", "void ui_idle(void) {\n"),
    ]),
    "p120": ("an SDK error that is already a status word is sent as 68xx instead of unchanged", [
        ("main.c", "        case 0x6000:\n        case 0x9000:\n            return e;\n", ""),
    ]),
    "p121": ("an SDK error is sent as 6800 plus its low 8 bits instead of its low 11", [
        ("main.c", "            return 0x6800 | (e & 0x7FF);", "            return 0x6800 | (e & 0xFF);"),
    ]),
    "p122": ("signing checks the session state only once", [
        ("tx_session.c",
         "    if (session_state != SESSION_ARMED) {\n        return SW_NOT_ARMED;\n    }\n"
         "    if (!digests_match(digest, committed_digest)) {",
         "    if (!digests_match(digest, committed_digest)) {"),
    ]),
    "p123": ('signing compares the digest only once', [
        ('tx_session.c',
         '    if (!digests_match(digest, committed_digest)) {\n        return SW_COMMIT_MISMATCH;\n    }\n    // the path last',
         '    // the path last'),
    ]),
    "p124": ("the review text counts as unchanged when its hash fails", [
        ("tx_session.c",
         "    if (!review_text_digest(digest)) {\n        return false;\n    }",
         "    if (!review_text_digest(digest)) {\n        return true;\n    }"),
    ]),
    "p125": ("signing reads the path again from the buffer, as v1.1.5 did, not the committed path", [
        ("tx_session.c",
         "    if (keys_sign_digest(committed_path, committed_digest, out, &signature_len) != CX_OK) {",
         "    unsigned int path[ELA_PATH_LEN];\n"
         "    keys_read_path(raw_tx + committed_body_len, path);\n"
         "    if (keys_sign_digest(path, committed_digest, out, &signature_len) != CX_OK) {"),
    ]),
    "p126": ('the key shown is derived from the path read for review, not from the committed copy', [
        ('main.c',
         '    CHECK_SW(signer_address(signing_path, signer_program_hash));\n\n    CHECK_SW(tx_parse_and_render(signer_program_hash));',
         '    CHECK_SW(signer_address(path, signer_program_hash));\n\n    CHECK_SW(tx_parse_and_render(signer_program_hash));'),
        ('main.c',
         '    CHECK_SW(signer_address(signing_path, signer_program_hash));\n    CHECK_SW(tx_parse_and_render(signer_program_hash));\n    if (raw_tx_ix',
         '    CHECK_SW(signer_address(path, signer_program_hash));\n    CHECK_SW(tx_parse_and_render(signer_program_hash));\n    if (raw_tx_ix'),
    ]),
    "p127": ("signing checks the committed path against its complement but not against the path rule", [
        ("tx_session.c", "    return keys_path_is_valid(committed_path);", "    return true;"),
    ]),
    "p110": ("a Nano S half is marked read when the heading on display matches, whatever its lines", [
        ("ui.c",
         "    if (memcmp(curr_tx_desc, tx_desc[curr_scr_ix], CURR_TX_DESC_LEN) != 0 ||\n"
         "        memcmp(curr_review_title, review_title[curr_scr_ix], MAX_TX_TEXT_WIDTH) != 0) {",
         "    if (memcmp(curr_review_title, review_title[curr_scr_ix], MAX_TX_TEXT_WIDTH) != 0) {"),
    ]),
    "p111": ("the Nano S read check trusts the complements of the read marks alone", [
        ("ui.c",
         "    return review_seen_top == every_screen && (review_seen_top_check & every_screen) == 0 &&\n"
         "           review_seen_bottom == every_screen && (review_seen_bottom_check & every_screen) == 0;",
         "    return (review_seen_top_check & every_screen) == 0 && (review_seen_bottom_check & every_screen) == 0;"),
    ]),
    "p112": ("the Nano S screen index is no longer brought back to the last screen before its text is copied", [
        ("ui.c", "    if (curr_scr_ix >= max_scr_ix) {\n        curr_scr_ix = max_scr_ix - 1;\n    }\n", ""),
    ]),
    "p113": ("a new review keeps the read marks it finds, so only the reset when the last review ended clears them", [
        ("ui.c",
         "void ui_start_review(void) {\n    reset_review_progress();\n    ui_top_sign();\n}",
         "void ui_start_review(void) {\n    ui_top_sign();\n}"),
    ]),
    "p114": ("both buttons on the Nano S Sign screen approve whenever the review is read, even while Sign is drawn again", [
        ("ui.c",
         "            if (review_complete != REVIEW_COMPLETE || !review_fully_read()) {\n"
         "                show_first_unread_half();\n"
         "            } else if (sign_screen_on_display()) {\n"
         "                io_seproxyhal_touch_approve(NULL);\n"
         "            }\n",
         "            if (review_complete == REVIEW_COMPLETE && review_fully_read()) {\n"
         "                io_seproxyhal_touch_approve(NULL);\n"
         "            } else {\n"
         "                show_first_unread_half();\n"
         "            }\n"),
    ]),
    "p115": ("Nano S elements drawn for one screen count towards the next screen drawn on from the same index", [
        ("ui.c",
         "    } else if (drawn != 0 && drawn < count && elements_drawn_of == layout &&\n"
         "               element == &layout[drawn]) {",
         "    } else if (drawn != 0 && drawn < count && element == &layout[drawn]) {"),
    ]),
    "p140": ("Approve on the address check replies whether or not a check is pending", [
        ("ui.c",
         "    unsigned short sw = SW_OK;\n    if (!address_check_pending) {\n        return;\n    }\n",
         "    unsigned short sw = SW_OK;\n"),
    ]),
    "p141": ("Reject on the address check replies whether or not a check is pending", [
        ("ui.c",
         "static void address_check_reject(void) {\n    if (!address_check_pending) {\n        return;\n    }\n",
         "static void address_check_reject(void) {\n"),
    ]),
    "p142": ("both buttons reject the address check on every page but Approve, the path and address pages too", [
        ("ui.c",
         "            } else if (page == ADDRESS_CHECK_REJECT_PAGE) {\n                address_check_reject();",
         "            } else {\n                address_check_reject();"),
    ]),
    "p143": ("returning to idle leaves an address check pending", [
        ("ui.c",
         "    reset_review_progress();\n    address_check_pending = false;\n\n",
         "    reset_review_progress();\n\n"),
    ]),
    "p144": ("a key request with any P1 but 00 shows the address, so P1 02 does", [
        ("main.c",
         "    if ((p1 != P1_KEY_SILENT && p1 != P1_KEY_SHOW) || G_io_apdu_buffer[OFFSET_P2] != 0) {",
         "    if (G_io_apdu_buffer[OFFSET_P2] != 0) {"),
        ("main.c",
         "    if (p1 == P1_KEY_SHOW) {\n        CHECK_SW(ui_start_address_check(path));",
         "    if (p1 != P1_KEY_SILENT) {\n        CHECK_SW(ui_start_address_check(path));"),
    ]),
    "p145": ("the address check shows paths the specification refuses", [
        ("main.c",
         "    if (!keys_path_is_valid(path)) {\n        return SW_BAD_PATH;\n    }\n    if (p1 == P1_KEY_SHOW) {",
         "    if (p1 != P1_KEY_SHOW && !keys_path_is_valid(path)) {\n        return SW_BAD_PATH;\n    }\n"
         "    if (p1 == P1_KEY_SHOW) {"),
    ]),
    "p146": ("Approve on the address check replies with the key of the device's first address", [
        ("ui.c",
         "    if (keys_get_public_key(address_check_path, G_io_apdu_buffer) == CX_OK) {",
         "    if (keys_get_public_key(DEFAULT_ACCOUNT_PATH, G_io_apdu_buffer) == CX_OK) {"),
    ]),
    "p147": ("a key request with P1 00 waits for the user as P1 01 does", [
        ("main.c",
         "    if (p1 == P1_KEY_SHOW) {\n        CHECK_SW(ui_start_address_check(path));",
         "    if (p1 == P1_KEY_SHOW || p1 == P1_KEY_SILENT) {\n        CHECK_SW(ui_start_address_check(path));"),
    ]),
    "p148": ("the address check shows the device's first address, whatever path was asked for", [
        ("ui.c",
         "    if (keys_get_public_key(path, pubkey) != CX_OK) {\n        return SW_CRYPTO_FAILED;\n    }\n"
         "    CHECK_SW(display_path_to_check(path));\n    CHECK_SW(display_address_to_check(pubkey));",
         "    if (keys_get_public_key(DEFAULT_ACCOUNT_PATH, pubkey) != CX_OK) {\n        return SW_CRYPTO_FAILED;\n    }\n"
         "    CHECK_SW(display_path_to_check(path));\n    CHECK_SW(display_address_to_check(pubkey));"),
    ]),
    "p149": ("an SDK error during the address check leaves it on screen, still pending", [
        ("ui.c", "        case UI_DENY:\n        case UI_ADDRESS_CHECK:\n            return true;",
         "        case UI_DENY:\n            return true;"),
    ]),
    "p170": ("a refused address check leaves its address on the account screen", [
        ("elastos.c",
         "    CHECK_SW(render_reviewed_address(program_hash, lines));\n"
         "    memcpy(current_public_key, lines, sizeof(current_public_key));\n    return SW_OK;",
         "    (void) lines;\n    return render_reviewed_address(program_hash, current_public_key);"),
    ]),
    "p200": ("Nano X: a layout drawn to its end counts as drawn with one of its elements never drawn", [
        ("ui.c", "    return count != 0 && index == count + 1 && layout_elements_drawn == count;",
         "    return count != 0 && index == count + 1;"),
    ]),
    "p201": ("approval throws away the first check of the whole review, so the second decides alone", [
        ("ui.c",
         "    if (review_shown_whole() && review_shown_whole()) {",
         "    bool whole = review_shown_whole();\n    whole = review_shown_whole();\n    if (whole) {"),
    ]),
    "p202": ("the account screen keeps the last address shown when its own key cannot be derived", [
        ("ui.c",
         "    if (keys_get_public_key(DEFAULT_ACCOUNT_PATH, pubkey) != CX_OK) {\n"
         "        display_no_public_key();\n        return;\n    }\n    display_public_key(pubkey);",
         "    if (keys_get_public_key(DEFAULT_ACCOUNT_PATH, pubkey) == CX_OK) {\n"
         "        display_public_key(pubkey);\n    }"),
    ]),
    "p203": ("the account screen keeps the last address shown when its program hash fails", [
        ("elastos.c",
         "    if (keys_program_hash(public_key, program_hash) != CX_OK) {\n"
         "        display_no_public_key();\n        return false;\n    }\n",
         "    if (keys_program_hash(public_key, program_hash) != CX_OK) {\n        return false;\n    }\n"),
    ]),
    "p204": ("the account screen's placeholder leaves the last line of the address shown before it", [
        ("elastos.c",
         "void display_no_public_key(void) {\n    memset(current_public_key, 0, sizeof(current_public_key));\n",
         "void display_no_public_key(void) {\n"),
    ]),
    "p180": ("a key request with one byte after its path is answered as if the byte were not there", [
        ("main.c",
         "    if (rx > APDU_HEADER_LENGTH + ELA_PATH_BYTES) {",
         "    if (rx > APDU_HEADER_LENGTH + ELA_PATH_BYTES + 1) {"),
    ]),
    "p181": ("an address check keeps a transaction still being received; only a key request answered at once ends it", [
        ("main.c",
         "        case INS_GET_PUBLIC_KEY:\n            Timer_Restart();\n            abandon_signing_session();\n",
         "        case INS_GET_PUBLIC_KEY:\n            Timer_Restart();\n"),
        ("main.c",
         "    if (keys_get_public_key(path, pubkey) != CX_OK) {\n        return SW_CRYPTO_FAILED;\n    }\n"
         "    memmove(G_io_apdu_buffer, pubkey, ELA_PUBKEY_LEN);",
         "    abandon_signing_session();\n"
         "    if (keys_get_public_key(path, pubkey) != CX_OK) {\n        return SW_CRYPTO_FAILED;\n    }\n"
         "    memmove(G_io_apdu_buffer, pubkey, ELA_PUBKEY_LEN);"),
    ]),
    "p182": ("only a key request answered at once restarts the exit timer", [
        ("main.c",
         "        case INS_GET_PUBLIC_KEY:\n            Timer_Restart();\n            abandon_signing_session();\n",
         "        case INS_GET_PUBLIC_KEY:\n            abandon_signing_session();\n"),
        ("main.c",
         "    if (keys_get_public_key(path, pubkey) != CX_OK) {\n        return SW_CRYPTO_FAILED;\n    }\n"
         "    memmove(G_io_apdu_buffer, pubkey, ELA_PUBKEY_LEN);",
         "    Timer_Restart();\n"
         "    if (keys_get_public_key(path, pubkey) != CX_OK) {\n        return SW_CRYPTO_FAILED;\n    }\n"
         "    memmove(G_io_apdu_buffer, pubkey, ELA_PUBKEY_LEN);"),
    ]),
    "p183": ("an unknown instruction restarts the exit timer", [
        ("main.c",
         "        default:\n            return SW_INS_NOT_SUPPORTED;",
         "        default:\n            Timer_Restart();\n            return SW_INS_NOT_SUPPORTED;"),
    ]),
    "p184": ("a sign part refused for its P1, P2 or length no longer restarts the exit timer", [
        ("main.c",
         "        case INS_SIGN:\n            Timer_Restart();\n            return handle_sign(rx, flags);",
         "        case INS_SIGN:\n            return handle_sign(rx, flags);"),
        ("main.c",
         "        return SW_WRONG_LENGTH;\n    }\n\n    if (!tx_session_is_receiving()) {",
         "        return SW_WRONG_LENGTH;\n    }\n    Timer_Restart();\n\n    if (!tx_session_is_receiving()) {"),
    ]),
    "p185": ("a button press while an address check waits no longer restarts the exit timer", [
        ("main.c",
         "        case SEPROXYHAL_TAG_BUTTON_PUSH_EVENT:  // for Nano S\n            Timer_Restart();\n",
         "        case SEPROXYHAL_TAG_BUTTON_PUSH_EVENT:  // for Nano S\n"
         "            if (uiState != UI_ADDRESS_CHECK) {\n                Timer_Restart();\n            }\n"),
    ]),
    "p186": ("the exit timer stops while an address check waits", [
        ("main.c",
         "static void Timer_Tick() {\n    if (exit_timer > 0) {",
         "static void Timer_Tick() {\n    if (exit_timer > 0 && uiState != UI_ADDRESS_CHECK) {"),
    ]),
    "p150": ("the second render reuses the signer's address worked out for the first", [
        ("main.c",
         "    CHECK_SW(signer_address(signing_path, signer_program_hash));\n"
         "    CHECK_SW(tx_parse_and_render(signer_program_hash));\n"
         "    if (raw_tx_ix != body_len ||",
         "    CHECK_SW(tx_parse_and_render(signer_program_hash));\n"
         "    if (raw_tx_ix != body_len ||"),
    ]),
    "p151": ("the review does not check that the first render read exactly the body it hashes", [
        ("main.c",
         "    // the bytes hashed and signed must be exactly those the parser read to its end\n"
         "    if (raw_tx_ix != body_len) {\n        return SW_COMMIT_MISMATCH;\n    }\n",
         ""),
    ]),
    "p152": ("the review does not check that the second render read exactly the body it hashed", [
        ("main.c",
         "    if (raw_tx_ix != body_len || !tx_session_text_matches()) {",
         "    if (!tx_session_text_matches()) {"),
    ]),
    "p153": ("signing checks the path before the review text in its second round, not last", [
        ("tx_session.c",
         "    if (!screen_count_matches() || !tx_session_text_matches() || !path_matches()) {",
         "    if (!screen_count_matches() || !path_matches() || !tx_session_text_matches()) {"),
    ]),
    "p154": ("new text for the Nano S display does not restart a drawing under way", [
        ("ui.c", "    elements_drawn = 0;\n    elements_drawn_of = NULL;\n    memmove(curr_tx_desc,",
         "    memmove(curr_tx_desc,"),
    ]),
    "p155": ("only a refused transaction ends the session, not any refused command", [
        ("main.c",
         "                if (sw != SW_OK) {\n                    abandon_signing_session();\n",
         "                if (sw != SW_OK) {\n"),
        ("main.c",
         "    CHECK_SW(prepare_review());\n",
         "    unsigned short review_sw = prepare_review();\n"
         "    if (review_sw != SW_OK) {\n        abandon_signing_session();\n        return review_sw;\n    }\n"),
    ]),
    "p156": ("signing no longer bounds the committed body length before hashing it", [
        ("tx_session.c",
         "    if (committed_body_len == 0 || committed_body_len > MAX_TX_RAW_LENGTH) {\n"
         "        return SW_NOT_ARMED;\n    }\n",
         ""),
    ]),
    "p157": ("an SDK error keeps a transaction still being received", [
        ("main.c",
         "                flags = 0;\n                abandon_signing_session();\n                tx = append_status_word(",
         "                flags = 0;\n                if (!tx_session_is_receiving()) {\n"
         "                    abandon_signing_session();\n                }\n                tx = append_status_word("),
    ]),
    "p158": ("the Nano S screen index is brought back only when past the screen count, not on it", [
        ("ui.c",
         "    if (curr_scr_ix >= max_scr_ix) {\n        curr_scr_ix = max_scr_ix - 1;\n    }\n",
         "    if (curr_scr_ix > max_scr_ix) {\n        curr_scr_ix = max_scr_ix - 1;\n    }\n"),
    ]),
    "p159": ("a button press while a review waits no longer restarts the exit timer", [
        ("main.c",
         "        case SEPROXYHAL_TAG_BUTTON_PUSH_EVENT:  // for Nano S\n            Timer_Restart();\n",
         "        case SEPROXYHAL_TAG_BUTTON_PUSH_EVENT:  // for Nano S\n"
         "            if (!tx_session_is_armed()) {\n                Timer_Restart();\n            }\n"),
    ]),
    "p171": ("a refused address check is not answered, so the key request waits with nothing to answer it", [
        ("main.c", "        CHECK_SW(ui_start_address_check(path));\n", "        ui_start_address_check(path);\n"),
    ]),
    "p172": ("a key request with P1 00 answers a failed derivation with whatever the key buffer held", [
        ("main.c",
         "    if (keys_get_public_key(path, pubkey) != CX_OK) {\n        return SW_CRYPTO_FAILED;\n    }\n"
         "    memmove(G_io_apdu_buffer, pubkey, ELA_PUBKEY_LEN);",
         "    keys_get_public_key(path, pubkey);\n    memmove(G_io_apdu_buffer, pubkey, ELA_PUBKEY_LEN);"),
    ]),
    "p173": ("Approve on the address check answers a failed derivation as a key", [
        ("ui.c",
         "    if (keys_get_public_key(address_check_path, G_io_apdu_buffer) == CX_OK) {\n"
         "        tx = ELA_PUBKEY_LEN;\n    } else {\n        sw = SW_CRYPTO_FAILED;\n    }\n",
         "    keys_get_public_key(address_check_path, G_io_apdu_buffer);\n    tx = ELA_PUBKEY_LEN;\n"),
    ]),
    "p174": ("the review's \"Signing with\" ignores a failed derivation or program hash", [
        ("main.c",
         "    if (keys_get_public_key(signing_path, pubkey) != CX_OK ||\n"
         "        keys_program_hash(pubkey, program_hash) != CX_OK) {\n        return SW_CRYPTO_FAILED;\n    }\n",
         "    keys_get_public_key(signing_path, pubkey);\n    keys_program_hash(pubkey, program_hash);\n"),
    ]),
    "p175": ("a failed signature is sent as a signature", [
        ("tx_session.c",
         "    if (keys_sign_digest(committed_path, committed_digest, out, &signature_len) != CX_OK) {\n"
         "        return SW_CRYPTO_FAILED;\n    }\n",
         "    keys_sign_digest(committed_path, committed_digest, out, &signature_len);\n"),
    ]),
    "p176": ("the review's \"Signing with\" ignores a failed program hash", [
        ("main.c",
         "    if (keys_get_public_key(signing_path, pubkey) != CX_OK ||\n"
         "        keys_program_hash(pubkey, program_hash) != CX_OK) {\n        return SW_CRYPTO_FAILED;\n    }\n",
         "    if (keys_get_public_key(signing_path, pubkey) != CX_OK) {\n        return SW_CRYPTO_FAILED;\n    }\n"
         "    keys_program_hash(pubkey, program_hash);\n"),
    ]),
    "p177": ("the address check shows an address worked out from a key never derived", [
        ("ui.c",
         "    if (keys_get_public_key(path, pubkey) != CX_OK) {\n        return SW_CRYPTO_FAILED;\n    }\n"
         "    CHECK_SW(display_path_to_check(path));\n    CHECK_SW(display_address_to_check(pubkey));",
         "    keys_get_public_key(path, pubkey);\n    CHECK_SW(display_path_to_check(path));\n"
         "    CHECK_SW(display_address_to_check(pubkey));"),
    ]),
    "p178": ("the address check shows an address whose program hash failed", [
        ("elastos.c",
         "    if (keys_program_hash(public_key, program_hash) != CX_OK) {\n        return SW_CRYPTO_FAILED;\n    }\n"
         "    CHECK_SW(render_reviewed_address(program_hash, lines));",
         "    keys_program_hash(public_key, program_hash);\n"
         "    CHECK_SW(render_reviewed_address(program_hash, lines));"),
    ]),
    "p179": ("the Nano S display hook counts an element whether or not the SDK sent it", [
        ("main.c", "    ui_element_drawn(!sent_before && io_seproxyhal_spi_is_status_sent() ? element : NULL);\n",
         "    (void) sent_before;\n    ui_element_drawn(element);\n"),
    ]),
    "p190": ("the Nano S display hook counts an element on a status out after the call alone", [
        ("main.c", "#if defined(TARGET_NANOS)\n    bool sent_before = io_seproxyhal_spi_is_status_sent();\n#endif  // TARGET_NANOS\n",
         ""),
        ("main.c", "    ui_element_drawn(!sent_before && io_seproxyhal_spi_is_status_sent() ? element : NULL);\n",
         "    ui_element_drawn(io_seproxyhal_spi_is_status_sent() ? element : NULL);\n"),
    ]),
    "p191": ("signing throws away the result of the first digest comparison", [
        ("tx_session.c",
         "    cx_hash_sha256(raw_tx, committed_body_len, digest, sizeof(digest));\n"
         "    if (!digests_match(digest, committed_digest)) {\n        return SW_COMMIT_MISMATCH;\n    }\n",
         "    cx_hash_sha256(raw_tx, committed_body_len, digest, sizeof(digest));\n"
         "    (void) digests_match(digest, committed_digest);\n"),
    ]),
    "p192": ("the account screen keeps the last address in its lines when its own key cannot be derived", [
        ("ui.c",
         "    if (keys_get_public_key(DEFAULT_ACCOUNT_PATH, pubkey) != CX_OK) {\n"
         "        display_no_public_key();\n        return;\n    }\n    display_public_key(pubkey);\n",
         "    if (keys_get_public_key(DEFAULT_ACCOUNT_PATH, pubkey) == CX_OK) {\n"
         "        display_public_key(pubkey);\n    }\n"),
    ]),
    "p193": ("the account screen keeps the last address in its lines when its program hash fails", [
        ("elastos.c",
         "    if (keys_program_hash(public_key, program_hash) != CX_OK) {\n"
         "        display_no_public_key();\n        return false;\n    }\n",
         "    if (keys_program_hash(public_key, program_hash) != CX_OK) {\n        return false;\n    }\n"),
    ]),
    "p194": ("the address check keeps its path in 24 bits per component, losing each top byte", [
        ("ui.c", "    memcpy(address_check_path, path, sizeof(address_check_path));\n",
         "    for (unsigned int i = 0; i < ELA_PATH_LEN; i++) {\n"
         "        address_check_path[i] = path[i] & 0xFFFFFF;\n    }\n"),
    ]),
    "p220": ("a key request with P1 00 answers any account: the account limit of the silent range is gone", [
        ("keys.c",
         "    if ((account & ~HARDENED) > MAX_BIP44_ACCOUNT_RECOMMENDED ||\n"
         "        index > MAX_BIP44_ADDRESS_INDEX_RECOMMENDED) {",
         "    if (index > MAX_BIP44_ADDRESS_INDEX_RECOMMENDED) {"),
    ]),
    "p221": ("a key request with P1 00 answers any index: the index limit of the silent range is gone", [
        ("keys.c",
         "    if ((account & ~HARDENED) > MAX_BIP44_ACCOUNT_RECOMMENDED ||\n"
         "        index > MAX_BIP44_ADDRESS_INDEX_RECOMMENDED) {",
         "    if ((account & ~HARDENED) > MAX_BIP44_ACCOUNT_RECOMMENDED) {"),
    ]),
    "p222": ("off by one: the account limit is taken as the first account outside the range, so a key "
             "request with P1 00 refuses account 100', which Ledger's Bitcoin app answers", [
        ("keys.c", "(account & ~HARDENED) > MAX_BIP44_ACCOUNT_RECOMMENDED",
         "(account & ~HARDENED) >= MAX_BIP44_ACCOUNT_RECOMMENDED"),
    ]),
    "p223": ("off by one: the index limit is taken as the first index outside the range, so a key "
             "request with P1 00 refuses index 50,000, which Ledger's Bitcoin app answers", [
        ("keys.c", "index > MAX_BIP44_ADDRESS_INDEX_RECOMMENDED", "index >= MAX_BIP44_ADDRESS_INDEX_RECOMMENDED"),
    ]),
    "p224": ("the silent range is checked once, so one skipped check answers a key outside it", [
        ("main.c",
         "    if (!keys_path_is_silent(path) || !keys_path_is_silent(path)) {\n",
         "    if (!keys_path_is_silent(path)) {\n"),
    ]),
    "p225": ("a key request with P1 00 derives its key before the silent range refuses it", [
        ("main.c",
         "    if (!keys_path_is_silent(path) || !keys_path_is_silent(path)) {\n"
         "        return SW_PATH_NEEDS_CHECK;\n    }\n"
         "    if (keys_get_public_key(path, pubkey) != CX_OK) {\n        return SW_CRYPTO_FAILED;\n    }\n",
         "    if (keys_get_public_key(path, pubkey) != CX_OK) {\n        return SW_CRYPTO_FAILED;\n    }\n"
         "    if (!keys_path_is_silent(path) || !keys_path_is_silent(path)) {\n"
         "        return SW_PATH_NEEDS_CHECK;\n    }\n"),
    ]),
    "p226": ("the address check refuses a key outside the silent range too, so no request reads it", [
        ("main.c",
         "    if (p1 == P1_KEY_SHOW) {\n        CHECK_SW(ui_start_address_check(path));\n",
         "    if (!keys_path_is_silent(path)) {\n        return SW_PATH_NEEDS_CHECK;\n    }\n"
         "    if (p1 == P1_KEY_SHOW) {\n        CHECK_SW(ui_start_address_check(path));\n"),
    ]),
    "p227": ("a key request with P1 00 outside the silent range gets the path status word, not 6D63", [
        ("main.c", "        return SW_PATH_NEEDS_CHECK;\n", "        return SW_BAD_PATH;\n"),
    ]),
    "p228": ("off by one the other way: a key request with P1 00 answers account 101', one past the limit", [
        ("keys.c", "(account & ~HARDENED) > MAX_BIP44_ACCOUNT_RECOMMENDED",
         "(account & ~HARDENED) > MAX_BIP44_ACCOUNT_RECOMMENDED + 1"),
    ]),
    "p229": ("off by one the other way: a key request with P1 00 answers index 50,001, one past the limit", [
        ("keys.c", "index > MAX_BIP44_ADDRESS_INDEX_RECOMMENDED", "index > MAX_BIP44_ADDRESS_INDEX_RECOMMENDED + 1"),
    ]),
    "p230": ("the silent range is checked before the path rule, so a refused path with P1 00 gets 6D63, not 6D58", [
        ("main.c",
         "    keys_read_path(G_io_apdu_buffer + APDU_HEADER_LENGTH, path);\n"
         "    if (!keys_path_is_valid(path)) {\n",
         "    keys_read_path(G_io_apdu_buffer + APDU_HEADER_LENGTH, path);\n"
         "    if (p1 == P1_KEY_SILENT && !keys_path_is_silent(path)) {\n"
         "        return SW_PATH_NEEDS_CHECK;\n    }\n"
         "    if (!keys_path_is_valid(path)) {\n"),
    ]),
    "p231": ("Nano S: right from the first page of the address check goes straight to the address, past the path", [
        ("ui.c",
         "    unsigned int next = page + 1;\n",
         "    unsigned int next = page == ADDRESS_CHECK_INTRO_PAGE ? ADDRESS_CHECK_ADDRESS_PAGE : page + 1;\n"),
    ]),
    "p232": ("the address check shows the path without its hardened marks, 44/2305/0/0/5 for 44'/2305'/0'/0/5", [
        ("elastos.c", "                 (path[i] & ELA_HARDENED) != 0 ? \"'\" : \"\",\n", "                 \"\",\n"),
    ]),
    "p233": ("Nano S: Approve on the address check answers without the pages of the path having been drawn", [
        ("ui.c",
         "    uint32_t every_page = (1u << ADDRESS_CHECK_PATH_PAGE) | (1u << ADDRESS_CHECK_ADDRESS_PAGE) |\n"
         "                          (1u << ADDRESS_CHECK_ADDRESS_REST_PAGE);\n"
         "    if (address_check_path_has_more_lines()) {\n"
         "        every_page |= 1u << ADDRESS_CHECK_PATH_REST_PAGE;\n"
         "    }\n",
         "    uint32_t every_page = (1u << ADDRESS_CHECK_ADDRESS_PAGE) | (1u << ADDRESS_CHECK_ADDRESS_REST_PAGE);\n"),
    ]),
    "p234": ("Nano X and Nano S Plus: the address check flow leaves out the path", [
        ("ui.c",
         "        &ux_address_check_intro_step,\n        &ux_address_check_path_step,\n",
         "        &ux_address_check_intro_step,\n"),
    ]),
    "p235": ("Nano X and Nano S Plus: Approve on the address check answers once Approve is drawn, "
             "whatever was drawn before", [
        ("ui.c",
         "    return (review_seen_top & every_step) == every_step &&\n"
         "           (review_seen_top_check & every_step) == 0 && approve_drawn;",
         "    return approve_drawn;"),
    ]),
    "p236": ("Nano X and Nano S Plus: the path's third line shows its second line again", [
        ("ui.c", "                   tx_desc[ADDRESS_CHECK_PATH_SCREEN][2]});",
         "                   tx_desc[ADDRESS_CHECK_PATH_SCREEN][1]});"),
    ]),
    "p237": ("Nano X and Nano S Plus: a refused Approve leaves the check's flow, so the buttons no longer "
             "reach the check", [
        ("ui.c", "        ux_flow_init(0, ux_address_check_flow, &ux_address_check_approve_step);\n", ""),
    ]),
    "p238": ("an address check step leaves Approve marked as drawn, so Approve answers from a position "
             "moved onto it without drawing it", [
        ("ui.c", "static void begin_address_check_step(unsigned int k) {\n    set_accept_drawn(false);\n",
         "static void begin_address_check_step(unsigned int k) {\n"),
    ]),
}


def main():
    variant, root = sys.argv[1], sys.argv[2]
    if variant == "clean":
        print("variant clean: source unchanged")
        return
    what, edits = PLANTS[variant]
    for name, old, new in edits:
        path = os.path.join(root, name)
        text = open(path).read()
        count = text.count(old)
        if count != 1:
            sys.exit(f"{variant}: expected one match in {name}, found {count}")
        open(path, "w").write(text.replace(old, new))
    print(f"variant {variant}: {what}")


if __name__ == "__main__":
    main()
