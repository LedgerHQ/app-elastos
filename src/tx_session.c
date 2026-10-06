/*
 * MIT License, see root folder for full license.
 */
#include <string.h>
#include "tx_session.h"
#include "sw.h"
#include "ui.h"

/** Multi-bit states, so one flipped bit or skipped instruction cannot arm the session. */
#define SESSION_ARMED     0xA55AC33Cu
#define SESSION_RECEIVING 0x3CC35AA5u
#define SESSION_IDLE      0u

static volatile uint32_t session_state;
static unsigned int committed_path[ELA_PATH_LEN];
/** Complement of committed_path, so one flipped bit cannot pick another key. */
static volatile unsigned int committed_path_check[ELA_PATH_LEN];
static uint8_t committed_digest[ELA_DIGEST_LEN];
static unsigned int committed_body_len;
/** Digest of the review text at commit time. */
static uint8_t committed_text_digest[ELA_DIGEST_LEN];

/** Review screen count and its complement, so one flipped bit is detected. */
static volatile unsigned int committed_screens;
static volatile unsigned int committed_screens_check;

void tx_session_reset(void) {
    session_state = SESSION_IDLE;
    raw_tx_ix = 0;
    raw_tx_len = 0;
    curr_scr_ix = 0;
    max_scr_ix = 0;
    committed_body_len = 0;
    committed_screens = 0;
    committed_screens_check = 0;
    explicit_bzero(committed_path, sizeof(committed_path));
    for (unsigned int i = 0; i < ELA_PATH_LEN; i++) {
        committed_path_check[i] = 0;
    }
    explicit_bzero(committed_digest, sizeof(committed_digest));
    memset(committed_text_digest, 0, sizeof(committed_text_digest));
    memset(tx_desc, 0, sizeof(tx_desc));
    memset(curr_tx_desc, 0, sizeof(curr_tx_desc));
    memset(review_title, 0, sizeof(review_title));
    memset(curr_review_title, 0, sizeof(curr_review_title));
}

bool tx_session_is_receiving(void) {
    return session_state == SESSION_RECEIVING;
}

void tx_session_begin(void) {
    tx_session_reset();
    session_state = SESSION_RECEIVING;
}

/** Volatile, so two calls are not merged and one skipped instruction cannot fake a match. */
static bool digests_match(const uint8_t a[ELA_DIGEST_LEN], const uint8_t b[ELA_DIGEST_LEN]) {
    volatile uint8_t diff = 0;
    for (unsigned int i = 0; i < ELA_DIGEST_LEN; i++) {
        diff |= a[i] ^ b[i];
    }
    return diff == 0;
}

/** Hashes the review title and every review line, all the user reads. False on hash failure. */
static bool review_text_digest(uint8_t out[ELA_DIGEST_LEN]) {
    cx_sha256_t hash;
    cx_sha256_init_no_throw(&hash);
    if (cx_hash_no_throw(&hash.header,
                         0,
                         (const uint8_t *) review_title,
                         sizeof(review_title),
                         NULL,
                         0) != CX_OK) {
        return false;
    }
    return cx_hash_no_throw(&hash.header,
                            CX_LAST,
                            (const uint8_t *) tx_desc,
                            sizeof(tx_desc),
                            out,
                            ELA_DIGEST_LEN) == CX_OK;
}

/** The only binding of the review text to the signed bytes: without it one flipped bit could
 * change the amount shown while the real one is signed. */
bool tx_session_text_matches(void) {
    uint8_t digest[ELA_DIGEST_LEN];
    if (!review_text_digest(digest)) {
        return false;
    }
    return digests_match(digest, committed_text_digest);
}

/**
 * Stores the path and its complement before any key is derived; the shown key comes from this copy.
 * Not caught: a fault inside the final signing derivation, as checking it needs more Nano S stack.
 */
const unsigned int *tx_session_commit_path(const unsigned int path[ELA_PATH_LEN]) {
    memcpy(committed_path, path, sizeof(committed_path));
    for (unsigned int i = 0; i < ELA_PATH_LEN; i++) {
        committed_path_check[i] = ~path[i];
    }
    return committed_path;
}

/** Records exactly what was shown, so approval can only ever sign those bytes. */
void tx_session_arm(const uint8_t digest[ELA_DIGEST_LEN],
                    unsigned int body_len,
                    unsigned int screens) {
    memcpy(committed_digest, digest, sizeof(committed_digest));
    committed_body_len = body_len;
    committed_screens = screens;
    committed_screens_check = ~screens;
    if (!review_text_digest(committed_text_digest)) {
        // a digest of zeros matches no text, so this transaction can never be signed
        memset(committed_text_digest, 0, sizeof(committed_text_digest));
    }
    session_state = SESSION_ARMED;
}

/** True if the committed path still matches its complement and is still valid. */
static bool path_matches(void) {
    for (unsigned int i = 0; i < ELA_PATH_LEN; i++) {
        if ((committed_path[i] ^ committed_path_check[i]) != ~0u) {
            return false;
        }
    }
    return keys_path_is_valid(committed_path);
}

/** The review ends after max_scr_ix screens, so a changed count could let Sign through with
 * screens never shown. */
static bool screen_count_matches(void) {
    unsigned int screens = committed_screens;
    return screens != 0 && (screens ^ committed_screens_check) == ~0u && max_scr_ix == screens;
}

bool tx_session_is_armed(void) {
    return session_state == SESSION_ARMED;
}

/** Rechecks the buffer digest, screen count, path and review text, each twice, then disarms, so one
 * approval gives at most one signature. */
unsigned short tx_session_sign(uint8_t *out, size_t out_capacity, unsigned int *out_len) {
    uint8_t digest[ELA_DIGEST_LEN];
    size_t signature_len = out_capacity;

    *out_len = 0;
    if (session_state != SESSION_ARMED) {
        return SW_NOT_ARMED;
    }
    if (committed_body_len == 0 || committed_body_len > MAX_TX_RAW_LENGTH) {
        return SW_NOT_ARMED;
    }
    if (!screen_count_matches() || !path_matches() || !tx_session_text_matches()) {
        return SW_COMMIT_MISMATCH;
    }
    cx_hash_sha256(raw_tx, committed_body_len, digest, sizeof(digest));
    if (!digests_match(digest, committed_digest)) {
        return SW_COMMIT_MISMATCH;
    }
    if (session_state != SESSION_ARMED) {
        return SW_NOT_ARMED;
    }
    if (!digests_match(digest, committed_digest)) {
        return SW_COMMIT_MISMATCH;
    }
    // the path last, just before the key is derived from it, so no long step lies between them
    if (!screen_count_matches() || !tx_session_text_matches() || !path_matches()) {
        return SW_COMMIT_MISMATCH;
    }
    session_state = SESSION_IDLE;

    if (keys_sign_digest(committed_path, committed_digest, out, &signature_len) != CX_OK) {
        return SW_CRYPTO_FAILED;
    }
    *out_len = (unsigned int) signature_len;
    return SW_OK;
}
