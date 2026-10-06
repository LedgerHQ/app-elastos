/*
 * MIT License, see root folder for full license.
 */
#ifndef TX_SESSION_H
#define TX_SESSION_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "keys.h"

/** Clears the signing session. Safe to call at any time. */
void tx_session_reset(void);

/** True while parts of a transaction are still arriving. */
bool tx_session_is_receiving(void);

/** Starts receiving a new transaction. */
void tx_session_begin(void);

/** Commits the signing path; returns the copy the review key must be derived from. */
const unsigned int *tx_session_commit_path(const unsigned int path[ELA_PATH_LEN]);

/** Commits the transaction on screen: digest, body length and screen count. */
void tx_session_arm(const uint8_t digest[ELA_DIGEST_LEN],
                    unsigned int body_len,
                    unsigned int screens);

/** True only when a transaction has been parsed, shown and committed. */
bool tx_session_is_armed(void);

/** True if the review text still matches the committed text. */
bool tx_session_text_matches(void);

/** Signs once and disarms; on SW_OK, out holds the DER signature and out_len its length. */
unsigned short tx_session_sign(uint8_t *out, size_t out_capacity, unsigned int *out_len);

#endif  // TX_SESSION_H
