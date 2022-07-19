/*
 * MIT License, see root folder for full license.
 */

#ifndef ELASTOS_H
#define ELASTOS_H

#include "os.h"
#include "cx.h"
#include <stdbool.h>
#include "os_io_seproxyhal.h"
#include "ui.h"
#include "sha256_hash_len.h"

/** length of tx.output.script_hash */
#define SCRIPT_HASH_LEN 20

/** length of tx.output.script_hash */
#define CODE_HASH_LEN 1 + SCRIPT_HASH_LEN

/** length of the checksum used to convert a tx.output.script_hash into an Address. */
#define CODE_HASH_CHECKSUM_LEN 4

/** length of a tx.output Address, after Base58 encoding. +1 for zero padding. */
#define ADDRESS_BASE58_LEN 34

/** length of a tx.output Address before encoding, which is the length of
 * <address_version>+<script_hash>+<checksum> */
#define ADDRESS_LEN (CODE_HASH_LEN + CODE_HASH_CHECKSUM_LEN)

extern unsigned char verification_script[35];

extern unsigned char public_key_encoded[33];

extern unsigned char script_hash[SCRIPT_HASH_LEN];

extern unsigned char code_hash[CODE_HASH_LEN];

extern unsigned char address[ADDRESS_LEN];

/** parse the raw transaction in raw_tx and fill up the screens in tx_desc. */
void display_tx_desc(void);

/** displays the "no public key" message, prior to a public key being requested. */
void display_no_public_key(void);

/** displays the public key, assumes length is 65. */
void display_public_key(const unsigned char* public_key);

#endif  // ELASTOS_H
