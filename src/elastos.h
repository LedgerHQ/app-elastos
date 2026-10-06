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
#include "keys.h"

/** length of tx.output.script_hash */
#define SCRIPT_HASH_LEN 20

/** length of tx.output.program_hash: address-type byte, then the script hash */
#define CODE_HASH_LEN (1 + SCRIPT_HASH_LEN)

/** length of the checksum used to convert a tx.output.script_hash into an Address. */
#define CODE_HASH_CHECKSUM_LEN 4

/** Base58 length of every standard and multisig address. */
#define ADDRESS_BASE58_LEN 34

/** length of a tx.output Address before encoding, which is the length of
 * <address_version>+<script_hash>+<checksum> */
#define ADDRESS_LEN (CODE_HASH_LEN + CODE_HASH_CHECKSUM_LEN)

/** Fills the review from raw_tx; returns SW_OK or why it cannot be shown in full. */
unsigned short tx_parse_and_render(const uint8_t signer_program_hash[ELA_PROGRAM_HASH_LEN]);

/** displays the "no public key" message, prior to a public key being requested. */
void display_no_public_key(void);

/** Puts a 65-byte public key's address on the address check; returns SW_OK or why not. */
unsigned short display_address_to_check(const unsigned char *public_key);

/** Puts a path such as 44'/2305'/0'/0/5 on the address check; returns SW_OK or why not. */
unsigned short display_path_to_check(const unsigned int path[ELA_PATH_LEN]);

/** Shows a 65-byte public key's address on the account screen; false if a placeholder shows. */
bool display_public_key(const unsigned char *public_key);

#endif  // ELASTOS_H
