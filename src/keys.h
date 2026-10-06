/*
 * MIT License, see root folder for full license.
 */
#ifndef KEYS_H
#define KEYS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "os.h"
#include "cx.h"

/** Components in an Elastos derivation path: 44'/2305'/account'/change/index. */
#define ELA_PATH_LEN 5

/** Size of a derivation path on the wire: five big-endian 32-bit values. */
#define ELA_PATH_BYTES (ELA_PATH_LEN * 4)

/** Hardened bit of a path component, written ' in the usual notation. */
#define ELA_HARDENED 0x80000000u

/** Size of an uncompressed P-256 public key. */
#define ELA_PUBKEY_LEN 65

/** Size of a program hash: one address-type byte followed by a 20-byte hash. */
#define ELA_PROGRAM_HASH_LEN 21

/** Size of the digest that is signed. */
#define ELA_DIGEST_LEN 32

/** Reads a derivation path from its wire form. */
void keys_read_path(const uint8_t *in, unsigned int path[ELA_PATH_LEN]);

/** Returns true only for 44'/2305'/account'/change/index with a hardened account. */
bool keys_path_is_valid(const unsigned int path[ELA_PATH_LEN]);

/** True only for a valid path with account 0' to 100' and index 0 to 50,000, answered silently. */
bool keys_path_is_silent(const unsigned int path[ELA_PATH_LEN]);

/** Derives the public key for a path. The private key never outlives the call. */
cx_err_t keys_get_public_key(const unsigned int path[ELA_PATH_LEN], uint8_t pubkey[ELA_PUBKEY_LEN]);

/** Computes the program hash that identifies the owner of an output paid to this key. */
cx_err_t keys_program_hash(const uint8_t pubkey[ELA_PUBKEY_LEN],
                           uint8_t program_hash[ELA_PROGRAM_HASH_LEN]);

/** Signs a digest with the key for a path and writes a DER signature. */
cx_err_t keys_sign_digest(const unsigned int path[ELA_PATH_LEN],
                          const uint8_t digest[ELA_DIGEST_LEN],
                          uint8_t *signature,
                          size_t *signature_len);

#endif  // KEYS_H
