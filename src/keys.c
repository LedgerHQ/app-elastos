/*
 * MIT License, see root folder for full license.
 */
#include <string.h>
#include "keys.h"

#define HARDENED      ELA_HARDENED
#define PURPOSE_BIP44 (HARDENED | 44u)
#define COIN_TYPE_ELA (HARDENED | 2305u)

/** OS derivation output: the private key, then chain code material. */
#define RAW_DERIVATION_LEN 64
#define PRIVATE_KEY_LEN    32

/** Address-type byte for a standard single-signature address. */
#define PREFIX_STANDARD 0x21

#define COMPRESSED_PUBKEY_LEN 33
#define OP_CHECKSIG           0xAC

/** Positions of the account and the index in the path. */
#define PATH_ACCOUNT 2
#define PATH_INDEX   4

/** Silent key range, same names and limits as Ledger's Bitcoin app (app-bitcoin-new,
 * src/constants.h). Essentials reads 44'/2305'/0'/0/i while pairing, well inside it. */
#define MAX_BIP44_ACCOUNT_RECOMMENDED       100u
#define MAX_BIP44_ADDRESS_INDEX_RECOMMENDED 50000u

/** Bytes are widened before shifting: shifting 0x80 into the sign bit of an int is undefined. */
void keys_read_path(const uint8_t *in, unsigned int path[ELA_PATH_LEN]) {
    for (unsigned int i = 0; i < ELA_PATH_LEN; i++) {
        const uint8_t *p = in + 4 * i;
        path[i] = ((uint32_t) p[0] << 24) | ((uint32_t) p[1] << 16) | ((uint32_t) p[2] << 8) |
                  (uint32_t) p[3];
    }
}

/** The OS only limits derivation to 44'/2305'; without this a non-standard path would sign with a
 * key the user's wallet never shows. */
bool keys_path_is_valid(const unsigned int path[ELA_PATH_LEN]) {
    return path[0] == PURPOSE_BIP44 && path[1] == COIN_TYPE_ELA && (path[2] & HARDENED) != 0 &&
           path[3] <= 1 && (path[4] & HARDENED) == 0;
}

/** Read through volatile so the compiler cannot merge the caller's two checks into one. */
bool keys_path_is_silent(const unsigned int path[ELA_PATH_LEN]) {
    const volatile unsigned int *components = path;
    unsigned int account = components[PATH_ACCOUNT];
    unsigned int index = components[PATH_INDEX];
    if (!keys_path_is_valid(path) || account < HARDENED) {
        return false;
    }
    // limits are inclusive, as in Ledger's Bitcoin app
    if ((account & ~HARDENED) > MAX_BIP44_ACCOUNT_RECOMMENDED ||
        index > MAX_BIP44_ADDRESS_INDEX_RECOMMENDED) {
        return false;
    }
    return true;
}

/** Wipes the raw output on every return, so a failure part way leaves no key material. */
static cx_err_t derive_private_key(const unsigned int path[ELA_PATH_LEN],
                                   cx_ecfp_private_key_t *private_key) {
    uint8_t raw[RAW_DERIVATION_LEN];
    cx_err_t err = os_derive_bip32_no_throw(CX_CURVE_256R1, path, ELA_PATH_LEN, raw, NULL);
    if (err == CX_OK) {
        err = cx_ecfp_init_private_key_no_throw(CX_CURVE_256R1, raw, PRIVATE_KEY_LEN, private_key);
    }
    explicit_bzero(raw, sizeof(raw));
    return err;
}

cx_err_t keys_get_public_key(const unsigned int path[ELA_PATH_LEN],
                             uint8_t pubkey[ELA_PUBKEY_LEN]) {
    cx_ecfp_private_key_t private_key;
    cx_ecfp_public_key_t public_key;
    cx_err_t err = derive_private_key(path, &private_key);
    if (err == CX_OK) {
        err = cx_ecfp_generate_pair_no_throw(CX_CURVE_256R1, &public_key, &private_key, true);
    }
    if (err == CX_OK) {
        memcpy(pubkey, public_key.W, ELA_PUBKEY_LEN);
    }
    explicit_bzero(&private_key, sizeof(private_key));
    return err;
}

/** 0x21 then RIPEMD160(SHA256(script)) of "push 33 bytes, compressed key, OP_CHECKSIG": what an
 * output paying this key carries. */
cx_err_t keys_program_hash(const uint8_t pubkey[ELA_PUBKEY_LEN],
                           uint8_t program_hash[ELA_PROGRAM_HASH_LEN]) {
    uint8_t script[1 + COMPRESSED_PUBKEY_LEN + 1];
    uint8_t sha256[ELA_DIGEST_LEN];
    cx_ripemd160_t ripemd;

    script[0] = COMPRESSED_PUBKEY_LEN;
    script[1] = (pubkey[ELA_PUBKEY_LEN - 1] & 1) ? 0x03 : 0x02;
    memcpy(script + 2, pubkey + 1, COMPRESSED_PUBKEY_LEN - 1);
    script[sizeof(script) - 1] = OP_CHECKSIG;
    cx_hash_sha256(script, sizeof(script), sha256, sizeof(sha256));

    program_hash[0] = PREFIX_STANDARD;
    cx_err_t err = cx_ripemd160_init_no_throw(&ripemd);
    if (err == CX_OK) {
        err = cx_hash_no_throw(&ripemd.header,
                               CX_LAST,
                               sha256,
                               sizeof(sha256),
                               program_hash + 1,
                               ELA_PROGRAM_HASH_LEN - 1);
    }
    return err;
}

/** RFC 6979 nonces. The SDK already returns low-S unless CX_NO_CANONICAL is passed, so no flag is
 * needed against malleability. */
cx_err_t keys_sign_digest(const unsigned int path[ELA_PATH_LEN],
                          const uint8_t digest[ELA_DIGEST_LEN],
                          uint8_t *signature,
                          size_t *signature_len) {
    cx_ecfp_private_key_t private_key;
    uint32_t info = 0;
    cx_err_t err = derive_private_key(path, &private_key);
    if (err == CX_OK) {
        err = cx_ecdsa_sign_no_throw(&private_key,
                                     CX_RND_RFC6979 | CX_LAST,
                                     CX_SHA256,
                                     digest,
                                     ELA_DIGEST_LEN,
                                     signature,
                                     signature_len,
                                     &info);
    }
    explicit_bzero(&private_key, sizeof(private_key));
    return err;
}
