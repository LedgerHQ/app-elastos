/*
 * MIT License, see root folder for full license.
 */
#ifndef SW_H
#define SW_H

#define SW_OK 0x9000

#define SW_NO_COMMAND 0x6982

/** Length mismatch, or a key request with more than its 20 path bytes. */
#define SW_WRONG_LENGTH 0x6700

/** The user rejected the transaction or the address check. */
#define SW_USER_REJECTED 0x6985

#define SW_WRONG_P1P2 0x6A86

#define SW_INS_NOT_SUPPORTED 0x6D00

#define SW_CLA_NOT_SUPPORTED 0x6E00

/** Transaction and path exceed the 1024-byte buffer. Code kept: the Essentials wallet knows it. */
#define SW_TX_TOO_LARGE 0x6D08

/** A key request with fewer than 20 path bytes. */
#define SW_PUBKEY_PATH_TOO_SHORT 0x6D09

/** The transaction ends before a field it declares. */
#define SW_TX_TRUNCATED 0x6D05

/** A multi-byte count, or a length not in shortest form or over 16 bits. */
#define SW_TX_VARINT_TOO_LARGE 0x6DFD

/** Too short to hold a body and a derivation path. */
#define SW_TX_TOO_SHORT 0x6D50

/** Version, type or payload version is not a plain ELA transfer. */
#define SW_TX_UNSUPPORTED 0x6D51

/** No outputs, or more than the review can show. */
#define SW_TX_OUTPUT_COUNT 0x6D52

/** An output carries a payload (vote, cross-chain and similar). */
#define SW_TX_OUTPUT_TYPE 0x6D53

/** An output is time-locked. */
#define SW_TX_OUTPUT_LOCK 0x6D54

/** An output is not the ELA asset. */
#define SW_TX_ASSET 0x6D55

#define SW_TX_NO_INPUTS 0x6D56

/** Bytes after the body, which would be signed unseen. */
#define SW_TX_TRAILING_BYTES 0x6D57

/** Path is outside 44'/2305'/account'/change/index. */
#define SW_BAD_PATH 0x6D58

/** An output pays an address type other than standard or multisig. */
#define SW_TX_ADDRESS_TYPE 0x6D59

/** An amount is negative or too wide to show whole on one line. */
#define SW_TX_AMOUNT 0x6D5A

/** An attribute other than a nonce or memo, a second of either, or a nonce over 8 bytes. */
#define SW_TX_ATTRIBUTE 0x6D5B

/** Non-zero lock time. */
#define SW_TX_LOCK_TIME 0x6D5C

/** Approval with no transaction committed for signing. */
#define SW_NOT_ARMED 0x6D5D

/** The review was not walked in full, or the bytes, digest, screen count, path or review text
 * differ from what was committed. */
#define SW_COMMIT_MISMATCH 0x6D5E

/** Key derivation or signing failed. */
#define SW_CRYPTO_FAILED 0x6D5F

/** An address is too wide to show whole. */
#define SW_TX_ADDRESS_TOO_WIDE 0x6D60

/** A poll vote memo not in the wallet's layout (amount over 17 characters included) or with a
 * choice the review cannot show. A vote amount too wide in pixels gets SW_TX_AMOUNT. */
#define SW_TX_POLL_VOTE 0x6D61

/** Memo text that cannot be shown whole: empty, not printable ASCII, or more screens than the
 * outputs leave. */
#define SW_TX_MEMO 0x6D62

/** A silent key request (P1 00) beyond account 100' or index 50,000, the Bitcoin app's limits.
 * Such a key needs the address check (P1 01). */
#define SW_PATH_NEEDS_CHECK 0x6D63

/** Returns the step's status word from the caller unless it is SW_OK. */
#define CHECK_SW(step)                   \
    do {                                 \
        unsigned short step_sw = (step); \
        if (step_sw != SW_OK) {          \
            return step_sw;              \
        }                                \
    } while (0)

#endif  // SW_H
