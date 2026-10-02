/*
 * MIT License, see root folder for full license.
 */
#ifndef BASE_ENCODING_H
#define BASE_ENCODING_H

#include <stddef.h>
#include <stdint.h>

/** Longest input: a 25-byte address. */
#define BASE58_MAX_INPUT_LEN 25

/** Writes in as NUL-terminated base58; returns its length, or 0 if in or the text is too long. */
size_t encode_base_58(const uint8_t *in, size_t in_len, char *out, size_t out_size);

#endif  // BASE_ENCODING_H
