/*
 * MIT License, see root folder for full license.
 */
#include <string.h>
#include "base-encoding.h"

/** 25 bytes need 25 * 8 / log2(58) = 34.1 digits, so 35. */
#define BASE58_MAX_DIGITS 35

#define BASE58_RADIX 58

/** array of base58 alphabet letters */
static const char BASE_58_ALPHABET[] = {'1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C',
                                        'D', 'E', 'F', 'G', 'H', 'J', 'K', 'L', 'M', 'N', 'P', 'Q',
                                        'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c',
                                        'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'm', 'n', 'o', 'p',
                                        'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z'};

/** Each leading zero byte becomes a '1', as Elastos addresses are written. Work is bounded by
 * the input size. */
size_t encode_base_58(const uint8_t *in, size_t in_len, char *out, size_t out_size) {
    uint8_t digits[BASE58_MAX_DIGITS];  // least significant first
    size_t digit_count = 0;
    size_t leading_zeros = 0;

    if (in_len > BASE58_MAX_INPUT_LEN) {
        return 0;
    }
    while (leading_zeros < in_len && in[leading_zeros] == 0) {
        leading_zeros++;
    }
    for (size_t i = leading_zeros; i < in_len; i++) {
        uint32_t carry = in[i];
        for (size_t k = 0; k < digit_count; k++) {
            carry += (uint32_t) digits[k] << 8;
            const uint32_t digit = carry % BASE58_RADIX;
            digits[k] = (uint8_t) digit;
            carry /= BASE58_RADIX;
        }
        while (carry != 0) {
            if (digit_count == BASE58_MAX_DIGITS) {
                return 0;
            }
            const uint32_t digit = carry % BASE58_RADIX;
            digits[digit_count++] = (uint8_t) digit;
            carry /= BASE58_RADIX;
        }
    }

    size_t len = leading_zeros + digit_count;
    if (len >= out_size) {
        return 0;
    }
    memset(out, BASE_58_ALPHABET[0], leading_zeros);
    for (size_t k = 0; k < digit_count; k++) {
        out[leading_zeros + k] = BASE_58_ALPHABET[digits[digit_count - 1 - k]];
    }
    out[len] = '\0';
    return len;
}
