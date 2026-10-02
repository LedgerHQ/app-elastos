/* Checks sha256.h against the FIPS 180-4 test vectors. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sha256.h"

static int check(const char *name, const uint8_t *msg, size_t len, const char *want_hex) {
    uint8_t got[SM_SHA256_LEN];
    char hex[2 * SM_SHA256_LEN + 1];
    sm_sha256(msg, len, got);
    for (unsigned i = 0; i < SM_SHA256_LEN; i++) snprintf(hex + 2 * i, 3, "%02x", got[i]);
    int ok = strcmp(hex, want_hex) == 0;
    printf("%s %s\n", ok ? "ok  " : "FAIL", name);
    return ok;
}

int main(void) {
    static uint8_t million[1000000];
    memset(million, 'a', sizeof(million));
    const char *two_blocks = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    int ok = check("empty", (const uint8_t *) "", 0,
                   "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") &
             check("abc", (const uint8_t *) "abc", 3,
                   "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad") &
             check("448 bits", (const uint8_t *) two_blocks, strlen(two_blocks),
                   "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1") &
             check("one million a", million, sizeof(million),
                   "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
    return ok ? 0 : 1;
}
