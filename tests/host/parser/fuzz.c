/*
 * Host fuzzer for the transaction parser, built from the real sources under the sanitizers.
 *
 * Every decision is checked against an independent reader of the same rules: a refusal must give
 * its exact status word, and an acceptance must render exactly: whole body read, amounts,
 * addresses, change labels, vote and memo screens, every line terminated. Some signers have an
 * address line too wide to show, which must be refused.
 *
 * The font width table is checked character by character first, as random cases rarely reach the
 * screen edge. "limits" checks the specification's memo limits instead (check_memo_limits).
 *
 * usage: ./fuzz <iterations> <seed> [accepted_out.txt]
 *        ./fuzz limits
 */
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <setjmp.h>

#include "os.h"
#include "cx.h"
#include "ui.h"
#include "sw.h"
#include "keys.h"

/* Included, not linked, so its static width table can be checked. */
#include "elastos.c"

/* ---- globals the app defines in ui.c ---- */
jmp_buf g_ela_jmp;
unsigned int g_last_throw;
enum UI_STATE uiState;
ux_state_t ux;
unsigned int curr_scr_ix;
unsigned int max_scr_ix;
unsigned char raw_tx[MAX_TX_RAW_LENGTH];
unsigned int raw_tx_ix;
unsigned int raw_tx_len;
char tx_desc[MAX_TX_TEXT_SCREENS][MAX_TX_TEXT_LINES][MAX_TX_TEXT_WIDTH];
char curr_tx_desc[MAX_TX_TEXT_LINES][MAX_TX_TEXT_WIDTH];
char current_public_key[MAX_TX_TEXT_LINES][MAX_TX_TEXT_WIDTH];
char review_title[MAX_TX_TEXT_SCREENS][MAX_TX_TEXT_WIDTH];
int exit_timer;
char timer_desc[MAX_TIMER_TEXT_WIDTH];

/* Referenced by display_public_key, which the fuzzer never calls. */
cx_err_t keys_program_hash(const uint8_t pubkey[ELA_PUBKEY_LEN], uint8_t ph[ELA_PROGRAM_HASH_LEN]) {
    (void) pubkey;
    memset(ph, 0x21, ELA_PROGRAM_HASH_LEN);
    return CX_OK;
}

static const uint8_t ELA[32] = {0xb0, 0x37, 0xdb, 0x96, 0x4a, 0x23, 0x14, 0x58, 0xd2, 0xd6, 0xff,
                                0xd5, 0xea, 0x18, 0x94, 0x4c, 0x4f, 0x90, 0xe6, 0x3d, 0x54, 0x7c,
                                0x5d, 0x3b, 0x98, 0x74, 0xdf, 0x66, 0xa4, 0xea, 0xd0, 0xa3};
/* program hash of EHEhJcvSmM83jVDViPoEPLaG9v9HiCpvUp, the signer on the test seed */
static const uint8_t SIGNER[21] = {0x21, 0x00, 0xe7, 0xe7, 0xa8, 0x7c, 0x86, 0x73, 0xc6, 0xa4, 0x5b,
                                   0x98, 0xf8, 0x7b, 0xff, 0xb3, 0xbe, 0x03, 0x94, 0x4e, 0x55};
/* addresses ground for one wide line: [0] third line 117 px, too wide everywhere; [1] third and
 * [2] second line 110 px, too wide on Nano S only */
static const uint8_t WIDE[3][21] = {
    {0x21, 0x69, 0x77, 0xba, 0x3c, 0xb8, 0xee, 0xaa, 0x0a, 0xb7, 0xf5, 0x43, 0x00, 0x18, 0xb1, 0x0e, 0x21, 0x16, 0x1f, 0x70, 0xd3},
    {0x21, 0x18, 0x29, 0x5a, 0xc4, 0xdb, 0x20, 0x35, 0xcd, 0xfb, 0xec, 0x14, 0x33, 0xb7, 0x3f, 0x46, 0x49, 0xda, 0x29, 0xe9, 0x80},
    {0x21, 0x38, 0xb4, 0xe6, 0x52, 0xe4, 0x4d, 0xa7, 0xf1, 0xd1, 0xc4, 0xac, 0x32, 0x3e, 0x7a, 0xc3, 0x62, 0x40, 0xbc, 0x24, 0xba},
};

/* Signers with their addresses written out by hand, so the signer screen is checked against text
 * neither encoder wrote. */
typedef struct {
    const uint8_t *ph;
    const char *address;
} signer_t;
static const signer_t SIGNERS[] = {
    {SIGNER, "EHEhJcvSmM83jVDViPoEPLaG9v9HiCpvUp"},
    {WIDE[0], "ESmZsYAfnQEviw3sEmbGkoWWWWWWMNwWmm"},
    {WIDE[1], "EKMfFZ58xxMct2uE5ZzrcUWWWWWWsWWVwQ"},
    {WIDE[2], "ENKk3TYE4v1WWWWWWWWWWWFwKfGk69Xh1C"},
};

/* ---------------------------------------------------------------- PRNG */
static uint64_t rng;
static uint64_t rnd(void) {
    rng ^= rng << 13;
    rng ^= rng >> 7;
    rng ^= rng << 17;
    return rng;
}
static unsigned rn(unsigned n) { return n ? (unsigned) (rnd() % n) : 0; }

/* ---------------------------------------------------------------- reference reader */
/* Three lines of at most 17 characters per screen. Memo text gets the screens a one-output
 * payment leaves: nine, less the signer, the output's two and the fee notice. */
#define REF_LINE_CHARS 17
#define REF_MEMO_MAX_LINES ((MAX_TX_TEXT_SCREENS - 1 - 2 - 1) * 3)

typedef struct {
    unsigned short sw; /* SW_OK or the expected refusal */
    unsigned outputs;
    uint64_t value[3];
    uint8_t ph[3][21];
    char address[3][35];
    bool vote; /* a poll vote memo, three screens after the signer */
    uint8_t poll_id[32];
    uint32_t choice;
    char vote_amount[18];
    unsigned memo_lines; /* memo text lines, three per screen after the signer; 0 for none */
    char memo_line[REF_MEMO_MAX_LINES][REF_LINE_CHARS + 1];
    bool signer_too_wide; /* refused: a line of the signer's address does not fit */
} ref_t;

static uint32_t le32(const uint8_t *p) {
    return (uint32_t) p[0] | ((uint32_t) p[1] << 8) | ((uint32_t) p[2] << 16) | ((uint32_t) p[3] << 24);
}
static uint64_t le64(const uint8_t *p) { return (uint64_t) le32(p) | ((uint64_t) le32(p + 4) << 32); }

#if defined(TARGET_NANOS)
#define REF_LINE_WIDTH_PX 108
#else
#define REF_LINE_WIDTH_PX 116
#endif

/* Width of each printable ASCII character in the review font, Open Sans regular 11 px, from the
 * SDKs' bagl_font_open_sans_regular_11px tables. Nano S differs in &, X and _. */
#if defined(TARGET_NANOS)
static const unsigned char REF_FONT_WIDTH[95] = {
    3, 3, 4, 7, 6, 9, 8, 2, 3, 3, 6, 6, 3, 4, 3, 4,
    6, 6, 6, 6, 8, 6, 6, 6, 6, 6, 3, 3, 6, 6, 6, 5,
    10, 7, 7, 7, 8, 6, 6, 8, 8, 3, 4, 7, 6, 10, 8, 9,
    7, 9, 7, 6, 7, 8, 7, 10, 6, 6, 6, 4, 4, 4, 6, 5,
    6, 6, 7, 5, 7, 6, 5, 6, 7, 3, 4, 6, 3, 10, 7, 7,
    7, 7, 4, 5, 4, 7, 6, 9, 6, 6, 5, 4, 6, 4, 6};
#else
static const unsigned char REF_FONT_WIDTH[95] = {
    3, 3, 4, 7, 6, 9, 9, 2, 3, 3, 6, 6, 3, 4, 3, 4,
    6, 6, 6, 6, 8, 6, 6, 6, 6, 6, 3, 3, 6, 6, 6, 5,
    10, 7, 7, 7, 8, 6, 6, 8, 8, 3, 4, 7, 6, 10, 8, 9,
    7, 9, 7, 6, 7, 8, 7, 10, 7, 6, 6, 4, 4, 4, 6, 6,
    6, 6, 7, 5, 7, 6, 5, 6, 7, 3, 4, 6, 3, 10, 7, 7,
    7, 7, 4, 5, 4, 7, 6, 9, 6, 6, 5, 4, 6, 4, 6};
#endif

/* 0 for a character the device must never show. */
static unsigned ref_char_width(unsigned char c) {
    return c >= 0x20 && c <= 0x7E ? REF_FONT_WIDTH[c - 0x20] : 0;
}

static unsigned ref_width(const char *s, size_t n) {
    unsigned w = 0;
    for (size_t k = 0; k < n; k++) w += ref_char_width((unsigned char) s[k]);
    return w;
}

static bool ref_line_may_end_after(uint8_t c) { return c == ' ' || c == ',' || c == ':'; }

/* Wraps memo text as the device must: each line the longest run of at most 17 characters that
 * fits, cut back after its last space, comma or colon if text follows. Returns the line count, or
 * 0 for text the device must refuse: empty, not printable ASCII, or too many lines. */
static unsigned ref_memo_lines(const uint8_t *t, size_t n, char lines[][REF_LINE_CHARS + 1]) {
    if (n == 0) return 0;
    for (size_t k = 0; k < n; k++)
        if (ref_char_width(t[k]) == 0) return 0;
    unsigned count = 0;
    for (size_t start = 0; start < n; count++) {
        size_t len = 0;
        unsigned px = 0;
        while (start + len < n && len < REF_LINE_CHARS && px + ref_char_width(t[start + len]) <= REF_LINE_WIDTH_PX)
            px += ref_char_width(t[start + len++]);
        if (start + len < n) {
            size_t end = len;
            while (end > 0 && !ref_line_may_end_after(t[start + end - 1])) end--;
            if (end > 0) len = end;
        }
        if (count == REF_MEMO_MAX_LINES) return 0;
        memcpy(lines[count], t + start, len);
        lines[count][len] = '\0';
        start += len;
    }
    return count;
}

/* Base58 of hash || SHA256(SHA256(hash))[0..4), by long division, apart from the app's encoder.
 * Returns the length. */
static unsigned ref_address(const uint8_t ph[21], char out[40]) {
    static const char B58[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    uint8_t num[25], h1[32], h2[32];
    memcpy(num, ph, 21);
    sm_sha256(ph, 21, h1);
    sm_sha256(h1, 32, h2);
    memcpy(num + 21, h2, 4);
    char rev[40];
    unsigned len = 0, nonzero;
    do {
        unsigned rem = 0;
        nonzero = 0;
        for (int k = 0; k < 25; k++) {
            unsigned cur = rem * 256 + num[k];
            num[k] = (uint8_t) (cur / 58);
            rem = cur % 58;
            nonzero |= num[k];
        }
        rev[len++] = B58[rem];
    } while (nonzero);
    for (unsigned k = 0; k < len; k++) out[k] = rev[len - 1 - k];
    out[len] = '\0';
    return len;
}

static bool ref_address_fits(const char *addr) {
    return ref_width(addr, 11) <= REF_LINE_WIDTH_PX && ref_width(addr + 11, 11) <= REF_LINE_WIDTH_PX &&
           ref_width(addr + 22, 12) <= REF_LINE_WIDTH_PX;
}

/* The wallet's vote amount: digits, then optionally a point and one to eight decimals. */
static bool ref_vote_amount_ok(const char *text) {
    const char *point = strchr(text, '.');
    size_t whole = point ? (size_t) (point - text) : strlen(text);
    size_t decimals = point ? strlen(point + 1) : 0;
    if (whole == 0 || (point && (decimals == 0 || decimals > 8))) return false;
    for (const char *c = text; *c; c++)
        if (c != point && (*c < '0' || *c > '9')) return false;
    return true;
}

static void fmt_amount(uint64_t v, char *out) {
    snprintf(out, 32, "%llu.%08llu", (unsigned long long) (v / 100000000ULL), (unsigned long long) (v % 100000000ULL));
}

/* Independent reading of the accept rules. Refusals follow byte order, so the first fault decides
 * the status word, as on the device. */
static ref_t reference(const uint8_t *b, size_t n, const uint8_t signer_ph[21]) {
    ref_t r;
    memset(&r, 0, sizeof(r));
    size_t i = 0;
#define REFUSE(code)   \
    do {               \
        r.sw = (code); \
        return r;      \
    } while (0)
#define NEED(k)                          \
    do {                                 \
        if (n - i < (size_t) (k))        \
            REFUSE(SW_TX_TRUNCATED);     \
    } while (0)
    if (n == 0 || n + 20 > MAX_TX_RAW_LENGTH) REFUSE(SW_TX_TOO_SHORT);
    NEED(1);
    uint8_t t = b[i++];
    bool v9 = false;
    if (t >= 9) {
        if (t != 9) REFUSE(SW_TX_UNSUPPORTED);
        v9 = true;
        NEED(1);
        t = b[i++];
    }
    if (t != 2) REFUSE(SW_TX_UNSUPPORTED);
    NEED(1);
    if (b[i++] != 0) REFUSE(SW_TX_UNSUPPORTED);
    NEED(1);
    unsigned na = b[i++], memos = 0, nonces = 0;
    if (na > 0xFC) REFUSE(SW_TX_VARINT_TOO_LARGE);
    for (unsigned a = 0; a < na; a++) {
        NEED(1);
        uint8_t usage = b[i];
        if (usage != 0x00 && usage != 0x81) REFUSE(SW_TX_ATTRIBUTE);
        i++;
        /* at most one nonce and one memo: a second is refused once its type is read */
        if ((usage == 0x00 ? ++nonces : ++memos) > 1) REFUSE(SW_TX_ATTRIBUTE);
        NEED(1);
        size_t l = b[i++];
        /* the three-byte length form only for a value one byte cannot hold */
        if (l == 0xFD) {
            NEED(2);
            l = (size_t) b[i] | ((size_t) b[i + 1] << 8);
            i += 2;
            if (l < 0xFD) REFUSE(SW_TX_VARINT_TOO_LARGE);
        } else if (l > 0xFC) {
            REFUSE(SW_TX_VARINT_TOO_LARGE);
        }
        /* the nonce is never shown: at most eight bytes, checked before they are read */
        if (usage == 0x00 && l > 8) REFUSE(SW_TX_ATTRIBUTE);
        NEED(l);
        /* any other memo is text, shown whole */
        if (usage == 0x81 && !(l >= 8 && memcmp(b + i, "pollvote", 8) == 0)) {
            r.memo_lines = ref_memo_lines(b + i, l, r.memo_line);
            if (r.memo_lines == 0) REFUSE(SW_TX_MEMO);
        }
        /* a memo that starts with the vote flag must be exactly the wallet's vote layout */
        if (usage == 0x81 && l >= 8 && memcmp(b + i, "pollvote", 8) == 0) {
            if (l < 45) REFUSE(SW_TX_POLL_VOTE);
            size_t amount_len = b[i + 44];
            if (l != 45 + amount_len || amount_len > 17) REFUSE(SW_TX_POLL_VOTE);
            memcpy(r.vote_amount, b + i + 45, amount_len);
            r.vote_amount[amount_len] = '\0';
            r.choice = le32(b + i + 40);
            if (r.choice > 999 || strlen(r.vote_amount) != amount_len || !ref_vote_amount_ok(r.vote_amount))
                REFUSE(SW_TX_POLL_VOTE);
            /* a vote in the wallet's layout with an amount too wide to show is refused as an amount */
            if (ref_width(r.vote_amount, amount_len) > REF_LINE_WIDTH_PX) REFUSE(SW_TX_AMOUNT);
            memcpy(r.poll_id, b + i + 8, 32);
            r.vote = true;
        }
        i += l;
    }
    NEED(1);
    unsigned ni = b[i++];
    if (ni > 0xFC) REFUSE(SW_TX_VARINT_TOO_LARGE);
    if (ni == 0) REFUSE(SW_TX_NO_INPUTS);
    for (unsigned k = 0; k < ni; k++) {
        NEED(38);
        i += 38;
    }
    NEED(1);
    unsigned no = b[i++];
    if (no > 0xFC) REFUSE(SW_TX_VARINT_TOO_LARGE);
    if (no == 0 || no > 3) REFUSE(SW_TX_OUTPUT_COUNT);
    /* signer, vote or memo, two screens per output and the fee must fit; if not, a vote is refused
     * as too many outputs and text as a memo */
    if (1 + (r.vote ? 3 : (r.memo_lines + 2) / 3) + 2 * no + 1 > MAX_TX_TEXT_SCREENS)
        REFUSE(r.vote ? SW_TX_OUTPUT_COUNT : SW_TX_MEMO);
    /* the signer's own address is shown whole too, or refused like any other */
    char signer[40];
    ref_address(signer_ph, signer);
    if (!ref_address_fits(signer)) {
        r.signer_too_wide = true;
        REFUSE(SW_TX_ADDRESS_TOO_WIDE);
    }
    for (unsigned k = 0; k < no; k++) {
        NEED(32);
        if (memcmp(b + i, ELA, 32) != 0) REFUSE(SW_TX_ASSET);
        i += 32;
        NEED(8);
        uint64_t v = le64(b + i);
        i += 8;
        if (v >> 63) REFUSE(SW_TX_AMOUNT);
        NEED(4);
        if (le32(b + i) != 0) REFUSE(SW_TX_OUTPUT_LOCK);
        i += 4;
        NEED(21);
        const uint8_t *ph = b + i;
        i += 21;
        if (ph[0] != 0x21 && ph[0] != 0x12) REFUSE(SW_TX_ADDRESS_TYPE);
        if (v9) {
            NEED(1);
            if (b[i++] != 0) REFUSE(SW_TX_OUTPUT_TYPE);
        }
        /* at most eight whole digits fit the line with the point and eight decimals */
        char amount[32];
        fmt_amount(v, amount);
        if (v / 100000000ULL >= 100000000ULL || ref_width(amount, strlen(amount)) > REF_LINE_WIDTH_PX)
            REFUSE(SW_TX_AMOUNT);
        if (ref_address(ph, r.address[k]) != 34) REFUSE(SW_TX_ADDRESS_TYPE);
        if (!ref_address_fits(r.address[k])) REFUSE(SW_TX_ADDRESS_TOO_WIDE);
        r.value[k] = v;
        memcpy(r.ph[k], ph, 21);
    }
    NEED(4);
    if (le32(b + i) != 0) REFUSE(SW_TX_LOCK_TIME);
    i += 4;
    if (i != n) REFUSE(SW_TX_TRAILING_BYTES);
    r.sw = SW_OK;
    r.outputs = no;
    return r;
#undef NEED
#undef REFUSE
}

/* ---------------------------------------------------------------- generator and mutator */
static size_t put(uint8_t *b, size_t i, const void *p, size_t n) {
    if (i + n > MAX_TX_RAW_LENGTH - 20) return i;
    memcpy(b + i, p, n);
    return i + n;
}
static size_t put8(uint8_t *b, size_t i, uint8_t v) { return put(b, i, &v, 1); }

/* A poll vote attribute: mostly the wallet's layout, sometimes slightly wrong, or a note with the
 * flag after its start. */
static size_t put_vote(uint8_t *b, size_t i, uint8_t usage) {
    static const char *const AMOUNTS[] = {"1234.5", "14", "0.00000001", "99999999.99999999", "7", "3.25",
                                          "12345678901234567", "123456789012345678", "", ".5", "5.",
                                          "1.123456789", "1e5", "-1", "4444444444444444", "0.0",
                                          "1.2.3", "1..2", " 5", "5 "};
    uint8_t memo[96];
    size_t n = 0;
    bool note = rn(12) == 0;
    if (note) {
        memcpy(memo, "type:text,msg:", 14);
        n = 14;
    }
    memcpy(memo + n, "pollvote", 8);
    n += 8;
    for (int k = 0; k < 32; k++) memo[n++] = (uint8_t) rnd();
    uint32_t choice = rn(4) != 0 ? rn(6) : rn(2) ? 998 + rn(4) : (uint32_t) rnd();
    for (int k = 0; k < 4; k++) memo[n++] = (uint8_t) (choice >> (8 * k));
    const char *amount = rn(3) != 0 ? AMOUNTS[rn(6)] : AMOUNTS[rn(sizeof(AMOUNTS) / sizeof(AMOUNTS[0]))];
    size_t amount_len = strlen(amount);
    memo[n++] = (uint8_t) (rn(20) == 0 ? amount_len + 1 - 2 * rn(2) : amount_len);
    memcpy(memo + n, amount, amount_len);
    if (amount_len > 0 && rn(20) == 0) memo[n + rn((unsigned) amount_len)] = 0; /* a NUL inside the text */
    n += amount_len;
    if (rn(30) == 0) n -= 1 + rn(8); /* cut short */
    i = put8(b, i, usage);
    if (rn(6) == 0) {
        /* padded to the three-byte length form, past what the layout declares */
        size_t padded = 253 + rn(40);
        memset(memo + n, 0, sizeof(memo) - n);
        i = put8(b, i, 0xFD);
        i = put8(b, i, (uint8_t) padded);
        i = put8(b, i, (uint8_t) (padded >> 8));
        i = put(b, i, memo, n);
        for (size_t k = n; k < padded; k++) i = put8(b, i, 0);
        return i;
    }
    i = put8(b, i, (uint8_t) n);
    return put(b, i, memo, n);
}

/* An attribute's usage and length: one byte, three from 253, or now and then a form the device
 * must refuse (three bytes below 253, or five bytes). */
static size_t put_attribute_head(uint8_t *b, size_t i, uint8_t usage, size_t len) {
    i = put8(b, i, usage);
    if (len > 0xFC || rn(24) == 0) {
        i = put8(b, i, 0xFD);
        i = put8(b, i, (uint8_t) len);
        return put8(b, i, (uint8_t) (len >> 8));
    }
    if (rn(40) == 0) {
        i = put8(b, i, 0xFE);
        for (int k = 0; k < 4; k++) i = put8(b, i, (uint8_t) (len >> (8 * k)));
        return i;
    }
    return put8(b, i, (uint8_t) len);
}

/* A nonce: mostly the wallet's one byte "0", else up to eight bytes, nine, or far more. */
static size_t put_nonce(uint8_t *b, size_t i, uint8_t usage) {
    size_t len = rn(3) == 0 ? 1 : rn(4) != 0 ? rn(9) : rn(3) != 0 ? 9 : 10 + rn(rn(4) == 0 ? 300 : 20);
    i = put_attribute_head(b, i, usage, len);
    for (size_t k = 0; k < len; k++) i = put8(b, i, len == 1 && rn(2) ? '0' : (uint8_t) rnd());
    return i;
}

/* A printable character from one of four mixes, so lines reach the screen edge by width as well
 * as by count. */
static uint8_t memo_char(unsigned mix) {
    static const char NARROW[] = " .,:;!'il()[]{}/-|jrtfIJ";
    static const char WIDE[] = "@MWmw%OQ&4DGHNU#ABX_";
    static const char WORDS[] = "abcdefghijklmnopqrstuvwxyz 0123456789";
    switch (mix) {
        case 0: return (uint8_t) (0x20 + rn(95));
        case 1: return (uint8_t) NARROW[rn(sizeof(NARROW) - 1)];
        case 2: return (uint8_t) WIDE[rn(sizeof(WIDE) - 1)];
        default: return (uint8_t) WORDS[rn(sizeof(WORDS) - 1)];
    }
}

/* A text memo: mostly "type:text,msg:" and a note of characters or words, up to past what the
 * screens hold; now and then empty or with a byte outside printable ASCII. */
static size_t put_memo_text(uint8_t *b, size_t i, uint8_t usage) {
    uint8_t memo[720];
    size_t n = 0;
    unsigned mix = rn(4);
    if (rn(3) != 0) {
        memcpy(memo, "type:text,msg:", 14);
        n = 14;
    }
    /* short, up to what two outputs leave, around what one output leaves, or far too long */
    unsigned pick = rn(10);
    size_t len = pick < 3 ? rn(24) : pick < 7 ? rn(170) : pick < 9 ? 140 + rn(130) : 200 + rn(500);
    if (rn(4) == 0) {
        /* words of 1 to 20 equal-width characters between break characters, so words that fill
         * a line exactly, or by one more, come often */
        static const char WORD_CHARS[] = "'!\"?$#4%@ilj fz5ABDGOMW";
        size_t end = n + len;
        while (n < end && n < sizeof(memo)) {
            char c = WORD_CHARS[rn(sizeof(WORD_CHARS) - 1)];
            for (size_t k = 1 + rn(20); k > 0 && n < sizeof(memo); k--) memo[n++] = (uint8_t) c;
            for (size_t k = 1 + (rn(4) == 0); k > 0 && n < sizeof(memo); k--) memo[n++] = (uint8_t) " ,:"[rn(3)];
        }
    } else {
        for (size_t k = 0; k < len && n < sizeof(memo); k++) memo[n++] = memo_char(rn(6) == 0 ? rn(4) : mix);
    }
    if (rn(30) == 0) n = 0;
    if (n > 0 && rn(10) == 0) {
        /* a control character, DEL, or a byte past ASCII, as a UTF-8 letter would bring */
        static const uint8_t BAD[] = {0x00, 0x09, 0x0A, 0x1B, 0x1F, 0x7F, 0x80, 0xC3, 0xE9, 0xFF};
        memo[rn((unsigned) n)] = BAD[rn(sizeof(BAD))];
    }
    i = put_attribute_head(b, i, usage, n);
    return put(b, i, memo, n);
}

/* A mostly well-formed transaction with occasional faults, to reach the accept path and every
 * refusal. Change goes to signer_ph. */
static size_t generate(uint8_t *b, const uint8_t signer_ph[21]) {
    size_t i = 0;
    bool v9 = rn(3) == 0;
    if (v9) i = put8(b, i, rn(20) == 0 ? (uint8_t) (9 + rn(3)) : 9);
    i = put8(b, i, rn(15) == 0 ? (uint8_t) rn(256) : 2);
    i = put8(b, i, rn(20) == 0 ? 1 : 0);
    /* many coins leave less room for a long memo */
    unsigned ni = rn(12) == 0 ? 0 : rn(6) == 0 ? 5 + rn(16) : 1 + rn(4);
    /* mostly the wallet's nonce and maybe a text or vote memo; else any mix, a kind too many, or
     * an unknown type */
    uint8_t kinds[4];
    unsigned na = 0, plan = rn(10);
    if (plan < 8) {
        if (rn(6) != 0) kinds[na++] = 0;
        if (rn(4) != 0) kinds[na++] = rn(3) == 0 ? 2 : 1;
        if (na == 2 && rn(8) == 0) {
            kinds[0] = kinds[1];
            kinds[1] = 0;
        }
    } else if (plan < 9 || rn(2)) {
        na = 2 + rn(2);
        for (unsigned a = 0; a < na; a++) kinds[a] = (uint8_t) rn(3);
    } else {
        na = rn(5);
        for (unsigned a = 0; a < na; a++) kinds[a] = (uint8_t) rn(4);
    }
    i = put8(b, i, (uint8_t) na);
    for (unsigned a = 0; a < na; a++) {
        uint8_t usage = kinds[a] == 3 ? (uint8_t) rn(256) : kinds[a] == 0 ? 0x00 : 0x81;
        /* usage is passed in, so a nonce's data can follow a memo's type and the other way round */
        if (rn(20) == 0) usage = usage == 0x00 ? 0x81 : 0x00;
        switch (kinds[a]) {
            case 0: i = put_nonce(b, i, usage); break;
            case 1: i = put_memo_text(b, i, usage); break;
            case 2: i = put_vote(b, i, usage); break;
            default: i = rn(2) ? put_nonce(b, i, usage) : put_memo_text(b, i, usage); break;
        }
    }
    i = put8(b, i, (uint8_t) ni);
    for (unsigned k = 0; k < ni * 38; k++) i = put8(b, i, (uint8_t) rnd());
    unsigned no = rn(10) == 0 ? rn(6) : 1 + rn(3);
    i = put8(b, i, (uint8_t) no);
    for (unsigned k = 0; k < no; k++) {
        uint8_t asset[32];
        memcpy(asset, ELA, 32);
        if (rn(15) == 0) asset[rn(32)] ^= 1;
        i = put(b, i, asset, 32);
        uint64_t v;
        switch (rn(7)) {
            case 0: v = 0; break;
            case 1: v = 1; break;
            case 2: v = rnd() >> rn(64); break;
            case 3: v = 9999999999999999ULL + rn(3); break; /* 99999999.99999999 +0..2 */
            case 4: /* 14 to 16 digits, half of them 4s: near the width limit */
                v = 0;
                for (unsigned d = 0, digits = 14 + rn(3); d < digits; d++) v = v * 10 + (rn(2) ? 4 : rn(10));
                break;
            default: v = rnd() % 5000000000000ULL; break;
        }
        uint8_t vb[8];
        for (int j = 0; j < 8; j++) vb[j] = (uint8_t) (v >> (8 * j));
        i = put(b, i, vb, 8);
        uint32_t lock = rn(12) == 0 ? (uint32_t) rnd() : 0;
        uint8_t lb[4] = {(uint8_t) lock, (uint8_t) (lock >> 8), (uint8_t) (lock >> 16), (uint8_t) (lock >> 24)};
        i = put(b, i, lb, 4);
        uint8_t ph[21];
        unsigned pick = rn(20);
        if (pick < 6) {
            memcpy(ph, signer_ph, 21);
        } else if (pick < 8) {
            /* not change: the signer's hash under the multisig prefix, or one bit off */
            memcpy(ph, signer_ph, 21);
            if (rn(2)) {
                ph[0] = 0x12;
            } else {
                ph[1 + rn(20)] ^= (uint8_t) (1u << rn(8));
            }
        } else if (pick < 10) {
            memcpy(ph, WIDE[rn(3)], 21);
        } else {
            for (int j = 0; j < 21; j++) ph[j] = (uint8_t) rnd();
            static const uint8_t prefixes[] = {0x21, 0x21, 0x21, 0x12, 0x4B, 0x1F, 0x1C, 0x3F, 0x00};
            ph[0] = prefixes[rn(sizeof(prefixes))];
        }
        i = put(b, i, ph, 21);
        if (v9) i = put8(b, i, rn(10) == 0 ? (uint8_t) rn(8) : 0);
    }
    uint32_t lt = rn(15) == 0 ? (uint32_t) rnd() : 0;
    uint8_t ltb[4] = {(uint8_t) lt, (uint8_t) (lt >> 8), (uint8_t) (lt >> 16), (uint8_t) (lt >> 24)};
    i = put(b, i, ltb, 4);
    if (rn(20) == 0) i = put8(b, i, (uint8_t) rnd()); /* trailing byte */
    return i;
}

static size_t mutate(uint8_t *b, size_t n) {
    static const uint8_t edges[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x08, 0x09, 0x0A, 0x12, 0x21, 0x81, 0xFC, 0xFD, 0xFE, 0xFF};
    unsigned m = 1 + rn(6);
    for (unsigned k = 0; k < m && n > 0; k++) {
        switch (rn(6)) {
            case 0: b[rn((unsigned) n)] ^= (uint8_t) (1u << rn(8)); break;
            case 1: b[rn((unsigned) n)] = edges[rn(sizeof(edges))]; break;
            case 2: n = rn((unsigned) n + 1); break; /* truncate */
            case 3:                                /* insert */
                if (n < MAX_TX_RAW_LENGTH - 21) {
                    size_t at = rn((unsigned) n + 1);
                    memmove(b + at + 1, b + at, n - at);
                    b[at] = (uint8_t) rnd();
                    n++;
                }
                break;
            case 4: /* delete */
                if (n > 1) {
                    size_t at = rn((unsigned) n);
                    memmove(b + at, b + at + 1, n - at - 1);
                    n--;
                }
                break;
            default: b[rn((unsigned) n)] = (uint8_t) rnd(); break;
        }
    }
    return n;
}

/* ---------------------------------------------------------------- oracle */
static unsigned long accepted, refused, failures, change_lookalikes, many_coins, votes;
static unsigned long wide_signers_refused, wide_signers_shown;
static unsigned long memos_shown, longest_memos_shown, memos_refused, attributes_refused;
static FILE *accepted_out;

static void fail(const char *why, const uint8_t *b, size_t n) {
    failures++;
    if (failures <= 10) {
        printf("FAIL: %s\n  tx(%zu)=", why, n);
        for (size_t i = 0; i < n; i++) printf("%02x", b[i]);
        printf("\n");
    }
}

static bool terminated(const char *s) { return memchr(s, '\0', MAX_TX_TEXT_WIDTH) != NULL; }

/* True if screen s shows addr on lines of 11, 11 and 12 characters. */
static bool shows_address(unsigned s, const char *addr) {
    return strlen(addr) == 34 && strncmp(tx_desc[s][0], addr, 11) == 0 && tx_desc[s][0][11] == '\0' &&
           strncmp(tx_desc[s][1], addr + 11, 11) == 0 && tx_desc[s][1][11] == '\0' &&
           strcmp(tx_desc[s][2], addr + 22) == 0;
}

static void check(const uint8_t *b, size_t n, const signer_t *signer) {
    memset(raw_tx, 0xEE, sizeof(raw_tx));
    memcpy(raw_tx, b, n);
    memset(raw_tx + n, 0x5A, 20);
    raw_tx_len = (unsigned) n + 20;
    raw_tx_ix = 0;
    memset(tx_desc, 0xEE, sizeof(tx_desc));
    memset(review_title, 0xEE, sizeof(review_title));

    ref_t r = reference(b, n, signer->ph);
    unsigned short sw = tx_parse_and_render(signer->ph);

    if (raw_tx_ix > n) fail("cursor moved past the end of the body", b, n);

    if (sw != SW_OK) {
        refused++;
        if (sw == r.sw && r.signer_too_wide) wide_signers_refused++;
        if (sw == r.sw && sw == SW_TX_MEMO) memos_refused++;
        if (sw == r.sw && sw == SW_TX_ATTRIBUTE) attributes_refused++;
        if (r.sw == SW_OK) {
            fail("device refused a transaction the reference accepts", b, n);
        } else if (sw != r.sw) {
            char why[96];
            snprintf(why, sizeof(why), "device refused with %04X, the reference with %04X", sw, r.sw);
            fail(why, b, n);
        }
        return;
    }
    accepted++;
    if (r.sw != SW_OK) {
        char why[96];
        snprintf(why, sizeof(why), "device accepted a transaction the reference refuses with %04X", r.sw);
        fail(why, b, n);
        return;
    }
    if (raw_tx_ix != n) fail("accepted without consuming the whole body", b, n);
    unsigned memo_screens = (r.memo_lines + 2) / 3;
    unsigned first_output = 1 + (r.vote ? 3 : memo_screens);
    if (max_scr_ix != first_output + 2 * r.outputs + 1)
        fail("screen count is not signer + vote or memo screens + 2 per output + fee", b, n);
    for (unsigned s = 0; s < max_scr_ix && s < MAX_TX_TEXT_SCREENS; s++) {
        if (!terminated(review_title[s])) fail("title not terminated", b, n);
        for (unsigned l = 0; l < MAX_TX_TEXT_LINES; l++)
            if (!terminated(tx_desc[s][l])) fail("line not terminated", b, n);
    }
    if (strcmp(review_title[0], "Signing with") != 0) fail("signer title wrong", b, n);
    if (!shows_address(0, signer->address)) fail("signer address differs from the reference", b, n);
    if (signer->ph != SIGNER) wide_signers_shown++;
    if (r.vote) {
        char choice[24], hex[65];
        snprintf(choice, sizeof(choice), "Choice %u", (unsigned) r.choice + 1);
        for (int k = 0; k < 32; k++) snprintf(hex + 2 * k, 3, "%02x", r.poll_id[k]);
        votes++;
        if (strcmp(review_title[1], "Poll vote") != 0 || strcmp(tx_desc[1][0], choice) != 0 ||
            strcmp(tx_desc[1][1], r.vote_amount) != 0 || strcmp(tx_desc[1][2], "ELA") != 0)
            fail("poll vote screen differs from the vote signed", b, n);
        for (unsigned part = 0; part < 2; part++) {
            char title[24];
            const char *h = hex + 32 * part;
            snprintf(title, sizeof(title), "Poll id %u of 2", part + 1);
            if (strcmp(review_title[2 + part], title) != 0 || strncmp(tx_desc[2 + part][0], h, 11) != 0 ||
                strncmp(tx_desc[2 + part][1], h + 11, 11) != 0 || strncmp(tx_desc[2 + part][2], h + 22, 10) != 0 ||
                strlen(tx_desc[2 + part][0]) != 11 || strlen(tx_desc[2 + part][1]) != 11 ||
                strlen(tx_desc[2 + part][2]) != 10)
                fail("poll id screen differs from the poll id signed", b, n);
        }
    }
    if (memo_screens > 0) {
        memos_shown++;
        if (memo_screens == 5) longest_memos_shown++;
        for (unsigned s = 0; s < memo_screens && 1 + s < MAX_TX_TEXT_SCREENS; s++) {
            char title[24];
            if (memo_screens == 1) {
                snprintf(title, sizeof(title), "Memo");
            } else {
                snprintf(title, sizeof(title), "Memo %u of %u", s + 1, memo_screens);
            }
            if (strcmp(review_title[1 + s], title) != 0) fail("memo title wrong", b, n);
            for (unsigned k = 0; k < 3; k++) {
                unsigned line = 3 * s + k;
                const char *want = line < r.memo_lines ? r.memo_line[line] : "";
                if (strncmp(tx_desc[1 + s][k], want, MAX_TX_TEXT_WIDTH) != 0)
                    fail("memo screen differs from the memo signed", b, n);
            }
        }
    }
    for (unsigned k = 0; k < r.outputs; k++) {
        unsigned s = first_output + 2 * k;
        char want[32], title[32];
        fmt_amount(r.value[k], want);
        if (strcmp(tx_desc[s][1], want) != 0) fail("displayed amount differs from the amount signed", b, n);
        bool own = memcmp(r.ph[k], signer->ph, 21) == 0;
        if (!own && memcmp(r.ph[k] + 1, signer->ph + 1, 20) == 0) change_lookalikes++;
        if (strcmp(tx_desc[s][0], own ? "Back to you" : "Send") != 0) fail("change label wrong", b, n);
        if (strcmp(tx_desc[s][2], "ELA") != 0) fail("unit line wrong", b, n);
        snprintf(title, sizeof(title), "Output %u of %u", k + 1, r.outputs);
        if (strcmp(review_title[s], title) != 0) fail("output title wrong", b, n);
        if (strcmp(review_title[s + 1], own ? "Your address" : "Recipient") != 0) fail("address title wrong", b, n);
        if (!shows_address(s + 1, r.address[k])) fail("displayed address differs from the reference", b, n);
    }
    if (strcmp(review_title[max_scr_ix - 1], "Network fee") != 0) fail("fee title wrong", b, n);
    if (strcmp(tx_desc[max_scr_ix - 1][0], "Not checked by") != 0 ||
        strcmp(tx_desc[max_scr_ix - 1][1], "this device.") != 0 ||
        strcmp(tx_desc[max_scr_ix - 1][2], "Set by the wallet") != 0)
        fail("fee notice wrong", b, n);
    /* count accepted payments of five or more coins; the input count follows the attributes */
    size_t at = (b[0] == 9) + 2, na = b[at++];
    for (size_t a = 0; a < na; a++) {
        size_t l = b[at + 1];
        at += 2;
        if (l == 0xFD) {
            l = (size_t) b[at] | ((size_t) b[at + 1] << 8);
            at += 2;
        }
        at += l;
    }
    if (b[at] >= 5) many_coins++;
    if (accepted_out && accepted <= 3000) {
        for (size_t i = 0; i < n; i++) fprintf(accepted_out, "%02x", b[i]);
        fprintf(accepted_out, "\n");
    }
}

/* Checks the parser's width table against the SDK font; a character the font lacks must be wider
 * than a line, so it never passes unmeasured. Returns the number of mismatches. */
static unsigned check_width_table(void) {
    unsigned bad = 0;
    for (int c = 1; c < 256; c++) {
        unsigned want = ref_char_width((char) c);
        unsigned got = char_width_px((char) c);
        if (want != 0 ? got != want : got <= REVIEW_LINE_WIDTH_PX) {
            if (bad++ < 10) printf("FAIL: width of '%c' (0x%02x) is %u px, the SDK font says %u\n", c, c, got, want);
        }
    }
    /* and at the edge: a line exactly as wide as the screen fits, one pixel more does not */
    for (int c = 1; c < 256; c++) {
        unsigned w = ref_char_width((char) c);
        if (w == 0) continue;
        char line[64];
        unsigned len = 0, width = w;
        line[len++] = (char) c;
        while (width + 3 <= REF_LINE_WIDTH_PX && len < sizeof(line) - 2) {
            line[len++] = 'i';
            width += 3;
        }
        while (width < REF_LINE_WIDTH_PX) {
            /* fill the last one or two pixels by widening 'i' (3 px) to 'r' (4 px) or 'c' (5 px) */
            unsigned gap = REF_LINE_WIDTH_PX - width;
            line[len - 1] = gap >= 2 ? 'c' : 'r';
            width += gap >= 2 ? 2 : 1;
        }
        line[len] = '\0';
        if (!line_fits(line)) {
            if (bad++ < 10) printf("FAIL: a %u px line with '%c' does not fit\n", width, c);
        }
        /* one pixel more: an 'i' after the character under test becomes an 'r' */
        line[1] = line[1] == 'i' ? 'r' : line[1] == 'r' ? 'c' : 'z';
        if (line_fits(line)) {
            if (bad++ < 10) printf("FAIL: a %u px line with '%c' fits\n", width + 1, c);
        }
    }
    return bad;
}

/* ---------------------------------------------------------------- memo limits */
/* The specification's limits: the longest memo, and note after the wallet's prefix, of any
 * printable characters that always fits one, two or three outputs. */
static const char WALLET_PREFIX[] = "type:text,msg:";
static const unsigned MEMO_LINE_BUDGET[3] = {15, 9, 3};
#if defined(TARGET_NANOS)
static const unsigned SPEC_ANY_MEMO[3] = {93, 57, 21};
static const unsigned SPEC_ANY_NOTE[3] = {86, 50, 14};
#else
static const unsigned SPEC_ANY_MEMO[3] = {101, 62, 23};
static const unsigned SPEC_ANY_NOTE[3] = {93, 54, 15};
#endif

/*
 * Breadth-first search for the shortest text needing more lines than a budget. The splitter sees a
 * character only by its width and whether a line may end after it, and a partial text's future only
 * by five numbers: lines closed, and the open line's length and width, in all and up to its last
 * break. Texts alike in these are searched as one.
 */
#define LIMIT_DIM_W (REF_LINE_WIDTH_PX + 1)
#define LIMIT_KEYS ((size_t) 15 * (REF_LINE_CHARS + 1) * LIMIT_DIM_W * (REF_LINE_CHARS + 1) * LIMIT_DIM_W)
#define LIMIT_MAX_STATES 4000000u

typedef struct {
    uint8_t closed;              /* lines closed before the line being filled */
    uint8_t n;                   /* characters on the line being filled */
    char line[REF_LINE_CHARS];   /* those characters */
    uint8_t c;                   /* the last character written, which led here */
    uint32_t parent;             /* the state it was written in */
} limit_state_t;

static uint8_t limit_seen[LIMIT_KEYS / 8 + 1];

/* Marks the state seen; returns 1 if one alike in the five numbers was seen before. */
static int limit_seen_before(unsigned closed, const char *line, unsigned n) {
    unsigned w = 0, b = 0, wb = 0;
    for (unsigned k = 0; k < n; k++) {
        w += ref_char_width((unsigned char) line[k]);
        if (ref_line_may_end_after((unsigned char) line[k])) {
            b = k + 1;
            wb = w;
        }
    }
    size_t key = (((((size_t) closed * (REF_LINE_CHARS + 1) + n) * LIMIT_DIM_W + w) * (REF_LINE_CHARS + 1) + b) *
                  LIMIT_DIM_W) + wb;
    int seen = (limit_seen[key / 8] >> (key % 8)) & 1;
    limit_seen[key / 8] |= (uint8_t) (1u << (key % 8));
    return seen;
}

/* For each line budget, the length of the shortest text after prefix needing more lines, and one
 * such text; every shorter one fits, as writing on never takes fewer lines. */
static unsigned long limit_search(const char *prefix, unsigned shortest[3], char witness[3][160]) {
    static char lines[REF_MEMO_MAX_LINES][REF_LINE_CHARS + 1];
    uint8_t reps[256];
    unsigned nreps = 0;
    /* one character for each width, and for each width a line may end after */
    for (unsigned c = 0x20; c <= 0x7E; c++) {
        bool taken = false;
        for (unsigned k = 0; k < nreps; k++)
            if (ref_char_width(reps[k]) == ref_char_width((uint8_t) c) &&
                ref_line_may_end_after(reps[k]) == ref_line_may_end_after((uint8_t) c))
                taken = true;
        if (!taken) reps[nreps++] = (uint8_t) c;
    }
    limit_state_t *states = malloc(LIMIT_MAX_STATES * sizeof(limit_state_t));
    if (states == NULL) {
        printf("FAIL: no memory for the memo limit search\n");
        exit(1);
    }
    memset(limit_seen, 0, sizeof(limit_seen));
    memset(&states[0], 0, sizeof(states[0]));
    size_t plen = strlen(prefix);
    if (plen > 0) {
        unsigned count = ref_memo_lines((const uint8_t *) prefix, plen, lines);
        states[0].closed = (uint8_t) (count - 1);
        states[0].n = (uint8_t) strlen(lines[count - 1]);
        memcpy(states[0].line, lines[count - 1], states[0].n);
    }
    limit_seen_before(states[0].closed, states[0].line, states[0].n);
    unsigned long count_states = 1;
    size_t layer_start = 0, layer_end = 1;
    unsigned found = 0;
    for (unsigned length = 1; found < 3 && layer_start < layer_end; length++) {
        for (size_t s = layer_start; s < layer_end; s++) {
            for (unsigned r = 0; r < nreps; r++) {
                uint8_t text[REF_LINE_CHARS + 1];
                memcpy(text, states[s].line, states[s].n);
                text[states[s].n] = reps[r];
                unsigned count = ref_memo_lines(text, states[s].n + 1u, lines);
                unsigned closed = states[s].closed + count - 1;
                for (unsigned k = 0; k < 3; k++) {
                    if (shortest[k] != 0 || closed < MEMO_LINE_BUDGET[k]) continue;
                    /* the text that got here, read back through the states that led to it */
                    shortest[k] = length;
                    found++;
                    size_t at = plen + length;
                    memcpy(witness[k], prefix, plen);
                    witness[k][at] = '\0';
                    witness[k][--at] = (char) reps[r];
                    for (size_t p = s; p != 0; p = states[p].parent) witness[k][--at] = (char) states[p].c;
                }
                if (closed >= MEMO_LINE_BUDGET[0]) continue;
                const char *last = lines[count - 1];
                unsigned n = (unsigned) strlen(last);
                if (limit_seen_before(closed, last, n)) continue;
                if (count_states == LIMIT_MAX_STATES) {
                    printf("FAIL: the memo limit search has more than %u states\n", LIMIT_MAX_STATES);
                    exit(1);
                }
                limit_state_t *t = &states[count_states++];
                t->closed = (uint8_t) closed;
                t->n = (uint8_t) n;
                memcpy(t->line, last, n);
                t->c = reps[r];
                t->parent = (uint32_t) s;
            }
        }
        layer_start = layer_end;
        layer_end = count_states;
    }
    free(states);
    return count_states;
}

/* A payment to the signer with the wallet's nonce and a memo under 253 bytes. */
static size_t memo_payment(uint8_t *b, const char *memo, size_t memo_len, unsigned outputs) {
    size_t i = 0;
    i = put8(b, i, 0x02); /* a transfer */
    i = put8(b, i, 0x00); /* payload version */
    i = put8(b, i, 0x02); /* two attributes: the nonce "0" and the memo */
    i = put8(b, i, 0x00);
    i = put8(b, i, 0x01);
    i = put8(b, i, '0');
    i = put8(b, i, 0x81);
    i = put8(b, i, (uint8_t) memo_len);
    i = put(b, i, memo, memo_len);
    i = put8(b, i, 0x01); /* one input */
    for (unsigned k = 0; k < 38; k++) i = put8(b, i, 0x5A);
    i = put8(b, i, (uint8_t) outputs);
    for (unsigned k = 0; k < outputs; k++) {
        static const uint8_t ONE_ELA[8] = {0x00, 0xE1, 0xF5, 0x05, 0, 0, 0, 0};
        static const uint8_t NO_LOCK[4] = {0};
        i = put(b, i, ELA, 32);
        i = put(b, i, ONE_ELA, 8);
        i = put(b, i, NO_LOCK, 4);
        i = put(b, i, SIGNER, 21);
    }
    static const uint8_t NO_LOCK_TIME[4] = {0};
    return put(b, i, NO_LOCK_TIME, 4);
}

/* Checks the searched limits equal the specification's, and that the device refuses the shortest
 * memo past each with 6D62, as the reference does, and accepts it one character shorter. */
static unsigned check_memo_limits(void) {
    unsigned bad = 0;
    for (unsigned with_prefix = 0; with_prefix < 2; with_prefix++) {
        const char *prefix = with_prefix ? WALLET_PREFIX : "";
        const unsigned *spec = with_prefix ? SPEC_ANY_NOTE : SPEC_ANY_MEMO;
        unsigned shortest[3] = {0, 0, 0};
        char witness[3][160];
        unsigned long searched = limit_search(prefix, shortest, witness);
        printf("memo limits%s: any %s of %u, %u or %u characters fits 1, 2 or 3 outputs (%lu states searched)\n",
               with_prefix ? " after the wallet's prefix" : "", with_prefix ? "note" : "memo", shortest[0] - 1,
               shortest[1] - 1, shortest[2] - 1, searched);
        for (unsigned k = 0; k < 3; k++) {
            if (shortest[k] - 1 != spec[k]) {
                printf("FAIL: with %u outputs the longest %s that always fits is %u, the specification says %u\n",
                       k + 1, with_prefix ? "note" : "memo", shortest[k] - 1, spec[k]);
                bad++;
            }
            uint8_t b[MAX_TX_RAW_LENGTH];
            size_t len = strlen(witness[k]);
            for (unsigned shorter = 0; shorter < 2; shorter++) {
                size_t n = memo_payment(b, witness[k], len - shorter, k + 1);
                unsigned long before = failures;
                ref_t r = reference(b, n, SIGNER);
                if (r.sw != (shorter ? SW_OK : SW_TX_MEMO)) {
                    printf("FAIL: the reference %s the memo \"%.*s\" with %u outputs\n", shorter ? "refuses" : "accepts",
                           (int) (len - shorter), witness[k], k + 1);
                    bad++;
                }
                check(b, n, &SIGNERS[0]);
                bad += (unsigned) (failures - before);
                failures = before;
            }
        }
    }
    return bad;
}

int main(int argc, char **argv) {
    if (argc > 1 && strcmp(argv[1], "limits") == 0) {
        failures += check_width_table();
        failures += check_memo_limits();
        printf("memo limits: failures %lu\n", failures);
        return failures ? 1 : 0;
    }
    unsigned long iters = argc > 1 ? strtoul(argv[1], NULL, 10) : 100000;
    rng = argc > 2 ? strtoull(argv[2], NULL, 0) : 0xE1A0001ULL;
    if (rng == 0) rng = 1;
    accepted_out = argc > 3 ? fopen(argv[3], "w") : NULL;

    failures += check_width_table();

    uint8_t b[MAX_TX_RAW_LENGTH];
    for (unsigned long it = 0; it < iters; it++) {
        /* one case in eight signs with a key whose address has a wide line */
        const signer_t *signer = rn(8) == 0 ? &SIGNERS[1 + rn(3)] : &SIGNERS[0];
        size_t n = generate(b, signer->ph);
        if (rn(2)) n = mutate(b, n);
        check(b, n, signer);
    }
    printf("iterations %lu  accepted %lu  refused %lu  failures %lu  (accepted change look-alikes %lu, "
           "five or more coins %lu, poll votes %lu, memos shown %lu of which on five screens %lu, wide "
           "signers refused %lu and shown %lu; refused as memos %lu and as attributes %lu)\n",
           iters, accepted, refused, failures, change_lookalikes, many_coins, votes, memos_shown,
           longest_memos_shown, wide_signers_refused, wide_signers_shown, memos_refused, attributes_refused);
    if (accepted_out) fclose(accepted_out);
    return failures ? 1 : 0;
}
