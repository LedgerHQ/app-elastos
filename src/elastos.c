/*
 * MIT License, see root folder for full license.
 */
#include <string.h>
#include "elastos.h"
#include "base-encoding.h"
#include "sw.h"

/** A first byte at or above this is a version, and the type follows. */
#define TX_VERSION_09 0x09

#define TX_TYPE_TRANSFER_ASSET 0x02

/** v9 output type with no payload; every other type carries one. */
#define OUTPUT_TYPE_NONE 0x00

/** The wallet writes one nonce and at most one memo. A second nonce is more data signed unseen;
 * a second memo could be the one chain readers take instead of the one shown. */
#define ATTRIBUTE_NONCE 0x00
#define ATTRIBUTE_MEMO  0x81
#define MAX_NONCES      1
#define MAX_MEMOS       1

/** The nonce is signed unseen, so its length is bounded. The wallet writes one byte; eight leave
 * room for a counter. */
#define MAX_NONCE_LEN 8

/** The only recipient types shown. Others (deposit 0x1F, stake 0x3F, cross-chain 0x4B, treasury
 * 0x1C, all-zero) would look like an ordinary payment, so they are refused. */
#define PREFIX_STANDARD 0x21
#define PREFIX_MULTISIG 0x12

#define ASSET_ID_LEN 32

/** previous transaction id, output index, sequence */
#define INPUT_LEN (32 + 2 + 4)

/** Review order: signer, memo if any, two screens per output, fee notice. */
#define SIGNER_SCREEN      0
#define MEMO_FIRST_SCREEN  1
#define SCREENS_PER_OUTPUT 2
#define FEE_NOTICE_SCREENS 1

/** Most outputs the review fits; more are refused, never shown in part. */
#define MAX_TX_OUTPUTS 3

/** Screens a one-output payment leaves for memo text. More outputs leave fewer, checked once
 * their count is read. */
#define MAX_MEMO_SCREENS \
    (MAX_TX_TEXT_SCREENS - MEMO_FIRST_SCREEN - SCREENS_PER_OUTPUT - FEE_NOTICE_SCREENS)

/** Leaves room for the line's terminator. */
#define WRAP_LINE_CHARS (MAX_TX_TEXT_WIDTH - 1)

/** Memo text is printable ASCII only, which every device's review font draws. */
#define FIRST_PRINTABLE_CHAR 0x20
#define LAST_PRINTABLE_CHAR  0x7E

/** A memo line may end after any of these, keeping words whole. */
#define MEMO_BREAKS " ,:"

/** A path line may end after a slash, keeping numbers whole. */
#define PATH_BREAKS "/"

/** Ten digits, the hardened mark and the slash. */
#define PATH_PART_CHARS (10 + 1 + 1)

/** Poll vote memo, as Essentials encodeVoteMemo writes it: "pollvote", 32-byte poll id, 32-bit
 * little-endian choice, one length byte, then the amount as ELA text. */
#define POLL_VOTE_FLAG_LEN  8
#define POLL_ID_LEN         32
#define POLL_VOTE_FIXED_LEN (POLL_VOTE_FLAG_LEN + POLL_ID_LEN + 4 + 1)

/** Choice and amount, then the poll id over two screens. */
#define POLL_VOTE_FIRST_SCREEN MEMO_FIRST_SCREEN
#define POLL_VOTE_SCREENS      3

/** Poll id hex characters per screen. */
#define POLL_ID_HEX_PER_SCREEN 32

/** Choices show from 1; a poll lists far fewer than this. */
#define MAX_POLL_CHOICE_INDEX 999

#define MAX_ELA_DECIMALS 8

#define SELA_PER_ELA 100000000ULL
#define ELA_DECIMALS 8

/** Width of the first row of CHARS_BY_WIDTH. */
#define NARROWEST_CHAR_PX 2

/* _, X and & are 1 px wider on Nano X and Nano S Plus than on Nano S. */
#if defined(TARGET_NANOS)
#define DIFFERING_5_PX "_"
#define DIFFERING_6_PX "X"
#define DIFFERING_7_PX ""
#define DIFFERING_8_PX "&"
#define DIFFERING_9_PX ""
#else
#define DIFFERING_5_PX ""
#define DIFFERING_6_PX "_"
#define DIFFERING_7_PX "X"
#define DIFFERING_8_PX ""
#define DIFFERING_9_PX "&"
#endif

/** Printable ASCII by pixel width in the review font (Open Sans 11 px), from the SDK font tables.
 * Stored inline, not as pointers: a pointer in flash keeps its link-time address. */
static const char CHARS_BY_WIDTH[][34] = {
    "'",
    " !(),.:;Iil",
    "\"-/J[\\]jrt{}",
    "?cfsz" DIFFERING_5_PX,
    "$*+012356789<=>EFLSYZ^`aegkvxy|~" DIFFERING_6_PX,
    "#ABCKPRTVbdhnopqu" DIFFERING_7_PX,
    "4DGHNU" DIFFERING_8_PX,
    "%OQw" DIFFERING_9_PX,
    "@MWm",
};

/** Largest count or length in its single-byte form. */
#define MAX_SINGLE_BYTE_COUNT 0xFC

/** Marks a three-byte length: this byte, then 16 bits. */
#define VARINT_16_BIT 0xFD

static const char POLL_VOTE_FLAG[POLL_VOTE_FLAG_LEN] = {'p', 'o', 'l', 'l', 'v', 'o', 't', 'e'};

static const char HEX_DIGITS[] = "0123456789abcdef";

/** ELA asset id as on the wire (Elastos.ELA core/manager.go, ELAAssetID). */
static const uint8_t ELA_ASSET_ID[ASSET_ID_LEN] = {
    0xb0, 0x37, 0xdb, 0x96, 0x4a, 0x23, 0x14, 0x58, 0xd2, 0xd6, 0xff, 0xd5, 0xea, 0x18, 0x94, 0x4c,
    0x4f, 0x90, 0xe6, 0x3d, 0x54, 0x7c, 0x5d, 0x3b, 0x98, 0x74, 0xdf, 0x66, 0xa4, 0xea, 0xd0, 0xa3};

/** Account screen placeholders. */
static const char NO_PUBLIC_KEY_0[] = "Could not get";
static const char NO_PUBLIC_KEY_1[] = "the address";
static const char ADDRESS_TOO_WIDE_0[] = "Address too wide";
static const char ADDRESS_TOO_WIDE_1[] = "to show here";

/** Scratch buffer for to_address. */
static unsigned char address[ADDRESS_LEN];

/** End of the body in raw_tx; the path after it is never parsed as transaction data. */
static unsigned int body_end;

static void set_line(char line[MAX_TX_TEXT_WIDTH], const char *text) {
    strlcpy(line, text, MAX_TX_TEXT_WIDTH);
}

static void set_title(unsigned int screen, const char *text) {
    strlcpy(review_title[screen], text, MAX_TX_TEXT_WIDTH);
}

/** Encodes a program hash and its checksum as a base58 address. */
static bool to_address(const uint8_t program_hash[CODE_HASH_LEN],
                       char out[ADDRESS_BASE58_LEN + 1]) {
    unsigned char address_hash_result_0[SHA256_HASH_LEN];
    unsigned char address_hash_result_1[SHA256_HASH_LEN];

    memmove(address, program_hash, CODE_HASH_LEN);

    cx_hash_sha256(program_hash, CODE_HASH_LEN, address_hash_result_0, SHA256_HASH_LEN);
    cx_hash_sha256(address_hash_result_0, SHA256_HASH_LEN, address_hash_result_1, SHA256_HASH_LEN);

    // add the first bytes of the hash as a checksum at the end of the address.
    memmove(address + CODE_HASH_LEN, address_hash_result_1, CODE_HASH_CHECKSUM_LEN);

    size_t len = encode_base_58(address, ADDRESS_LEN, out, ADDRESS_BASE58_LEN + 1);
    return len == ADDRESS_BASE58_LEN;
}

/** Splits an address over lines of 11, 11 and 12 characters. Width is not checked here; see
 * render_reviewed_address. */
static bool render_address(const uint8_t program_hash[CODE_HASH_LEN],
                           char lines[MAX_TX_TEXT_LINES][MAX_TX_TEXT_WIDTH]) {
    char encoded[ADDRESS_BASE58_LEN + 1];
    if (!to_address(program_hash, encoded)) {
        return false;
    }
    memset(lines, 0, MAX_TX_TEXT_LINES * MAX_TX_TEXT_WIDTH);
    memcpy(lines[0], encoded, 11);
    memcpy(lines[1], encoded + 11, 11);
    memcpy(lines[2], encoded + 22, 12);
    return true;
}

/** Pixel width in the review font. A character not in the table counts as wider than a line. */
static unsigned int char_width_px(char c) {
    for (unsigned int i = 0; i < sizeof(CHARS_BY_WIDTH) / sizeof(CHARS_BY_WIDTH[0]); i++) {
        if (c != '\0' && strchr(CHARS_BY_WIDTH[i], c) != NULL) {
            return NARROWEST_CHAR_PX + i;
        }
    }
    return REVIEW_LINE_WIDTH_PX + 1;
}

/** A wider line loses characters: Nano X and S Plus elide its middle, Nano S drops its end. */
static bool line_fits(const char *line) {
    unsigned int width = 0;
    for (; *line != '\0'; line++) {
        width += char_width_px(*line);
    }
    return width <= REVIEW_LINE_WIDTH_PX;
}

/** Refuses an address with a line too wide to show whole. */
static unsigned short render_reviewed_address(const uint8_t program_hash[CODE_HASH_LEN],
                                              char lines[MAX_TX_TEXT_LINES][MAX_TX_TEXT_WIDTH]) {
    if (!render_address(program_hash, lines)) {
        return SW_TX_ADDRESS_TYPE;
    }
    for (unsigned int k = 0; k < MAX_TX_TEXT_LINES; k++) {
        if (!line_fits(lines[k])) {
            return SW_TX_ADDRESS_TOO_WIDE;
        }
    }
    return SW_OK;
}

/** Sela as ELA with all eight decimals, unpadded, such as "0.00000001". An amount too wide for
 * one line is refused, never cut. */
static unsigned short format_amount(uint64_t sela, char *out, size_t out_len) {
    char whole_digits[20];
    unsigned int whole_len = 0;
    uint64_t whole = sela / SELA_PER_ELA;
    const uint64_t fraction_sela = sela % SELA_PER_ELA;
    uint32_t fraction = (uint32_t) fraction_sela;

    do {
        whole_digits[whole_len++] = (char) ('0' + (whole % 10));
        whole /= 10;
    } while (whole != 0);

    if (whole_len + 1 + ELA_DECIMALS + 1 > out_len) {
        return SW_TX_AMOUNT;
    }

    unsigned int pos = 0;
    while (whole_len > 0) {
        out[pos++] = whole_digits[--whole_len];
    }
    out[pos++] = '.';
    for (int i = ELA_DECIMALS - 1; i >= 0; i--) {
        out[pos + i] = (char) ('0' + (fraction % 10));
        fraction /= 10;
    }
    pos += ELA_DECIMALS;
    out[pos] = '\0';

    if (!line_fits(out)) {
        return SW_TX_AMOUNT;
    }
    return SW_OK;
}

static unsigned short next_byte(uint8_t *out) {
    if (raw_tx_ix >= body_end) {
        return SW_TX_TRUNCATED;
    }
    *out = raw_tx[raw_tx_ix++];
    return SW_OK;
}

/** Bound checked by subtraction before the cursor moves, so it cannot overflow. */
static unsigned short read_bytes(uint8_t *out, unsigned int count) {
    if (count > body_end - raw_tx_ix) {
        return SW_TX_TRUNCATED;
    }
    memcpy(out, raw_tx + raw_tx_ix, count);
    raw_tx_ix += count;
    return SW_OK;
}

static unsigned short skip_bytes(unsigned int count) {
    if (count > body_end - raw_tx_ix) {
        return SW_TX_TRUNCATED;
    }
    raw_tx_ix += count;
    return SW_OK;
}

static unsigned short read_u32_le(uint32_t *out) {
    uint8_t b[4];
    CHECK_SW(read_bytes(b, sizeof(b)));
    *out = (uint32_t) b[0] | ((uint32_t) b[1] << 8) | ((uint32_t) b[2] << 16) |
           ((uint32_t) b[3] << 24);
    return SW_OK;
}

static unsigned short read_u64_le(uint64_t *out) {
    uint32_t low;
    uint32_t high;
    CHECK_SW(read_u32_le(&low));
    CHECK_SW(read_u32_le(&high));
    *out = (uint64_t) low | ((uint64_t) high << 32);
    return SW_OK;
}

/** Single-byte form only: 253 or more inputs or outputs cannot fit the buffer, and the wallet
 * never writes that many attributes. */
static unsigned short next_count(uint8_t *out) {
    CHECK_SW(next_byte(out));
    if (*out > MAX_SINGLE_BYTE_COUNT) {
        return SW_TX_VARINT_TOO_LARGE;
    }
    return SW_OK;
}

/** Attribute data length, one or three bytes. As on the chain, the three-byte form must hold
 * 253 or more, so each length has one encoding. */
static unsigned short next_data_length(unsigned int *out) {
    uint8_t first;
    CHECK_SW(next_byte(&first));
    if (first <= MAX_SINGLE_BYTE_COUNT) {
        *out = first;
        return SW_OK;
    }
    if (first != VARINT_16_BIT) {
        return SW_TX_VARINT_TOO_LARGE;
    }
    uint8_t b[2];
    CHECK_SW(read_bytes(b, sizeof(b)));
    *out = (unsigned int) b[0] | ((unsigned int) b[1] << 8);
    if (*out < VARINT_16_BIT) {
        return SW_TX_VARINT_TOO_LARGE;
    }
    return SW_OK;
}

/** Wallet vote amount text: digits, then optionally a point and one to eight decimals. */
static bool is_vote_amount(const char *text) {
    unsigned int digits = 0;
    unsigned int decimals = 0;
    bool point = false;
    for (; *text != '\0'; text++) {
        if (*text == '.' && !point && digits > 0) {
            point = true;
        } else if (*text >= '0' && *text <= '9') {
            if (point) {
                decimals++;
            } else {
                digits++;
            }
        } else {
            return false;
        }
    }
    return digits > 0 && (!point || (decimals > 0 && decimals <= MAX_ELA_DECIMALS));
}

static void to_hex(const uint8_t *in, unsigned int count, char *out) {
    for (unsigned int i = 0; i < count; i++) {
        out[2 * i] = HEX_DIGITS[in[i] >> 4];
        out[2 * i + 1] = HEX_DIGITS[in[i] & 0x0F];
    }
    out[2 * count] = '\0';
}

static void render_poll_id_part(unsigned int screen, const char *title, const char *hex) {
    set_title(screen, title);
    memcpy(tx_desc[screen][0], hex, 11);
    memcpy(tx_desc[screen][1], hex + 11, 11);
    memcpy(tx_desc[screen][2], hex + 22, 10);
}

static bool is_memo_char(uint8_t c) {
    return c >= FIRST_PRINTABLE_CHAR && c <= LAST_PRINTABLE_CHAR;
}

/** Text wrapped onto tx_desc lines from first_screen. break_chars and break_width measure the
 * line up to its last break, 0 while it has none. */
typedef struct {
    unsigned int first_screen;
    unsigned int max_lines;
    unsigned int line;
    unsigned int chars;
    unsigned int width;
    unsigned int break_chars;
    unsigned int break_width;
} text_wrap_t;

static char *wrap_line(const text_wrap_t *wrap, unsigned int k) {
    return tx_desc[wrap->first_screen + k / MAX_TX_TEXT_LINES][k % MAX_TX_TEXT_LINES];
}

/** Checks characters and pixels, as for amounts and addresses, so no line is cut on screen. */
static bool wrap_fits(const text_wrap_t *wrap, unsigned int c_width) {
    return wrap->chars < WRAP_LINE_CHARS && wrap->width + c_width <= REVIEW_LINE_WIDTH_PX;
}

/** False once the text has used all its lines. */
static bool wrap_next_line(text_wrap_t *wrap) {
    wrap->line++;
    wrap->chars = 0;
    wrap->width = 0;
    wrap->break_chars = 0;
    wrap->break_width = 0;
    return wrap->line < wrap->max_lines;
}

/** A full line ends after its last break and the rest moves down, so words stay whole; a line
 * with no break ends where full. Characters are never added or dropped. */
static bool wrap_char(text_wrap_t *wrap, char c, const char *breaks) {
    unsigned int c_width = char_width_px(c);
    if (!wrap_fits(wrap, c_width)) {
        unsigned int kept = wrap->break_chars != 0 ? wrap->break_chars : wrap->chars;
        unsigned int carried = wrap->chars - kept;
        unsigned int carried_width = wrap->break_chars != 0 ? wrap->width - wrap->break_width : 0;
        char *full = wrap_line(wrap, wrap->line);
        if (!wrap_next_line(wrap)) {
            return false;
        }
        memcpy(wrap_line(wrap, wrap->line), full + kept, carried);
        memset(full + kept, 0, carried);
        wrap->chars = carried;
        wrap->width = carried_width;
        // still no room: the carried word keeps this line and c starts the next
        if (!wrap_fits(wrap, c_width) && !wrap_next_line(wrap)) {
            return false;
        }
    }
    wrap_line(wrap, wrap->line)[wrap->chars++] = c;
    wrap->width += c_width;
    if (c != '\0' && strchr(breaks, c) != NULL) {
        wrap->break_chars = wrap->chars;
        wrap->break_width = wrap->width;
    }
    return true;
}

/** Shows memo text byte for byte, as signed; empty, non-printable or too long text is refused. */
static unsigned short render_memo_text(unsigned int data_len, unsigned int *screens) {
    text_wrap_t wrap = {MEMO_FIRST_SCREEN, MAX_MEMO_SCREENS * MAX_TX_TEXT_LINES, 0, 0, 0, 0, 0};

    // the wallet leaves an empty memo out
    if (data_len == 0) {
        return SW_TX_MEMO;
    }
    for (unsigned int i = 0; i < data_len; i++) {
        uint8_t c;
        CHECK_SW(next_byte(&c));
        if (!is_memo_char(c) || !wrap_char(&wrap, (char) c, MEMO_BREAKS)) {
            return SW_TX_MEMO;
        }
    }

    *screens = wrap.line / MAX_TX_TEXT_LINES + 1;
    if (*screens == 1) {
        set_title(MEMO_FIRST_SCREEN, "Memo");
        return SW_OK;
    }
    // numbered so the user can tell how much memo is left
    for (unsigned int s = 0; s < *screens; s++) {
        char title[MAX_TX_TEXT_WIDTH];
        snprintf(title, sizeof(title), "Memo %d of %d", (int) (s + 1), (int) *screens);
        set_title(MEMO_FIRST_SCREEN + s, title);
    }
    return SW_OK;
}

/** A memo starting with the vote flag must match the wallet's vote layout exactly and is shown
 * as a vote; any other memo is shown as text. */
static unsigned short parse_memo(unsigned int data_len, unsigned int *screens, bool *is_vote) {
    if (data_len > body_end - raw_tx_ix) {
        return SW_TX_TRUNCATED;
    }
    if (data_len < POLL_VOTE_FLAG_LEN ||
        memcmp(raw_tx + raw_tx_ix, POLL_VOTE_FLAG, POLL_VOTE_FLAG_LEN) != 0) {
        return render_memo_text(data_len, screens);
    }
    if (data_len < POLL_VOTE_FIXED_LEN) {
        return SW_TX_POLL_VOTE;
    }

    uint8_t poll_id[POLL_ID_LEN];
    uint32_t choice;
    uint8_t amount_len;
    char amount[MAX_TX_TEXT_WIDTH];
    CHECK_SW(skip_bytes(POLL_VOTE_FLAG_LEN));
    CHECK_SW(read_bytes(poll_id, sizeof(poll_id)));
    CHECK_SW(read_u32_le(&choice));
    CHECK_SW(next_byte(&amount_len));
    if (data_len != POLL_VOTE_FIXED_LEN + amount_len || amount_len >= sizeof(amount)) {
        return SW_TX_POLL_VOTE;
    }
    CHECK_SW(read_bytes((uint8_t *) amount, amount_len));
    amount[amount_len] = '\0';
    // a NUL inside would hide the rest of what is signed
    if (choice > MAX_POLL_CHOICE_INDEX || strlen(amount) != amount_len || !is_vote_amount(amount)) {
        return SW_TX_POLL_VOTE;
    }
    // refused as a too-wide amount, not a bad vote, so the wallet does not suggest an update
    if (!line_fits(amount)) {
        return SW_TX_AMOUNT;
    }

    char choice_line[MAX_TX_TEXT_WIDTH];
    snprintf(choice_line, sizeof(choice_line), "Choice %d", (int) (choice + 1));
    set_title(POLL_VOTE_FIRST_SCREEN, "Poll vote");
    set_line(tx_desc[POLL_VOTE_FIRST_SCREEN][0], choice_line);
    set_line(tx_desc[POLL_VOTE_FIRST_SCREEN][1], amount);
    set_line(tx_desc[POLL_VOTE_FIRST_SCREEN][2], "ELA");

    char hex[2 * POLL_ID_LEN + 1];
    to_hex(poll_id, sizeof(poll_id), hex);
    render_poll_id_part(POLL_VOTE_FIRST_SCREEN + 1, "Poll id 1 of 2", hex);
    render_poll_id_part(POLL_VOTE_FIRST_SCREEN + 2, "Poll id 2 of 2", hex + POLL_ID_HEX_PER_SCREEN);
    *screens = POLL_VOTE_SCREENS;
    *is_vote = true;
    return SW_OK;
}

/** Names the signing key, not the coins' source: the device cannot see whose coins the inputs
 * spend, and the key may sign for a multisig. */
static unsigned short render_signer(unsigned int screen,
                                    const uint8_t signer_program_hash[CODE_HASH_LEN]) {
    set_title(screen, "Signing with");
    return render_reviewed_address(signer_program_hash, tx_desc[screen]);
}

/** Two screens per output: the amount, then the address. */
static unsigned short render_output(unsigned int screen,
                                    unsigned int index,
                                    unsigned int count,
                                    uint64_t sela,
                                    const uint8_t program_hash[CODE_HASH_LEN],
                                    bool returns_to_signer) {
    char title[MAX_TX_TEXT_WIDTH];

    snprintf(title, sizeof(title), "Output %d of %d", (int) (index + 1), (int) count);
    set_title(screen, title);
    set_line(tx_desc[screen][0], returns_to_signer ? "Back to you" : "Send");
    CHECK_SW(format_amount(sela, tx_desc[screen][1], MAX_TX_TEXT_WIDTH));
    set_line(tx_desc[screen][2], "ELA");

    set_title(screen + 1, returns_to_signer ? "Your address" : "Recipient");
    return render_reviewed_address(program_hash, tx_desc[screen + 1]);
}

/** The device cannot see input values, so it cannot know the fee. No number is shown: any
 * number here would read as the fee. */
static void render_fee_notice(unsigned int screen) {
    set_title(screen, "Network fee");
    set_line(tx_desc[screen][0], "Not checked by");
    set_line(tx_desc[screen][1], "this device.");
    set_line(tx_desc[screen][2], "Set by the wallet");
}

/** Complete parse or refuse: every body byte is understood and every output and memo shown.
 * Only the nonce, at most MAX_NONCE_LEN bytes, is signed unseen. */
unsigned short tx_parse_and_render(const uint8_t signer_program_hash[ELA_PROGRAM_HASH_LEN]) {
    uint8_t asset_id[ASSET_ID_LEN];
    uint8_t program_hash[CODE_HASH_LEN];
    unsigned int memo_screens = 0;
    bool memo_is_vote = false;

    if (raw_tx_len <= BIP44_BYTE_LENGTH || raw_tx_len > MAX_TX_RAW_LENGTH) {
        return SW_TX_TOO_SHORT;
    }
    body_end = raw_tx_len - BIP44_BYTE_LENGTH;
    raw_tx_ix = 0;
    max_scr_ix = 0;
    memset(tx_desc, 0, sizeof(tx_desc));
    memset(review_title, 0, sizeof(review_title));

    uint8_t version = 0;
    uint8_t type;
    CHECK_SW(next_byte(&type));
    if (type >= TX_VERSION_09) {
        if (type != TX_VERSION_09) {
            return SW_TX_UNSUPPORTED;
        }
        version = type;
        CHECK_SW(next_byte(&type));
    }
    if (type != TX_TYPE_TRANSFER_ASSET) {
        return SW_TX_UNSUPPORTED;
    }
    // a transfer's payload is empty; only version 0 is defined
    uint8_t payload_version;
    CHECK_SW(next_byte(&payload_version));
    if (payload_version != 0) {
        return SW_TX_UNSUPPORTED;
    }

    uint8_t attributes;
    unsigned int nonces = 0;
    unsigned int memos = 0;
    CHECK_SW(next_count(&attributes));
    for (unsigned int i = 0; i < attributes; i++) {
        uint8_t usage;
        CHECK_SW(next_byte(&usage));
        if (usage == ATTRIBUTE_NONCE) {
            nonces++;
        } else if (usage == ATTRIBUTE_MEMO) {
            memos++;
        } else {
            return SW_TX_ATTRIBUTE;
        }
        if (nonces > MAX_NONCES || memos > MAX_MEMOS) {
            return SW_TX_ATTRIBUTE;
        }
        unsigned int data_len;
        CHECK_SW(next_data_length(&data_len));
        if (usage == ATTRIBUTE_MEMO) {
            CHECK_SW(parse_memo(data_len, &memo_screens, &memo_is_vote));
        } else {
            if (data_len > MAX_NONCE_LEN) {
                return SW_TX_ATTRIBUTE;
            }
            CHECK_SW(skip_bytes(data_len));
        }
    }

    uint8_t inputs;
    CHECK_SW(next_count(&inputs));
    if (inputs == 0) {
        return SW_TX_NO_INPUTS;
    }
    for (unsigned int i = 0; i < inputs; i++) {
        CHECK_SW(skip_bytes(INPUT_LEN));
    }

    uint8_t outputs;
    CHECK_SW(next_count(&outputs));
    if (outputs == 0 || outputs > MAX_TX_OUTPUTS) {
        return SW_TX_OUTPUT_COUNT;
    }
    // the memo must leave room for every output and the fee notice
    if (MEMO_FIRST_SCREEN + memo_screens + SCREENS_PER_OUTPUT * outputs + FEE_NOTICE_SCREENS >
        MAX_TX_TEXT_SCREENS) {
        return memo_is_vote ? SW_TX_OUTPUT_COUNT : SW_TX_MEMO;
    }

    CHECK_SW(render_signer(SIGNER_SCREEN, signer_program_hash));
    unsigned int screen = MEMO_FIRST_SCREEN + memo_screens;

    for (unsigned int i = 0; i < outputs; i++) {
        CHECK_SW(read_bytes(asset_id, sizeof(asset_id)));
        if (memcmp(asset_id, ELA_ASSET_ID, sizeof(ELA_ASSET_ID)) != 0) {
            return SW_TX_ASSET;
        }
        uint64_t sela;
        CHECK_SW(read_u64_le(&sela));
        // the chain stores amounts as signed 64-bit values
        if ((sela >> 63) != 0) {
            return SW_TX_AMOUNT;
        }
        // a non-zero output lock can freeze the output, possibly for good
        uint32_t output_lock;
        CHECK_SW(read_u32_le(&output_lock));
        if (output_lock != 0) {
            return SW_TX_OUTPUT_LOCK;
        }
        CHECK_SW(read_bytes(program_hash, sizeof(program_hash)));
        if (program_hash[0] != PREFIX_STANDARD && program_hash[0] != PREFIX_MULTISIG) {
            return SW_TX_ADDRESS_TYPE;
        }
        if (version >= TX_VERSION_09) {
            uint8_t output_type;
            CHECK_SW(next_byte(&output_type));
            if (output_type != OUTPUT_TYPE_NONE) {
                return SW_TX_OUTPUT_TYPE;
            }
        }
        bool returns_to_signer =
            memcmp(program_hash, signer_program_hash, ELA_PROGRAM_HASH_LEN) == 0;
        CHECK_SW(render_output(screen, i, outputs, sela, program_hash, returns_to_signer));
        screen += SCREENS_PER_OUTPUT;
    }

    // the wallet always writes a lock time of 0; anything else delays the transfer
    uint32_t lock_time;
    CHECK_SW(read_u32_le(&lock_time));
    if (lock_time != 0) {
        return SW_TX_LOCK_TIME;
    }

    // leftover bytes would be signed unseen
    if (raw_tx_ix != body_end) {
        return SW_TX_TRAILING_BYTES;
    }

    render_fee_notice(screen++);
    max_scr_ix = screen;
    return SW_OK;
}

void display_no_public_key(void) {
    memset(current_public_key, 0, sizeof(current_public_key));
    set_line(current_public_key[0], NO_PUBLIC_KEY_0);
    set_line(current_public_key[1], NO_PUBLIC_KEY_1);
}

/** Lines are built apart and copied only once they fit: the account screen draws from them and
 * must never show an address the computer asked for. */
unsigned short display_address_to_check(const unsigned char *public_key) {
    uint8_t program_hash[ELA_PROGRAM_HASH_LEN];
    char lines[MAX_TX_TEXT_LINES][MAX_TX_TEXT_WIDTH];
    if (keys_program_hash(public_key, program_hash) != CX_OK) {
        return SW_CRYPTO_FAILED;
    }
    CHECK_SW(render_reviewed_address(program_hash, lines));
    memcpy(current_public_key, lines, sizeof(current_public_key));
    return SW_OK;
}

/** Wraps like memo text, breaking after a slash. The longest path the rule allows takes three
 * lines: 44'/2305'/, 2147483647'/1/, 2147483647. */
unsigned short display_path_to_check(const unsigned int path[ELA_PATH_LEN]) {
    text_wrap_t wrap = {ADDRESS_CHECK_PATH_SCREEN, MAX_TX_TEXT_LINES, 0, 0, 0, 0, 0};

    memset(tx_desc[ADDRESS_CHECK_PATH_SCREEN], 0, sizeof(tx_desc[ADDRESS_CHECK_PATH_SCREEN]));
    for (unsigned int i = 0; i < ELA_PATH_LEN; i++) {
        char part[PATH_PART_CHARS + 1];
        snprintf(part,
                 sizeof(part),
                 "%d%s%s",
                 (int) (path[i] & ~ELA_HARDENED),
                 (path[i] & ELA_HARDENED) != 0 ? "'" : "",
                 i + 1 < ELA_PATH_LEN ? "/" : "");
        for (const char *c = part; *c != '\0'; c++) {
            if (!wrap_char(&wrap, *c, PATH_BREAKS)) {
                return SW_BAD_PATH;
            }
        }
    }
    return SW_OK;
}

/** An address too wide to show whole is replaced by a message, never cut. */
bool display_public_key(const unsigned char *public_key) {
    uint8_t program_hash[ELA_PROGRAM_HASH_LEN];
    if (keys_program_hash(public_key, program_hash) != CX_OK) {
        display_no_public_key();
        return false;
    }
    unsigned short sw = render_reviewed_address(program_hash, current_public_key);
    if (sw == SW_TX_ADDRESS_TOO_WIDE) {
        memset(current_public_key, 0, sizeof(current_public_key));
        set_line(current_public_key[0], ADDRESS_TOO_WIDE_0);
        set_line(current_public_key[1], ADDRESS_TOO_WIDE_1);
        return false;
    }
    if (sw != SW_OK) {
        display_no_public_key();
        return false;
    }
    return true;
}
