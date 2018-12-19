/*
 * MIT License, see root folder for full license.
 */
#include "elastos.h"
// #include "base-encoding.h"

/** MAX_TX_TEXT_WIDTH in blanks, used for clearing a line of text */
static const char TXT_BLANK[] = "                 \0";

/** a period, for displaying the decimal point. */
// static const char TXT_PERIOD[] = ".";

/** Label when a public key has not been set yet */
static const char NO_PUBLIC_KEY_0[] = "No Public Key";
static const char NO_PUBLIC_KEY_1[] = "Requested Yet";

/** the current version of the address field */
#define ADDRESS_VERSION 33

/** length of tx.output.script_hash */
#define SCRIPT_HASH_LEN 20

/** length of the checksum used to convert a tx.output.script_hash into an Address. */
#define SCRIPT_HASH_CHECKSUM_LEN 4

/** length of a tx.output Address, after Base58 encoding. +1 for zero padding. */
#define ADDRESS_BASE58_LEN 35

/** length of a tx.output Address before encoding, which is the length of <address_version>+<script_hash>+<checksum> */
#define ADDRESS_LEN (1 + SCRIPT_HASH_LEN + SCRIPT_HASH_CHECKSUM_LEN)

/** the length of a SHA256 hash */
#define SHA256_HASH_LEN 32

void display_no_public_key() {
	os_memmove(current_public_key[0], TXT_BLANK, sizeof(TXT_BLANK));
	os_memmove(current_public_key[1], TXT_BLANK, sizeof(TXT_BLANK));
	os_memmove(current_public_key[2], TXT_BLANK, sizeof(TXT_BLANK));
	os_memmove(current_public_key[0], NO_PUBLIC_KEY_0, sizeof(NO_PUBLIC_KEY_0));
	os_memmove(current_public_key[1], NO_PUBLIC_KEY_1, sizeof(NO_PUBLIC_KEY_1));
	publicKeyNeedsRefresh = 0;
}

// TODO: figure out why this doesnt work in its own file.
/** encodes in_length bytes from in into the given base, using the given alphabet. writes the converted bytes to out, stopping when it converts out_length bytes. */
static unsigned int encode_base_x(const char * alphabet, const unsigned int alphabet_len, const void * in, const unsigned int in_length, char * out,
		const unsigned int out_length) {
	char tmp[64];
	char buffer[128];
	unsigned char buffer_ix;
	unsigned char startAt;
	unsigned char zeroCount = 0;
	if (in_length > sizeof(tmp)) {
		hashTainted = 1;
		THROW(0x6D11);
	}
	os_memmove(tmp, in, in_length);
	while ((zeroCount < in_length) && (tmp[zeroCount] == 0)) {
		++zeroCount;
	}
	buffer_ix = 2 * in_length;
	if (buffer_ix > sizeof(buffer)) {
		hashTainted = 1;
		THROW(0x6D12);
	}

	startAt = zeroCount;
	while (startAt < in_length) {
		unsigned short remainder = 0;
		unsigned char divLoop;
		for (divLoop = startAt; divLoop < in_length; divLoop++) {
			unsigned short digit256 = (unsigned short) (tmp[divLoop] & 0xff);
			unsigned short tmpDiv = remainder * 256 + digit256;
			tmp[divLoop] = (unsigned char) (tmpDiv / alphabet_len);
			remainder = (tmpDiv % alphabet_len);
		}
		if (tmp[startAt] == 0) {
			++startAt;
		}
		buffer[--buffer_ix] = *(alphabet + remainder);
	}
	while ((buffer_ix < (2 * in_length)) && (buffer[buffer_ix] == *(alphabet + 0))) {
		++buffer_ix;
	}
	while (zeroCount-- > 0) {
		buffer[--buffer_ix] = *(alphabet + 0);
	}
	const unsigned int true_out_length = (2 * in_length) - buffer_ix;
	if (true_out_length > out_length) {
		THROW(0x6D14);
	}
	os_memmove(out, (buffer + buffer_ix), true_out_length);
	return true_out_length;
}

/** array of base58 alphabet letters */
static const char BASE_58_ALPHABET[] = {
	'1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'J', 'K', 'L', 'M', 'N', 'P', 'Q',
	'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
	'w', 'x', 'y', 'z'
};

/** encodes in_length bytes from in into base-58, writes the converted bytes to out, stopping when it converts out_length bytes.  */
static unsigned int encode_base_58(const void *in, const unsigned int in_len, char *out, const unsigned int out_len) {
	return encode_base_x(BASE_58_ALPHABET, sizeof(BASE_58_ALPHABET), in, in_len, out, out_len);
}
// TODO: figure out why this doesnt work in its own file.

void public_key_hash160(unsigned char * in, unsigned short inlen, unsigned char *out, unsigned short outlen) {
	union {
		cx_sha256_t shasha;
		cx_ripemd160_t riprip;
	} u;
	unsigned char buffer[32];

	cx_sha256_init(&u.shasha);
	cx_hash(&u.shasha.header, CX_LAST, in, inlen, buffer, sizeof(buffer));
	cx_ripemd160_init(&u.riprip);
	cx_hash(&u.riprip.header, CX_LAST, buffer, 32, out, outlen);
}

static void to_address(char * dest, unsigned int dest_len, const unsigned char * script_hash) {
	static cx_sha256_t address_hash;
	unsigned char address_hash_result_0[SHA256_HASH_LEN];
	unsigned char address_hash_result_1[SHA256_HASH_LEN];

	// concatenate the ADDRESS_VERSION and the address.
	unsigned char address[ADDRESS_LEN];
	address[0] = ADDRESS_VERSION;
	os_memmove(address + 1, script_hash, SCRIPT_HASH_LEN);

	// do a sha256 hash of the address twice.
	cx_sha256_init(&address_hash);
	cx_hash(&address_hash.header, CX_LAST, address, SCRIPT_HASH_LEN + 1, address_hash_result_0, sizeof(address_hash_result_0));
	cx_sha256_init(&address_hash);
	cx_hash(&address_hash.header, CX_LAST, address_hash_result_0, SHA256_HASH_LEN, address_hash_result_1, sizeof(address_hash_result_1));

	// add the first bytes of the hash as a checksum at the end of the address.
	os_memmove(address + 1 + SCRIPT_HASH_LEN, address_hash_result_1, SCRIPT_HASH_CHECKSUM_LEN);

	// encode the version + address + cehcksum in base58
	encode_base_58(address, ADDRESS_LEN, dest, dest_len);
}

void display_public_key(const unsigned char * public_key) {
	os_memmove(current_public_key[0], TXT_BLANK, sizeof(TXT_BLANK));
	os_memmove(current_public_key[1], TXT_BLANK, sizeof(TXT_BLANK));
	os_memmove(current_public_key[2], TXT_BLANK, sizeof(TXT_BLANK));


	unsigned char public_key_encoded[33];
	public_key_encoded[0] = ((public_key[64] & 1) ? 0x03 : 0x02);
	os_memmove(public_key_encoded + 1, public_key + 1, 32);

	unsigned char verification_script[35];
	verification_script[0] = 0x21;
	os_memmove(verification_script + 1, public_key_encoded, sizeof(public_key_encoded));
	verification_script[sizeof(verification_script) - 1] = 0xAC;

	unsigned char script_hash[SCRIPT_HASH_LEN];
	for (int i = 0; i < SCRIPT_HASH_LEN; i++) {
		script_hash[i] = 0x00;
	}

	public_key_hash160(verification_script, sizeof(verification_script), script_hash, sizeof(script_hash));
	unsigned char script_hash_rev[SCRIPT_HASH_LEN];
	for (int i = 0; i < SCRIPT_HASH_LEN; i++) {
		script_hash_rev[i] = script_hash[SCRIPT_HASH_LEN - (i + 1)];
	}

	char address_base58[ADDRESS_BASE58_LEN];
	for (int i = 0; i < ADDRESS_BASE58_LEN; i++) {
		address_base58[i] = '.';
	}
	unsigned int address_base58_len_0 = 11;
	unsigned int address_base58_len_1 = 11;
	unsigned int address_base58_len_2 = 12;
	char * address_base58_0 = address_base58;
	char * address_base58_1 = address_base58 + address_base58_len_0;
	char * address_base58_2 = address_base58 + address_base58_len_0 + address_base58_len_1;
	// to_address(address_base58, ADDRESS_BASE58_LEN, script_hash);

	os_memmove(current_public_key[0], address_base58_0, address_base58_len_0);
	os_memmove(current_public_key[1], address_base58_1, address_base58_len_1);
	os_memmove(current_public_key[2], address_base58_2, address_base58_len_2);
	publicKeyNeedsRefresh = 0;
}

/** parse the raw transaction in raw_tx and fill up the screens in tx_desc. */
void display_tx_desc() {
	unsigned int scr_ix = 0;
	//char temp_buffer[MAX_TX_TEXT_WIDTH];
	//unsigned int temp_buffer_len = 0;

	while(scr_ix < MAX_TX_TEXT_SCREENS) {
		os_memmove(tx_desc[scr_ix][0], TXT_BLANK, sizeof(TXT_BLANK));
		os_memmove(tx_desc[scr_ix][1], TXT_BLANK, sizeof(TXT_BLANK));
		os_memmove(tx_desc[scr_ix][2], TXT_BLANK, sizeof(TXT_BLANK));

		// TODO: parse the TX into screens.

		scr_ix++;
	}
}
