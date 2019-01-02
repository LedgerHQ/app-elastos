/*
 * MIT License, see root folder for full license.
 */
#include "elastos.h"
#include "base-encoding.h"

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

unsigned char verification_script[35];

void display_no_public_key() {
	os_memmove(current_public_key[0], TXT_BLANK, sizeof(TXT_BLANK));
	os_memmove(current_public_key[1], TXT_BLANK, sizeof(TXT_BLANK));
	os_memmove(current_public_key[2], TXT_BLANK, sizeof(TXT_BLANK));
	os_memmove(current_public_key[0], NO_PUBLIC_KEY_0, sizeof(NO_PUBLIC_KEY_0));
	os_memmove(current_public_key[1], NO_PUBLIC_KEY_1, sizeof(NO_PUBLIC_KEY_1));
	publicKeyNeedsRefresh = 0;
}

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
	unsigned char address_hash_result_0[SHA256_HASH_LEN];
	unsigned char address_hash_result_1[SHA256_HASH_LEN];

	// concatenate the ADDRESS_VERSION and the address.
	unsigned char address[ADDRESS_LEN];
	address[0] = ADDRESS_VERSION;
	os_memmove(address + 1, script_hash, SCRIPT_HASH_LEN);

	cx_hash_sha256(script_hash, SCRIPT_HASH_LEN,address_hash_result_0,SHA256_HASH_LEN);
	cx_hash_sha256(address_hash_result_0,SHA256_HASH_LEN,address_hash_result_1,SHA256_HASH_LEN);

	// add the first bytes of the hash as a checksum at the end of the address.
	os_memmove(address + 1 + SCRIPT_HASH_LEN, address_hash_result_1, SCRIPT_HASH_CHECKSUM_LEN);

	// encode the version + address + cehcksum in base58
	encode_base_58(address, ADDRESS_LEN, dest, dest_len, false);
}

void display_public_key(const unsigned char * public_key) {
	os_memmove(current_public_key[0], TXT_BLANK, sizeof(TXT_BLANK));
	os_memmove(current_public_key[1], TXT_BLANK, sizeof(TXT_BLANK));
	os_memmove(current_public_key[2], TXT_BLANK, sizeof(TXT_BLANK));


	unsigned char public_key_encoded[33];
	public_key_encoded[0] = ((public_key[64] & 1) ? 0x03 : 0x02);
	os_memmove(public_key_encoded + 1, public_key + 1, 32);

	verification_script[0] = 33;
	os_memmove(verification_script + 1, public_key_encoded, sizeof(public_key_encoded));
	verification_script[sizeof(verification_script) - 1] = 0xAC;

	unsigned char script_hash[SCRIPT_HASH_LEN];
	for (int i = 0; i < SCRIPT_HASH_LEN; i++) {
		script_hash[i] = 0x00;
	}

	public_key_hash160(verification_script, sizeof(verification_script), script_hash, sizeof(script_hash));

	char address_base58[ADDRESS_BASE58_LEN+1];
	for (int i = 0; i < ADDRESS_BASE58_LEN; i++) {
		address_base58[i] = '.';
	}
	address_base58[ADDRESS_BASE58_LEN] = 0x00;

	for (int i = 0; i < SCRIPT_HASH_LEN; i++) {
		script_hash[i] = 0xFF;
	}

	to_address(address_base58, ADDRESS_BASE58_LEN, script_hash);

	unsigned int address_base58_len_0 = 11;
	unsigned int address_base58_len_1 = 11;
	unsigned int address_base58_len_2 = 12;
	char * address_base58_0 = address_base58;
	char * address_base58_1 = address_base58 + address_base58_len_0;
	char * address_base58_2 = address_base58 + address_base58_len_0 + address_base58_len_1;

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
