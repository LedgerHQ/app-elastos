/*
 * MIT License, see root folder for full license.
 */
#include "elastos.h"
#include "base-encoding.h"

/** version 9, where parsing changed */
#define VERSION9 9

/** length of tx.output.value */
#define VALUE_LEN 8

/** the position of the decimal point, 8 characters in from the right side */
#define DECIMAL_PLACE_OFFSET 8

/** length of the checksum used to convert a tx.output.script_hash into an Address. */
#define SCRIPT_HASH_CHECKSUM_LEN 4

/** MAX_TX_TEXT_WIDTH in blanks, used for clearing a line of text */
static const char const TXT_BLANK[] = "                 \0";

static const char const TXT_AMOUNT_ELA[] = "Amount ELA\0";

static const char const TXT_CHANGE_ELA[] = "Change ELA\0";

static const char const TXT_FEE_ELA[] = "Fee ELA\0";

/** text to display if an asset's base-10 encoded value is too low to display */
static const char const TXT_LOW_VALUE[] = "Low Value\0";

/** a period, for displaying the decimal point. */
static const char const TXT_PERIOD[] = ".";

/** Label when a public key has not been set yet */
static const char const NO_PUBLIC_KEY_0[] = "No Public Key";
static const char const NO_PUBLIC_KEY_1[] = "Requested Yet";

unsigned char address[ADDRESS_LEN];

void display_no_public_key() {
	os_memmove(current_public_key[0], TXT_BLANK, sizeof(TXT_BLANK));
	os_memmove(current_public_key[1], TXT_BLANK, sizeof(TXT_BLANK));
	os_memmove(current_public_key[2], TXT_BLANK, sizeof(TXT_BLANK));
	os_memmove(current_public_key[0], NO_PUBLIC_KEY_0, sizeof(NO_PUBLIC_KEY_0));
	os_memmove(current_public_key[1], NO_PUBLIC_KEY_1, sizeof(NO_PUBLIC_KEY_1));
	publicKeyNeedsRefresh = 0;
}

void public_key_hash160(unsigned char * in, unsigned short inlen, unsigned char *out, unsigned short outlen) {
	cx_sha256_t shasha;
	cx_ripemd160_t riprip;
	unsigned char buffer[SHA256_HASH_LEN];
	cx_sha256_init(&shasha);
	cx_hash(&shasha.header, CX_LAST, in, inlen, buffer, sizeof(buffer));
	cx_ripemd160_init(&riprip);
	cx_hash(&riprip.header, CX_LAST, buffer, sizeof(buffer), out, outlen);
}

static void to_address(char * dest, unsigned int dest_len, const unsigned char * src, unsigned int src_len) {
	unsigned char address_hash_result_0[SHA256_HASH_LEN];
	unsigned char address_hash_result_1[SHA256_HASH_LEN];

	os_memmove(address, src, src_len);

	cx_hash_sha256(src, src_len,address_hash_result_0,SHA256_HASH_LEN);
	cx_hash_sha256(address_hash_result_0,SHA256_HASH_LEN,address_hash_result_1,SHA256_HASH_LEN);

	// add the first bytes of the hash as a checksum at the end of the address.
	os_memmove(address + src_len, address_hash_result_1, CODE_HASH_CHECKSUM_LEN);

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

	unsigned char verification_script[35];
	verification_script[0] = 33;
	os_memmove(verification_script + 1, public_key_encoded, sizeof(public_key_encoded));
	verification_script[sizeof(verification_script) - 1] = 0xAC;

	unsigned char script_hash[SCRIPT_HASH_LEN];
	for (int i = 0; i < SCRIPT_HASH_LEN; i++) {
		script_hash[i] = 0x00;
	}

	public_key_hash160(verification_script, sizeof(verification_script), script_hash, sizeof(script_hash));

	unsigned char code_hash[CODE_HASH_LEN];
	code_hash[0] = 33;
	os_memmove(code_hash + 1, script_hash, sizeof(script_hash));

	char address_base58[ADDRESS_BASE58_LEN+1];
	for (int i = 0; i < ADDRESS_BASE58_LEN; i++) {
		address_base58[i] = '.';
	}
	address_base58[ADDRESS_BASE58_LEN] = 0x00;

	to_address(address_base58, ADDRESS_BASE58_LEN, code_hash, sizeof(code_hash));

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

/** skips the given number of bytes in the raw_tx buffer. If this goes off the end of the buffer, throw an error. */
static void skip_raw_tx(unsigned int tx_skip) {
	raw_tx_ix += tx_skip;
	if (raw_tx_ix >= raw_tx_len) {
		hashTainted = 1;
		THROW(0x6D03);
	}
}

/** returns the next byte in raw_tx and increments raw_tx_ix. If this would increment raw_tx_ix over the end of the buffer, throw an error. */
static unsigned char next_raw_tx() {
	if (raw_tx_ix < raw_tx_len) {
		unsigned char retval = raw_tx[raw_tx_ix];
		raw_tx_ix += 1;
		return retval;
	} else {
		hashTainted = 1;
		THROW(0x6D05);
		return 0;
	}
}

/** returns the number of bytes to read for the next varbytes array.
 *  Currently throws an error if the encoded value should be over 253,
 *   which should never happen in this use case of a varbyte array
 */
static unsigned char next_raw_tx_varbytes_num() {
	unsigned char num = next_raw_tx();
	switch (num) {
	case 0xFD:
		hashTainted = 1;
		THROW(0x6DFD);
		break;
	case 0xFE:
		hashTainted = 1;
		THROW(0x6DFE);
		break;
	case 0xFF:
		hashTainted = 1;
		THROW(0x6DFF);
		break;
	default:
		break;
	}
	return num;
}

/** fills the array in arr with the given number of bytes from raw_tx. */
static void next_raw_tx_arr(unsigned char * arr, unsigned int length) {
	for (unsigned int ix = 0; ix < length; ix++) {
		*(arr + ix) = next_raw_tx();
	}
}
/** converts a value to base10 with a decimal point at DECIMAL_PLACE_OFFSET, which should be 100,000,000 or 100 million, thus the suffix 100m */
static void to_base10_100m(char * dest, const unsigned char * value, const unsigned int dest_len) {
	// reverse the array
	unsigned char reverse_value[VALUE_LEN];
	for (int ix = 0; ix < VALUE_LEN; ix++) {
		reverse_value[ix] = *(value + ((VALUE_LEN - 1) - ix));
	}

	// encode in base10
	char base10_buffer[MAX_TX_TEXT_WIDTH];
	unsigned int buffer_len = encode_base_10(reverse_value, VALUE_LEN, base10_buffer, MAX_TX_TEXT_WIDTH, false);

	// place the decimal place.
	unsigned int dec_place_ix = buffer_len - DECIMAL_PLACE_OFFSET;
	if (buffer_len < DECIMAL_PLACE_OFFSET) {
		os_memmove(dest, TXT_LOW_VALUE, sizeof(TXT_LOW_VALUE));
	} else {
		os_memmove(dest + dec_place_ix, TXT_PERIOD, sizeof(TXT_PERIOD));
		os_memmove(dest, base10_buffer, dec_place_ix);
		os_memmove(dest + dec_place_ix + 1, base10_buffer + dec_place_ix, buffer_len - dec_place_ix);
	}
}

/** array of capital letter hex values */
static const char const HEX_CAP[] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F', };

/** returns the minimum of two ints. */
static unsigned int min(unsigned int i0, unsigned int i1) {
	if (i0 < i1) {
		return i0;
	} else {
		return i1;
	}
}

/** converts a byte array in src to a hex array in dest, using only dest_len bytes of dest before stopping. */
static void to_hex(char * dest, const unsigned char * src, const unsigned int dest_len) {
	for (unsigned int src_ix = 0, dest_ix = 0; dest_ix < dest_len; src_ix++, dest_ix += 2) {
		unsigned char src_c = *(src + src_ix);
		unsigned char nibble0 = (src_c >> 4) & 0xF;
		unsigned char nibble1 = src_c & 0xF;

		*(dest + dest_ix + 0) = HEX_CAP[nibble0];
		*(dest + dest_ix + 1) = HEX_CAP[nibble1];
	}
}

/** parse the raw transaction in raw_tx and fill up the screens in tx_desc. */
/** only parse out the send-to address and amount from the txos, skip the rest.  */
void display_tx_desc() {
	unsigned int scr_ix = 0;

	char hex_buffer[MAX_TX_TEXT_WIDTH];
	unsigned int hex_buffer_len = 0;

	// read TxType;
	unsigned char tx_type_or_version = next_raw_tx();
	// unsigned char tx_type;
	// unsigned char tx_version = 0;

	if (tx_type_or_version >= VERSION9) {
		// tx_version = tx_type_or_version;
		// tx_type =
        next_raw_tx();
	} else {
		// tx_type = tx_type_or_version;
	}

	// read payload version.
	// unsigned char payload_version =
    next_raw_tx();

// read number of attributes
	unsigned char num_attr = next_raw_tx_varbytes_num();

	for(int attr_ix = 0; attr_ix < num_attr; attr_ix++ ) {
		// attribute usage
		// unsigned char usage =
		next_raw_tx();

		// skip the attribute data since we don't display it.
		unsigned char attr_data_len = next_raw_tx_varbytes_num();
		skip_raw_tx(attr_data_len);
	}

	// read number of inputs
	unsigned char num_inputs = next_raw_tx_varbytes_num();

	for(int input_ix = 0; input_ix < num_inputs; input_ix++ ) {
		// skip tx id, since we don't display it.
		skip_raw_tx(32);

		// skip referer tx output index, since we don't display it.
		skip_raw_tx(2);

		// skip sequence, since we don't display it.
		skip_raw_tx(4);
	}

	// read number of outputs
	unsigned char num_outputs = next_raw_tx_varbytes_num();


	unsigned char script_hash[SCRIPT_HASH_LEN];
	// unsigned int script_hash_len0 = 6;
	// unsigned int script_hash_len1 = 7;
	// unsigned int script_hash_len2 = 7;
	// unsigned char * script_hash0 = script_hash;
	// unsigned char * script_hash1 = script_hash + script_hash_len0;
	// unsigned char * script_hash2 = script_hash + script_hash_len0 + script_hash_len1;

	char address_base58[ADDRESS_BASE58_LEN];
	unsigned int address_base58_len_0 = 11;
	unsigned int address_base58_len_1 = 11;
	unsigned int address_base58_len_2 = 12;
	char * address_base58_0 = address_base58;
	char * address_base58_1 = address_base58 + address_base58_len_0;
	char * address_base58_2 = address_base58 + address_base58_len_0 + address_base58_len_1;

	unsigned char value[VALUE_LEN];
	unsigned char program_hash[CODE_HASH_LEN];
	unsigned char output_type;
	unsigned char output_payload_contents_len;
	unsigned char output_payload_contents_ix;
	unsigned char output_payload_candidates_len;
	unsigned char output_payload_candidates_ix;
	unsigned char output_payload_candidate_len;

	for(int output_ix = 0; output_ix < num_outputs; output_ix++ ) {
		// skip asset id, since we don't display it.
		skip_raw_tx(32);

		// read the value.
		next_raw_tx_arr(value,sizeof(value));

		// display the value
		if (scr_ix < MAX_TX_TEXT_SCREENS) {
			os_memset(tx_desc[scr_ix], '\0', CURR_TX_DESC_LEN);
			// os_memmove(tx_desc[scr_ix][0], TXT_ASSET_ELA, sizeof(TXT_ASSET_ELA));
			if(output_ix == 0) {
				os_memmove(tx_desc[scr_ix][0], TXT_AMOUNT_ELA, sizeof(TXT_AMOUNT_ELA));
			}
			if(output_ix == 1) {
				os_memmove(tx_desc[scr_ix][0], TXT_CHANGE_ELA, sizeof(TXT_CHANGE_ELA));
			}
			if(output_ix == 2) {
				os_memmove(tx_desc[scr_ix][0], TXT_FEE_ELA, sizeof(TXT_FEE_ELA));
			}

			to_base10_100m(tx_desc[scr_ix][1], value, MAX_TX_TEXT_WIDTH);
			os_memmove(tx_desc[scr_ix][2], TXT_BLANK, sizeof(TXT_BLANK));

			unsigned char found_nonzero = 0;
			for(int zero_ix = 0; (zero_ix < MAX_TX_TEXT_WIDTH-2) && (found_nonzero == 0); zero_ix++) {
				if(tx_desc[scr_ix][1][zero_ix] == '0') {
					tx_desc[scr_ix][1][zero_ix] = ' ';
				} else {
					found_nonzero = 1;
				}
			}

			scr_ix++;
		}

		// skip the output lock.
		skip_raw_tx(4);

		next_raw_tx_arr(program_hash,sizeof(program_hash));

		os_memmove(script_hash, program_hash, SCRIPT_HASH_LEN);
		to_address(address_base58, ADDRESS_BASE58_LEN, program_hash, CODE_HASH_LEN);

		if (scr_ix < MAX_TX_TEXT_SCREENS) {
			os_memset(tx_desc[scr_ix], '\0', CURR_TX_DESC_LEN);
			os_memmove(tx_desc[scr_ix][0], address_base58_0, address_base58_len_0);
			os_memmove(tx_desc[scr_ix][1], address_base58_1, address_base58_len_1);
			os_memmove(tx_desc[scr_ix][2], address_base58_2, address_base58_len_2);

			scr_ix++;
		}

		if (tx_type_or_version >= VERSION9) {
			output_type = next_raw_tx();
			if (output_type == 1) {
				// Output.Payload.Version = smartEncodedTx.readUInt8();
				next_raw_tx();

				// const ContentsLen = readVarUint(smartEncodedTx);
				output_payload_contents_len = next_raw_tx_varbytes_num();

				for(output_payload_contents_ix = 0;
				    output_payload_contents_ix < output_payload_contents_len;
				    output_payload_contents_ix++) {
					// Content.Votetype = smartEncodedTx.readUInt8();
					next_raw_tx();

					// const CandidatesLen = readVarUint(smartEncodedTx);
					output_payload_candidates_len = next_raw_tx_varbytes_num();

					for(output_payload_candidates_ix = 0;
					    output_payload_candidates_ix < output_payload_candidates_len;
					    output_payload_candidates_ix++) {

						output_payload_candidate_len = next_raw_tx_varbytes_num();
						skip_raw_tx(output_payload_candidate_len);
					}
				}
			}
		}
	}

	// skip the lock time.
	skip_raw_tx(4);

	max_scr_ix = scr_ix;

	while(scr_ix < MAX_TX_TEXT_SCREENS) {
		os_memmove(tx_desc[scr_ix][0], TXT_BLANK, sizeof(TXT_BLANK));
		os_memmove(tx_desc[scr_ix][1], TXT_BLANK, sizeof(TXT_BLANK));
		os_memmove(tx_desc[scr_ix][2], TXT_BLANK, sizeof(TXT_BLANK));

		scr_ix++;
	}
}
