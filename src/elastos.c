/*
 * MIT License, see root folder for full license.
 */
#include "elastos.h"

/** MAX_TX_TEXT_WIDTH in blanks, used for clearing a line of text */
static const char TXT_BLANK[] = "                 ";

/** a period, for displaying the decimal point. */
static const char TXT_PERIOD[] = ".";

/** Label when a public key has not been set yet */
static const char NO_PUBLIC_KEY_0[] = "No Public Key";
static const char NO_PUBLIC_KEY_1[] = "Requested Yet";

void display_no_public_key() {
	os_memmove(current_public_key[0], TXT_BLANK, sizeof(TXT_BLANK));
	os_memmove(current_public_key[1], TXT_BLANK, sizeof(TXT_BLANK));
	os_memmove(current_public_key[2], TXT_BLANK, sizeof(TXT_BLANK));
	os_memmove(current_public_key[0], NO_PUBLIC_KEY_0, sizeof(NO_PUBLIC_KEY_0));
	os_memmove(current_public_key[1], NO_PUBLIC_KEY_1, sizeof(NO_PUBLIC_KEY_1));
	publicKeyNeedsRefresh = 0;
}



void display_public_key(const unsigned char * public_key) {
	os_memmove(current_public_key[0], TXT_BLANK, sizeof(TXT_BLANK));
	os_memmove(current_public_key[1], TXT_BLANK, sizeof(TXT_BLANK));
	os_memmove(current_public_key[2], TXT_BLANK, sizeof(TXT_BLANK));

	// TODO: display the public key.
	publicKeyNeedsRefresh = 0;
}

/** parse the raw transaction in raw_tx and fill up the screens in tx_desc. */
unsigned char display_tx_desc() {
	unsigned int scr_ix = 0;
	char temp_buffer[MAX_TX_TEXT_WIDTH];
	unsigned int temp_buffer_len = 0;

	while(scr_ix < MAX_TX_TEXT_SCREENS) {
		os_memmove(tx_desc[scr_ix][0], TXT_BLANK, sizeof(TXT_BLANK));
		os_memmove(tx_desc[scr_ix][1], TXT_BLANK, sizeof(TXT_BLANK));
		os_memmove(tx_desc[scr_ix][2], TXT_BLANK, sizeof(TXT_BLANK));

		// TODO: parse the TX into screens.

		scr_ix++;
	}
}
