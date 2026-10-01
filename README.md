# blue-app-elastos

The Elastos app for Ledger Nano S, Nano X and Nano S Plus. It gives a wallet the public keys of an
Elastos account, and signs plain ELA transfers on the Elastos main chain after the user has
reviewed every output on the device: each amount and address in full, which outputs come back as
change, the memo, either a poll vote or the text of a note shown whole, and a notice that the fee is
not checked by the device. A transaction with any output, amount, address, vote or memo text the
device cannot show in full is refused. One thing is signed without being shown, because it moves no
value: the nonce, which may hold at most 8 bytes (Essentials always writes the one byte "0").

The Elastos Essentials wallet reaches a Ledger only over Bluetooth, so today it works with the
Nano X. The Nano S and Nano S Plus have no Bluetooth; on those the app needs a wallet that connects
over USB.

Notes written in Essentials are shown on the device before signing. Essentials always sends two
outputs, the payment and the change, so on the Nano X any note of up to 54 characters of plain
ASCII (letters, digits, spaces and common punctuation) fits, ordinary sentences usually fit up to
about 100 characters, and 139 is the most that can. A longer note, or one with any other character,
such as an accented letter, an emoji or another script, is refused before anything is shown; send
it with a shorter plain note.

A wallet can read the keys of accounts 0' to 100', at address indexes 0 to 50,000, without a button
press, as Elastos Essentials does while pairing: the same limits as Ledger's Bitcoin app. The device
sends any other key only after the user has seen its path and address and approved them, so a
connected computer cannot list every account of the device unnoticed.

To check a receive address, choose the wallet's option to show it on the device, once the wallet
offers one: the device shows "Verify address", then the path of the address, such as
44'/2305'/0'/0/5 for the sixth receive address of the first account, then the address. Press the
right button to move on and the left one to go back. Check that the path is the account and
address you expect, and compare every character of the address with the one the wallet shows. If
they match, press both buttons on Approve; if not, press both buttons on Reject and do not use that
address. Elastos Essentials does not offer this yet.

- [APP_SPECIFICATION.md](APP_SPECIFICATION.md): the commands, status words, the transactions the
  app signs, and what the review shows.
- [tests/README.md](tests/README.md): the emulator tests and the host fuzzers.

## Build

With Ledger's app builder image, from this folder:

```bash
docker run --rm -v "$(pwd):/app" -w /app ghcr.io/ledgerhq/ledger-app-builder/ledger-app-builder-lite:latest sh -c 'make BOLOS_SDK=$NANOX_SDK'
```

Use `$NANOS_SDK` or `$NANOSP_SDK` for the other devices. The app is built in `build/nanox/bin`,
`build/nanos/bin` or, for Nano S Plus, `build/nanos2/bin`.

## Test

The tests in `tests/` are the supported way to exercise the app. The emulator tests drive the
built app on Nano X and Nano S Plus, screen by screen; the host tests run its parser and signing
code on a computer, Nano S included, since no emulator runs Nano S. Both run in CI.
[tests/README.md](tests/README.md) says what they check and how to run them.

## License

MIT, except `src/main.c`, the `Makefile` and five glyphs, which come from Ledger's sample
application and SDK and remain under the Apache License 2.0. See [LICENSE](LICENSE) and
[LICENSE-APACHE-2.0](LICENSE-APACHE-2.0).
