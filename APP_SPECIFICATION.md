# Technical specification

## About

This document describes the APDU interface of the Elastos app and the transactions it signs.

The app:

- returns the public key for an Elastos derivation path at once, without asking the user (P1
  `00`), but only for accounts `0'` to `100'` and indexes up to 50,000, the limits of Ledger's
  Bitcoin app; such a request for any other path the path rule allows is refused with `6D63` and
  shows nothing;
- when asked (P1 `01`), first shows the path and its address on the device so the user can check
  them, and sends the key only once the user approves; this is the only way to read the key of a
  path outside that range, so a wallet refused with `6D63` must ask again with P1 `01`;
- signs a plain ELA transfer on the Elastos main chain, after the user has reviewed every output
  on the device.

It runs on Nano S, Nano X and Nano S Plus, over USB, and over Bluetooth on Nano X. Keys are on
the P-256 curve (secp256r1), under `44'/2305'`.

## Derivation paths

Every command carries a path of exactly five components, each a 4-byte big-endian number:
`44'/2305'/account'/change/index`, with a hardened account, `change` 0 or 1, and a non-hardened
index. Any other path is refused with `6D58`. A key request answered without asking the user (GET
PUBLIC KEY with P1 `00`) is answered for only part of the paths this rule allows; for the others it
is refused with `6D63`, showing nothing, and the key is read with P1 `01` instead: see below.

## APDUs

All commands use class `80`.

### GET PUBLIC KEY

Returns the public key for a path. With P1 `00` the reply comes at once, without asking the user,
but only for an account from `0'` to `100'` and an index from 0 to 50,000. These are the two
numbers Ledger's Bitcoin app uses, with the same comparison: it exports a key without showing it
only for an account up to `100'`, and gives the addresses of a standard wallet only up to index
50,000. The Elastos Essentials wallet reads several keys in a row while pairing, all of them
`44'/2305'/0'/0/i`, and sends only this value. Any other path the rule above allows is refused
with `6D63`, so a computer cannot read the keys of every account and address without the user
seeing it. With P1 `01` the device first
shows the path and its address, for any path the rule above allows (see The address check, below),
and the reply waits for the user, so a user can check a receive address on the device. This is the
only way to read a key outside the range of P1 `00`.

| CLA | INS | P1 | P2 | Lc | Data |
| --- | --- | --- | --- | --- | --- |
| 80 | 04 | `00`: reply at once (account up to `100'`, index up to 50,000), `01`: show the path and the address first | 00 | ignored | the 20-byte path |

The wallet sends `Lc` = `00` followed by the 20 path bytes, so the app checks the number of bytes
received rather than `Lc`: exactly 20 path bytes, or `6D09` if fewer arrive and `6700` if more.

Replies:

- P1 `00`: the 65-byte uncompressed public key (`04`, X, Y), then `9000`.
- P1 `01`, approved: the same 65 bytes, then `9000`. Rejected: `6985`.
- Refused at once, with nothing shown: first `6A86` for any other P1, or a P2 other than `00`;
  then `6D09` or `6700` for the path length; `6D58` for a path outside the rule above; with P1
  `00`, `6D63` for an account above `100'` or an index above 50,000, before any key is
  derived; and with P1 `01`, `6D60` for an address with a line too wide to show whole.

After an approved check, a wallet should make sure the key in the reply is the one it expects for
that path, the key behind the address it shows the user, and treat any other reply as a failed
check. Versions before the address check ignore P1: they answer P1 `01` at once with the key and
show nothing, and answer P1 `00` for any account and index. So a wallet must know the app supports
the check before it tells the user an address was checked: by the app's version (1.2.0 and later
have the check; 1.1.5 and earlier do not), or by sending P2 `01`, which this app refuses with
`6A86` and older versions answer with the key. While the check waits for the user, new commands
are turned away: see Waiting for the user, below.

### SIGN

Streams a transaction and its path, shows the transaction, and signs it if the user approves.

| CLA | INS | P1 | P2 | Lc | Data |
| --- | --- | --- | --- | --- | --- |
| 80 | 02 | `00`: more parts follow, `80`: last part | 00 | length of Data | the next part of the payload |

The payload is the unsigned transaction body followed by the 20-byte path, cut into parts of at
most 255 bytes. The whole payload is at most 1024 bytes. `Lc` must equal the number of data bytes
received.

- Each part with P1 `00` is answered `9000`.
- The part with P1 `80` completes the payload. If the transaction can be shown in full, the review
  starts and the reply waits for the user; otherwise it is refused at once with a status word below.
- Approved: the DER-encoded ECDSA signature, and nothing else, then `9000`. The signature is over
  SHA-256 of the transaction body, with deterministic nonces (RFC 6979) and a low S.
- Rejected: `6985`.

A key request, and any command the app refuses, ends any transaction still being received. While the review waits for the user, new
commands are turned away: see Waiting for the user, below.

### EXIT

| CLA | INS | P1 | P2 | Lc |
| --- | --- | --- | --- | --- |
| 80 | FF | ignored | ignored | ignored |

The app ends any signing session and closes. There is no reply.

## Waiting for the user

A review (SIGN) and an address check (GET PUBLIC KEY with P1 `01`) wait for the user in the same
way. While one waits, a new command of any kind never reaches the app, so the screen on display
stays until the user answers it on the device:

- on Nano X and Nano S Plus the SDK answers the new command at once with `6901`;
- on Nano S the SDK drops it without an answer, and the reply that was waiting (the signature, the
  public key, or `6985`) arrives later as the answer to it. A wallet should accept a key reply only
  if it is `04` and 64 bytes followed by `9000`, and a signature reply only if it is valid DER.
  Even so, a key request sent during an address check can be answered with the key of the address
  being checked, so a wallet should send nothing else while a review or an address check waits.

On Nano S the wait can also end with no reply. The app closes itself after about 7 minutes (4098
clock ticks) with no button press and no sign or key request reaching it, including while a
review or an address check waits, and the wallet sees the device leave the app. A USB reset ends
the wait too: the app returns to its home screen and starts its transport again.

## Status words

| SW | Meaning |
| --- | --- |
| `9000` | Success |
| `6700` | `Lc` does not match the data received, the command is shorter than its header, or a key request carries more than its 20 path bytes |
| `6982` | No command was received |
| `6985` | The user rejected the transaction, or the address shown for checking |
| `6A86` | P1 or P2 is not allowed for this command |
| `6D00` | Unknown instruction |
| `6E00` | Unknown class |
| `6D05` | The transaction ends before a field it declares |
| `6D08` | The payload does not fit in 1024 bytes |
| `6D09` | A key request carries fewer than 20 path bytes |
| `6D50` | The payload is no longer than the path |
| `6D51` | Not a plain transfer: wrong version, type or payload version |
| `6D52` | No outputs, or more than the review can show |
| `6D53` | An output carries a payload (a vote or similar) |
| `6D54` | An output is time-locked |
| `6D55` | An output is not ELA |
| `6D56` | The transaction spends no coins |
| `6D57` | Bytes follow the end of the transaction |
| `6D58` | The path is not `44'/2305'/account'/change/index` |
| `6D59` | An output pays an address type other than standard or multisig |
| `6D5A` | An amount, including the amount of a poll vote, is negative or too wide to show whole on one line |
| `6D5B` | An attribute other than a nonce or a memo, a second nonce or a second memo, or a nonce of more than 8 bytes |
| `6D5C` | The transaction has a lock time |
| `6D5D` | Approval arrived with no transaction committed |
| `6D5E` | The review walked was not the whole committed review, or the bytes, digest, number of screens, path or review text changed after it was committed |
| `6D5F` | Key derivation or signing failed |
| `6D60` | An address is too wide to show whole on its review or address check lines |
| `6D61` | A memo marked as a poll vote does not have the wallet's vote layout (an amount of more than 17 characters included) |
| `6D62` | Memo text cannot be shown whole: it is empty, holds a byte other than printable ASCII (`20` to `7E`), or needs more screens than the outputs leave |
| `6D63` | A key request without the address check (P1 `00`) for an account above `100'` or an index above 50,000: that key is sent only through the address check (P1 `01`) |
| `6DFD` | An attribute, input or output count starts with `FD`, `FE` or `FF`; or an attribute's data length starts with `FE` or `FF`, whatever its value, or is `FD xx xx` holding less than 253 |
| `6901` | Sent by the SDK, not the app: a review or an address check is waiting for the user |
| `6800` to `6FFF` | An SDK call failed with an error that is not a status word (see below) |

When an SDK call fails while a command is handled, the app ends any signing session and answers
with the SDK's error. An error that is already a status word, from `6000` to `6FFF` or from `9000`
to `9FFF`, is sent unchanged, so a wallet can receive a code this table does not list, or one it
does list, such as `6985`, that the SDK chose and the app did not. Any other error is sent as
`6800` plus its low 11 bits, which can also match a code above. A review or an address check on
screen when an SDK call fails, including while its reply is sent, closes and the home screen
returns. On Nano S, after a USB reset or a reply that finds no command to answer, the app sends
nothing and starts its transport again. On Nano X and Nano S Plus the SDK handles a USB reset
itself: a review or an address check waiting for the user stays on screen, new commands keep
getting `6901` until the user answers on the device, and the reply then goes to whichever computer
is connected.

## Transactions the app signs

Only a plain ELA transfer that the device can show in full. Every byte of the body must be read
and understood, or the transaction is refused:

- version: none (version 0) or `09`;
- type `02` (TransferAsset), payload version `00`, empty payload;
- attributes: at most one nonce (`00`), of at most 8 bytes, and at most one memo (`81`), in
  either order; a data length may use the three-byte form `FD xx xx` only for 253 bytes or more;
- at least one input; inputs are skipped, since they carry no amounts;
- one to three outputs, each in the ELA asset, with an amount below 2^63 that fits the screen,
  no output lock, a standard (`21`) or multisig (`12`) address that fits the screen, and on
  version 9 an output type of `00` with no payload;
- a lock time of `00000000` and nothing after it.

The device cannot learn what the spent coins hold, so it cannot check the fee.

### The nonce

The nonce only makes two otherwise identical transactions differ. It moves no value, no output
depends on it, and nothing on the chain gives its bytes a meaning, so it is signed without being
shown. So that it cannot carry data the user never sees, a transaction may hold one nonce of at
most 8 bytes; Elastos Essentials writes the one byte `30`, the text "0". A second nonce, or a
longer one, is refused with `6D5B` before anything is shown.

### Memos

A transaction may hold one memo, either a poll vote or text, and either kind is shown in full. A
second memo of either kind is refused with `6D5B`: readers of the chain take one memo, which could
otherwise be another than the one shown.

### Memo text

A memo that does not start with `pollvote` is text, and is shown on its own screens, every byte as
it is signed, including the prefix "type:text,msg:" that Essentials writes before the user's note.
It may hold only printable ASCII, `20` to `7E`, the characters the review font of every device has.

The text is wrapped onto lines at words. A line holds at most 17 characters, and only as many as
fit it in pixels, measured with the review font's own width of each character, as amounts and
addresses are (116 pixels on Nano X and Nano S Plus, 108 on Nano S, where three characters, `&`,
`X` and `_`, are a pixel narrower). When the next character does not fit, the line ends after its
last space, comma or colon, and the word after it goes on to the next line. Only a line with none
of these, filled by one word, ends where it is full, inside a word longer than a line. Nothing is
added, dropped or moved: a space where a line ends stays at the end of that line, and a space after
a word that fills a whole line starts the next one; either way it cannot be seen. The wallet's
memo "type:text,msg:Rent for October", for example, shows as "type:text,msg:" and "Rent for
October". Each screen holds three lines, headed "Memo", or "Memo 1 of n" to "Memo n of n" when the
text takes n screens. On Nano S a screen whose second and third lines are empty still has its
second half, shown blank, and it must be shown like any other.

The review has nine screens at most: the signer, the memo, two for each output, and the fee
notice. So memo text may take five screens with one output, three with two, and one with three:
15, 9 or 3 lines. How much text fits depends on its words and letters:

| Outputs | Full lines, every device | Any text, Nano X and Nano S Plus | Any text, Nano S |
| --- | --- | --- | --- |
| 1 | memo 255, note 241 | memo 101, note 93 | memo 93, note 86 |
| 2 | memo 153, note 139 | memo 62, note 54 | memo 57, note 50 |
| 3 | memo 51, note 37 | memo 23, note 15 | memo 21, note 14 |

A memo counts all of its bytes. A note counts the user's characters after the 14 that Essentials
writes first, "type:text,msg:", so a note of 93 is a memo of 107 bytes. Full lines hold 17
characters each, the most a line can: that is the longest memo that fits, on every device. Lines
that end sooner, at a space before a long word, or that hold wider characters, take more lines,
so a shorter memo can be refused. The last two columns are the limits for any printable text,
whatever its words and letters: any memo or note no longer than that fits, and one character more
can be refused, since text made mostly of spaces and words just narrower than a line leaves the
most room unused at the ends of lines. They come from an exhaustive search,
run by the host tests on the reference line splitter in `tests/host/parser`. It writes every text
one character at a time, taking characters of the same width, and those a line may end after,
as one, and goes on from each state a line can be in only with the shortest text that reaches it,
since the rest of a text depends only on the lines so far and on the line being filled: its
characters, its width, and where in it a line may last end. The shortest text that does not fit
is then sent to the app's own parser, which must refuse it with `6D62` and accept it one character
shorter. Memo text that is empty, holds a byte outside printable ASCII, or needs more screens than
its outputs leave is refused with `6D62` before anything is shown.

### Poll votes

Elastos Essentials casts a mainchain poll vote as a transfer back to the voter, with the vote in
the memo: the 8 bytes `pollvote`, the 32-byte poll id, the choice index as a 4-byte little-endian
number, one length byte, and the vote amount as ELA text (digits, then optionally a point and one
to eight decimals, at most 17 characters, the most the wallet writes). A memo that starts with
`pollvote` must have exactly this layout, whatever its length form or position, with a choice
index below 1000 and an amount that fits the screen (one too wide gets `6D5A`); any other layout
is refused with `6D61`. Like any memo, it must be the transaction's only one. A vote takes three
review screens, so it fits with at most two outputs; with three it is refused with `6D52`.

The poll results are counted off the chain. A vote counts only while the coin paid by the vote
transaction's first output stays unspent: any later transaction that spends that coin before the
poll ends withdraws the vote. The device cannot tell which coins carry votes, so such a payment
shows as an ordinary one.

## The review

On Nano X and Nano S Plus, one screen each, in this order; on Nano S each screen is shown in two
halves:

1. "Review Transaction" (Nano S: "Review Tx").
2. "Signing with": the address of the signing key, on three lines of 11, 11 and 12 characters.
   The device cannot see whose coins the inputs spend. The same signature also serves a multisig
   address this key belongs to, so this screen names the key that signs, not where the coins come
   from, and change back to such a multisig shows as a payment to its address.
3. For a poll vote: "Poll vote", "Choice N" (numbered from 1), the amount, "ELA"; then "Poll id 1
   of 2" and "Poll id 2 of 2", the poll id in hex over six lines. For memo text: "Memo", or "Memo
   1 of n" to "Memo n of n", and the text, three lines a screen (see Memo text).
4. For each output: "Output k of n", "Send" or "Back to you", the amount with all eight decimals,
   "ELA"; then "Recipient" or "Your address" and the full address. An output is "Back to you" only
   when it pays exactly the signing key's own address.
5. "Network fee": "Not checked by this device. Set by the wallet".
6. Accept or Reject (Nano S: "Sign Tx" or "Deny Tx"). On Nano S, Sign works only after both
   halves of every screen have been shown, and only on the Sign screen itself.

An amount or an address line that would not fit the screen whole is refused, never cut. Memo text
is wrapped onto further lines instead, and is refused with `6D62` only when it needs more screens
than the outputs leave (see Memo text).

The transaction is rendered twice when it arrives, and the two renderings must match. Before
signing, the app checks that the review the user walked through was the whole committed review
(on Nano S, both halves of every screen, with Sign the screen on display; on Nano X and Nano S
Plus, every step of the flow, with Accept the step on display), and that the bytes, the digest,
the number of screens, the path and the review text are the ones committed when the review was
built. A screen counts as shown only once it has been drawn in full: on Nano S when its last
element has been handed to the display after the others, in order; on Nano X and Nano S Plus when
the SDK's drawing of the step's layout ran to its end.

## The address check

A key request with P1 `01` shows the derivation path and the address of its path, for any path the
path rule allows, in this order:

- on Nano X and Nano S Plus, one screen each: "Verify address"; "Path" and the path; "Address" and
  the address on three lines of 11, 11 and 12 characters; "Approve"; "Reject";
- on Nano S: "Verify address"; "Path" and the first line of the path; its second and third lines,
  only when it takes more than one; address lines 1 and 2; lines 2 and 3; "Approve"; "Reject".

The path is shown in its usual notation: each component in decimal, with `'` after a hardened one
and `/` between two, such as `44'/2305'/0'/0/5`. It wraps as memo text does, with the same limits,
a line ending after its last `/` that fits, so no number is ever cut. Most paths take one or two
lines; the longest the rule allows, `44'/2305'/2147483647'/1/2147483647`, takes three:
`44'/2305'/`, `2147483647'/1/` and `2147483647`.

On every device the right button moves on and the left one goes back, stopping at the first and
last screens, and both buttons together act only on Approve and Reject. Approve works only once
every screen of the path and of the address, and Approve itself, has been drawn in full, each
counted as a review screen is (see The review); before that, both buttons on Approve do nothing:
the user goes back to any screen of the path or the address that was not drawn in full, if there is
one, then presses them again. Approve sends the public key of the path, Reject sends `6985`, and
either returns to the home screen. Nothing is signed. As in the review, an address with a line too
wide for the screen is never cut: the request is refused with `6D60` before anything is shown.

## The account screen

The home screen's Display Account (Nano S: right from the home screen) shows the device's own
first address, `44'/2305'/0'/0/0`, headed "First address" on Nano X and Nano S Plus. It never
shows a key the computer asked for: a wallet that wants the user to check another address asks
for the address check instead. An address with a line too wide for the screen is not shown cut:
the screen reads "Address too wide / to show here" instead.
