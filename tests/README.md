# Tests

Two suites guard the fixes from the security audit. Both run in CI.

## Functional tests (Ragger, on the Speculos emulator)

The audit attacks in `vectors/audit_vectors.json` that the device cannot show truthfully must be
refused with a named status word and no review on screen. The three that are plain transfers (the
fee slot, the digit truncation and the fee burn) must sign, with every output shown. Every
transaction the app accepts is reviewed screen by screen: each screen's text is checked exactly,
most against a golden snapshot in `snapshots/`, and the signature is verified over the
transaction's own bytes. Every line must fit the screen whole: an amount or address that would be
cut is refused. Other tests press both buttons on every review screen before Accept, run several
reviews in one app session, use Quit and Back, and check keys for unusual paths against keys
derived off the device. A path outside `44'/2305'/account'/change/index`, such as a hardened
change, gets no key and no review. A key request without the address check (P1 00) is answered
up to account 100' and index 50,000, on either change branch, with the key derived off the device,
and refused at once with 6D63, showing nothing, for account 101', index 50,001 and the three paths
below whose account and index each use more than one byte. A memo of exactly the poll vote flag,
`pollvote`, is refused as a vote with nothing of its layout, not shown as text. Memo text is shown
whole after the signer, wrapped at words, on one screen, over two, and at the longest the review
holds with one, two and three outputs (255, 153 and 51 bytes of full lines), including memos in
both length forms. Its lines are also ended by the width of the screen: a word exactly 116 px wide
is drawn whole, its next letter moved to the next line, and a line of words ending at a space at
exactly 116 px is drawn whole, the next word moved on. One byte more than the longest, a byte
outside printable ASCII, a line feed, a NUL, or an empty memo is refused with 6D62, and a second
memo, a second nonce or a nonce of 9 bytes with 6D5B. A command of 2, 3 or 4 bytes, too short for
its own header, gets 6700 with class 80 or any other, and the home screen stays as it was.

The address check (a key request with P1 01) is walked screen by screen against golden snapshots,
for two paths: the path shown, headed "Path", must be the path asked for in its usual notation,
such as 44'/2305'/0'/0/0, the address shown the one computed off the device from the key, and the
reply after Approve the same key a silent request returns. Three more paths, whose account and
index each use more than one byte, are walked the same way, the last the longest the device takes,
44'/2305'/2147483647'/1/2147483647, whose path is shown on three lines: there the address shown
and the key sent on Approve must both be those derived off the device. So are account 101' and
index 50,001, the first just outside the range a request without the check is answered for, after
that request is refused with 6D63. Reject answers 6985 and leaves the app ready for a key request and a signature;
on account 101' the key is then still refused without the check. Both buttons before Approve do
nothing, the wallet's zero length byte works, and a bad P1 or P2 or a refused path is answered at
once with nothing shown. So is a key request with one or three bytes after its path, with P1 00 or
01: it gets 6700. A command sent while the check waits, a second check included, gets the SDK's
6901, and the check then still answers with its key. That last reply is read on Speculos's APDU
socket, because its web interface hands the 6901 to the request that opened the check as well. A
key request in the middle of a transaction ends it, with P1 00 and with a check approved or
rejected: the wallet's next transfer is then reviewed and signed on its own bytes. 163 tests run on
each device.

Build the app first. From this folder:

```bash
pip install -r requirements.txt
pytest --device nanox
pytest --device nanosp
```

From the repository root, as CI runs them:

```bash
pip install -r tests/requirements.txt
pytest tests --device nanox
```

After a deliberate change to what the screens show, regenerate the snapshots with
`--golden_run`, look at every changed image, and commit them with the change.

The tests use the public test phrase from `test-data.txt` (never use it for real funds).
Speculos has no Nano S model, so Nano S is skipped here and covered by the host tests.

## Host tests (`host/`)

The real parser and signing code, built on the host under AddressSanitizer and
UndefinedBehaviorSanitizer:

- `host/parser`: built for each device. Generated and mutated transactions, including poll votes,
  memo text of printable characters from narrow to wide, or of words that fill a line exactly or
  by one character more, up to past what the review holds and now and then with a byte outside
  printable ASCII, and a nonce or a memo one too many or a nonce past 8 bytes, some signed by a key
  whose own address has a line too wide for the screen. Every refusal must carry exactly the
  status word a second, independently written reader predicts, and every accepted transaction must
  show each amount, address, vote and memo letter for letter as that reader computes them, the
  memo wrapped at words line by line as that reader wraps it with its own copy of each SDK's font
  widths. The review font's width table is checked character by character, for every printable
  character. Then, for each device, the memo limits the specification states for any text are
  checked by an exhaustive search: that reader's line splitter is run on every text, one character
  at a time, with characters of the same width taken as one and each state a line can be in reached
  by its shortest text only, for the shortest memo and note that one, two or three outputs leave too
  few lines for; the app's parser must refuse each with 6D62 and accept it one character shorter.
- `host/state_machine`: the Nano S app started through its real `main()`, then APDU sequences,
  button presses, clock ticks, and exceptions from the SDK such as a USB reset or an error while a
  reply is sent. As on the Nano S SDK, a command sent while a review waits is dropped, each screen
  reaches the display one element at a time through the app's own display and event code, and a
  button press can arrive while a reply is still being sent. Some cases skip one store when a screen
  is put on the display, as one skipped instruction would (the layout, the button handler, or the
  index the redraw starts from), cut one screen's drawing short, skip the call that sends one
  element of a review half to the display, or skip once the drawing loop's check that nothing was
  sent yet for the event, so an element of a review half reaches the app's display hook with a
  status already out and is never sent. The display can then show one screen, or part of one, while
  another screen's buttons are live. A review half counts as shown only if the display holds it in
  full. Every signature must match the bytes and key that were on screen, every review screen must
  have been shown on the display before any signature, both buttons must have been pressed on the
  Sign screen shown, every screen must draw exactly its own text with nothing painted over it, no
  reply may start inside another, a key or a review may only follow a path the specification allows,
  and the app must recover from every exception, with no review left on screen and no transaction
  left half received, and close only when asked. After an SDK error the reply must be the status
  word the specification gives: an error that is a status word already, such as 6700 or 9001,
  unchanged, and any other as 6800 plus its low 11 bits. Key requests come with P1 01, which shows
  the address for the user to check, on paths the specification allows and refuses, and with a P1 or
  P2 no key request may carry; those with P1 00 or 01 on an allowed path also come with 1 to 4 bytes
  after it. Requests with P1 00 also come at the edges of the range they are answered for, accounts
  0' to 100' and indexes up to 50,000: the last account and index inside it, and the first account
  and the first index outside it, whose addresses requests with P1 01 show. A request with P1 00
  inside the range must be answered at once with the key of exactly its path and leave the screen as
  it was; one outside it must get exactly 6D63, derive no key and show nothing; any other P1, or a
  P2 other than 00, must get 6A86; then one with bytes after its path, 6700, whatever its Lc says,
  and one with fewer than its 20 path bytes, 6D09; then one on a path the specification refuses,
  6D58, before its range is looked at; and a refused request must show nothing. No key of the host
  build has an address with a line too wide for the screen, so one path is given such an address: a
  request with P1 01 for it must get 6D60 at once, from the home screen or the account screen, show
  nothing and leave nothing pending. An address check must show the path, headed "Path", in its
  usual notation, worked out here from the request's own bytes, on as many lines as it takes, the
  second page of the path only when it takes more than one, then the address. It must be answered
  only by both buttons: on Approve, with the key of exactly the path shown, or on Reject, with 6985.
  The host build's stand-in key depends on every bit of each part of the path, so a path that lost a
  top byte gets another key. Approve may answer only while the display holds it in full, once every
  line of the path and of the address has been on the display in full, even after a display fault,
  which cases now also make by not sending one element of a page of the path, of the address or of
  Approve; with no fault it must answer then. Once per run, on the longest path, each element of
  each of those pages in turn is not sent: both buttons on Approve must then answer nothing, until
  the page is drawn again in full. Approve or Reject with no check waiting must send nothing, and
  after the answer, or an SDK error, the app must be on the idle screen with nothing pending. Once any key
  request is answered, the app must no longer be receiving a transaction. Checks approved, rejected,
  read back, answered early and ended by each kind of SDK error are also walked through once per
  run. Now and then one crypto step fails for one command or press, after writing its output: the
  key derivation, the key setup, the public key, the program hash or the signature. A key request
  with P1 00 or 01, the last part of a sign request, Approve on an address check and Accept on a
  review must then get exactly 6D5F with no data, leave nothing on screen or pending, and sign
  nothing; once per run each is made to fail through every step it reaches, and the app must then
  still return a key and sign. After an address check of another path is approved, each step the
  account screen reaches is made to fail in turn, and both of its parts must then read
  "Could not get / the address", not the address just checked. Before the cases it checks that
  one flipped bit in the committed
  screen count, bytes or path, in any byte of the committed digest, of the review text or of the
  digest committed for that text, in the read marks or their complements, or in the screen index,
  cannot reach the signing key (for the screen count, the path and the text, whether it lands before
  the first check or between the two). A flipped index between two recipient screens, which share
  their heading but not their address, marks nothing read, and one past the last screen is brought
  back to it, also when Up leaves it on exactly the number of screens, on a review of seven screens
  and on one of nine. What was read of a review ended by an exception is forgotten twice, on the way
  back to idle and when the next review is put up; with either reset skipped once, a second review
  taken the short way to Sign still does not sign. Both buttons on Sign while the app draws it again
  leave the review signable, and approval itself refuses until Sign is drawn in full, so one skipped
  check at the button cannot sign; a screen drawn on from where that redraw stopped does not count
  as drawn. When the user moves to another half while a half is drawn again and the call that would
  put the new half up is skipped, the drawing under way does not count as the new half. An element
  of a review half whose call to the display is skipped, so it never reaches the display, does not
  count towards that half, nor does one handed to the display hook with a status already out after
  the drawing loop's check of the status is skipped. It also checks that the second check of the
  session state refuses on its own, and each digest comparison when one fault makes the other pass;
  that a key request with P1 00 for account 101', index 50,001 or the last account and index of all
  is refused with 6D63, with no key derived, when one fault makes either of its two checks of the
  range pass, and is still answered inside the range; that a failed
  hash of the review text signs nothing; that one flipped bit in the path left in the buffer, in the
  path the "Signing with" key came from while the review is built, even only while the key is
  derived, in that key or its address before the review is first shown, or in the committed path
  while signing hashes the review text, cannot sign with a key other than the one shown; that a path
  the specification refuses cannot sign even if one fault skips the check at review; that a fault in
  the text while the review is first rendered stops the commit; that one flipped bit in the
  committed body length signs nothing and never makes signing read past the buffer; that when one
  flipped bit of the length leaves bytes after the body unread, nothing signs, even with one of the
  two checks of that length skipped; that key material is wiped on every path; that the idle timer
  closes the app on exactly the 4098th tick, the number the specification gives, also while a review
  or an address check waits, counted again from each button press and from each sign or key request,
  whether the app accepts or refuses it, but not from a command of another kind; that after any
  refused command, SDK error or key request in the middle of a transaction (a key request answered
  at once, or one whose address check the user approves or rejects), the wallet's next transfer is
  reviewed and signs; and that after a USB reset the app carries on if the stack canary is intact
  and resets the device if it changed.
- `host/nanox_gate`: the Nano X and Nano S Plus screens, built with a stand-in for the SDK's flow
  engine. Each check runs on a six-screen transfer and on a nine-screen poll vote, which fills the
  review flow to its last slot. The review position is moved the way a fault would: straight to
  Accept, the last step skipped, one bit flipped to jump from any step to a later one, from Reject
  to Accept, or from Accept back one step and then to Accept again without drawing it. The flow is
  corrupted: a step duplicated, the Reject slot or the end marker overwritten. Its shape alone is
  corrupted, with every step drawn and Accept on screen: two steps swapped, the intro replaced, or
  the Accept slot replaced and the position then moved past the end marker onto an Accept that a
  longer review left there (on the transfer only; this takes two faults, as a swap takes two
  stores). The gate's own marks are corrupted: a bit set in the drawn-step mask or cleared in its
  complement, the Accept flag or its complement left set, or one bit flipped in either. The layout
  call of one review step, or of Accept, is skipped, so the step's screen is never drawn, or its
  drawing is cut short at each of its elements in turn, so the screen is never updated, or the draw
  of each of its elements in turn is skipped while the drawing runs on to its end, so the screen is
  updated with that element missing. And the first of the two checks at approval is made to pass,
  or else the second. Accept must then refuse to sign, and an honest walk must still sign. A
  review, and an address check, must count as on screen at every step and no longer once Accept,
  Reject, Approve or a return to idle has closed it: that is how an SDK error finds a review to
  close. The account screen must show the device's own address whole and, for an address with a
  line too wide for the screen, "Address too wide / to show here" instead of the address cut.
  After a check of another address is approved, a failed derivation of the account screen's own
  key, or a failed program hash, must show "Could not get / the address", never the address just
  checked. The address check, on a path of one line, one of two and the longest the device takes,
  of three, must be the intro, the path headed "Path" with exactly the lines written out by hand,
  the address, Approve and Reject; an honest walk must approve, and Approve must answer nothing
  when the position jumps over the path or the address or from the intro to Approve, moves back
  to Approve from Reject without drawing it, or when the layout call of the path, the address or
  Approve is skipped, its drawing cut short at each element, or the draw of each element skipped.

The host tests need Python 3.10 or later and a C compiler with AddressSanitizer and
UndefinedBehaviorSanitizer (clang on macOS, gcc on Linux). The state-machine fuzzer's cases are
generated by `host/state_machine/gen_corpus.py`, which imports
`application_client/elastos_transaction.py`, whose `int | None` annotations need 3.10; the
python3 of Apple's developer tools is 3.9, on which that import fails. On Linux the C library
must be glibc 2.38 or later, as in Ubuntu 24.04 and Debian 13: 2.38 is the first with `strlcpy`,
which the app's `src/elastos.c` calls, and with an older one none of the three builds.

```bash
make -C host              # run all three
make -C host controls     # 199 planted bugs; each must be caught
```

`host/check_pic_objects.py` checks the objects built from the app's sources, on every device, for
data holding flash addresses, which would crash the app on the device. It allows only the objects
the SDK fixes up itself, by the exact names that `src/ui.c` gives them for that device through
the flow macros and the Nano S screens it displays, and fails on any other such data, whatever its
name or shape; `make -C host` runs its self-test, which checks that tables added to `ui.c` are
never allowed. It does not check the SDK's objects, nor the glyph object the SDK generates from
the app's icons and its own: every icon in it holds the flash addresses of its colours and
bitmap, which the SDK fixes up itself each time it draws the icon, so the check would fail on
each of them.

`host/check_double_checks.py` reads the disassembly of each device's app and fails unless every
path to signing still makes and acts on each doubled check twice: the screen count, path and text
checks before and after the two comparisons of the committed digest, and the two checks that the
review was shown whole; and unless every path to the key a request without the address check
returns still makes and acts on both checks that its path is in the silent range. A check counts
only on the way a branch on its result goes when the check passed, so a call whose result is
thrown away does not count. The compiler merges two checks it
can prove agree, as it merges the two digest comparisons if the `volatile` in `digests_match` is
removed, and the host tests, which run the source, cannot see that.

`host/check_stack_depth.py` reads a Nano S build made with `CFLAGS += -fstack-usage` and adds up
the stack that pressing Sign needs at its deepest: the frames from `main` down to the call that
signs, as the compiler reports them and the disassembly confirms, the crypto library's depth,
measured from the SDK's sources, and one interrupt. It fails if that is more than the stack the
build leaves, or if the app's frames on that path grow past the budget pinned in the script: 560
bytes today, 1,516 in all of the 1,760 left. The link only makes sure the globals leave enough
stack, no emulator runs Nano S and the host tests run on the host's stack, so nothing else sees
a new local variable on that path.

CI runs all three on its own build of the app, the stack check on a second Nano S build that must
be the same app byte for byte, and checks on that build that the stack protector is on for Nano X
and Nano S Plus and the stack canary is on for Nano S. It also checks that no device was built for
debugging, as `DEBUG=1` or a `DEBUG` set in the `Makefile` would do: no app may link the SDK's
debug print code, and none of the app's sources may carry debug information. That build uses the
builder image pinned by digest in the repository's `.github/workflows/host_tests.yml`. The app the
emulator tests run is built by Ledger's build workflow in the latest builder image, which that
workflow gives no way to pin, and the app Ledger ships is not built with this pin either. So these
six checks show that the source builds right with the pinned SDK and compiler, not that the tested
or the shipped binary does: a newer SDK or compiler in the latest image can build a different
binary, which could hold a flash address in its data, lose the stack protector or the canary, make
or act on a doubled check only once, link debug print code, or need more stack to sign, while this
job still passes. To check a newer toolchain, move the pin to it.
