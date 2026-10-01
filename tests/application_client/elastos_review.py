"""Reads review screens and builds the exact screens expected."""
import time
from pathlib import Path

import pytest
from ragger.backend.interface import BackendInterface
from ragger.error import ExceptionRAPDU
from ragger.navigator import Navigator, NavInsID


def screen_lines(backend: BackendInterface) -> list[str]:
    return [event["text"].strip() for event in backend.get_current_screen_content()["events"]]


def walk_review(backend: BackendInterface, navigator: Navigator, snapshots_path: Path, test_name: str,
                final: str = "Accept") -> list[list[str]]:
    """Walks right, comparing each screen with its snapshot, then presses both on final. Returns
    the screens before final."""
    screens: list[list[str]] = []

    def record_then_right(*_args, **_kwargs) -> None:
        screens.append(screen_lines(backend))
        backend.right_click()

    navigator.add_callback(NavInsID.RIGHT_CLICK, record_then_right)
    navigator.navigate_until_text_and_compare(NavInsID.RIGHT_CLICK, [NavInsID.BOTH_CLICK], final,
                                              snapshots_path, test_name)
    return screens


def settled_lines(backend: BackendInterface, differ_from: list[str] | None = None,
                  timeout: float = 10.0) -> list[str]:
    """Screen text once the same on three reads 0.1 s apart and unlike differ_from, so a redraw or
    a half-drawn screen is never taken for the next one."""
    deadline = time.monotonic() + timeout
    last, same = None, 0
    while time.monotonic() < deadline:
        lines = screen_lines(backend)
        same = same + 1 if lines == last else 0
        last = lines
        if same >= 2 and lines != differ_from:
            return lines
        time.sleep(0.1)
    raise TimeoutError(f"the screen did not settle on a new screen after {differ_from}")


def assert_refused_showing_nothing(backend: BackendInterface, apdu: bytes, status: int) -> None:
    """Refused at once, home screen kept; a check shown instead sends no reply and times out."""
    home = settled_lines(backend)
    with pytest.raises(ExceptionRAPDU) as refused:
        backend.exchange_raw(apdu, tick_timeout=100)
    assert refused.value.status == status, f"{refused.value.status:04X} != {status:04X}"
    assert settled_lines(backend) == home


def walk_review_text(backend: BackendInterface, final: str = "Accept",
                     press_both_on_each: bool = False) -> list[list[str]]:
    """Walks right without snapshots, then presses both on final; returns the screens before it.
    press_both_on_each first presses both on each screen, which must not move it."""
    screens: list[list[str]] = []
    lines = settled_lines(backend)
    while lines != [final]:
        screens.append(lines)
        if press_both_on_each:
            backend.both_click()
            assert settled_lines(backend) == lines, f"both buttons left the screen {lines}"
        backend.right_click()
        lines = settled_lines(backend, differ_from=lines)
    backend.both_click()
    return screens


# Pixel widths of ASCII 0x20 to 0x7E in the Nano X and Nano S Plus review font, from the SDK's
# bagl_font_open_sans_regular_11px.json. Nano S differs in &, X and _ but is not emulated.
FONT_WIDTH = (3, 3, 4, 7, 6, 9, 9, 2, 3, 3, 6, 6, 3, 4, 3, 4,
              6, 6, 6, 6, 8, 6, 6, 6, 6, 6, 3, 3, 6, 6, 6, 5,
              10, 7, 7, 7, 8, 6, 6, 8, 8, 3, 4, 7, 6, 10, 8, 9,
              7, 9, 7, 6, 7, 8, 7, 10, 7, 6, 6, 4, 4, 4, 6, 6,
              6, 6, 7, 5, 7, 6, 5, 6, 7, 3, 4, 6, 3, 10, 7, 7,
              7, 7, 4, 5, 4, 7, 6, 9, 6, 6, 5, 4, 6, 4, 6)
LINE_WIDTH_PX = 116
LINE_CHARS = 17
LINES_PER_SCREEN = 3
LINE_ENDS = b" ,:"


def line_width(text: str) -> int:
    return sum(FONT_WIDTH[ord(c) - 0x20] for c in text)


def wrapped_lines(text: bytes, line_ends: bytes) -> list[str]:
    """Lines as the device wraps them: at most 17 characters and 116 px, cut back to end after the
    last line_ends character when more text follows. Every character is kept."""
    lines, start = [], 0
    while start < len(text):
        end, width = start, 0
        while (end < len(text) and end - start < LINE_CHARS
               and width + FONT_WIDTH[text[end] - 0x20] <= LINE_WIDTH_PX):
            width += FONT_WIDTH[text[end] - 0x20]
            end += 1
        if end < len(text):
            ends = [k + 1 for k in range(start, end) if text[k] in line_ends]
            if ends:
                end = ends[-1]
        lines.append(text[start:end].decode("ascii"))
        start = end
    return lines


def memo_lines(memo: bytes) -> list[str]:
    return wrapped_lines(memo, LINE_ENDS)


def path_text(path: bytes) -> str:
    """The path as the address check shows it, such as 44'/2305'/0'/0/5."""
    parts = [int.from_bytes(path[k:k + 4], "big") for k in range(0, len(path), 4)]
    return "/".join(f"{part & 0x7FFFFFFF}{chr(39) if part & 0x80000000 else ''}" for part in parts)


def path_lines(path: bytes) -> list[str]:
    """Path lines, each ending after a /, so no number is cut."""
    return wrapped_lines(path_text(path).encode(), b"/")


# Longest memo per output count: the screens of nine left after the signer, two per output and
# the fee notice, at 3 lines of 17 characters.
LONGEST_MEMO = {1: 5 * 3 * LINE_CHARS, 2: 3 * 3 * LINE_CHARS, 3: 1 * 3 * LINE_CHARS}

# A note that fills every line to 17 characters within the pixel limit, so LONGEST_MEMO bytes fit
# exactly: "Re:" completes the wallet's 14-character first line, and each part is one line.
FULL_LINE_START = "Re:"
FULL_LINE_PARTS = ("rent of the flat ", "paid in full for ", "the year 2024 by ", "the tenant, with ",
                   "all of the bills ", "and the receipt: ", "number 2024-117, ")


def full_line_memo(length: int) -> bytes:
    """A wallet memo of exactly length bytes, every line 17 characters."""
    prefix = b"type:text,msg:"
    parts = "".join(FULL_LINE_PARTS)
    note = (FULL_LINE_START + parts * (1 + length // len(parts))).encode()
    return prefix + note[:length - len(prefix)]


def memo_screens(memo: bytes) -> list[list[str]]:
    """Three lines per screen, titled "Memo" or "Memo k of n"; the emulator trims each line."""
    lines = memo_lines(memo)
    pages = [lines[k:k + LINES_PER_SCREEN] for k in range(0, len(lines), LINES_PER_SCREEN)]
    titles = ["Memo"] if len(pages) == 1 else [f"Memo {k} of {len(pages)}" for k in range(1, len(pages) + 1)]
    return [[title, *(line.strip() for line in page)] for title, page in zip(titles, pages)]


def split_address(address: str) -> list[str]:
    return [address[:11], address[11:22], address[22:]]


def format_ela(sela: int) -> str:
    """As the device shows amounts: all eight decimals, no padding."""
    return f"{sela // 10 ** 8}.{sela % 10 ** 8:08d}"


def expected_review(signer: str, outputs: list[tuple[bool, int, str]],
                    vote: tuple[int, str, bytes] | None = None, memo: bytes | None = None) -> list[list[str]]:
    """Every screen before Accept. outputs: (returns_to_signer, sela, address); vote: (choice from
    1, amount text, poll id); memo: a non-vote memo, shown where a vote would be."""
    screens = [["Review", "Transaction"], ["Signing with", *split_address(signer)]]
    if memo is not None:
        screens += memo_screens(memo)
    if vote is not None:
        choice, amount, poll_id = vote
        h = poll_id.hex()
        screens += [["Poll vote", f"Choice {choice}", amount, "ELA"],
                    ["Poll id 1 of 2", h[0:11], h[11:22], h[22:32]],
                    ["Poll id 2 of 2", h[32:43], h[43:54], h[54:64]]]
    for k, (is_change, sela, address) in enumerate(outputs, start=1):
        screens.append([f"Output {k} of {len(outputs)}", "Back to you" if is_change else "Send",
                        format_ela(sela), "ELA"])
        screens.append(["Your address" if is_change else "Recipient", *split_address(address)])
    screens.append(["Network fee", "Not checked by", "this device.", "Set by the wallet"])
    return screens
