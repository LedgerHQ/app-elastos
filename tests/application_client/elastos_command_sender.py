"""APDU commands and status words of the Elastos app."""
from contextlib import contextmanager
from enum import IntEnum
from typing import Generator

from ragger.backend.interface import BackendInterface, RAPDU

CLA = 0x80
MAX_CHUNK = 255


class InsType(IntEnum):
    SIGN = 0x02
    GET_PUBLIC_KEY = 0x04
    EXIT = 0xFF


class P1(IntEnum):
    MORE = 0x00
    LAST = 0x80


class KeyP1(IntEnum):
    """Key request P1, as in src/ui.h."""
    SILENT = 0x00
    SHOW = 0x01


class Errors(IntEnum):
    """Status words, as in src/sw.h."""
    SW_OK = 0x9000
    SW_NO_COMMAND = 0x6982
    SW_WRONG_LENGTH = 0x6700
    SW_USER_REJECTED = 0x6985
    SW_WRONG_P1P2 = 0x6A86
    SW_INS_NOT_SUPPORTED = 0x6D00
    SW_CLA_NOT_SUPPORTED = 0x6E00
    SW_TX_TOO_LARGE = 0x6D08
    SW_PUBKEY_PATH_TOO_SHORT = 0x6D09
    SW_TX_TRUNCATED = 0x6D05
    SW_TX_VARINT_TOO_LARGE = 0x6DFD
    SW_TX_TOO_SHORT = 0x6D50
    SW_TX_UNSUPPORTED = 0x6D51
    SW_TX_OUTPUT_COUNT = 0x6D52
    SW_TX_OUTPUT_TYPE = 0x6D53
    SW_TX_OUTPUT_LOCK = 0x6D54
    SW_TX_ASSET = 0x6D55
    SW_TX_NO_INPUTS = 0x6D56
    SW_TX_TRAILING_BYTES = 0x6D57
    SW_BAD_PATH = 0x6D58
    SW_TX_ADDRESS_TYPE = 0x6D59
    SW_TX_AMOUNT = 0x6D5A
    SW_TX_ATTRIBUTE = 0x6D5B
    SW_TX_LOCK_TIME = 0x6D5C
    SW_TX_ADDRESS_TOO_WIDE = 0x6D60
    SW_TX_POLL_VOTE = 0x6D61
    SW_TX_MEMO = 0x6D62
    SW_PATH_NEEDS_CHECK = 0x6D63
    # sent by the SDK, not the app, while a review or address check waits
    SW_REVIEW_PENDING = 0x6901


def split_payload(payload: bytes) -> list[bytes]:
    return [payload[i:i + MAX_CHUNK] for i in range(0, len(payload), MAX_CHUNK)] or [b""]


def raw_apdu(ins: int, p1: int, data: bytes, p2: int = 0, lc: int | None = None) -> bytes:
    """By hand, so tests can send a length byte that disagrees with the data."""
    return bytes([CLA, ins, p1, p2, len(data) if lc is None else lc]) + data


class ElastosCommandSender:
    """Sends commands as Elastos Essentials does."""

    def __init__(self, backend: BackendInterface) -> None:
        self.backend = backend

    def get_public_key(self, path: bytes) -> RAPDU:
        return self.backend.exchange(cla=CLA, ins=InsType.GET_PUBLIC_KEY, data=path)

    def get_public_key_wallet_framing(self, path: bytes) -> RAPDU:
        """The wallet sends a zero length byte before the 20 path bytes."""
        return self.backend.exchange_raw(raw_apdu(InsType.GET_PUBLIC_KEY, 0, path, lc=0))

    @contextmanager
    def show_address(self, path: bytes, wallet_framing: bool = False) -> Generator[None, None, None]:
        """Opens the address check; the block runs while it is on screen."""
        apdu = raw_apdu(InsType.GET_PUBLIC_KEY, KeyP1.SHOW, path, lc=0 if wallet_framing else None)
        with self.backend.exchange_async_raw(apdu):
            yield

    def send_leading_parts(self, payload: bytes) -> bytes:
        """Sends all but the last part and returns it: the last one starts the review."""
        parts = split_payload(payload)
        for part in parts[:-1]:
            self.backend.exchange(cla=CLA, ins=InsType.SIGN, p1=P1.MORE, data=part)
        return parts[-1]

    @contextmanager
    def sign(self, body: bytes, path: bytes) -> Generator[None, None, None]:
        """Streams body then path; the block runs while the review is on screen."""
        last = self.send_leading_parts(body + path)
        with self.backend.exchange_async(cla=CLA, ins=InsType.SIGN, p1=P1.LAST, data=last):
            yield

    def sign_expecting_refusal(self, body: bytes, path: bytes, tick_timeout: int = 100) -> RAPDU:
        """A review shown instead of a refusal sends no reply, so the exchange times out."""
        last = self.send_leading_parts(body + path)
        return self.backend.exchange_raw(raw_apdu(InsType.SIGN, P1.LAST, last), tick_timeout=tick_timeout)

    def get_async_response(self) -> RAPDU | None:
        return self.backend.last_async_response
