"""Framing and session: bad or interleaved messages are refused, never signed, leave no state."""
import pytest
from ragger.error import ExceptionRAPDU
from requests.exceptions import ConnectionError as EmulatorGone

from application_client.elastos_command_sender import (CLA, P1, ElastosCommandSender, Errors, InsType, raw_apdu,
                                                       split_payload)
from application_client.elastos_review import (expected_review, screen_lines, settled_lines, walk_review,
                                               walk_review_text)
from application_client.elastos_transaction import PH_MERCHANT, ela, wallet_memo, wallet_tx
from application_client.elastos_utils import DEFAULT_PATH, base58_address, der_length, program_hash, verify_signature

# First part of a two-part transaction, to leave a stream open
STREAM_FIRST_PART = split_payload(wallet_tx(ela(1), ela(2), PH_MERCHANT,
                                            memo="Invoice 2024-117 for consulting, paid in full.") + DEFAULT_PATH)[0]


def assert_error(backend, apdu: bytes, status: int) -> None:
    with pytest.raises(ExceptionRAPDU) as error:
        backend.exchange_raw(apdu)
    assert error.value.status == status, f"{error.value.status:04X} != {status:04X}"
    backend.wait_for_home_screen()


def assert_next_transfer_signs(backend, client: ElastosCommandSender, key: bytes) -> None:
    """The next transfer signs on its own bytes, not joined to parts of an earlier stream."""
    me_ph = program_hash(key)
    me = base58_address(me_ph)
    body = wallet_tx(ela(1.5), ela(48.49), me_ph)
    with client.sign(body, DEFAULT_PATH):
        assert settled_lines(backend) == ["Review", "Transaction"], "the next transaction was not reviewed"
        screens = walk_review_text(backend)
    assert screens == expected_review(me, [(False, ela(1.5), base58_address(PH_MERCHANT)), (True, ela(48.49), me)],
                                      memo=wallet_memo())
    reply = client.get_async_response().data
    assert len(reply) == der_length(reply) and verify_signature(key, body, reply)


def check_address(backend, client: ElastosCommandSender, key: bytes, final: str) -> None:
    home = settled_lines(backend)
    if final == "Approve":
        with client.show_address(DEFAULT_PATH):
            walk_review_text(backend, final=final)
        assert client.get_async_response().data == key
    else:
        with pytest.raises(ExceptionRAPDU) as rejected:
            with client.show_address(DEFAULT_PATH):
                walk_review_text(backend, final=final)
        assert rejected.value.status == Errors.SW_USER_REJECTED
    assert settled_lines(backend) == home


def test_length_byte_larger_than_data(backend):
    """v1.1.5 trusted the length byte and copied stale buffer bytes."""
    assert_error(backend, raw_apdu(InsType.SIGN, P1.LAST, b"\x02" * 100, lc=0xFF), Errors.SW_WRONG_LENGTH)


def test_length_byte_smaller_than_data(backend):
    assert_error(backend, raw_apdu(InsType.SIGN, P1.MORE, b"\x02" * 10, lc=5), Errors.SW_WRONG_LENGTH)


@pytest.mark.parametrize("p1, p2", [(P1.LAST, 1), (0x01, 0), (0x81, 0)])
def test_bad_p1_or_p2(backend, p1, p2):
    assert_error(backend, raw_apdu(InsType.SIGN, p1, b"\x02", p2=p2), Errors.SW_WRONG_P1P2)


def test_unknown_class_and_instruction(backend):
    assert_error(backend, bytes([0xE0, InsType.GET_PUBLIC_KEY, 0, 0, 20]) + DEFAULT_PATH, Errors.SW_CLA_NOT_SUPPORTED)
    assert_error(backend, bytes([CLA, 0x08, 0, 0, 20]) + DEFAULT_PATH, Errors.SW_INS_NOT_SUPPORTED)


@pytest.mark.parametrize("cla", [pytest.param(CLA, id="class-80"), pytest.param(0xE0, id="class-e0")])
@pytest.mark.parametrize("size", [pytest.param(2, id="2-bytes"), pytest.param(3, id="3-bytes"),
                                  pytest.param(4, id="4-bytes")])
def test_command_shorter_than_its_header(backend, cla, size):
    """Too short for its 5-byte header: 6700 whatever the class, home screen unchanged."""
    home = settled_lines(backend)
    assert_error(backend, bytes([cla, InsType.GET_PUBLIC_KEY, 0, 0])[:size], Errors.SW_WRONG_LENGTH)
    assert settled_lines(backend) == home


@pytest.mark.parametrize("size", [10, 19, 20])
def test_payload_no_longer_than_the_path(backend, size):
    """v1.1.5 showed an empty review for these and faulted on approval."""
    assert_error(backend, raw_apdu(InsType.SIGN, P1.LAST, b"\x02" * size), Errors.SW_TX_TOO_SHORT)


def test_stream_longer_than_the_buffer(backend):
    for _ in range(4):
        backend.exchange_raw(raw_apdu(InsType.SIGN, P1.MORE, bytes(255)))
    assert_error(backend, raw_apdu(InsType.SIGN, P1.LAST, bytes(5)), Errors.SW_TX_TOO_LARGE)


def test_stream_that_fills_the_buffer_exactly(backend):
    """A full 1024-byte buffer reaches the parser, which refuses its content."""
    payload = bytes(1024 - len(DEFAULT_PATH)) + DEFAULT_PATH
    parts = split_payload(payload)
    assert [len(p) for p in parts] == [255, 255, 255, 255, 4]
    for part in parts[:-1]:
        backend.exchange_raw(raw_apdu(InsType.SIGN, P1.MORE, part))
    assert_error(backend, raw_apdu(InsType.SIGN, P1.LAST, parts[-1]), Errors.SW_TX_UNSUPPORTED)


def test_exit_instruction_closes_the_app(backend):
    """0xFF exits without replying."""
    client = ElastosCommandSender(backend)
    assert len(client.get_public_key(DEFAULT_PATH).data) == 65
    with pytest.raises(TimeoutError):
        backend.exchange_raw(bytes([CLA, InsType.EXIT, 0, 0, 0]), tick_timeout=100)
    with pytest.raises(EmulatorGone):
        client.get_public_key(DEFAULT_PATH)


def test_request_during_a_review_is_turned_away(backend):
    """The SDK answers 6901 to every command while a review waits, so the review stays as shown."""
    client = ElastosCommandSender(backend)
    ph = program_hash(client.get_public_key(DEFAULT_PATH).data)
    body = wallet_tx(ela(1), ela(2), ph)
    # Speculos's web API also gives 6901 to the request that opened the review
    with pytest.raises(ExceptionRAPDU):
        with client.sign(body, DEFAULT_PATH):
            for apdu in (raw_apdu(InsType.GET_PUBLIC_KEY, 0, DEFAULT_PATH),
                         raw_apdu(InsType.SIGN, P1.LAST, body + DEFAULT_PATH)):
                with pytest.raises(ExceptionRAPDU) as busy:
                    backend.exchange_raw(apdu, tick_timeout=100)
                assert busy.value.status == Errors.SW_REVIEW_PENDING
            assert screen_lines(backend) == ["Review", "Transaction"]


@pytest.mark.parametrize("final", [
    pytest.param(None, id="silent"),
    pytest.param("Approve", id="check-approved"),
    pytest.param("Reject", id="check-rejected"),
])
def test_key_request_drops_a_partial_transaction(backend, final):
    """A key request mid-stream ends it, P1 00 or a check either way; else the part sent before it
    would join the next transfer."""
    client = ElastosCommandSender(backend)
    # key first, so the request under test is the only one mid-stream
    key = client.get_public_key(DEFAULT_PATH).data
    backend.exchange_raw(raw_apdu(InsType.SIGN, P1.MORE, STREAM_FIRST_PART))
    if final is None:
        assert client.get_public_key(DEFAULT_PATH).data == key
    else:
        check_address(backend, client, key, final)
    assert_next_transfer_signs(backend, client, key)


def test_refusal_leaves_no_state_behind(backend, navigator, default_screenshot_path, test_name):
    client = ElastosCommandSender(backend)
    key = client.get_public_key(DEFAULT_PATH).data
    with pytest.raises(ExceptionRAPDU):
        client.sign_expecting_refusal(bytes(40), DEFAULT_PATH)
    body = wallet_tx(ela(1.5), ela(48.49), program_hash(key))
    with client.sign(body, DEFAULT_PATH):
        walk_review(backend, navigator, default_screenshot_path, test_name)
    assert verify_signature(key, body, client.get_async_response().data)


@pytest.mark.parametrize("leading_parts, apdu, status", [
    pytest.param([STREAM_FIRST_PART], raw_apdu(InsType.SIGN, P1.LAST, b"\x02" * 100, lc=0xFF),
                 Errors.SW_WRONG_LENGTH, id="length-byte"),
    pytest.param([STREAM_FIRST_PART], raw_apdu(InsType.SIGN, 0x01, b"\x02"), Errors.SW_WRONG_P1P2, id="p1"),
    pytest.param([STREAM_FIRST_PART], raw_apdu(InsType.SIGN, P1.LAST, b"\x02", p2=1), Errors.SW_WRONG_P1P2,
                 id="p2"),
    pytest.param([STREAM_FIRST_PART], bytes([CLA, 0x08, 0, 0, 20]) + DEFAULT_PATH, Errors.SW_INS_NOT_SUPPORTED,
                 id="instruction"),
    pytest.param([STREAM_FIRST_PART], bytes([0xE0, InsType.GET_PUBLIC_KEY, 0, 0, 20]) + DEFAULT_PATH,
                 Errors.SW_CLA_NOT_SUPPORTED, id="class"),
    pytest.param([bytes(255)] * 4, raw_apdu(InsType.SIGN, P1.LAST, bytes(5)), Errors.SW_TX_TOO_LARGE,
                 id="stream-too-long"),
])
def test_error_mid_stream_ends_the_transaction(backend, leading_parts, apdu, status):
    """An error mid-stream ends it, so the next transaction signs on its own bytes. The home screen
    cannot show this: no review was up before the error either."""
    client = ElastosCommandSender(backend)
    # key first: a key request ends a stream itself and would hide the error's effect
    key = client.get_public_key(DEFAULT_PATH).data
    for part in leading_parts:
        backend.exchange_raw(raw_apdu(InsType.SIGN, P1.MORE, part))
    assert_error(backend, apdu, status)
    assert_next_transfer_signs(backend, client, key)
