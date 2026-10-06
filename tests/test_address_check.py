"""Address check (P1 01): shows the path and address, and sends the key only on Approve."""
import socket

import pytest
from ragger.error import ExceptionRAPDU

from application_client.elastos_command_sender import P1, ElastosCommandSender, Errors, InsType, KeyP1, raw_apdu
from application_client.elastos_review import (assert_refused_showing_nothing, path_lines, settled_lines,
                                               split_address, walk_review, walk_review_text)
from application_client.elastos_transaction import ela, wallet_tx
from application_client.elastos_utils import (CHECK_ONLY_KEYS, DEFAULT_PATH, HARDENED, INDEPENDENT_KEYS, base58_address,
                                              pack_path, program_hash, uncompressed_key, verify_signature)

OTHER_PATH = pack_path(account=1, index=7)


def expected_check(public_key: bytes, path: bytes) -> list[list[str]]:
    """Every screen before Approve, the address computed off the device."""
    return [["Verify", "address"], ["Path", *path_lines(path)],
            ["Address", *split_address(base58_address(program_hash(public_key)))]]


class ApduSocket:
    """Raw Speculos APDU socket. The web API hands a 6901 to every waiting request, the one that
    opened the check included, so it cannot show the check's own reply."""

    def __init__(self, backend) -> None:
        # Ragger has no public getter for the APDU port
        self.sock = socket.create_connection(("127.0.0.1", backend._apdu_port), timeout=10)

    def __enter__(self) -> "ApduSocket":
        return self

    def __exit__(self, *_args) -> None:
        self.sock.close()

    def send(self, apdu: bytes) -> None:
        self.sock.sendall(len(apdu).to_bytes(4, "big") + apdu)

    def receive(self) -> bytes:
        """Next reply: data, then the status word."""
        size = int.from_bytes(self._receive_exactly(4), "big")
        return self._receive_exactly(size + 2)

    def _receive_exactly(self, size: int) -> bytes:
        data = b""
        while len(data) < size:
            part = self.sock.recv(size - len(data))
            assert part, "Speculos closed the APDU socket"
            data += part
        return data


@pytest.mark.parametrize("path, snapshots", [
    pytest.param(DEFAULT_PATH, "", id="default-path"),
    pytest.param(OTHER_PATH, "_account_1_index_7", id="account-1-index-7"),
])
def test_approved_check_returns_the_key(backend, navigator, default_screenshot_path, test_name, path, snapshots):
    """Shows the key's address and returns the same key as a silent request."""
    client = ElastosCommandSender(backend)
    key = client.get_public_key(path).data
    with client.show_address(path):
        screens = walk_review(backend, navigator, default_screenshot_path, test_name + snapshots, final="Approve")
    assert screens == expected_check(key, path)
    reply = client.get_async_response().data
    assert len(reply) == 65 and reply == key


@pytest.mark.parametrize("name", list(INDEPENDENT_KEYS))
def test_check_matches_an_independent_derivation(backend, navigator, default_screenshot_path, test_name, name):
    """Multi-byte account and index: path, address and key match an off-device derivation. Only
    these cases catch a check that keeps part of a component."""
    path, compressed_key = INDEPENDENT_KEYS[name]
    key = uncompressed_key(bytes.fromhex(compressed_key))
    client = ElastosCommandSender(backend)
    with client.show_address(path):
        screens = walk_review(backend, navigator, default_screenshot_path, f"{test_name}_{name.replace('-', '_')}",
                              final="Approve")
    assert screens == expected_check(key, path)
    assert client.get_async_response().data == key


@pytest.mark.parametrize("name", list(CHECK_ONLY_KEYS))
def test_check_sends_a_key_outside_the_silent_range(backend, navigator, default_screenshot_path, test_name, name):
    """One past the silent range: refused without the check, and the off-device key on Approve."""
    path, compressed_key = CHECK_ONLY_KEYS[name]
    key = uncompressed_key(bytes.fromhex(compressed_key))
    client = ElastosCommandSender(backend)
    assert_refused_showing_nothing(backend, raw_apdu(InsType.GET_PUBLIC_KEY, KeyP1.SILENT, path),
                                   Errors.SW_PATH_NEEDS_CHECK)
    with client.show_address(path):
        screens = walk_review(backend, navigator, default_screenshot_path, f"{test_name}_{name.replace('-', '_')}",
                              final="Approve")
    assert screens == expected_check(key, path)
    assert client.get_async_response().data == key


def test_rejected_check_outside_the_silent_range(backend):
    """Reject answers 6985 with no key, and the key stays refused without the check."""
    path, compressed_key = CHECK_ONLY_KEYS["account-101"]
    key = uncompressed_key(bytes.fromhex(compressed_key))
    client = ElastosCommandSender(backend)
    home = settled_lines(backend)
    with pytest.raises(ExceptionRAPDU) as rejected:
        with client.show_address(path):
            screens = walk_review_text(backend, final="Reject")
    assert rejected.value.status == Errors.SW_USER_REJECTED
    assert screens == expected_check(key, path) + [["Approve"]]
    assert settled_lines(backend) == home
    assert_refused_showing_nothing(backend, raw_apdu(InsType.GET_PUBLIC_KEY, KeyP1.SILENT, path),
                                   Errors.SW_PATH_NEEDS_CHECK)


def test_rejected_check_leaves_the_app_ready(backend, navigator, default_screenshot_path, test_name):
    """Reject answers 6985; key requests and signing still work after."""
    client = ElastosCommandSender(backend)
    home = settled_lines(backend)
    key = client.get_public_key(DEFAULT_PATH).data
    with pytest.raises(ExceptionRAPDU) as rejected:
        with client.show_address(DEFAULT_PATH):
            screens = walk_review(backend, navigator, default_screenshot_path, test_name, final="Reject")
    assert rejected.value.status == Errors.SW_USER_REJECTED
    assert screens == expected_check(key, DEFAULT_PATH) + [["Approve"]]
    assert settled_lines(backend) == home
    assert client.get_public_key(DEFAULT_PATH).data == key
    body = wallet_tx(ela(1), ela(2), program_hash(key))
    with client.sign(body, DEFAULT_PATH):
        walk_review_text(backend)
    assert verify_signature(key, body, client.get_async_response().data)


def test_both_buttons_do_nothing_before_approve(backend):
    client = ElastosCommandSender(backend)
    key = client.get_public_key(OTHER_PATH).data
    with client.show_address(OTHER_PATH):
        screens = walk_review_text(backend, final="Approve", press_both_on_each=True)
    assert screens == expected_check(key, OTHER_PATH)
    assert client.get_async_response().data == key


@pytest.mark.parametrize("p1, p2", [
    pytest.param(0x02, 0, id="p1-02"),
    pytest.param(KeyP1.SHOW, 1, id="show-p2-01"),
    pytest.param(KeyP1.SILENT, 1, id="silent-p2-01"),
])
def test_bad_p1_or_p2_is_refused(backend, p1, p2):
    assert_refused_showing_nothing(backend, raw_apdu(InsType.GET_PUBLIC_KEY, p1, DEFAULT_PATH, p2=p2),
                                   Errors.SW_WRONG_P1P2)


@pytest.mark.parametrize("path", [
    pytest.param(pack_path(change=HARDENED | 1), id="change-1-hardened"),
    pytest.param(pack_path(hardened_account=False), id="account-not-hardened"),
])
def test_refused_path_shows_nothing(backend, path):
    assert_refused_showing_nothing(backend, raw_apdu(InsType.GET_PUBLIC_KEY, KeyP1.SHOW, path), Errors.SW_BAD_PATH)


@pytest.mark.parametrize("p1", [pytest.param(KeyP1.SILENT, id="silent"), pytest.param(KeyP1.SHOW, id="show")])
@pytest.mark.parametrize("extra", [pytest.param(1, id="1-byte"), pytest.param(3, id="3-bytes")])
def test_bytes_after_the_path_are_refused(backend, p1, extra):
    """1 to 3 extra bytes cannot form a sixth component, so only these catch a lax length check."""
    assert_refused_showing_nothing(backend, raw_apdu(InsType.GET_PUBLIC_KEY, p1, DEFAULT_PATH + bytes(extra)),
                                   Errors.SW_WRONG_LENGTH)


def test_wallet_framing_with_zero_length_byte(backend):
    client = ElastosCommandSender(backend)
    key = client.get_public_key(DEFAULT_PATH).data
    with client.show_address(DEFAULT_PATH, wallet_framing=True):
        assert walk_review_text(backend, final="Approve") == expected_check(key, DEFAULT_PATH)
    assert client.get_async_response().data == key


def test_request_during_a_check_is_turned_away(backend):
    """The SDK answers 6901 to every command while the check waits, a second check included; the
    check still replies with its key on Approve."""
    client = ElastosCommandSender(backend)
    key = client.get_public_key(DEFAULT_PATH).data
    body = wallet_tx(ela(1), ela(2), program_hash(key))
    home = settled_lines(backend)
    busy = Errors.SW_REVIEW_PENDING.to_bytes(2, "big")
    with ApduSocket(backend) as device:
        device.send(raw_apdu(InsType.GET_PUBLIC_KEY, KeyP1.SHOW, DEFAULT_PATH))
        assert settled_lines(backend, differ_from=home) == expected_check(key, DEFAULT_PATH)[0]
        turned_away = (raw_apdu(InsType.GET_PUBLIC_KEY, KeyP1.SILENT, DEFAULT_PATH),
                       raw_apdu(InsType.GET_PUBLIC_KEY, KeyP1.SHOW, OTHER_PATH),
                       raw_apdu(InsType.SIGN, P1.LAST, body + DEFAULT_PATH))
        for apdu in turned_away:
            with pytest.raises(ExceptionRAPDU) as refused:
                backend.exchange_raw(apdu, tick_timeout=100)
            assert refused.value.status == Errors.SW_REVIEW_PENDING
        assert walk_review_text(backend, final="Approve") == expected_check(key, DEFAULT_PATH)
        replies = [device.receive() for _ in range(len(turned_away) + 1)]
        assert replies == [busy] * len(turned_away) + [key + b"\x90\x00"]
        assert settled_lines(backend) == home
        assert client.get_public_key(DEFAULT_PATH).data == key
