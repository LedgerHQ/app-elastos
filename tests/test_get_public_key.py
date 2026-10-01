"""Public key requests: valid and refused paths, the silent range, and the account screen."""
import pytest
from ragger.error import ExceptionRAPDU
from ragger.navigator import NavInsID
from requests.exceptions import ConnectionError as EmulatorGone

from application_client.elastos_command_sender import CLA, ElastosCommandSender, Errors, InsType, KeyP1, raw_apdu
from application_client.elastos_review import assert_refused_showing_nothing, screen_lines
from application_client.elastos_utils import (CHECK_ONLY_KEYS, DEFAULT_PATH, HARDENED, INDEPENDENT_KEYS, SILENT_KEYS,
                                              base58_address, pack_path, program_hash)

# From the test phrase at 44'/2305'/0'/0/0.
TEST_ADDRESS = "EHEhJcvSmM83jVDViPoEPLaG9v9HiCpvUp"
TEST_COMPRESSED_KEY = "023845038e7a3f5f3a0d014f4327b6fa5744f5224aea240de802fcfe08740c349a"


def test_default_path_returns_the_test_key(backend):
    key = ElastosCommandSender(backend).get_public_key(DEFAULT_PATH).data
    assert len(key) == 65 and key[0] == 0x04
    assert (bytes([0x02 + (key[64] & 1)]) + key[1:33]).hex() == TEST_COMPRESSED_KEY
    assert base58_address(program_hash(key)) == TEST_ADDRESS


def test_wallet_framing_with_zero_length_byte(backend):
    client = ElastosCommandSender(backend)
    assert client.get_public_key_wallet_framing(DEFAULT_PATH).data == client.get_public_key(DEFAULT_PATH).data


def test_other_accounts_give_other_keys(backend):
    client = ElastosCommandSender(backend)
    other = client.get_public_key(pack_path(account=1, change=1, index=7)).data
    assert len(other) == 65 and other != client.get_public_key(DEFAULT_PATH).data


@pytest.mark.parametrize("path", [
    pytest.param(pack_path(hardened_account=False), id="account-not-hardened"),
    pytest.param(pack_path(index=0x80000000), id="index-hardened"),
    pytest.param(pack_path(change=2), id="change-not-0-or-1"),
    # hardened 0 or 1 is neither: the wallet never shows these branches
    pytest.param(pack_path(change=HARDENED | 0), id="change-0-hardened"),
    pytest.param(pack_path(change=HARDENED | 1), id="change-1-hardened"),
    pytest.param(pack_path(coin_type=0), id="bitcoin-coin-type"),
    pytest.param(pack_path(purpose=49), id="purpose-49"),
    pytest.param(pack_path(hardened_purpose=False), id="purpose-44-not-hardened"),
    pytest.param(pack_path(hardened_coin_type=False), id="coin-type-2305-not-hardened"),
])
def test_non_standard_paths_are_refused(backend, path):
    with pytest.raises(ExceptionRAPDU) as refused:
        ElastosCommandSender(backend).get_public_key(path)
    assert refused.value.status == Errors.SW_BAD_PATH


@pytest.mark.parametrize("path, compressed_key", [
    pytest.param(path, compressed_key, id=name) for name, (path, compressed_key) in SILENT_KEYS.items()
])
def test_keys_at_the_edge_of_the_silent_range(backend, path, compressed_key):
    """P1 00 answers up to account 100' and index 50,000, as Ledger's Bitcoin app; 50,000 takes two
    bytes, so a decoding fault gives a key other than the off-device one."""
    key = ElastosCommandSender(backend).get_public_key(path).data
    assert (bytes([0x02 + (key[64] & 1)]) + key[1:33]).hex() == compressed_key


@pytest.mark.parametrize("path", [
    pytest.param(path, id=name) for name, (path, _) in {**CHECK_ONLY_KEYS, **INDEPENDENT_KEYS}.items()
])
def test_keys_outside_the_silent_range_need_the_check(backend, path):
    """Above account 100' or index 50,000, P1 00 gets 6D63; test_address_check reads these keys."""
    assert_refused_showing_nothing(backend, raw_apdu(InsType.GET_PUBLIC_KEY, KeyP1.SILENT, path),
                                   Errors.SW_PATH_NEEDS_CHECK)


def test_longer_path_is_refused(backend):
    """The key of the first five components is not the one asked for."""
    with pytest.raises(ExceptionRAPDU) as refused:
        backend.exchange(cla=CLA, ins=InsType.GET_PUBLIC_KEY, data=DEFAULT_PATH + bytes(4))
    assert refused.value.status == Errors.SW_WRONG_LENGTH


def test_short_path_is_refused(backend):
    with pytest.raises(ExceptionRAPDU) as refused:
        backend.exchange(cla=CLA, ins=InsType.GET_PUBLIC_KEY, data=DEFAULT_PATH[:19])
    assert refused.value.status == Errors.SW_PUBKEY_PATH_TOO_SHORT


def test_account_screen_ignores_key_requests(backend, navigator, default_screenshot_path, test_name):
    """Shows the device's first address whatever key the computer asked for."""
    ElastosCommandSender(backend).get_public_key(pack_path(index=1))
    navigator.navigate_and_compare(default_screenshot_path, test_name,
                                   [NavInsID.RIGHT_CLICK, NavInsID.BOTH_CLICK],
                                   screen_change_before_first_instruction=False)
    lines = screen_lines(backend)
    assert lines[0] == "First address"
    assert "".join(lines[1:4]) == TEST_ADDRESS
    backend.right_click()
    backend.wait_for_screen_change()
    assert screen_lines(backend) == ["Back"]
    backend.both_click()
    backend.wait_for_home_screen()


def test_quit_closes_the_app(backend):
    for _ in range(3):
        backend.right_click()
        backend.wait_for_screen_change()
    assert screen_lines(backend) == ["Quit"]
    # the emulator may exit before answering the click
    with pytest.raises(EmulatorGone):
        backend.both_click()
        ElastosCommandSender(backend).get_public_key(DEFAULT_PATH)
