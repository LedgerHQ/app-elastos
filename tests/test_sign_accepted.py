"""Signing after a full review of outputs, signer, memo and fee notice; the signature covers
exactly the reviewed bytes, and nothing follows it."""
import json
from pathlib import Path

import pytest
from ragger.error import ExceptionRAPDU

from application_client.elastos_command_sender import ElastosCommandSender, Errors
from application_client.elastos_review import (LINE_WIDTH_PX, LONGEST_MEMO, expected_review, full_line_memo,
                                               line_width, memo_lines, memo_screens, walk_review, walk_review_text)
from application_client.elastos_transaction import (PH_MERCH2, PH_MERCHANT, PH_MULTISIG, build_tx, ela, output,
                                                    payment_with_memo, poll_vote_memo, poll_vote_tx, txinput,
                                                    wallet_memo, wallet_tx)
from application_client.elastos_utils import (DEFAULT_PATH, base58_address, der_length, is_low_s, pack_path,
                                              program_hash, verify_signature)

AUDIT_VECTORS = json.loads((Path(__file__).parent / "vectors" / "audit_vectors.json").read_text())

# v1.1.5's signature of baseline-clean; signing is deterministic, so the fix must match it.
BASELINE_SIGNATURE_V115 = bytes.fromhex(
    "304402204f00a3a21754435adee49b2f6b38850f2638e0878700dda5ff20efb6f5e66bba"
    "022056e60d83c67d08b70cfd0c923bff922ebf43c89a0c75939d6dd12b64ae5d003c")

MERCHANT = base58_address(PH_MERCHANT)
MERCHANT_2 = base58_address(PH_MERCH2)
MULTISIG = base58_address(PH_MULTISIG)

# Two memo screens long, and pushes the wallet's payment past one message
INVOICE_NOTE = "Invoice 2024-117 for consulting, paid in full. Thank you!"


def sign_and_check(backend, navigator, snapshots_path, test_name, body: bytes, expected_screens,
                   path: bytes = DEFAULT_PATH) -> bytes:
    client = ElastosCommandSender(backend)
    public_key = client.get_public_key(path).data
    with client.sign(body, path):
        screens = walk_review(backend, navigator, snapshots_path, test_name)
    reply = client.get_async_response().data
    assert screens == expected_screens(public_key)
    assert len(reply) == der_length(reply), "nothing may follow the signature"
    assert verify_signature(public_key, body, reply)
    assert is_low_s(reply)
    return reply


def signer_of(public_key: bytes) -> tuple[str, bytes]:
    ph = program_hash(public_key)
    return base58_address(ph), ph


def test_baseline_matches_v115_signature(backend, navigator, default_screenshot_path, test_name):
    body = bytes.fromhex(AUDIT_VECTORS["baseline-clean"]["tx"])

    def expected(key):
        me, _ = signer_of(key)
        return expected_review(me, [(True, ela(0.01), me), (True, 5139956, me)])

    assert sign_and_check(backend, navigator, default_screenshot_path, test_name, body,
                          expected) == BASELINE_SIGNATURE_V115


def test_wallet_send_with_change(backend, navigator, default_screenshot_path, test_name):
    me_key = ElastosCommandSender(backend).get_public_key(DEFAULT_PATH).data
    me, me_ph = signer_of(me_key)
    body = wallet_tx(ela(1.5), ela(48.49), me_ph)
    sign_and_check(backend, navigator, default_screenshot_path, test_name, body,
                   lambda _: expected_review(me, [(False, ela(1.5), MERCHANT), (True, ela(48.49), me)],
                                             memo=wallet_memo()))


def test_wallet_send_with_zero_change(backend, navigator, default_screenshot_path, test_name):
    """The wallet always adds a change output, even when it is zero."""
    me, me_ph = signer_of(ElastosCommandSender(backend).get_public_key(DEFAULT_PATH).data)
    body = wallet_tx(ela(2), 0, me_ph)
    sign_and_check(backend, navigator, default_screenshot_path, test_name, body,
                   lambda _: expected_review(me, [(False, ela(2), MERCHANT), (True, 0, me)], memo=wallet_memo()))


def test_memo_is_shown(backend, navigator, default_screenshot_path, test_name):
    """A non-vote memo is shown whole after the signer, the "type:text,msg:" prefix included."""
    me, me_ph = signer_of(ElastosCommandSender(backend).get_public_key(DEFAULT_PATH).data)
    body = wallet_tx(ela(1.5), ela(48.49), me_ph, memo="Rent for October")
    sign_and_check(backend, navigator, default_screenshot_path, test_name, body,
                   lambda _: expected_review(me, [(False, ela(1.5), MERCHANT), (True, ela(48.49), me)],
                                             memo=wallet_memo("Rent for October")))


def test_memo_over_two_screens(backend, navigator, default_screenshot_path, test_name):
    """Headed "Memo 1 of 2" and "Memo 2 of 2"."""
    me, _ = signer_of(ElastosCommandSender(backend).get_public_key(DEFAULT_PATH).data)
    memo = wallet_memo(INVOICE_NOTE)
    assert len(memo_screens(memo)) == 2
    body = payment_with_memo(memo, [output(PH_MERCHANT, ela(12))])
    sign_and_check(backend, navigator, default_screenshot_path, test_name, body,
                   lambda _: expected_review(me, [(False, ela(12), MERCHANT)], memo=memo))


@pytest.mark.parametrize("outputs", [1, 2, 3])
def test_longest_memo_that_fits(backend, navigator, default_screenshot_path, test_name, outputs):
    """The memo gets the screens of nine left after the signer, outputs and fee: five, three or one.
    One byte more is refused in test_sign_refused."""
    me, me_ph = signer_of(ElastosCommandSender(backend).get_public_key(DEFAULT_PATH).data)
    memo = full_line_memo(LONGEST_MEMO[outputs])
    assert all(len(line) == 17 for line in memo_lines(memo))
    payees = [(False, ela(1), MERCHANT, PH_MERCHANT), (False, ela(2), MERCHANT_2, PH_MERCH2),
              (True, ela(3), me, me_ph)][:outputs]
    body = payment_with_memo(memo, [output(ph, sela) for _, sela, _, ph in payees])
    sign_and_check(backend, navigator, default_screenshot_path, f"{test_name}_{outputs}_outputs", body,
                   lambda _: expected_review(me, [(own, sela, address) for own, sela, address, _ in payees],
                                             memo=memo))


def test_memo_lines_broken_by_width(backend, navigator, default_screenshot_path, test_name):
    """Lines ended by width, not 17 characters: eleven m and two i, then "m ", ten W and a space,
    are each exactly 116 px, shown whole with no "...", and push the next character on."""
    me, _ = signer_of(ElastosCommandSender(backend).get_public_key(DEFAULT_PATH).data)
    memo = wallet_memo("m" * 11 + "ii" + "m " + "W" * 10 + " Wi")
    lines = memo_lines(memo)
    assert lines == ["type:text,msg:", "m" * 11 + "ii", "m " + "W" * 10 + " ", "Wi"]
    assert [line_width(line) for line in lines[1:3]] == [LINE_WIDTH_PX, LINE_WIDTH_PX]
    assert line_width(lines[1] + lines[2][0]) > LINE_WIDTH_PX
    assert line_width(lines[2] + lines[3][0]) > LINE_WIDTH_PX
    body = payment_with_memo(memo, [output(PH_MERCHANT, ela(1))])
    sign_and_check(backend, navigator, default_screenshot_path, test_name, body,
                   lambda _: expected_review(me, [(False, ela(1), MERCHANT)], memo=memo))


def test_fee_slot_output_is_shown_as_a_payment(backend, navigator, default_screenshot_path, test_name):
    """v1.1.5 labelled this third output, 950 ELA to another address, as the fee."""
    body = bytes.fromhex(AUDIT_VECTORS["b-fee-slot"]["tx"])
    attacker = "EdULVVQJNEE222GyEHGeubnTaSSmBttLgE"

    def expected(key):
        me, _ = signer_of(key)
        return expected_review(me, [(False, ela(1), "EacksRXrSsufWF1qJCxfZeX6ggxFBMviny"), (True, ela(48), me),
                                    (False, ela(950), attacker)])

    sign_and_check(backend, navigator, default_screenshot_path, test_name, body, expected)


def test_amounts_keep_every_digit(backend, navigator, default_screenshot_path, test_name):
    """v1.1.5 cut amounts short on screen."""
    body = bytes.fromhex(AUDIT_VECTORS["f-digit-truncation"]["tx"])
    recipient = "EacksRXrSsufWF1qJCxfZeX6ggxFBMviny"

    def expected(key):
        me, _ = signer_of(key)
        return expected_review(me, [(False, 99999999, recipient), (False, 123456789, recipient),
                                    (False, 1, recipient)])

    sign_and_check(backend, navigator, default_screenshot_path, test_name, body, expected)


def test_widest_amount(backend, navigator, default_screenshot_path, test_name):
    body = build_tx([output(PH_MERCHANT, ela(28_000_000) + 12345678)])
    sign_and_check(backend, navigator, default_screenshot_path, test_name, body,
                   lambda key: expected_review(signer_of(key)[0], [(False, ela(28_000_000) + 12345678, MERCHANT)]))


def test_amount_at_the_edge_of_the_screen(backend, navigator, default_screenshot_path, test_name):
    """115 px, 1 px inside the line: shown with every digit."""
    body = build_tx([output(PH_MERCHANT, 1444444440000000)])
    sign_and_check(backend, navigator, default_screenshot_path, test_name, body,
                   lambda key: expected_review(signer_of(key)[0], [(False, 1444444440000000, MERCHANT)]))


def test_three_outputs_and_two_coins(backend, navigator, default_screenshot_path, test_name):
    me, me_ph = signer_of(ElastosCommandSender(backend).get_public_key(DEFAULT_PATH).data)
    body = build_tx([output(PH_MERCHANT, ela(1)), output(PH_MERCH2, ela(2)), output(me_ph, ela(3))],
                    inputs=[txinput(index=0), txinput(index=1)])
    sign_and_check(backend, navigator, default_screenshot_path, test_name, body,
                   lambda _: expected_review(me, [(False, ela(1), MERCHANT), (False, ela(2), MERCHANT_2),
                                                  (True, ela(3), me)]))


def test_version_9_transfer(backend, navigator, default_screenshot_path, test_name):
    me, me_ph = signer_of(ElastosCommandSender(backend).get_public_key(DEFAULT_PATH).data)
    body = build_tx([output(PH_MERCHANT, ela(3), otype=0), output(me_ph, ela(4), otype=0)], version=9)
    sign_and_check(backend, navigator, default_screenshot_path, test_name, body,
                   lambda _: expected_review(me, [(False, ela(3), MERCHANT), (True, ela(4), me)]))


def test_multisig_recipient(backend, navigator, default_screenshot_path, test_name):
    body = build_tx([output(PH_MULTISIG, ela(1))])
    sign_and_check(backend, navigator, default_screenshot_path, test_name, body,
                   lambda key: expected_review(signer_of(key)[0], [(False, ela(1), MULTISIG)]))


def test_other_account_recognises_its_own_change(backend, navigator, default_screenshot_path, test_name):
    """Change comes from the signing path: account 0's address is a recipient for account 1."""
    path = pack_path(account=1, change=1, index=7)
    client = ElastosCommandSender(backend)
    me, me_ph = signer_of(client.get_public_key(path).data)
    default, default_ph = signer_of(client.get_public_key(DEFAULT_PATH).data)
    body = build_tx([output(default_ph, ela(5)), output(me_ph, ela(6))])
    sign_and_check(backend, navigator, default_screenshot_path, test_name, body,
                   lambda _: expected_review(me, [(False, ela(5), default), (True, ela(6), me)]), path=path)


def test_key_with_an_odd_y(backend, navigator, default_screenshot_path, test_name):
    """An odd Y changes the address script's first byte; 44'/2305'/0'/0/1 has one."""
    path = pack_path(index=1)
    client = ElastosCommandSender(backend)
    key = client.get_public_key(path).data
    assert key[64] & 1, "the test needs a key with an odd Y"
    me, me_ph = signer_of(key)
    default, default_ph = signer_of(client.get_public_key(DEFAULT_PATH).data)
    body = build_tx([output(default_ph, ela(5)), output(me_ph, ela(6))])
    sign_and_check(backend, navigator, default_screenshot_path, test_name, body,
                   lambda _: expected_review(me, [(False, ela(5), default), (True, ela(6), me)]), path=path)


def test_twenty_coins(backend, navigator, default_screenshot_path, test_name):
    """The wallet consolidates up to 20 coins in one Ledger payment."""
    me, me_ph = signer_of(ElastosCommandSender(backend).get_public_key(DEFAULT_PATH).data)
    body = build_tx([output(PH_MERCHANT, ela(19)), output(me_ph, ela(0.9999))],
                    inputs=[txinput(index=k) for k in range(20)])
    sign_and_check(backend, navigator, default_screenshot_path, test_name, body,
                   lambda _: expected_review(me, [(False, ela(19), MERCHANT), (True, ela(0.9999), me)]))


def test_fee_burn_is_shown_as_two_outputs(backend, navigator, default_screenshot_path, test_name):
    """The device cannot see input values, so it shows both outputs and flags the fee unchecked."""
    body = bytes.fromhex(AUDIT_VECTORS["k-fee-burn"]["tx"])

    def expected(key):
        me, _ = signer_of(key)
        return expected_review(me, [(False, ela(100), "EacksRXrSsufWF1qJCxfZeX6ggxFBMviny"), (True, ela(100), me)])

    sign_and_check(backend, navigator, default_screenshot_path, test_name, body, expected)


def test_poll_vote(backend, navigator, default_screenshot_path, test_name):
    """Essentials votes by paying yourself with the vote in the memo; the device shows the choice
    (from 1, as the wallet lists them), the amount and the whole poll id."""
    me, me_ph = signer_of(ElastosCommandSender(backend).get_public_key(DEFAULT_PATH).data)
    poll_id = bytes.fromhex("9f2c6a1e0b7d4c3a8e5f1b2d6c0a9e7f3b4d5c6a7e8f9a0b1c2d3e4f5a6b7c8d")
    body = poll_vote_tx(me_ph, ela(1234.5), ela(0.9999), poll_vote_memo(poll_id, 1, "1234.5"))
    sign_and_check(backend, navigator, default_screenshot_path, test_name, body,
                   lambda _: expected_review(me, [(True, ela(1234.5), me), (True, ela(0.9999), me)],
                                             vote=(2, "1234.5", poll_id)))


def test_two_part_transaction(backend, navigator, default_screenshot_path, test_name):
    """A memo pushes the transaction past one message."""
    me, me_ph = signer_of(ElastosCommandSender(backend).get_public_key(DEFAULT_PATH).data)
    body = wallet_tx(ela(1), ela(2), me_ph, memo=INVOICE_NOTE)
    assert len(body) + 20 > 255
    sign_and_check(backend, navigator, default_screenshot_path, test_name, body,
                   lambda _: expected_review(me, [(False, ela(1), MERCHANT), (True, ela(2), me)],
                                             memo=wallet_memo(INVOICE_NOTE)))


@pytest.mark.parametrize("memo_bytes", [
    pytest.param(252, id="longest-single-byte-length"),
    pytest.param(253, id="shortest-three-byte-length"),
])
def test_long_memo(backend, navigator, default_screenshot_path, test_name, memo_bytes):
    """253 bytes or more take a three-byte length, which the node and so the device accept."""
    me, _ = signer_of(ElastosCommandSender(backend).get_public_key(DEFAULT_PATH).data)
    memo = full_line_memo(memo_bytes)
    body = payment_with_memo(memo, [output(PH_MERCHANT, ela(1))])
    assert len(memo_screens(memo)) == 5
    sign_and_check(backend, navigator, default_screenshot_path, f"{test_name}_{memo_bytes}", body,
                   lambda _: expected_review(me, [(False, ela(1), MERCHANT)], memo=memo))


@pytest.mark.parametrize("kind", ["payment", "poll-vote"])
def test_both_buttons_do_nothing_before_accept(backend, kind):
    """Both buttons do nothing before Accept, the intro included."""
    client = ElastosCommandSender(backend)
    key = client.get_public_key(DEFAULT_PATH).data
    me, me_ph = signer_of(key)
    if kind == "payment":
        body = wallet_tx(ela(1.5), ela(48.49), me_ph)
        expected = expected_review(me, [(False, ela(1.5), MERCHANT), (True, ela(48.49), me)], memo=wallet_memo())
    else:
        poll_id = bytes(range(32))
        body = poll_vote_tx(me_ph, ela(14), ela(0.9999), poll_vote_memo(poll_id, 0, "14"))
        expected = expected_review(me, [(True, ela(14), me), (True, ela(0.9999), me)], vote=(1, "14", poll_id))
    with client.sign(body, DEFAULT_PATH):
        screens = walk_review_text(backend, press_both_on_each=True)
    assert screens == expected
    reply = client.get_async_response().data
    assert len(reply) == der_length(reply) and verify_signature(key, body, reply)


def test_reviews_one_after_another(backend):
    """After a short, a rejected and a refused review, a longer review still shows every screen."""
    client = ElastosCommandSender(backend)
    key = client.get_public_key(DEFAULT_PATH).data
    me, me_ph = signer_of(key)
    short = build_tx([output(PH_MERCHANT, ela(1))])
    long = build_tx([output(PH_MERCHANT, ela(1)), output(PH_MERCH2, ela(950)), output(me_ph, ela(3))])
    poll_id = bytes(range(32))
    vote = poll_vote_tx(me_ph, ela(14), ela(0.9999), poll_vote_memo(poll_id, 2, "14"))
    with client.sign(short, DEFAULT_PATH):
        assert walk_review_text(backend) == expected_review(me, [(False, ela(1), MERCHANT)])
    assert verify_signature(key, short, client.get_async_response().data)
    with pytest.raises(ExceptionRAPDU) as rejected:
        with client.sign(short, DEFAULT_PATH):
            walk_review_text(backend, final="Reject")
    assert rejected.value.status == Errors.SW_USER_REJECTED
    with pytest.raises(ExceptionRAPDU):
        client.sign_expecting_refusal(bytes(40), DEFAULT_PATH)
    for body, outputs, vote_screens in (
            (long, [(False, ela(1), MERCHANT), (False, ela(950), MERCHANT_2), (True, ela(3), me)], None),
            (vote, [(True, ela(14), me), (True, ela(0.9999), me)], (3, "14", poll_id))):
        with client.sign(body, DEFAULT_PATH):
            assert walk_review_text(backend) == expected_review(me, outputs, vote=vote_screens)
        assert verify_signature(key, body, client.get_async_response().data)


def test_user_rejects(backend, navigator, default_screenshot_path, test_name):
    client = ElastosCommandSender(backend)
    me, me_ph = signer_of(client.get_public_key(DEFAULT_PATH).data)
    with pytest.raises(ExceptionRAPDU) as rejected:
        with client.sign(wallet_tx(ela(1.5), ela(48.49), me_ph), DEFAULT_PATH):
            walk_review(backend, navigator, default_screenshot_path, test_name, final="Reject")
    assert rejected.value.status == Errors.SW_USER_REJECTED
