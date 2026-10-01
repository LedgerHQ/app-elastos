"""Unshowable transactions are refused at once, without a review or leftover state."""
import json
from pathlib import Path

import pytest
from ragger.error import ExceptionRAPDU

from application_client.elastos_command_sender import ElastosCommandSender, Errors
from application_client.elastos_review import LONGEST_MEMO, full_line_memo
from application_client.elastos_transaction import (ATTR_DESCRIPTION, ATTR_MEMO, ATTR_NONCE, PH_CROSSCHAIN,
                                                    PH_DEPOSIT, attribute, build_tx, ela, output, payment_with_memo,
                                                    poll_vote_memo, wallet_memo)
from application_client.elastos_utils import DEFAULT_PATH, HARDENED, pack_path

AUDIT_VECTORS = json.loads((Path(__file__).parent / "vectors" / "audit_vectors.json").read_text())
REFUSED_AUDIT_VECTORS = {name: v for name, v in AUDIT_VECTORS.items() if v["expect"] != "sign"}
BASELINE = bytes.fromhex(AUDIT_VECTORS["baseline-clean"]["tx"])
FAKE_ASSET = bytes.fromhex("a3" * 32)
PAY = output(bytes([0x21]) + bytes(20), ela(1))
POLL_ID = bytes(range(32))
NONCE = attribute(ATTR_NONCE, b"0")


def vote_attr(memo: bytes) -> bytes:
    return attribute(ATTR_MEMO, memo)


def memo_one_byte_too_long(outputs: int) -> bytes:
    return payment_with_memo(full_line_memo(LONGEST_MEMO[outputs] + 1), [PAY] * outputs)

CONSTRUCTED = {
    "four-outputs": (build_tx([output(bytes([0x21]) + bytes(20), ela(1))] * 4), Errors.SW_TX_OUTPUT_COUNT),
    "thirteen-outputs": (build_tx([output(bytes([0x21]) + bytes(20), ela(1))] * 13), Errors.SW_TX_OUTPUT_COUNT),
    "no-outputs": (build_tx([]), Errors.SW_TX_OUTPUT_COUNT),
    "no-inputs": (build_tx([output(bytes([0x21]) + bytes(20), ela(1))], inputs=[]), Errors.SW_TX_NO_INPUTS),
    "other-asset": (build_tx([output(bytes([0x21]) + bytes(20), ela(1), asset=FAKE_ASSET)]), Errors.SW_TX_ASSET),
    "output-lock": (build_tx([output(bytes([0x21]) + bytes(20), ela(1), lock=0xFFFFFFFF)]), Errors.SW_TX_OUTPUT_LOCK),
    "lock-time": (build_tx([output(bytes([0x21]) + bytes(20), ela(1))], locktime=5), Errors.SW_TX_LOCK_TIME),
    "description-attribute": (build_tx([output(bytes([0x21]) + bytes(20), ela(1))],
                                       attrs=[attribute(ATTR_DESCRIPTION, b"x")]), Errors.SW_TX_ATTRIBUTE),
    "crosschain-address": (build_tx([output(PH_CROSSCHAIN, ela(1))]), Errors.SW_TX_ADDRESS_TYPE),
    "deposit-address": (build_tx([output(PH_DEPOSIT, ela(1))]), Errors.SW_TX_ADDRESS_TYPE),
    "negative-amount": (build_tx([output(bytes([0x21]) + bytes(20), (1 << 63) + 5)]), Errors.SW_TX_AMOUNT),
    "amount-too-wide-to-show": (build_tx([output(bytes([0x21]) + bytes(20), ela(1_000_000_000))]), Errors.SW_TX_AMOUNT),
    # 17 characters, but 117 px: the Nano X would replace its middle digits with "..."
    "amount-wider-than-the-screen": (build_tx([output(bytes([0x21]) + bytes(20), 1444444444000000)]), Errors.SW_TX_AMOUNT),
    # ESmZsYAfnQEviw3sEmbGkoWWWWWWMNwWmm: its third line is 117 px, so the Nano X would add "..."
    "address-wider-than-the-screen": (build_tx([output(bytes.fromhex("216977ba3cb8eeaa0ab7f5430018b10e21161f70d3"), ela(1))]),
                                      Errors.SW_TX_ADDRESS_TOO_WIDE),
    "version-10": (bytes([0x0A]) + build_tx([output(bytes([0x21]) + bytes(20), ela(1))]), Errors.SW_TX_UNSUPPORTED),
    "payload-version-1": (build_tx([output(bytes([0x21]) + bytes(20), ela(1))], payload_version=1), Errors.SW_TX_UNSUPPORTED),
    "record-type": (build_tx([output(bytes([0x21]) + bytes(20), ela(1))], txtype=0x03), Errors.SW_TX_UNSUPPORTED),
    "v9-output-with-payload": (build_tx([output(bytes([0x21]) + bytes(20), ela(1), otype=1, opayload=b"\x00\x00")],
                                        version=9), Errors.SW_TX_OUTPUT_TYPE),
    # the node requires a three-byte memo length to be 253 or more
    "memo-length-not-canonical": (build_tx([output(bytes([0x21]) + bytes(20), ela(1))],
                                           attrs=[bytes([ATTR_MEMO, 0xFD, 0xFC, 0x00]) + b"m" * 0xFC]),
                                  Errors.SW_TX_VARINT_TOO_LARGE),
    "memo-length-five-bytes": (build_tx([output(bytes([0x21]) + bytes(20), ela(1))],
                                        attrs=[bytes([ATTR_MEMO, 0xFE, 0x00, 0x01, 0x00, 0x00]) + b"m" * 0x100]),
                               Errors.SW_TX_VARINT_TOO_LARGE),
    # a memo that starts with "pollvote" must be exactly the wallet's vote layout
    "poll-vote-amount-with-nine-decimals": (build_tx([PAY], attrs=[vote_attr(poll_vote_memo(POLL_ID, 0, "1.123456789"))]),
                                            Errors.SW_TX_POLL_VOTE),
    "poll-vote-amount-with-a-nul": (build_tx([PAY], attrs=[vote_attr(poll_vote_memo(POLL_ID, 0, "4\x0044"))]),
                                    Errors.SW_TX_POLL_VOTE),
    "poll-vote-amount-not-a-number": (build_tx([PAY], attrs=[vote_attr(poll_vote_memo(POLL_ID, 0, "1e5"))]),
                                      Errors.SW_TX_POLL_VOTE),
    "poll-vote-longer-than-its-layout": (build_tx([PAY], attrs=[vote_attr(poll_vote_memo(POLL_ID, 0, "1") + b"x")]),
                                         Errors.SW_TX_POLL_VOTE),
    # the bare flag is an empty vote, not a note to sign unseen
    "poll-vote-flag-only": (build_tx([PAY], attrs=[vote_attr(b"pollvote")]), Errors.SW_TX_POLL_VOTE),
    "poll-vote-choice-1001": (build_tx([PAY], attrs=[vote_attr(poll_vote_memo(POLL_ID, 1000, "1"))]),
                              Errors.SW_TX_POLL_VOTE),
    # one memo at most: chain readers take one, which may not be the one shown
    "two-poll-votes": (build_tx([PAY], attrs=[vote_attr(poll_vote_memo(POLL_ID, 0, "1")),
                                              vote_attr(poll_vote_memo(POLL_ID, 1, "1"))]), Errors.SW_TX_ATTRIBUTE),
    "poll-vote-and-a-note": (build_tx([PAY], attrs=[vote_attr(poll_vote_memo(POLL_ID, 0, "1")),
                                                    attribute(ATTR_MEMO, b"type:text,msg:hi")]), Errors.SW_TX_ATTRIBUTE),
    "a-note-and-a-poll-vote": (build_tx([PAY], attrs=[attribute(ATTR_MEMO, b"type:text,msg:hi"),
                                                      vote_attr(poll_vote_memo(POLL_ID, 0, "1"))]), Errors.SW_TX_ATTRIBUTE),
    "two-memos": (build_tx([PAY], attrs=[NONCE, attribute(ATTR_MEMO, wallet_memo("one")),
                                         attribute(ATTR_MEMO, wallet_memo("two"))]), Errors.SW_TX_ATTRIBUTE),
    # one nonce at most, of at most 8 bytes: it is signed without being shown
    "two-nonces": (build_tx([PAY], attrs=[NONCE, attribute(ATTR_NONCE, b"1")]), Errors.SW_TX_ATTRIBUTE),
    "nonce-of-9-bytes": (build_tx([PAY], attrs=[attribute(ATTR_NONCE, bytes(range(1, 10)))]), Errors.SW_TX_ATTRIBUTE),
    # the vote layout is checked in a long memo and after the nonce too
    "poll-vote-padded-past-its-layout": (build_tx([PAY], attrs=[vote_attr(poll_vote_memo(POLL_ID, 0, "1") + bytes(220))]),
                                         Errors.SW_TX_POLL_VOTE),
    "malformed-vote-after-the-nonce": (build_tx([PAY], attrs=[NONCE, vote_attr(poll_vote_memo(POLL_ID, 0, "1..2"))]),
                                       Errors.SW_TX_POLL_VOTE),
    # other memos are shown whole, or refused: too long, not printable ASCII, or empty
    "memo-one-byte-too-long-for-one-output": (memo_one_byte_too_long(1), Errors.SW_TX_MEMO),
    "memo-one-byte-too-long-for-two-outputs": (memo_one_byte_too_long(2), Errors.SW_TX_MEMO),
    "memo-one-byte-too-long-for-three-outputs": (memo_one_byte_too_long(3), Errors.SW_TX_MEMO),
    "memo-of-700-bytes": (payment_with_memo(b"m" * 700, [PAY]), Errors.SW_TX_MEMO),
    "memo-not-ascii": (payment_with_memo(wallet_memo("café"), [PAY]), Errors.SW_TX_MEMO),
    "memo-with-a-line-feed": (payment_with_memo(wallet_memo("line one\nline two"), [PAY]), Errors.SW_TX_MEMO),
    "memo-with-a-nul": (payment_with_memo(wallet_memo("paid\x00 in full"), [PAY]), Errors.SW_TX_MEMO),
    "memo-empty": (payment_with_memo(b"", [PAY]), Errors.SW_TX_MEMO),
    # a vote takes three screens, so three outputs no longer fit the review
    "poll-vote-with-three-outputs": (build_tx([PAY] * 3, attrs=[vote_attr(poll_vote_memo(POLL_ID, 0, "1"))]),
                                     Errors.SW_TX_OUTPUT_COUNT),
    "one-trailing-byte": (BASELINE + b"\x00", Errors.SW_TX_TRAILING_BYTES),
    "truncated": (BASELINE[:-6], Errors.SW_TX_TRUNCATED),
}


def assert_refused_without_review(backend, body: bytes, status: int, path: bytes = DEFAULT_PATH) -> None:
    client = ElastosCommandSender(backend)
    with pytest.raises(ExceptionRAPDU) as refused:
        client.sign_expecting_refusal(body, path)
    assert refused.value.status == status, f"{refused.value.status:04X} != {status:04X}"
    backend.wait_for_home_screen()
    # no state left: the next request is answered
    assert len(client.get_public_key(DEFAULT_PATH).data) == 65


@pytest.mark.parametrize("name", sorted(REFUSED_AUDIT_VECTORS))
def test_audit_attacks_are_refused(backend, name):
    vector = REFUSED_AUDIT_VECTORS[name]
    assert_refused_without_review(backend, bytes.fromhex(vector["tx"]), Errors[vector["expect"]])


@pytest.mark.parametrize("name", sorted(CONSTRUCTED))
def test_unshowable_transactions_are_refused(backend, name):
    body, status = CONSTRUCTED[name]
    assert_refused_without_review(backend, body, status)


@pytest.mark.parametrize("path", [
    pytest.param(pack_path(hardened_account=False), id="account-not-hardened"),
    pytest.param(pack_path(coin_type=0), id="bitcoin-coin-type"),
    # hardened 0 or 1 is neither: the wallet never shows these branches
    pytest.param(pack_path(change=HARDENED | 0), id="change-0-hardened"),
    pytest.param(pack_path(change=HARDENED | 1), id="change-1-hardened"),
    pytest.param(pack_path(hardened_purpose=False), id="purpose-44-not-hardened"),
    pytest.param(pack_path(hardened_coin_type=False), id="coin-type-2305-not-hardened"),
])
def test_non_standard_signing_paths_are_refused(backend, path):
    assert_refused_without_review(backend, BASELINE, Errors.SW_BAD_PATH, path)
