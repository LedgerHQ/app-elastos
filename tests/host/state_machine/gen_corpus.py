#!/usr/bin/env python3
"""Generate corpus.h for the state-machine fuzzer.

Each entry is an APDU as a host sends it: [0x80, 0x02, P1, 0x00, Lc, chunk], P1 = 0x80 on the last
chunk, the 20-byte path after the body. Legitimate transfers let the fuzzer reach deep review
states; attack transactions from tests/vectors, refused paths and malformed key requests are mixed
in. Key requests also come at the edges of the range P1 00 is answered for.

stub_program_hash matches the harness stubs, so outputs paying the signer are labelled as change.

usage: gen_corpus.py <output corpus.h>
"""
import hashlib
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
TESTS = os.path.abspath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, TESTS)
from application_client import elastos_transaction as B  # noqa: E402

VECTORS = {name: v["tx"] for name, v in
           json.load(open(os.path.join(TESTS, "vectors", "audit_vectors.json"))).items()}

PATH_STD = bytes.fromhex("8000002C" "80000901" "80000000" "00000000" "00000000")
PATH_ACCOUNT_1 = bytes.fromhex("8000002C" "80000901" "80000001" "00000001" "00000007")
PATH_BAD = bytes.fromhex("8000002C" "80000901" "00000000" "00000000" "00000000")
# Edges of the range a key request without the address check (P1 00) is answered for, as in
# Ledger's Bitcoin app: 100'/1/50000 is inside, account 101' and index 50,001 are not.
PATH_SILENT_EDGE = bytes.fromhex("8000002C" "80000901" "80000064" "00000001" "0000C350")
PATH_ACCOUNT_101 = bytes.fromhex("8000002C" "80000901" "80000065" "00000000" "00000000")
PATH_INDEX_50001 = bytes.fromhex("8000002C" "80000901" "80000000" "00000000" "0000C351")
# Refused paths one bit from an allowed one. The OS will not derive an unhardened purpose or coin
# type but the stub does, so only the app's own rule stops them here.
REFUSED_PATHS = [
    ("hardened_change_0", bytes.fromhex("8000002C" "80000901" "80000000" "80000000" "00000000")),
    ("hardened_change_1", bytes.fromhex("8000002C" "80000901" "80000000" "80000001" "00000000")),
    ("unhardened_purpose", bytes.fromhex("0000002C" "80000901" "80000000" "00000000" "00000000")),
    ("unhardened_coin", bytes.fromhex("8000002C" "00000901" "80000000" "00000000" "00000000")),
]


def stub_program_hash(path: bytes) -> bytes:
    """The program hash the stubs in stubs/os.h and stubs/cx.h derive for a path."""
    x = 0xE1A5
    for i in range(5):
        x = (x * 31 + int.from_bytes(path[4 * i:4 * i + 4], "big")) & 0xFFFFFFFF
        x ^= x >> 16
    raw = []
    for _ in range(64):
        x = (x * 1103515245 + 12345) & 0xFFFFFFFF
        raw.append((x >> 16) & 0xFF)
    w = [4] + [raw[i % 32] ^ i for i in range(1, 65)]
    script = bytes([33, 0x03 if w[64] & 1 else 0x02]) + bytes(w[1:33]) + bytes([0xAC])
    ripemd = hashlib.sha256(hashlib.sha256(script).digest()).digest()[:20]
    return bytes([0x21]) + bytes(b ^ 0x3C for b in ripemd)


SIGNER_PH = stub_program_hash(PATH_STD)


def out(sela, ph=B.PH_MERCHANT, **kw):
    return B.output(ph, sela, **kw)


def tx(outputs, attrs=None, inputs=None, locktime=0, version=0):
    return B.build_tx(outputs, attrs=attrs, inputs=inputs, locktime=locktime, version=version)


def wallet_tx(send, change, memo):
    attrs = [B.attribute(0x00, bytes.fromhex("0102030405060708")),
             B.attribute(0x81, ("type:text,msg:" + memo).encode())]
    return tx([out(send), out(change, SIGNER_PH)], attrs=attrs)


def sign_apdus(body: bytes, path: bytes = PATH_STD, chunk: int = 255):
    payload = body + path
    apdus, offset = [], 0
    while offset != len(payload):
        part = payload[offset:offset + chunk]
        p1 = 0x80 if offset + len(part) == len(payload) else 0x00
        apdus.append(bytes([0x80, 0x02, p1, 0x00, len(part)]) + part)
        offset += len(part)
    return apdus


LEGIT = [
    ("baseline_clean", bytes.fromhex(VECTORS["baseline-clean"]), PATH_STD),
    ("wallet_send_change", wallet_tx(B.ela(1.5), B.ela(48.49), "hello"), PATH_STD),
    ("wallet_zero_change", wallet_tx(B.ela(2), 0, "x"), PATH_STD),
    ("three_outputs", tx([out(B.ela(1)), out(B.ela(2), B.PH_MERCH2), out(B.ela(3), SIGNER_PH)]), PATH_STD),
    ("v9_transfer", tx([out(B.ela(3), otype=0), out(B.ela(4), SIGNER_PH, otype=0)], version=9), PATH_STD),
    ("multisig_recipient", tx([out(B.ela(1), bytes([0x12]) + b"\x42" * 20)]), PATH_STD),
    ("widest_amount", tx([out(B.ela(28_000_000) + 12345678)]), PATH_STD),
    ("other_account", wallet_tx(B.ela(7), B.ela(1), "acct"), PATH_ACCOUNT_1),
    ("poll_vote", B.poll_vote_tx(SIGNER_PH, B.ela(14), B.ela(0.9999), B.poll_vote_memo(bytes(range(32)), 1, "14")),
     PATH_STD),
]
# long enough to need two parts, short enough to be shown
MULTI = ("two_part_memo", wallet_tx(B.ela(1), B.ela(2), "Invoice 2024-117 for consulting, paid in full. Thank you!"),
         PATH_STD)
ATTACKS = [
    ("a_4th_output", bytes.fromhex(VECTORS["a-4th-output"]), PATH_STD),
    ("d2_vote_v1", bytes.fromhex(VECTORS["d2-vote-v1"]), PATH_STD),
    ("e_crosschain_v9", bytes.fromhex(VECTORS["e-crosschain-v9"]), PATH_STD),
    ("g_record_forgery", bytes.fromhex(VECTORS["g-record-forgery"]), PATH_STD),
    ("baseline_demo_trailing", bytes.fromhex(VECTORS["baseline-demo"]), PATH_STD),
    ("bad_path", bytes.fromhex(VECTORS["baseline-clean"]), PATH_BAD),
] + [(f"path_{nm}", bytes.fromhex(VECTORS["baseline-clean"]), path) for nm, path in REFUSED_PATHS]


def c_array(name: str, data: bytes) -> str:
    return f"static const unsigned char {name}[] = {{{', '.join(f'0x{b:02x}' for b in data)}}};\n"


def main():
    lines = ["/* generated by gen_corpus.py, do not edit */\n"]
    entries = []  # (c name, length)

    def add(name, data):
        lines.append(c_array(name, data))
        entries.append((name, len(data)))
        return len(entries) - 1

    legit_first, legit_parts = [], []
    for nm, body, path in LEGIT + [MULTI]:
        apdus = sign_apdus(body, path)
        legit_first.append(len(entries))
        legit_parts.append(len(apdus))
        for i, a in enumerate(apdus):
            add(f"c_{nm}_{i}", a)
    assert legit_parts[-1] == 2 and legit_parts[1] == 1
    for nm, body, path in ATTACKS:
        for i, a in enumerate(sign_apdus(body, path)):
            add(f"c_{nm}_{i}", a)
    pub_ix = add("c_getpub", bytes([0x80, 0x04, 0x00, 0x00, 20]) + PATH_STD)
    key_allowed = [pub_ix, add("c_getpub_lc0", bytes([0x80, 0x04, 0x00, 0x00, 0x00]) + PATH_STD)]
    add("c_getpub_badpath", bytes([0x80, 0x04, 0x00, 0x00, 20]) + PATH_BAD)
    key_allowed.append(add("c_getpub_account_1", bytes([0x80, 0x04, 0x00, 0x00, 20]) + PATH_ACCOUNT_1))
    key_allowed.append(add("c_getpub_silent_edge", bytes([0x80, 0x04, 0x00, 0x00, 20]) + PATH_SILENT_EDGE))
    for nm, path in REFUSED_PATHS:
        add(f"c_getpub_{nm}", bytes([0x80, 0x04, 0x00, 0x00, 20]) + path)
    add("c_getsigned_removed", bytes([0x80, 0x08, 0x00, 0x00, 20]) + PATH_STD)
    # address checks: first those that must show (the second account's first, so its key is not the
    # device's first address), then those refused, with P1 00 requests outside the silent range
    addr_first = add("c_showpub_account_1", bytes([0x80, 0x04, 0x01, 0x00, 20]) + PATH_ACCOUNT_1)
    add("c_showpub", bytes([0x80, 0x04, 0x01, 0x00, 20]) + PATH_STD)
    add("c_showpub_lc0", bytes([0x80, 0x04, 0x01, 0x00, 0x00]) + PATH_STD)
    add("c_showpub_account_101", bytes([0x80, 0x04, 0x01, 0x00, 20]) + PATH_ACCOUNT_101)
    add("c_showpub_index_50001", bytes([0x80, 0x04, 0x01, 0x00, 20]) + PATH_INDEX_50001)
    addr_shown = len(entries) - addr_first
    add("c_getpub_account_101", bytes([0x80, 0x04, 0x00, 0x00, 20]) + PATH_ACCOUNT_101)
    add("c_getpub_index_50001", bytes([0x80, 0x04, 0x00, 0x00, 20]) + PATH_INDEX_50001)
    add("c_showpub_badpath", bytes([0x80, 0x04, 0x01, 0x00, 20]) + PATH_BAD)
    for nm, path in REFUSED_PATHS:
        add(f"c_showpub_{nm}", bytes([0x80, 0x04, 0x01, 0x00, 20]) + path)
    for p1, p2 in [(0x02, 0x00), (0x80, 0x00), (0xFF, 0x00), (0x01, 0x01), (0x00, 0x01)]:
        add(f"c_getpub_p1_{p1:02x}_p2_{p2:02x}", bytes([0x80, 0x04, p1, p2, 20]) + PATH_STD)
    addr_count = len(entries) - addr_first

    lines.append("typedef struct { const unsigned char *p; unsigned int n; } corpus_apdu_t;\n")
    lines.append("static const corpus_apdu_t CORPUS[] = {\n")
    lines += [f"    {{{nm}, {ln}}},\n" for nm, ln in entries]
    lines.append("};\n")
    lines.append(f"#define CORPUS_COUNT {len(entries)}\n")
    # per legitimate transfer: first corpus index and number of parts
    lines.append(f"static const unsigned int LEGIT_FIRST[] = {{{', '.join(map(str, legit_first))}}};\n")
    lines.append(f"static const unsigned int LEGIT_PARTS[] = {{{', '.join(map(str, legit_parts))}}};\n")
    lines.append(f"#define LEGIT_COUNT {len(legit_first)}\n")
    lines.append(f"#define GETPUB_IX {pub_ix}\n")
    # address checks: first index, count, and how many at the start must show
    lines.append(f"#define ADDR_FIRST {addr_first}\n")
    lines.append(f"#define ADDR_COUNT {addr_count}\n")
    lines.append(f"#define ADDR_SHOWN {addr_shown}\n")
    # allowed key requests, which the fuzzer also sends with bytes after the path: those get 6700
    key_allowed += range(addr_first, addr_first + addr_shown)
    lines.append(f"static const unsigned int KEY_ALLOWED[] = {{{', '.join(map(str, key_allowed))}}};\n")
    lines.append(f"#define KEY_ALLOWED_COUNT {len(key_allowed)}\n")
    # the recovery check at the end of every case signs the wallet-shaped transfer
    lines.append(f"#define TAIL_SIGN_IX {legit_first[1]}\n")

    with open(sys.argv[1], "w") as f:
        f.write("".join(lines))
    print(f"wrote corpus.h: {len(entries)} APDUs; legitimate transfers and parts: {legit_parts}")


if __name__ == "__main__":
    main()
