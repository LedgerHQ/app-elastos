"""Off-device reference for paths, addresses and signatures."""
import hashlib

from Crypto.Hash import RIPEMD160
from ecdsa import NIST256p, VerifyingKey
from ecdsa.util import sigdecode_der

HARDENED = 0x80000000
BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
P256_ORDER = NIST256p.order


def pack_path(account: int = 0, change: int = 0, index: int = 0, hardened_account: bool = True,
              coin_type: int = 2305, purpose: int = 44, hardened_purpose: bool = True,
              hardened_coin_type: bool = True) -> bytes:
    """Big-endian 44'/2305'/account'/change/index; change and index are used as given."""
    parts = [(HARDENED if hardened_purpose else 0) | purpose, (HARDENED if hardened_coin_type else 0) | coin_type,
             (HARDENED if hardened_account else 0) | account, change, index]
    return b"".join(p.to_bytes(4, "big") for p in parts)


DEFAULT_PATH = pack_path()

# Compressed keys derived off the device (SLIP-10, P-256) for multi-byte accounts and indexes, so
# a component decoded wrongly on the device gives a different key
INDEPENDENT_KEYS = {
    "large-components": (pack_path(account=65537, change=1, index=65538),
                         "029f8058fd5ad97d6caa075b379615b9295c2dccb22b839411f358b1e8b2e0bc52"),
    "every-byte-used": (pack_path(account=16909060, index=0x7FFFFFFF),
                        "030ca1db23a6fe0a9a7a43e949dea08c4a883fb7d5f1d5b932031ac26e38d2a1c6"),
    # longest path; the address check shows it on three lines
    "longest-path": (pack_path(account=0x7FFFFFFF, change=1, index=0x7FFFFFFF),
                     "03fa248de2f069c0b6eed5c0870065be84263172e5f3a3813c10b29754e2551b46"),
}

# Edges of the range P1 00 answers without the check, as Ledger's Bitcoin app: accounts 0' to 100',
# indexes to 50,000. CHECK_ONLY_KEYS are one past it and need the check (P1 01).
SILENT_KEYS = {
    "last-account-and-index": (pack_path(account=100, index=50000),
                               "0341b7645fb3d07f03f0359911e05fd387498f4e3c606833f76b921c30ebeba063"),
    "change-1": (pack_path(change=1), "02d35f471d0fff10d19f4b1c21e9ac876b66c1bd7543dd7ca44efa8c2d0963a841"),
}
CHECK_ONLY_KEYS = {
    "account-101": (pack_path(account=101), "03326a348455498b95786ea591715e09dc663edaf516d966c4d84e65723cde8b53"),
    "index-50001": (pack_path(index=50001), "03dffab70bd63855d1940d0266f5b9d6e766981bfd37bcc6cafa54c2053913dd15"),
}


def uncompressed_key(compressed: bytes) -> bytes:
    """The 65-byte uncompressed form the device sends."""
    return VerifyingKey.from_string(compressed, curve=NIST256p).to_string("uncompressed")


def program_hash(public_key: bytes) -> bytes:
    """0x21 followed by RIPEMD160(SHA256(push 33, compressed key, OP_CHECKSIG))."""
    compressed = bytes([0x03 if public_key[64] & 1 else 0x02]) + public_key[1:33]
    script = bytes([0x21]) + compressed + bytes([0xAC])
    # pycryptodome: some OpenSSL builds drop RIPEMD-160 from hashlib
    return bytes([0x21]) + RIPEMD160.new(hashlib.sha256(script).digest()).digest()


def base58_address(program_hash21: bytes) -> str:
    payload = program_hash21 + hashlib.sha256(hashlib.sha256(program_hash21).digest()).digest()[:4]
    n = int.from_bytes(payload, "big")
    out = ""
    while n > 0:
        n, r = divmod(n, 58)
        out = BASE58_ALPHABET[r] + out
    return out


def verify_signature(public_key: bytes, body: bytes, der: bytes) -> bool:
    key = VerifyingKey.from_string(public_key, curve=NIST256p)
    return key.verify(der, body, hashfunc=hashlib.sha256, sigdecode=sigdecode_der)


def is_low_s(der: bytes) -> bool:
    _, s = sigdecode_der(der, P256_ORDER)
    return s <= P256_ORDER // 2


def der_length(der: bytes) -> int:
    """From the DER header, so bytes after the signature are not counted."""
    return der[1] + 2
