"""Unsigned Elastos main chain transactions, in Elastos.ELA's SerializeUnsigned byte order."""
ELA_ASSET = bytes.fromhex("b037db964a231458d2d6ffd5ea18944c4f90e63d547c5d3b9874df66a4ead0a3")
DEMO_TXID = "4f7b54a22418633bc5cf2b4a9a445b64e89b0e54d193abb14387bba5c6e9e006"

TX_TRANSFER_ASSET = 0x02
ATTR_NONCE = 0x00
ATTR_MEMO = 0x81
ATTR_DESCRIPTION = 0x90

# Program hash prefixes: 0x21 standard, 0x12 multisig, 0x4B cross-chain, 0x1F deposit.
PH_MERCHANT = bytes.fromhex("21bf8e2bb92e0604a0f3c1ea15e2d7e8729175795d")
PH_MERCH2 = bytes.fromhex("21c624cab1438f8fdde9933222a8f1dd699c75f802")
PH_ATTACKER = bytes.fromhex("21" + "de" * 20)
PH_MULTISIG = bytes([0x12]) + b"\x42" * 20
PH_CROSSCHAIN = bytes([0x4B]) + b"\x11" * 20
PH_DEPOSIT = bytes([0x1F]) + b"\x11" * 20


def varuint(n: int) -> bytes:
    if n < 0xFD:
        return bytes([n])
    if n <= 0xFFFF:
        return b"\xfd" + n.to_bytes(2, "little")
    if n <= 0xFFFFFFFF:
        return b"\xfe" + n.to_bytes(4, "little")
    return b"\xff" + n.to_bytes(8, "little")


def ela(amount: float) -> int:
    """ELA to sela, 10^8 per ELA."""
    return int(round(amount * 10 ** 8))


def attribute(usage: int, data: bytes) -> bytes:
    return bytes([usage]) + varuint(len(data)) + data


def txinput(txid_hex: str = DEMO_TXID, index: int = 0, sequence: int = 0) -> bytes:
    return bytes.fromhex(txid_hex) + index.to_bytes(2, "little") + sequence.to_bytes(4, "little")


def output(program_hash: bytes, sela: int, asset: bytes = ELA_ASSET, lock: int = 0,
           otype: int | None = None, opayload: bytes = b"") -> bytes:
    """Set otype only for version 9 transactions, which carry an output type."""
    b = asset + (sela & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "little") + lock.to_bytes(4, "little") + program_hash
    if otype is not None:
        b += bytes([otype]) + opayload
    return b


def build_tx(outputs: list[bytes], attrs: list[bytes] | None = None, inputs: list[bytes] | None = None,
             locktime: int = 0, version: int = 0, txtype: int = TX_TRANSFER_ASSET,
             payload_version: int = 0, payload: bytes = b"") -> bytes:
    attrs = [attribute(ATTR_NONCE, bytes.fromhex("11223344"))] if attrs is None else attrs
    inputs = [txinput()] if inputs is None else inputs
    b = bytes([version]) if version >= 9 else b""
    b += bytes([txtype, payload_version]) + payload
    b += varuint(len(attrs)) + b"".join(attrs)
    b += varuint(len(inputs)) + b"".join(inputs)
    b += varuint(len(outputs)) + b"".join(outputs)
    return b + locktime.to_bytes(4, "little")


def poll_vote_memo(poll_id: bytes, choice: int, amount: str) -> bytes:
    """Essentials' vote memo (encodeVoteMemo): "pollvote", 32-byte poll id, u32 LE choice, then a
    length byte and the amount as ELA text."""
    return b"pollvote" + poll_id + choice.to_bytes(4, "little") + bytes([len(amount)]) + amount.encode()


def poll_vote_tx(signer_program_hash: bytes, vote: int, change: int, memo: bytes) -> bytes:
    """As Essentials builds it: nonce "0", the vote memo, and vote and change to the signer."""
    attrs = [attribute(ATTR_NONCE, b"0"), attribute(ATTR_MEMO, memo)]
    return build_tx([output(signer_program_hash, vote), output(signer_program_hash, change)], attrs=attrs)


def payment_with_memo(memo: bytes, outputs: list[bytes]) -> bytes:
    """With the wallet's one-byte nonce "0"."""
    return build_tx(outputs, attrs=[attribute(ATTR_NONCE, b"0"), attribute(ATTR_MEMO, memo)])


def wallet_memo(memo: str = "hello") -> bytes:
    """Essentials prefixes the note with "type:text,msg:"; the device shows the prefix too."""
    return ("type:text,msg:" + memo).encode()


def wallet_tx(send: int, change: int, signer_program_hash: bytes, memo: str = "hello",
              recipient: bytes = PH_MERCHANT) -> bytes:
    """Essentials' Ledger payment: nonce, memo, payment, and change to the signer even if zero. The
    nonce is 8 bytes, the longest the device takes unshown; the wallet's own is "0"."""
    attrs = [attribute(ATTR_NONCE, bytes.fromhex("0102030405060708")), attribute(ATTR_MEMO, wallet_memo(memo))]
    return build_tx([output(recipient, send), output(signer_program_hash, change)], attrs=attrs)
