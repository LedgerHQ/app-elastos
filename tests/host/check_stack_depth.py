#!/usr/bin/env python3
"""Checks that the Nano S stack is deep enough for pressing Sign.

On Nano S the stack is what the globals leave of the RAM (1,760 bytes today). APP_STACK_MIN_SIZE
fails the link below 1,600, but nothing limits how deep the code goes. Sign goes deepest, as the
crypto library signs on the app's stack; every other path was measured well within it. Running past
the bottom overwrites the canary, and the reply's io_exchange then resets the device instead of
sending the signature. No emulator runs Nano S and the host tests use the host's stack, so only
the build shows this.

From a Nano S build with CFLAGS += -fstack-usage (same app, byte for byte), this adds up:
- the frames of SIGN_CHAIN, each call on it checked in the disassembly but the one via a pointer;
- below keys_sign_digest, the deepest of everything it calls; calls the chain makes and returns
  from on the way go far less deep and are not added;
- the crypto library's own depth (CRYPTO_LIBRARY_DEPTH): the OS pops the two registers its stub
  pushes before the library runs;
- one interrupt frame.
Each frame is the compiler's .su figure, which must equal what the prologue pushes and subtracts
from sp; code without a .su file, such as the C library, gets its prologue's. A frame sized at run
time, or an sp change this cannot size, stops the check.

It fails if the sum exceeds the stack from _stack to _estack, or if the app's frames grow past
APP_FRAMES_BUDGET.

usage: check_stack_depth.py <Nano S build folder>
       reads <folder>/bin/app.elf and the .su files under <folder>/obj; needs
       arm-none-eabi-objdump and arm-none-eabi-nm on the PATH
"""
import os
import re
import subprocess
import sys

from check_double_checks import (BRANCH, CALL, CONDITIONAL_BRANCH, NOT_CODE, CheckError,
                                 disassemble, is_return, may_jump, target)

# The functions on the stack when Sign is pressed, outermost first. The SDK calls the button
# handler of the screen on display through a pointer.
SIGN_CHAIN = ("main", "elastos_main", "io_exchange", "io_seproxyhal_handle_event", "io_event",
              "io_seproxyhal_button_push", "bagl_ui_sign_nanos_button",
              "io_seproxyhal_touch_approve", "tx_session_sign", "keys_sign_digest")
CALLED_THROUGH_POINTER = (("io_seproxyhal_button_push", "bagl_ui_sign_nanos_button"),)
# The OS crypto library's depth in bytes for each function reached below keys_sign_digest.
# Estimated from the Nano S SDK's lib_cxng built with the app's flags and -fstack-usage: the
# signature is cx_ecdsa_sign_no_throw 360, cx_rng_rfc6979_init 64, cx_rfc6979_hmacVK 48,
# cx_hmac_final 288, cx_hash_update 8, cx_sha256_update 40, cx_sha256_block 88, memcpy 28; the key
# setup is cx_ecfp_init_private_key_no_throw 24, memmove 28.
CRYPTO_LIBRARY_DEPTH = {
    "cx_ecdsa_sign_no_throw": 924,
    "cx_ecfp_init_private_key_no_throw": 52,
}
CRYPTO_ENTRY = "cx_trampoline_helper"
# An interrupt pushes eight registers on the stack of the code it stops.
INTERRUPT_FRAME = 32
# The app's frames on the deepest Sign path, as measured. Raise it only for a change weighed
# against the room left.
APP_FRAMES_BUDGET = 560
# longjmp returns sp to a caller's setjmp, so it never goes deeper.
RESTORES_STACK = ("longjmp",)
# os_longjmp asks the OS for the try context through SVC_Call, which calls os_longjmp again if the
# OS fails: a loop that only throws further up. So a function met again after os_longjmp counts its
# own frame and is not followed.
THROWS = "os_longjmp"
SU_LINE = re.compile(r"^.*:(\w+)\t(\d+)\t(\S+)$")
SUBTRACTS_FROM_SP = re.compile(r"^sub(?:\.w|w)?$")
SP_IMMEDIATE = re.compile(r"^sp,(?:sp,)?#(\d+)$")


def stack_bounds(elf: str) -> tuple[int, int]:
    """_stack, the stack's lowest address, and _estack."""
    lines = subprocess.run(["arm-none-eabi-nm", elf], check=True, capture_output=True,
                           text=True).stdout.splitlines()
    symbols = {parts[2]: int(parts[0], 16) for parts in (line.split() for line in lines)
               if len(parts) == 3}
    if "_stack" not in symbols or "_estack" not in symbols:
        raise CheckError(f"{elf}: no _stack or _estack symbol; is this a Nano S build?")
    return symbols["_stack"], symbols["_estack"]


def compiler_frames(obj_dir: str) -> dict:
    """Each function's .su frames as a set of (bytes, kind); a static or inline header function
    can appear in several files."""
    frames = {}
    for folder, _, files in os.walk(obj_dir):
        for file in (f for f in files if f.endswith(".su")):
            for line in open(os.path.join(folder, file)):
                match = SU_LINE.match(line.rstrip("\n"))
                if not match:
                    raise CheckError(f"{file}: cannot read '{line.strip()}'")
                frames.setdefault(match.group(1), set()).add((int(match.group(2)), match.group(3)))
    if not frames:
        raise CheckError(f"{obj_dir}: no .su files; build Nano S with CFLAGS += -fstack-usage")
    return frames


def prologue_frame(name: str, body: list) -> int:
    """What the function pushes and subtracts from sp before its first branch or call; any other
    sp change stops the check."""
    frame, in_prologue = 0, True
    for at, mnemonic, operands in body:
        if NOT_CODE.match(mnemonic):
            continue
        if may_jump(mnemonic, operands) or CALL.match(mnemonic):
            in_prologue = False
        pushes = mnemonic.startswith("push")
        subtracts = SUBTRACTS_FROM_SP.match(mnemonic) and SP_IMMEDIATE.match(
            operands.replace(" ", ""))
        if in_prologue and pushes:
            frame += 4 * len(operands.strip("{}").split(","))
        elif in_prologue and subtracts:
            frame += int(subtracts.group(1))
        elif pushes or subtracts or writes_sp(mnemonic, operands):
            raise CheckError(f"{name} at {at:x}: cannot size '{mnemonic} {operands}'")
    return frame


def writes_sp(mnemonic: str, operands: str) -> bool:
    """True if the instruction sets sp other than by push, pop or adding back a constant."""
    if not operands.startswith("sp") or mnemonic.startswith(("str", "cmp")):
        return False
    adds_back = mnemonic.startswith("add") and SP_IMMEDIATE.match(operands.replace(" ", ""))
    return not adds_back


def own_frame(name: str, body: list, frames: dict) -> int:
    """The compiler's frame, which must match the prologue's, or the prologue's if unreported."""
    frame = prologue_frame(name, body)
    reported = frames.get(name)
    if reported is None:
        return frame
    if (frame, "static") not in reported:
        raise CheckError(f"{name}: the prologue takes {frame} bytes, the .su files report "
                         f"{sorted(reported)}")
    return frame


def is_crypto_stub(body: list) -> bool:
    """True for the SDK's stub that calls into the OS crypto library."""
    code = [(mnemonic, operands) for _, mnemonic, operands in body if not NOT_CODE.match(mnemonic)]
    return (len(code) == 3 and code[0] == ("push", "{r0, r1}") and code[1][0] == "ldr"
            and code[1][1].startswith("r0,") and BRANCH.match(code[2][0]) is not None
            and code[2][1].endswith(f"<{CRYPTO_ENTRY}>"))


def callees(address: int, functions: dict) -> set[int]:
    """Addresses the function calls or jumps to; a jump this cannot follow stops the check."""
    name, body = functions[address]
    first, last = body[0][0], body[-1][0]
    found = set()
    for at, mnemonic, operands in body:
        here = f"{name} at {at:x}"
        if NOT_CODE.match(mnemonic) or is_return(mnemonic, operands):
            continue
        if CALL.match(mnemonic) or BRANCH.match(mnemonic) or CONDITIONAL_BRANCH.match(mnemonic):
            to = target(operands, here)
            if to == first and CALL.match(mnemonic):
                raise CheckError(f"{here}: {name} calls itself")
            if first <= to <= last:
                continue  # a branch within the function; Thumb-1 writes long ones as bl
            if to not in functions:
                raise CheckError(f"{here}: goes to {to:x}, which starts no function")
            found.add(to)
        elif may_jump(mnemonic, operands):
            raise CheckError(f"{here}: cannot follow '{mnemonic} {operands}'")
    return found


def deepest(address: int, functions: dict, frames: dict, calling: tuple = ()) -> tuple:
    """Most stack a call here takes, own frame included: (bytes, crypto library's share, path of
    (function, frame))."""
    name, body = functions[address]
    if address in calling:
        loop = [functions[caller][0] for caller in calling[calling.index(address):]]
        if THROWS not in loop:
            raise CheckError(f"{name} calls itself again through {' > '.join(loop)}")
        frame = own_frame(name, body, frames)
        return frame, 0, ((name, frame),)
    if name in RESTORES_STACK:
        return 0, 0, ((name, 0),)
    if is_crypto_stub(body):
        if name not in CRYPTO_LIBRARY_DEPTH:
            raise CheckError(f"{name} runs in the crypto library, whose depth for it is not "
                             f"measured: measure it and add it to CRYPTO_LIBRARY_DEPTH")
        depth = CRYPTO_LIBRARY_DEPTH[name]
        return depth, depth, ((name, f"(crypto library) {depth}"),)
    frame = own_frame(name, body, frames)
    below = (0, 0, ())
    for callee in callees(address, functions):
        found = deepest(callee, functions, frames, calling + (address,))
        below = max(below, found, key=lambda way: way[0])
    return frame + below[0], below[1], ((name, frame),) + below[2]


def chain_frames(functions: dict, names: dict, frames: dict) -> list:
    """Frames of SIGN_CHAIN but the last, after checking each still calls the next."""
    addresses = []
    for name in SIGN_CHAIN:
        if len(names.get(name, [])) != 1:
            raise CheckError(f"{len(names.get(name, []))} functions are named {name}")
        addresses.append(names[name][0])
    for (caller, callee), at, to in zip(zip(SIGN_CHAIN, SIGN_CHAIN[1:]), addresses, addresses[1:]):
        body = functions[at][1]
        if (caller, callee) in CALLED_THROUGH_POINTER:
            calls = any(mnemonic == "blx" and operands.startswith("r") for _, mnemonic, operands
                        in body)
        else:
            calls = any(CALL.match(mnemonic) and target(operands, f"{caller} at {here:x}") == to
                        for here, mnemonic, operands in body)
        if not calls:
            raise CheckError(f"{caller} no longer calls {callee}: teach SIGN_CHAIN what pressing "
                             f"Sign runs now")
    return [(name, own_frame(name, functions[at][1], frames))
            for name, at in zip(SIGN_CHAIN[:-1], addresses)]


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: check_stack_depth.py <Nano S build folder>")
        return 1
    build_dir = sys.argv[1]
    elf = os.path.join(build_dir, "bin", "app.elf")
    try:
        stack, estack = stack_bounds(elf)
        frames = compiler_frames(os.path.join(build_dir, "obj"))
        functions, names = disassemble(elf)
        chain = chain_frames(functions, names, frames)
        below, library, path = deepest(names[SIGN_CHAIN[-1]][0], functions, frames)
    except CheckError as error:
        print(f"{error}: teach check_stack_depth.py what it means rather than let it pass")
        return 1
    app = sum(frame for _, frame in chain) + below - library
    need, left = app + library + INTERRUPT_FRAME, estack - stack
    print(f"{build_dir}: " + " > ".join(f"{name} {frame}" for name, frame in chain + list(path)))
    print(f"{build_dir}: pressing Sign needs {need} bytes of stack: the app's frames {app} "
          f"(budget {APP_FRAMES_BUDGET}), the crypto library {library}, an interrupt "
          f"{INTERRUPT_FRAME}; the build leaves {left}")
    failures = []
    if need > left:
        failures.append(f"{build_dir}: pressing Sign needs {need} bytes of stack but the build "
                        f"leaves {left}: the reply would reset the device instead of signing")
    if app > APP_FRAMES_BUDGET:
        failures.append(f"{build_dir}: the app's frames on the Sign path grew from "
                        f"{APP_FRAMES_BUDGET} to {app} bytes, so Sign needs {need} of the {left} "
                        f"bytes of stack; weigh that, then raise APP_FRAMES_BUDGET in "
                        f"check_stack_depth.py")
    for failure in failures:
        print(failure)
    if failures:
        return 1
    if app < APP_FRAMES_BUDGET:
        print(f"{build_dir}: the app's frames are below their budget: lower APP_FRAMES_BUDGET to "
              f"{app} to keep the pin tight")
    print(f"{build_dir}: pressing Sign fits the stack with {left - need} bytes to spare")
    return 0


if __name__ == "__main__":
    sys.exit(main())
