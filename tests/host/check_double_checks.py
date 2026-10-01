#!/usr/bin/env python3
"""Checks each device's disassembly: every check the source makes twice, before signing and before
returning a key without the address check, must still be made and acted on twice.

One fault can skip one check, so the source doubles them, but the compiler may merge two checks it
can prove equal (without the volatile in digests_match it keeps only the first comparison). The
host fuzzers run the source, so only the disassembly shows this.

Checks are counted along every path from entry to the call that signs or derives the key. A check
passes only on the way a branch on its result takes when it returned true: cbz or cbnz r0, or beq
or bne straight after cmp r0, #0, before r0 is overwritten. Calls into OUTLINED_FUNCTION_<n> are
followed. A check that is no longer a function was inlined, as clang does once one call is left,
and is reported as lost. A jump this cannot follow, such as through a table or register, stops it.

Written against clang 21.1.8 in the builder image pinned by .github/workflows/host_tests.yml.

usage: check_double_checks.py <app build folder>...   (needs arm-none-eabi-objdump on the PATH)
       reads <folder>/bin/app.elf of each folder given
"""
import os
import re
import subprocess
import sys

# Per function: the call that signs or derives the key, and the check groups every path to it must
# pass in order, any order within a group. handle_get_public_key is inlined into elastos_main.
DOUBLED_CHECKS = {
    "tx_session_sign": ("keys_sign_digest", (
        ("the first check of the screen count, path and text",
         ("screen_count_matches", "path_matches", "tx_session_text_matches")),
        ("two comparisons of the committed digest", ("digests_match", "digests_match")),
        ("the second check of the screen count, text and path",
         ("screen_count_matches", "tx_session_text_matches", "path_matches")),
    )),
    "io_seproxyhal_touch_approve": ("tx_session_sign", (
        ("two checks that the review was shown whole",
         ("review_shown_whole", "review_shown_whole")),
    )),
    "elastos_main": ("keys_get_public_key", (
        ("two checks that the key asked for without the address check is in the silent range",
         ("keys_path_is_silent", "keys_path_is_silent")),
    )),
}
OUTLINED = "OUTLINED_FUNCTION_"
SYMBOL = re.compile(r"^([0-9a-f]+) <(.+)>:$")
INSTRUCTION = re.compile(r"^\s*([0-9a-f]+):\t[^\t]*\t([^\t]+)\t?([^\t]*)")
TARGET = re.compile(r"\b([0-9a-f]+) <[^>]+>$")
CONDITION = "(?:eq|ne|cs|hs|cc|lo|mi|pl|vs|vc|hi|ls|ge|lt|gt|le)"
CONDITIONAL_BRANCH = re.compile(rf"^(?:b{CONDITION}(?:\.n|\.w)?|cbn?z)$")
BRANCH = re.compile(r"^b(?:al)?(?:\.n|\.w)?$")
CALL = re.compile(rf"^bl({CONDITION})?(?:\.w)?$")
IT_BLOCK = re.compile(r"^it[te]{0,3}$")
RETURN = re.compile(r"^(?:pop|ldm)")
NOT_CODE = re.compile(r"^(?:\.word|\.short|\.byte|udf|bkpt)")
NOT_A_BRANCH = ("bic", "bfc", "bfi")
TESTS_ZERO = re.compile(r"^cb(n?)z(?:\.n)?$")
COMPARES_WITH_ZERO = re.compile(r"^cmp(?:\.n|\.w)?$")
BRANCHES_ON_ZERO = re.compile(r"^b(eq|ne)(?:\.n|\.w)?$")
# Instructions that write no register, or only a written-back base register (checked apart).
WRITES_NO_REGISTER = ("cmp", "cmn", "tst", "teq", "str", "stm", "push", "b", "cb", "tb", "it",
                      "nop", "svc", "cps", "dmb", "dsb", "isb", "pld")
WRITEBACK_OF_R0 = re.compile(r"\br0!|\[r0\],|\[r0,[^\]]*\]!")


class CheckError(Exception):
    """Disassembly this cannot follow exactly: teach it, do not guess."""


def disassemble(elf: str) -> tuple[dict, dict]:
    """Functions by address as (name, instructions), and addresses by name, since static functions
    such as the outlined ones can share a name."""
    lines = subprocess.run(["arm-none-eabi-objdump", "-d", elf], check=True, capture_output=True,
                           text=True).stdout.splitlines()
    functions, names, current = {}, {}, None
    for line in lines:
        symbol = SYMBOL.match(line)
        instruction = INSTRUCTION.match(line)
        if symbol:
            current = []
            functions[int(symbol.group(1), 16)] = (symbol.group(2), current)
            names.setdefault(symbol.group(2), []).append(int(symbol.group(1), 16))
        elif instruction and current is not None:
            current.append((int(instruction.group(1), 16), instruction.group(2).strip(),
                            instruction.group(3).strip()))
    return functions, names


def target(operands: str, where: str) -> int:
    match = TARGET.search(operands)
    if not match:
        raise CheckError(f"{where}: cannot tell where '{operands}' goes")
    return int(match.group(1), 16)


def is_return(mnemonic: str, operands: str) -> bool:
    return (RETURN.match(mnemonic) is not None and re.search(r"\bpc\b", operands) is not None) or \
        (mnemonic == "bx" and operands == "lr")


def may_jump(mnemonic: str, operands: str) -> bool:
    """True if the instruction can go anywhere but the next one."""
    branches = mnemonic.startswith(("b", "cb", "tb")) and not mnemonic.startswith(NOT_A_BRANCH)
    return branches or re.match(r"pc\b", operands) is not None or is_return(mnemonic, operands)


def calls_made(address: int, functions: dict, where: str) -> tuple[str, ...]:
    """The functions a call to this address runs: itself, or every call in an outlined run."""
    name, body = functions.get(address, (None, None))
    if name is None:
        raise CheckError(f"{where}: calls {address:x}, which starts no function")
    if not name.startswith(OUTLINED):
        return (name,)
    calls = ()
    for index, (at, mnemonic, operands) in enumerate(body):
        here, last = f"{name} at {at:x}", index == len(body) - 1
        if mnemonic in ("bl", "bl.w"):
            calls += calls_made(target(operands, here), functions, here)
        elif last and mnemonic == "bx" and operands == "lr":
            return calls
        elif last and BRANCH.match(mnemonic):
            return calls + calls_made(target(operands, here), functions, here)
        elif may_jump(mnemonic, operands) or IT_BLOCK.match(mnemonic):
            break
    raise CheckError(f"{where}: {name} is not a straight run of instructions")


def writes_r0(mnemonic: str, operands: str) -> bool:
    """True if the instruction may overwrite r0. Calls are not judged here: each leaves its own
    result in r0."""
    if WRITEBACK_OF_R0.search(operands):
        return True
    if mnemonic.startswith(("ldm", "pop")):
        return re.search(r"\{[^}]*\br0\b", operands) is not None
    writes_first = mnemonic.startswith(NOT_A_BRANCH + ("strex",))
    if mnemonic.startswith(WRITES_NO_REGISTER) and not writes_first:
        return False
    written = 2 if mnemonic.startswith(("ldrd", "umull", "smull", "umlal", "smlal")) else 1
    return "r0" in [operand.strip() for operand in operands.split(",")[:written]]


def result_survives(address: int, functions: dict) -> bool:
    """True if the last callee's result is still in r0 when a call here returns: always for a
    function, and for an outlined run only if nothing after its last call writes r0."""
    name, body = functions[address]
    if not name.startswith(OUTLINED):
        return True
    survives = False
    for index, (at, mnemonic, operands) in enumerate(body):
        if mnemonic in ("bl", "bl.w") or (index == len(body) - 1 and BRANCH.match(mnemonic)):
            survives = result_survives(target(operands, f"{name} at {at:x}"), functions)
        elif writes_r0(mnemonic, operands):
            survives = False
    return survives


def compares_r0_with_zero(mnemonic: str, operands: str) -> bool:
    return COMPARES_WITH_ZERO.match(mnemonic) is not None and operands.replace(" ", "") == "r0,#0"


def passing_way(mnemonic: str, operands: str, compared: bool) -> int | None:
    """For a branch testing a check's result in r0, the index in ways_on's list taken when it
    returned true; None otherwise. compared: the previous instruction was cmp r0, #0."""
    zero_test = TESTS_ZERO.match(mnemonic)
    if zero_test and operands.split(",")[0].strip() == "r0":
        return 1 if zero_test.group(1) else 0
    zero_branch = BRANCHES_ON_ZERO.match(mnemonic)
    if zero_branch and compared:
        return 1 if zero_branch.group(1) == "ne" else 0
    return None


def conditional_instructions(body: list) -> set[int]:
    """Indexes of the instructions an IT block makes conditional."""
    conditional, left = set(), 0
    for index, (_, mnemonic, _) in enumerate(body):
        if left:
            conditional.add(index)
            left -= 1
        elif IT_BLOCK.match(mnemonic):
            left = len(mnemonic) - 1
    return conditional


def ways_on(body: list, index: int, conditional: bool, functions: dict, where: str) -> list:
    """Each way on from the instruction: (functions called, next index, or None on leaving)."""
    at, mnemonic, operands = body[index]
    here = f"{where} at {at:x}"
    following = index + 1 if index + 1 < len(body) else None

    def jump(address: int) -> tuple:
        inside = [i for i, (other, _, _) in enumerate(body) if other == address]
        if inside:
            return (), inside[0]
        if body[0][0] <= address <= body[-1][0]:
            raise CheckError(f"{here}: branches into the middle of an instruction")
        return calls_made(address, functions, here), None  # a tail call: runs it, then leaves

    if NOT_CODE.match(mnemonic):
        return []
    if IT_BLOCK.match(mnemonic):
        return [((), following)]
    if CONDITIONAL_BRANCH.match(mnemonic):
        return [((), following), jump(target(operands, here))]
    if BRANCH.match(mnemonic):
        return [jump(target(operands, here))] + ([((), following)] if conditional else [])
    call = CALL.match(mnemonic)
    if call:
        made = [(calls_made(target(operands, here), functions, here), following)]
        return made + ([((), following)] if conditional or call.group(1) else [])
    if is_return(mnemonic, operands):
        return [((), None)] + ([((), following)] if conditional else [])
    if may_jump(mnemonic, operands):
        raise CheckError(f"{here}: cannot follow '{mnemonic} {operands}'")
    return [((), following)]


def missed_checks(function: str, functions: dict, names: dict, label: str) -> list[str]:
    """Every path from entry that reaches the goal without passing all checks in order, or why
    the function cannot be walked."""
    goal, groups = DOUBLED_CHECKS[function]
    if len(names.get(function, [])) != 1:
        return [f"{label}: {len(names.get(function, []))} functions are named {function}"]
    checks = {check for _, group in groups for check in group}
    for check in sorted(checks):
        found = len(names.get(check, []))
        if found == 0:
            return [f"{label}: {check} is not a function of this build; a check called only once "
                    f"is inlined, and this script sees a check only as a call"]
        if found > 1:
            return [f"{label}: {found} functions are named {check}"]
    body = functions[names[function][0]][1]
    conditional = conditional_instructions(body)

    def passed(progress: tuple, callee: str) -> tuple:
        group, left = progress
        if group == len(groups) or callee not in left:
            return progress
        left = list(left)
        left.remove(callee)
        if not left:
            group += 1
            left = groups[group][1] if group < len(groups) else ()
        return group, tuple(sorted(left))

    def returned(calls: tuple, mnemonic: str, operands: str, at: int) -> tuple | None:
        """(check, call address) if the call leaves a check's result in r0, else None."""
        if not calls or calls[-1] not in checks or not CALL.match(mnemonic):
            return None
        if not result_survives(target(operands, f"{label}: {function} at {at:x}"), functions):
            return None
        return calls[-1], at

    # Each state: instruction index, progress through the groups, the untested check whose result
    # is in r0 (or None), and whether the previous instruction was cmp r0, #0.
    seen, missed, lost, reached = set(), set(), set(), False
    waiting = [(0, (0, tuple(sorted(groups[0][1]))), None, False)]
    while waiting:
        state = waiting.pop()
        if state in seen:
            continue
        seen.add(state)
        index, progress, pending, compared = state
        at, mnemonic, operands = body[index]
        passing = passing_way(mnemonic, operands, compared) if pending else None
        ways = ways_on(body, index, index in conditional, functions, f"{label}: {function}")
        for way, (calls, following) in enumerate(ways):
            now, result = progress, pending
            if passing is not None:
                # the check passes only on the way taken when it returned true
                result = None
                if way == passing:
                    now = passed(now, pending[0])
            for callee in calls:
                if callee == goal:
                    reached = True
                    if now[0] < len(groups):
                        missed.add(f"{label}: a path through {function} calls {goal} at "
                                   f"{at:x} before passing, in order, "
                                   f"{groups[now[0]][0]}; missing: {', '.join(now[1])}")
            if calls:
                result = returned(calls, mnemonic, operands, at)
            elif passing is None and writes_r0(mnemonic, operands):
                result = None
            if pending and passing is None and result != pending:
                lost.add(pending)
            if following is not None:
                waiting.append((following, now, result,
                                result is not None and compares_r0_with_zero(mnemonic, operands)))
    if not reached:
        missed.add(f"{label}: {function} never calls {goal}")
    if missed:
        missed |= {f"{label}: {function} calls {check} at {at:x} and no branch tests what it "
                   f"returns before r0 is overwritten" for check, at in lost}
    return sorted(missed)


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: check_double_checks.py <app build folder>...")
        return 1
    failures = []
    try:
        for build_dir in sys.argv[1:]:
            functions, names = disassemble(os.path.join(build_dir, "bin", "app.elf"))
            for function in DOUBLED_CHECKS:
                failures += missed_checks(function, functions, names, build_dir)
    except CheckError as error:
        print(f"{error}: teach check_double_checks.py what it means rather than let it pass")
        return 1
    for failure in failures:
        print(failure)
    if failures:
        print("one fault can skip a check made once: keep each doubled check a call of its own, "
              "with a branch on what it returns")
        return 1
    print(f"{', '.join(sys.argv[1:])}: every doubled check before signing, and before a key "
          f"returned without the address check, is made and acted on twice")
    return 0


if __name__ == "__main__":
    sys.exit(main())
