#!/usr/bin/env python3
"""Checks the app's built objects for data that holds flash addresses.

The app runs wherever the OS loads it, so a pointer stored in flash or initialised data keeps its
link-time address unless the SDK runs it through PIC(). Such data shows as R_ARM_ABS32 relocations
in a section that is loaded but not run. The SDK runs only two kinds of app data through PIC(),
both in ui.c: the objects its flow macros define (Nano X, Nano S Plus) and the element arrays given
to UX_DISPLAY (Nano S). Only those are allowed, by exact name read from src/ui.c, only in ui.o and
only on the device that compiles them. This covers Nano S, which the emulator suite cannot run.

Only objects under obj/app are checked. The SDK's are not, nor gen_src/glyphs.o: its icon tables
hold flash addresses that lib_bagl runs through PIC() on every draw.

usage: check_pic_objects.py <app build folder>...   (needs arm-none-eabi-readelf on the PATH)
       the folder's name (nanos, nanox or nanos2) tells the device; src/ui.c must be the one built
       check_pic_objects.py --self-test             (no toolchain needed)
       checks that tables of text pointers added to src/ui.c are never allowed
"""
import os
import re
import subprocess
import sys

UI_SOURCE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "src", "ui.c")
UI_OBJECT = os.path.join("src", "ui.o")
DEVICES = {"nanos": "TARGET_NANOS", "nanox": "TARGET_NANOX", "nanos2": "TARGET_NANOS2"}

# The objects each flow macro defines from its name, as lib_ux/include/ux_flow_engine.h does. Any
# other flow macro in ui.c stops the check.
FLOW_MACRO_OBJECTS = {
    "UX_STEP_NOCB": ("", "_val"),
    "UX_STEP_NOCB_INIT": ("", "_val"),
    "UX_STEP_CB": ("", "_val", "_validate", "_validate_step"),
    "UX_STEP_VALID": ("", "_val", "_validate", "_validate_step"),
    "UX_STEP_CB_INIT": ("", "_val", "_validate", "_validate_step"),
    "UX_FLOW": ("",),
}
FLOW_MACRO = re.compile(r"\b(UX_(?:STEP|FLOW|DEF)\w*)\s*\(\s*(\w+)")
ELEMENT_ARRAY = re.compile(r"\bconst\s+bagl_element_t\s+(\w+)\s*\[[^\]]*\]\s*=")
DISPLAYED = re.compile(r"\bUX_DISPLAY\s*\(\s*(\w+)\s*,")
COMMENT_OR_LITERAL = re.compile(r'//[^\n]*|/\*.*?\*/|"(?:\\.|[^"\\\n])*"|\'(?:\\.|[^\'\\\n])*\'', re.S)
CONDITIONAL = re.compile(r"^\s*#\s*(if|ifdef|ifndef|elif|else|endif)\b(.*)$")
DIRECTIVE = re.compile(r"^\s*#")
SECTION = re.compile(r"^Relocation section '([^']+)'")
SECTION_FLAGS = re.compile(r"^\s*\[\s*\d+\]\s+(\S+)\s+\S+\s+[0-9a-f]+\s+[0-9a-f]+\s+[0-9a-f]+\s+[0-9a-f]+\s+([A-Za-z]*)\s")


class CheckError(Exception):
    """ui.c holds something this cannot read exactly: teach it, do not guess."""


def without_comments(source: str) -> str:
    """The source without comments and with literals emptied, lines kept, so no name in a
    comment or string counts as defined."""
    def blank(match: re.Match) -> str:
        text = match.group(0)
        if text.startswith("/"):
            return "\n" * text.count("\n")
        return '""' if text.startswith('"') else "' '"
    return COMMENT_OR_LITERAL.sub(blank, source.replace("\\\n", ""))


def condition_holds(expression: str, device: str) -> bool:
    """Evaluates a #if of defined(TARGET_*), !, && and ||, the only kind ui.c uses."""
    def is_defined(match: re.Match) -> str:
        name = match.group(1) or match.group(2)
        if not name.startswith("TARGET_"):
            raise CheckError(f"ui.c: cannot tell whether {name} is defined on {device}")
        return " True " if name == DEVICES[device] else " False "
    python = re.sub(r"defined\s*\(\s*(\w+)\s*\)|defined\s+(\w+)", is_defined, expression)
    python = python.replace("&&", " and ").replace("||", " or ").replace("!", " not ")
    if not re.fullmatch(r"(\s|\(|\)|\d+|True|False|and|or|not)+", python):
        raise CheckError(f"ui.c: cannot evaluate #if {expression.strip()} on {device}")
    return eval(python)


def device_source(source: str, device: str) -> str:
    """The lines of ui.c the preprocessor keeps for a device, without directives."""
    kept, groups, active = [], [], True
    for line in without_comments(source).splitlines():
        match = CONDITIONAL.match(line)
        if not match:
            if active and not DIRECTIVE.match(line):
                kept.append(line)
            continue
        kind, rest = match.group(1), match.group(2)
        if kind in ("if", "ifdef", "ifndef"):
            expression = rest if kind == "if" else f"defined({rest.strip()})"
            holds = active and condition_holds(expression, device)
            holds = holds if kind != "ifndef" else active and not holds
            groups.append([active, holds])
            active = holds
        elif not groups:
            raise CheckError(f"ui.c: #{kind} without #if")
        elif kind == "elif":
            parent, taken = groups[-1]
            active = parent and not taken and condition_holds(rest, device)
            groups[-1][1] = taken or active
        elif kind == "else":
            parent, taken = groups[-1]
            active = parent and not taken
            groups[-1][1] = True
        else:
            active = groups.pop()[0]
    return "\n".join(kept)


def allowed_objects(source: str, device: str) -> set[str]:
    """The ui.c objects the SDK runs through PIC() on a device: flow macro objects and element
    arrays given to UX_DISPLAY."""
    text = device_source(source, device)
    allowed = set()
    for macro, name in FLOW_MACRO.findall(text):
        if macro not in FLOW_MACRO_OBJECTS:
            raise CheckError(f"ui.c: {macro} is not a flow macro this check knows the objects of")
        allowed |= {name + suffix for suffix in FLOW_MACRO_OBJECTS[macro]}
    displayed = set(DISPLAYED.findall(text))
    return allowed | {name for name in ELEMENT_ARRAY.findall(text) if name in displayed}


def readelf(option: str, path: str) -> list[str]:
    return subprocess.run(["arm-none-eabi-readelf", option, path], check=True, capture_output=True,
                          text=True).stdout.splitlines()


def offending_sections(path: str, allowed: set[str]) -> list[str]:
    """Absolute relocations into data (loaded, not run) other than the allowed objects'. A section
    whose flags cannot be read counts as data, so a change in readelf's output fails."""
    flags = {m.group(1): m.group(2) for m in map(SECTION_FLAGS.match, readelf("-SW", path)) if m}
    allowed_here = {f".rodata.{name}" for name in allowed}
    bad, target, data = [], None, False
    for line in readelf("-rW", path):
        match = SECTION.match(line)
        if match:
            target = re.sub(r"^\.rela?(?=\.)", "", match.group(1))
            data = target not in flags or ("A" in flags[target] and "X" not in flags[target])
        elif data and "R_ARM_ABS32" in line and target not in allowed_here:
            bad.append(f"{target}: {line.split()[-1]}")
    return bad


def app_objects(build_dir: str) -> list[str]:
    """Every object file under obj/app; the glyph object is in gen_src (see the top)."""
    found = []
    for root, _, files in os.walk(os.path.join(build_dir, "obj", "app")):
        found += [os.path.join(root, f) for f in files if f.endswith(".o")]
    return sorted(found)


# Text pointer tables the SDK never fixes up: named like SDK objects, through a typedef or struct,
# an element array never displayed, and on Nano S a table named like the Nano X idle flow.
SELF_TEST_TABLES = """
typedef const char *text_t;
const text_t ux_step_headings[] = {"Output", "Recipient"};
struct heading { const char *text; };
const struct heading bagl_ui_headings_nanos[] = {{"Output"}, {"Recipient"}};
const bagl_element_t bagl_ui_hidden_nanos[] = {{{0}, "Output"}};
#if defined(TARGET_NANOS)
const text_t ux_idle_flow[] = {"Output", "Recipient"};
#endif
"""
SELF_TEST_NEVER_ALLOWED = {
    "nanos": {"ux_step_headings", "bagl_ui_headings_nanos", "bagl_ui_hidden_nanos", "ux_idle_flow"},
    "nanox": {"ux_step_headings", "bagl_ui_headings_nanos", "bagl_ui_hidden_nanos"},
    "nanos2": {"ux_step_headings", "bagl_ui_headings_nanos", "bagl_ui_hidden_nanos"},
}


def self_test(source: str) -> int:
    """Fails if any table above would be allowed on any device, or if adding them changes what the
    real ui.c allows."""
    failures = []
    for device, never in SELF_TEST_NEVER_ALLOWED.items():
        real = allowed_objects(source, device)
        with_tables = allowed_objects(source + SELF_TEST_TABLES, device)
        wrong = (with_tables ^ real) | (with_tables & never)
        if not real:
            failures.append(f"{device}: no object of ui.c is allowed")
        if wrong:
            failures.append(f"{device}: allowed, or no longer allowed, once the tables are added: "
                            f"{sorted(wrong)}")
    for failure in failures:
        print(failure)
    if failures:
        return 1
    print("only the objects ui.c gives the SDK are allowed, and no table added to it is")
    return 0


def main() -> int:
    source = open(UI_SOURCE).read()
    try:
        if sys.argv[1:] == ["--self-test"]:
            return self_test(source)
        failures, objects = [], 0
        for build_dir in sys.argv[1:]:
            device = os.path.basename(os.path.normpath(build_dir))
            if device not in DEVICES:
                print(f"{build_dir}: not a build folder named for a device ({', '.join(DEVICES)})")
                return 1
            allowed = allowed_objects(source, device)
            for path in app_objects(build_dir):
                objects += 1
                # only ui.o may hold the objects ui.c gives the SDK
                is_ui = os.path.relpath(path, os.path.join(build_dir, "obj", "app")) == UI_OBJECT
                failures += [f"{path}: {entry}"
                             for entry in offending_sections(path, allowed if is_ui else set())]
    except CheckError as error:
        print(f"{error}: teach check_pic_objects.py what it means rather than let it pass")
        return 1
    if objects == 0:
        print("no app object files found")
        return 1
    for failure in failures:
        print(failure)
    if failures:
        print("data holding flash addresses breaks on the device: store the data inline or build it at run time")
        return 1
    print(f"no flash addresses stored in data in {objects} objects")
    return 0


if __name__ == "__main__":
    sys.exit(main())
