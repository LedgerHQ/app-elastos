#!/usr/bin/env bash
# Builds the state-machine fuzzer for one variant of the source.
#
# usage: build.sh <variant> <output directory>
#   clean      the source as it is
#   pN         the source with one planted bug from plant.py (parser and gate plants: ../Makefile)
#
# main_shim.c is main.c without the ARM-only boot instruction and with main renamed, since the
# driver has its own main. Any other difference fails the build.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"
VARIANT="$1"
OUT="$2"
CC="${CC:-cc}"

rm -rf "$OUT"
mkdir -p "$OUT"
cp -R "$ROOT/src" "$OUT/src"
python3 "$HERE/gen_corpus.py" "$OUT/corpus.h"
python3 "$HERE/plant.py" "$VARIANT" "$OUT/src"

sed -e '/__asm volatile("cpsie i");/d' \
    -e 's/__attribute__((section(".boot"))) int main(void)/int elastos_device_main(void)/' \
    "$OUT/src/main.c" > "$OUT/main_shim.c"
changed=$(diff "$OUT/src/main.c" "$OUT/main_shim.c" | grep -c '^[<>]' || true)
if [ "$changed" -ne 3 ]; then
    echo "main_shim.c should differ from main.c in exactly two lines:" >&2
    diff "$OUT/src/main.c" "$OUT/main_shim.c" >&2 || true
    exit 1
fi

# the app's stack canary, so main()'s check of it is built; -fno-common: see ../Makefile
"$CC" -g -O1 -DTARGET_NANOS -DHAVE_BOLOS_APP_STACK_CANARY -fsanitize=address,undefined -fno-sanitize-recover=all \
    -fno-omit-frame-pointer -fno-common \
    -I "$HERE/stubs" -I "$HERE/../common" -I "$OUT" -I "$OUT/src" \
    -Wno-unused-function -Wno-unused-variable -Wno-deprecated-declarations \
    -Wno-unused-parameter -Wno-incompatible-pointer-types-discards-qualifiers \
    -Wno-duplicate-decl-specifier \
    -o "$OUT/sm_fuzz" "$HERE/sm_fuzz.c"
echo "built $OUT/sm_fuzz ($VARIANT)"
