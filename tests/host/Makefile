# Host tests, built from the real sources under AddressSanitizer and UndefinedBehaviorSanitizer.
#
#   make            build and run everything
#   make RUNS=N     cases per run
#   make controls   build each planted bug and check the fuzzer it targets catches it
#
# The parser fuzzer is built per device: the line width (108 px on Nano S, 116 px elsewhere) and
# the widths of &, X and _ differ.
# Needs Python 3.10+ for the int | None in elastos_transaction.py (Apple's python3 is 3.9), and on
# Linux glibc 2.38+ for strlcpy.

RUNS ?= 200000
SEED ?= 1
ROOT := ../..
# -fno-common: Apple clang puts uninitialised globals such as raw_tx in common storage, which
# AddressSanitizer does not watch.
SAN := -g -O1 -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer -fno-common
PLANTS := p1 p2 p3 p4 p5 p6 p7 p8 p9 p10 p11 p12 p14 p16 p17 p18 p19 p20 p21 p22 p23 \
          p29 p30 p31 p32 p33 p34 p35 p36 p44 p45 p46 p47 p48 p49 p50 p51 p52 p53 p54 \
          p62 p63 p64 p65 p66 p67 p68 p69 \
          p80 p81 p82 p83 p84 p85 p86 \
          p90 p91 p92 p93 p94 p95 p96 p97 p98 p99 p101 p102 p103 \
          p110 p111 p112 p113 p114 p115 \
          p120 p121 p122 p123 p124 p125 p126 p127 \
          p140 p141 p142 p143 p144 p145 p146 p147 p148 p149 \
          p150 p151 p152 p153 p154 p155 p156 p157 p158 p159 \
          p171 p172 p173 p174 p175 p176 p177 p178 p179 \
          p180 p181 p182 p183 p184 p185 p186 \
          p190 p191 p192 p193 p194 \
          p220 p221 p222 p223 p224 p225 p226 p227 p228 p229 p230 \
          p231 p232 p233
PARSER_PLANTS := p13 p15 p24 p25 p26 p27 p28 p37 p38 p39 p40 p41 p42 p43 p100 \
                 p210 p211 p212 p213 p214 p215 p216 p217 p218 p219
GATE_PLANTS := p59 p60 p61 p70 p71 p72 p73 p74 p75 p76 p77 p78 p79 p104 p105 p106 \
               p130 p131 p132 p133 p160 p161 p162 p163 p164 p165 p170 \
               p200 p201 p202 p203 p204 p234 p235 p236 p237 p238

.PHONY: all check-pic check-sha256 parser state-machine nanox-gate controls clean

all: check-pic check-sha256 parser state-machine nanox-gate

# A pointer stored in flash keeps its link-time address unless PIC() fixes it, and only the device
# crashes. This grep sees the plainest const pointer table; CI runs check_pic_objects.py on built
# objects, and its self-test runs here.
check-pic:
	@if grep -nE '^[[:space:]]*(static[[:space:]]+)?const[[:space:]]+[A-Za-z_]+[[:space:]]*\*[[:space:]]*(const[[:space:]]+)?[A-Za-z_][A-Za-z0-9_]*[[:space:]]*\[[^]]*\][[:space:]]*=' $(ROOT)/src/*.c $(ROOT)/src/*.h; then \
	    echo "const tables of pointers break on the device: store the data inline"; exit 1; \
	else \
	    echo "no const tables of pointers in src"; \
	fi
	python3 check_pic_objects.py --self-test

build/check_sha256: common/check_sha256.c common/sha256.h
	@mkdir -p build
	$(CC) -O1 -I common -o $@ $<

check-sha256: build/check_sha256
	./build/check_sha256

build/parser_fuzz_%: parser/fuzz.c $(wildcard parser/stubs/*.h) common/sha256.h $(wildcard $(ROOT)/src/*)
	@mkdir -p build
	$(CC) $(SAN) -DTARGET_$(shell echo $* | tr a-z A-Z) -I parser/stubs -I common -I $(ROOT)/src \
	    -Wno-deprecated-declarations -Wno-duplicate-decl-specifier \
	    -o $@ parser/fuzz.c $(ROOT)/src/base-encoding.c

parser: build/parser_fuzz_nanox build/parser_fuzz_nanos build/parser_fuzz_nanos2
	./build/parser_fuzz_nanox $(RUNS) $(SEED)
	./build/parser_fuzz_nanos $(RUNS) $(SEED)
	./build/parser_fuzz_nanos2 $(RUNS) $(SEED)
	./build/parser_fuzz_nanox limits
	./build/parser_fuzz_nanos limits
	./build/parser_fuzz_nanos2 limits

state-machine:
	CC=$(CC) state_machine/build.sh clean build/sm/clean
	./build/sm/clean/sm_fuzz $(RUNS) $(SEED)

# The Nano X and Nano S Plus approval gate under faults.
GATE_FLAGS := $(SAN) -DTARGET_NANOX -DAPPVERSION='"host"' -I nanox_gate/stubs -I state_machine/stubs \
	-I common -Wno-deprecated-declarations -Wno-duplicate-decl-specifier -Wno-unused-function
build/nanox_gate: nanox_gate/gate.c $(wildcard nanox_gate/stubs/*.h) $(wildcard state_machine/stubs/*.h) $(wildcard $(ROOT)/src/*)
	@mkdir -p build
	$(CC) $(GATE_FLAGS) -I $(ROOT)/src -o $@ nanox_gate/gate.c

nanox-gate: build/nanox_gate
	./build/nanox_gate

# Each planted bug must make its fuzzer fail; a pass means the fuzzer lost its teeth.
controls:
	@for p in $(PLANTS); do \
	    CC=$(CC) state_machine/build.sh $$p build/sm/$$p > /dev/null || exit 1; \
	    if ./build/sm/$$p/sm_fuzz 50000 7 > build/sm/$$p/run.log 2>&1; then \
	        echo "$$p NOT caught"; exit 1; \
	    else \
	        echo "$$p caught: $$(grep -m1 -oE '!!! [A-Z][0-9]|runtime error|AddressSanitizer' build/sm/$$p/run.log)"; \
	    fi; \
	done
	@for p in $(PARSER_PLANTS); do \
	    rm -rf build/pp/$$p && mkdir -p build/pp/$$p && cp -R $(ROOT)/src build/pp/$$p/src; \
	    python3 state_machine/plant.py $$p build/pp/$$p/src > /dev/null || exit 1; \
	    for t in NANOX NANOS NANOS2; do \
	        $(CC) $(SAN) -DTARGET_$$t -I parser/stubs -I common -I build/pp/$$p/src \
	            -Wno-deprecated-declarations -Wno-duplicate-decl-specifier -o build/pp/$$p/fuzz_$$t \
	            parser/fuzz.c build/pp/$$p/src/base-encoding.c || exit 1; \
	        if ./build/pp/$$p/fuzz_$$t 50000 7 > build/pp/$$p/run_$$t.log 2>&1; then \
	            echo "$$p NOT caught on $$t"; exit 1; \
	        else \
	            echo "$$p caught on $$t: $$(grep -m1 -oE 'FAIL: .*' build/pp/$$p/run_$$t.log)"; \
	        fi; \
	    done; \
	done

	@for p in $(GATE_PLANTS); do \
	    rm -rf build/gp/$$p && mkdir -p build/gp/$$p && cp -R $(ROOT)/src build/gp/$$p/src; \
	    python3 state_machine/plant.py $$p build/gp/$$p/src > /dev/null || exit 1; \
	    $(CC) $(GATE_FLAGS) -I build/gp/$$p/src -o build/gp/$$p/gate nanox_gate/gate.c || exit 1; \
	    if ./build/gp/$$p/gate > build/gp/$$p/run.log 2>&1; then \
	        echo "$$p NOT caught"; exit 1; \
	    else \
	        echo "$$p caught: $$(grep -m1 -oE '!!! G[0-9]+|runtime error|AddressSanitizer' build/gp/$$p/run.log)"; \
	    fi; \
	done

clean:
	rm -rf build
