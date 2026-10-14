# Build system for the detector (phases 5-8 on top of src/module_scanner.c).
#
# GNU make reads this file in preference to "Makefile", so the original
# Makefile is left untouched. Everything here builds from the sources that
# exist; it never edits another file.
#
#   make            build ./detector
#   make test       unit + integration tests
#   make asan       sanitizer build + all tests + fuzzing
#   make check      everything, plus the legacy CLI build check
#   make legacy     build the original phase-2 CLI (src/main.c) as-is
#   make docker-test / docker-demo / docker-shell

CC      ?= gcc
CSTD     = -std=c11 -D_POSIX_C_SOURCE=200809L -D_DEFAULT_SOURCE
WARN     = -Wall -Wextra -Wpedantic -Wshadow -Wformat=2
CFLAGS  ?= -O2 -g
CFLAGS  += $(CSTD) $(WARN)

# Sources of the original phase 1-4 CLI that this build does not use
# (see docs/STATUS.md for why).
LEGACY_SRCS = src/main.c src/metadata.c src/report_helper.c src/utilities.c \
              src/finalize.c
APP_MAIN    = src/cli.c

LIB_SRCS = $(filter-out $(LEGACY_SRCS) $(APP_MAIN),$(wildcard src/*.c))
UT_SRCS  = $(wildcard tests/unit/*.c)

BUILD   ?= build
TARGET   = detector
LIB_OBJS = $(LIB_SRCS:src/%.c=$(BUILD)/%.o)
UT_OBJS  = $(UT_SRCS:tests/unit/%.c=$(BUILD)/ut/%.o)
UT_BIN   = $(BUILD)/unit_tests

SAN_FLAGS = -fsanitize=address,undefined -fno-omit-frame-pointer -O1 -g
SAN_LD    = -fsanitize=address,undefined

.PHONY: all clean test unit integration asan fuzz check demo legacy legacy-check \
        docker-build docker-test docker-demo docker-shell

all: $(TARGET)

ifneq ($(wildcard $(APP_MAIN)),)
$(TARGET): $(LIB_OBJS) $(BUILD)/cli.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)
else
$(TARGET):
	@echo "no command line front end yet ($(APP_MAIN) missing)"; exit 1
endif

$(BUILD)/%.o: src/%.c $(wildcard src/*.h) | $(BUILD)
	$(CC) $(CFLAGS) -c -o $@ $<

$(BUILD)/ut/%.o: tests/unit/%.c $(wildcard src/*.h tests/unit/*.h) | $(BUILD)/ut
	$(CC) $(CFLAGS) -Isrc -c -o $@ $<

$(UT_BIN): $(UT_OBJS) $(LIB_OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$(BUILD) $(BUILD)/ut:
	mkdir -p $@

# --- tests -----------------------------------------------------------------
unit: $(UT_BIN)
	./$(UT_BIN)

integration: $(TARGET)
	DETECTOR=./$(TARGET) bash tests/run_tests.sh

test: unit integration

# Rebuild everything with AddressSanitizer + UBSan; run unit + integration
# tests and the mutation fuzzer against the instrumented binaries.
asan:
	$(MAKE) clean
	$(MAKE) BUILD=build-asan CFLAGS="$(SAN_FLAGS)" LDFLAGS="$(SAN_LD)" unit $(TARGET)
	DETECTOR=./$(TARGET) bash tests/run_tests.sh
	DETECTOR=./$(TARGET) bash tests/fuzz.sh
	$(MAKE) clean

fuzz:
	$(MAKE) clean
	$(MAKE) BUILD=build-asan CFLAGS="$(SAN_FLAGS)" LDFLAGS="$(SAN_LD)" $(TARGET)
	DETECTOR=./$(TARGET) bash tests/fuzz.sh
	$(MAKE) clean

check: test legacy-check asan

demo: $(TARGET)
	DETECTOR=./$(TARGET) bash scripts/demo.sh

# --- the original phase-2 CLI (src/main.c) ----------------------------------
# Its sources are UTF-16 files, which compilers cannot read. They are
# converted into build/legacy/ on the fly; the files in src/ are never
# modified. Its header also lacks the scanner prototypes, which
# src/scanner_decl.h supplies via -include.
LEGACY_BUILD = $(BUILD)/legacy
LEGACY_BIN   = $(LEGACY_BUILD)/detector-legacy
LEGACY_UTF   = $(LEGACY_BUILD)/main.c $(LEGACY_BUILD)/metadata.c $(LEGACY_BUILD)/metadata.h

$(LEGACY_BUILD)/%: src/% scripts/to_utf8.sh | $(LEGACY_BUILD)
	sh scripts/to_utf8.sh $< $@

$(LEGACY_BUILD):
	mkdir -p $@

$(LEGACY_BIN): $(LEGACY_UTF) src/module_scanner.c
	$(CC) $(CFLAGS) -include scanner_decl.h -I$(LEGACY_BUILD) -Isrc -o $@ \
	    $(LEGACY_BUILD)/main.c $(LEGACY_BUILD)/metadata.c src/module_scanner.c

legacy: $(LEGACY_BIN)

legacy-check: $(LEGACY_BIN)
	@$(LEGACY_BIN) 2>&1 | grep -q 'scan' && echo "legacy CLI builds and runs"

# --- docker ----------------------------------------------------------------
docker-build:
	docker build -t kmrd-detector .

docker-test: docker-build
	docker run --rm kmrd-detector

docker-demo: docker-build
	docker run --rm kmrd-detector make demo

docker-shell: docker-build
	docker run --rm -it kmrd-detector bash

# build/ keeps its tracked .gitignore
clean:
	find build -mindepth 1 ! -name .gitignore -delete 2>/dev/null || true
	rm -rf build-asan $(TARGET)
