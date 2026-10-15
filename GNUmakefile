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
#
# Output is kept short (one line per compile/link step, a banner per test
# stage). Use `make V=1 ...` to see the full compiler commands and the
# complete list of unit tests.

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

MAKEFLAGS += --no-print-directory
ifeq ($(V),1)
  Q        :=
  UT_FLAGS :=
  say       = @true
else
  Q        := @
  UT_FLAGS := -q
  say       = @printf '  %-5s %s\n' $(1) $(2)
endif
# stage banner: coloured on a terminal, plain otherwise
banner = @if [ -t 1 ]; then printf '\033[1;36m==>\033[0m \033[1m%s\033[0m\n' '$(1)'; else printf '==> %s\n' '$(1)'; fi

SAN_FLAGS = -fsanitize=address,undefined -fno-omit-frame-pointer -O1 -g
SAN_LD    = -fsanitize=address,undefined

.PHONY: all clean test unit integration asan fuzz check demo legacy legacy-check \
        docker-build docker-test docker-demo docker-shell

all: $(TARGET)

ifneq ($(wildcard $(APP_MAIN)),)
$(TARGET): $(LIB_OBJS) $(BUILD)/cli.o
	$(call say,LD,$@)
	$(Q)$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)
else
$(TARGET):
	@echo "no command line front end yet ($(APP_MAIN) missing)"; exit 1
endif

$(BUILD)/%.o: src/%.c $(wildcard src/*.h) | $(BUILD)
	$(call say,CC,$<)
	$(Q)$(CC) $(CFLAGS) -c -o $@ $<

$(BUILD)/ut/%.o: tests/unit/%.c $(wildcard src/*.h tests/unit/*.h) | $(BUILD)/ut
	$(call say,CC,$<)
	$(Q)$(CC) $(CFLAGS) -Isrc -c -o $@ $<

$(UT_BIN): $(UT_OBJS) $(LIB_OBJS)
	$(call say,LD,$@)
	$(Q)$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$(BUILD) $(BUILD)/ut:
	$(Q)mkdir -p $@

# --- tests -----------------------------------------------------------------
unit: $(UT_BIN)
	$(call banner,unit tests)
	$(Q)./$(UT_BIN) $(UT_FLAGS)

integration: $(TARGET)
	$(call banner,integration tests: fabricated /proc + /sys systems and the live kernel)
	$(Q)DETECTOR=./$(TARGET) bash tests/run_tests.sh
	$(call banner,terminal UI and monitor tests)
	$(Q)DETECTOR=./$(TARGET) bash tests/run_ui_tests.sh

test: unit integration

# Rebuild everything with AddressSanitizer + UBSan; run unit + integration
# tests and the mutation fuzzer against the instrumented binaries.
asan:
	$(call banner,sanitizer build: AddressSanitizer + UBSan)
	$(Q)$(MAKE) clean
	$(Q)$(MAKE) BUILD=build-asan CFLAGS="$(SAN_FLAGS)" LDFLAGS="$(SAN_LD)" unit $(TARGET)
	$(call banner,integration tests under sanitizers)
	$(Q)DETECTOR=./$(TARGET) bash tests/run_tests.sh
	$(Q)DETECTOR=./$(TARGET) bash tests/run_ui_tests.sh
	$(call banner,mutation fuzzing under sanitizers)
	$(Q)DETECTOR=./$(TARGET) bash tests/fuzz.sh
	$(Q)$(MAKE) clean

fuzz:
	$(Q)$(MAKE) clean
	$(Q)$(MAKE) BUILD=build-asan CFLAGS="$(SAN_FLAGS)" LDFLAGS="$(SAN_LD)" $(TARGET)
	$(call banner,mutation fuzzing under sanitizers)
	$(Q)DETECTOR=./$(TARGET) bash tests/fuzz.sh
	$(Q)$(MAKE) clean

check: test legacy-check asan
	$(call banner,all checks passed)

demo: $(TARGET)
	$(Q)DETECTOR=./$(TARGET) bash scripts/demo.sh

# --- the original phase-2 CLI (src/main.c) ----------------------------------
# Its sources are UTF-16 files, which compilers cannot read. They are
# converted into build/legacy/ on the fly; the files in src/ are never
# modified. Its header also lacks the scanner prototypes, which
# src/scanner_decl.h supplies via -include.
LEGACY_BUILD = $(BUILD)/legacy
LEGACY_BIN   = $(LEGACY_BUILD)/detector-legacy
LEGACY_UTF   = $(LEGACY_BUILD)/main.c $(LEGACY_BUILD)/metadata.c $(LEGACY_BUILD)/metadata.h

$(LEGACY_BUILD)/%: src/% scripts/to_utf8.sh | $(LEGACY_BUILD)
	$(call say,UTF8,$<)
	$(Q)sh scripts/to_utf8.sh $< $@

$(LEGACY_BUILD):
	$(Q)mkdir -p $@

$(LEGACY_BIN): $(LEGACY_UTF) src/module_scanner.c
	$(call say,LD,$@)
	$(Q)$(CC) $(CFLAGS) -include scanner_decl.h -I$(LEGACY_BUILD) -Isrc -o $@ \
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
	$(Q)find build -mindepth 1 ! -name .gitignore -delete 2>/dev/null || true
	$(Q)rm -rf build-asan $(TARGET)
