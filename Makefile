CC      ?= gcc
CSTD     = -std=c11 -D_POSIX_C_SOURCE=200809L -D_DEFAULT_SOURCE
WARN     = -Wall -Wextra -Wpedantic -Wshadow -Wformat=2
CFLAGS  ?= -O2 -g
CFLAGS  += $(CSTD) $(WARN)

LIB_SRCS = src/util.c src/module_scanner.c src/moddep.c src/metadata.c \
           src/scan.c src/baseline.c src/analyzer.c src/risk.c src/report.c
MAIN_SRC = src/main.c

BUILD   ?= build
TARGET   = detector
LIB_OBJS = $(LIB_SRCS:src/%.c=$(BUILD)/%.o)
MAIN_OBJ = $(MAIN_SRC:src/%.c=$(BUILD)/%.o)
TEST_BIN = $(BUILD)/test_unit

SAN_FLAGS = -fsanitize=address,undefined -fno-omit-frame-pointer -O1 -g

.PHONY: all clean test unit integration asan fuzz check demo \
        docker-build docker-test docker-demo docker-shell

all: $(TARGET)

$(TARGET): $(LIB_OBJS) $(MAIN_OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$(BUILD)/%.o: src/%.c $(wildcard src/*.h) | $(BUILD)
	$(CC) $(CFLAGS) -c -o $@ $<

$(BUILD):
	mkdir -p $(BUILD)

$(TEST_BIN): tests/test_unit.c $(LIB_OBJS) | $(BUILD)
	$(CC) $(CFLAGS) -Isrc -o $@ $^ $(LDFLAGS)

# --- tests -----------------------------------------------------------------
unit: $(TEST_BIN)
	./$(TEST_BIN)

integration: $(TARGET)
	DETECTOR=./$(TARGET) bash tests/run_tests.sh

test: unit integration

# Rebuild everything with AddressSanitizer + UBSan and run all tests.
asan:
	$(MAKE) clean
	$(MAKE) BUILD=build-asan CFLAGS="$(SAN_FLAGS)" LDFLAGS="-fsanitize=address,undefined" \
	    unit $(TARGET)
	DETECTOR=./$(TARGET) bash tests/run_tests.sh
	DETECTOR=./$(TARGET) bash tests/fuzz.sh
	$(MAKE) clean

# Fuzz an already-built sanitizer binary (run `make asan` flow first).
fuzz:
	$(MAKE) clean
	$(MAKE) BUILD=build-asan CFLAGS="$(SAN_FLAGS)" LDFLAGS="-fsanitize=address,undefined" $(TARGET)
	DETECTOR=./$(TARGET) bash tests/fuzz.sh
	$(MAKE) clean

# Everything: normal build + tests, then sanitizer build + tests + fuzzing.
check: test asan

demo: $(TARGET)
	DETECTOR=./$(TARGET) bash scripts/demo.sh

# --- docker ----------------------------------------------------------------
docker-build:
	docker build -t kmrd-detector .

docker-test: docker-build
	docker run --rm kmrd-detector

docker-demo: docker-build
	docker run --rm kmrd-detector make demo

docker-shell: docker-build
	docker run --rm -it kmrd-detector bash

clean:
	rm -rf build build-asan $(TARGET)
