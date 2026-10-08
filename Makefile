CC = gcc
CFLAGS = -Wall -Wextra -O2
LDFLAGS = -lm

SRCS = src/main.c src/module_scanner.c src/metadata.c src/baseline.c src/analyzer.c src/risk.c
OBJS = $(SRCS:.c=.o)

TARGET = detector

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

src/%.o: src/%.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(OBJS) $(TARGET)

.PHONY: all clean