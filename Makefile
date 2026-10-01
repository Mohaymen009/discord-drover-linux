CC      ?= gcc
CFLAGS  ?= -O2 -Wall -Wextra
LIB      = build/libdrover.so
SRC      = src/drover_linux.c

.PHONY: all clean test

all: $(LIB)

$(LIB): $(SRC)
	@mkdir -p build
	$(CC) $(CFLAGS) -fPIC -shared -o $@ $< -ldl -lpthread

test: $(LIB)
	@mkdir -p build
	$(CC) $(CFLAGS) -o build/test_sender tests/test_sender.c
	bash tests/run_tests.sh

clean:
	rm -rf build
