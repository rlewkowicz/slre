CC      ?= cc
CFLAGS  ?= -O2 -Wall -Wextra -fomit-frame-pointer
LDFLAGS ?=

.PHONY: all test bench asan clean

all: unit_test

unit_test: unit_test.c slre.c slre.h
	$(CC) $(CFLAGS) -o $@ unit_test.c slre.c $(LDFLAGS)

bench: bench.c slre.c slre.h
	$(CC) $(CFLAGS) -o $@ bench.c slre.c $(LDFLAGS)

test: unit_test
	./unit_test

run-bench: bench
	./bench

asan: unit_test.c slre.c slre.h
	$(CC) -O0 -g -fsanitize=address,undefined -Wall -Wextra \
		-o unit_test_asan unit_test.c slre.c $(LDFLAGS)
	./unit_test_asan

clean:
	rm -f unit_test bench unit_test_asan
