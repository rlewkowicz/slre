CC      ?= cc
CSTD    ?= -std=c23
CFLAGS  ?= -O2 -Wall -Wextra -fomit-frame-pointer
LDFLAGS ?=

# Benchmark uses clock_gettime, which needs a recent POSIX feature
# level on glibc.
BENCH_CFLAGS = -D_POSIX_C_SOURCE=200809L

.PHONY: all test bench run-bench asan portable-syntax clean

all: unit_test

unit_test: unit_test.c hfre.c hfre.h
	$(CC) $(CSTD) $(CFLAGS) -o $@ unit_test.c hfre.c $(LDFLAGS)

bench: bench.c hfre.c hfre.h
	$(CC) $(CSTD) $(CFLAGS) $(BENCH_CFLAGS) -o $@ bench.c hfre.c $(LDFLAGS)

test: unit_test
	./unit_test

run-bench: bench
	./bench

asan: unit_test.c hfre.c hfre.h
	$(CC) $(CSTD) -O0 -g -fsanitize=address,undefined -Wall -Wextra \
		-o unit_test_asan unit_test.c hfre.c $(LDFLAGS)
	./unit_test_asan

# Portable syntax-only check: no codegen, no linking, just verify the
# sources are clean under -std=c23 -pedantic-errors. Bench uses POSIX
# clock_gettime so we keep the POSIX feature flag here too.
portable-syntax: hfre.c hfre.h unit_test.c bench.c
	$(CC) -std=c23 -Wall -Wextra -pedantic-errors -fsyntax-only hfre.c
	$(CC) -std=c23 -Wall -Wextra -pedantic-errors -fsyntax-only unit_test.c
	$(CC) -std=c23 -Wall -Wextra -pedantic-errors $(BENCH_CFLAGS) \
		-fsyntax-only bench.c

clean:
	rm -f unit_test bench unit_test_asan
