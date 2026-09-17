CC      ?= cc
CSTD    ?= -std=c23
RELEASE_CFLAGS ?= -O3 -flto -Wall -Wextra -fomit-frame-pointer
CFLAGS  ?= $(NATIVE_CFLAGS)
LDFLAGS ?=
NATIVE_CFLAGS  ?= $(RELEASE_CFLAGS) -march=native

# Benchmark uses clock_gettime, which needs a recent POSIX feature
# level on glibc.
BENCH_CFLAGS = -D_POSIX_C_SOURCE=200809L

.PHONY: all test test-scalar test-alloc test-release test-native bench bench-scalar \
	bench-release bench-native run-bench asan asan-scalar portable-syntax clean

all: unit_test

unit_test: unit_test.c hfre.c hfre.h Makefile
	$(CC) $(CSTD) $(CFLAGS) -o $@ unit_test.c hfre.c $(LDFLAGS)

bench: bench.c hfre.c hfre.h Makefile
	$(CC) $(CSTD) $(CFLAGS) $(BENCH_CFLAGS) -o $@ bench.c hfre.c $(LDFLAGS)

test: unit_test
	./unit_test

unit_test_scalar: unit_test.c hfre.c hfre.h Makefile
	$(CC) $(CSTD) $(CFLAGS) -DHFRE_DISABLE_SIMD -o $@ unit_test.c hfre.c $(LDFLAGS)

test-scalar: unit_test_scalar
	./unit_test_scalar

allocation_test: allocation_test.c hfre.c hfre.h Makefile
	$(CC) $(CSTD) $(CFLAGS) -o $@ allocation_test.c $(LDFLAGS)

test-alloc: allocation_test
	./allocation_test

bench_scalar: bench.c hfre.c hfre.h Makefile
	$(CC) $(CSTD) $(CFLAGS) $(BENCH_CFLAGS) -DHFRE_DISABLE_SIMD \
		-o $@ bench.c hfre.c $(LDFLAGS)

bench-scalar: bench_scalar

# Separate outputs avoid reusing a binary built with another profile.
# LTO flags apply to compilation and linking here.
unit_test_release: unit_test.c hfre.c hfre.h Makefile
	$(CC) $(CSTD) $(RELEASE_CFLAGS) -o $@ unit_test.c hfre.c $(LDFLAGS)

test-release: unit_test_release
	./unit_test_release

bench_release: bench.c hfre.c hfre.h Makefile
	$(CC) $(CSTD) $(RELEASE_CFLAGS) $(BENCH_CFLAGS) -o $@ bench.c hfre.c $(LDFLAGS)

bench-release: bench_release

unit_test_native: unit_test.c hfre.c hfre.h Makefile
	$(CC) $(CSTD) $(NATIVE_CFLAGS) -o $@ unit_test.c hfre.c $(LDFLAGS)

test-native: unit_test_native
	./unit_test_native

bench_native: bench.c hfre.c hfre.h Makefile
	$(CC) $(CSTD) $(NATIVE_CFLAGS) $(BENCH_CFLAGS) -o $@ bench.c hfre.c $(LDFLAGS)

bench-native: bench_native

run-bench: bench
	./bench

asan: unit_test.c allocation_test.c hfre.c hfre.h
	$(CC) $(CSTD) -O0 -g -fsanitize=address,undefined -Wall -Wextra \
		-o unit_test_asan unit_test.c hfre.c $(LDFLAGS)
	./unit_test_asan
	$(CC) $(CSTD) -O0 -g -fsanitize=address,undefined -Wall -Wextra \
		-o allocation_test_asan allocation_test.c $(LDFLAGS)
	./allocation_test_asan

asan-scalar: unit_test.c hfre.c hfre.h
	$(CC) $(CSTD) -O0 -g -fsanitize=address,undefined -Wall -Wextra \
		-DHFRE_DISABLE_SIMD -o unit_test_asan_scalar unit_test.c hfre.c $(LDFLAGS)
	./unit_test_asan_scalar

# Portable syntax-only check: no codegen, no linking, just verify the
# sources are clean under -std=c23 -pedantic-errors. Bench uses POSIX
# clock_gettime so we keep the POSIX feature flag here too.
portable-syntax: hfre.c hfre.h unit_test.c bench.c allocation_test.c
	$(CC) -std=c23 -Wall -Wextra -pedantic-errors -fsyntax-only hfre.c
	$(CC) -std=c23 -Wall -Wextra -pedantic-errors -DHFRE_DISABLE_SIMD -fsyntax-only hfre.c
	$(CC) -std=c23 -Wall -Wextra -pedantic-errors -fsyntax-only unit_test.c
	$(CC) -std=c23 -Wall -Wextra -pedantic-errors -fsyntax-only allocation_test.c
	$(CC) -std=c23 -Wall -Wextra -pedantic-errors $(BENCH_CFLAGS) \
		-fsyntax-only bench.c

clean:
	rm -f unit_test bench unit_test_asan unit_test_scalar bench_scalar unit_test_asan_scalar \
		allocation_test allocation_test_asan unit_test_release unit_test_native \
		bench_release bench_native
