hfre — hyper fast regular expressions
=====================================

A small, portable C23 regex engine. UTF-8 input is supported
transparently, captures use byte offsets into the original buffer,
and the engine guarantees no catastrophic backtracking.

* Compile-once / exec-many API: `hfre_compile`, `hfre_exec`,
  `hfre_capture_count`, `hfre_free`. A one-shot `hfre_match` wrapper
  is also provided.
* Pike VM (with captures) and a no-capture Thompson VM, dispatched
  automatically based on whether the caller asked for capture
  offsets.
* Compile-time analyses produce prefilter metadata used to
  short-circuit the VM whenever possible: anchored-start detection,
  256-bit byte-class bitmaps, pure-literal extraction, simple
  greedy-class-repeat shape detection, single- and small-set
  first-byte filters, and a dominator-based required-literal scan
  (Boyer-Moore-Horspool / adaptive `memchr` and word-at-a-time filtering).
* Runtime-dispatched AVX2 scans dense literal candidates and long ASCII
  class repeats on supported Intel and AMD CPUs. Other CPUs use the
  portable implementation; no global AVX compiler flag is required.
* Case-sensitive literal-only patterns, including `^literal`, `literal$`, and
  `^literal$`, and simple greedy rune/class repeats skip VM allocation
  and unrelated compile-time analyses. Case-insensitive classes traverse
  the Unicode fold table once per class.
* VM scratch uses one arena, with storage shared between mutually exclusive
  VMs. A compact bounded DFA cache uses byte-sized transition indices.
  `hfre_exec` performs no allocations.
* Builds clean under `-std=c23 -Wall -Wextra -pedantic-errors` and
  runs clean under `-fsanitize=address,undefined`.
* No dependency outside libc.

# Build

```
make             # builds unit_test
make test        # runs the unit tests
make test-scalar # tests with HFRE_DISABLE_SIMD
make test-alloc  # allocation accounting and failure injection
make bench       # builds bench with default -O3 -flto flags
make bench-scalar # builds bench_scalar with HFRE_DISABLE_SIMD
make bench-release test-release # -O3 -flto, builds bench_release
make bench-native test-native   # also -march=native, builds bench_native
make asan CC=clang        # ASAN/UBSAN, including allocation tests
make asan-scalar CC=clang # ASAN/UBSAN without SIMD
make portable-syntax   # -std=c23 -pedantic-errors -fsyntax-only
```

The default is the release profile: `-O3 -flto -fomit-frame-pointer`.
It had the best geometric mean across the 25 benchmark workloads and
the best compiled-matching aggregate in the compiler comparison.
Release builds retain runtime CPU dispatch. Native builds target the
build machine's instruction set; rebuild on the destination CPU when
using that profile. Both profiles include `-fomit-frame-pointer`.
`RELEASE_CFLAGS` and `NATIVE_CFLAGS` can be overridden independently.
See [performance notes](docs/performance.md) for compiler experiments,
memory usage, SIMD, and threading.

# Benchmarks

Nanoseconds per call on an Intel Core i9-12900K, Linux, GCC 16.2.1,
measured 2026-09-17. Results are medians of five runs per configuration,
rotating configuration order and running serially with `taskset -c 2`.
CPU 2 was verified as a **P-core** through Linux's `cpu_core` topology
(CPUs 0–15; E-cores are 16–23). AVX2 was active in both builds.

**Release** uses `-std=c23 -O3 -flto -fomit-frame-pointer`.
**Native** adds `-march=native`. These are current performance numbers,
not measurements on AMD or a guarantee for other workloads.

`hfre_match` recompiles on every call:

| Workload | Release (ns) | Native (ns) |
| -------- | -----------: | ----------: |
| literal needle in 4KB | 173.6 | 177.0 |
| HTTP request capture | 984.6 | 919.6 |
| [a-z]+ icase 1KB upper | 215.0 | 191.3 |
| ^(a*)CONTROL on CONTROL | 518.0 | 508.0 |
| zzz[0-9]+ late in 16KB | 822.6 | 838.1 |
| (GET\|POST\|PUT\|DELETE) | 916.8 | 892.4 |
| UTF-8 emoji 🦀 | 46.7 | 47.6 |

`hfre_exec` reuses a compiled regex:

| Workload | Release (ns) | Native (ns) |
| -------- | -----------: | ----------: |
| literal needle in 4KB | 109.8 | 109.9 |
| HTTP request capture | 370.4 | 361.1 |
| [a-z]+ icase 1KB upper | 25.3 | 25.3 |
| ^(a*)CONTROL on CONTROL | 49.7 | 70.8 |
| zzz[0-9]+ late in 16KB | 165.0 | 168.2 |
| (GET\|POST\|PUT\|DELETE) | 46.7 | 49.8 |
| UTF-8 emoji 🦀 | 5.8 | 5.7 |
| [A-Za-z0-9_]+ on words | 7.8 | 7.9 |
| .*error in 8KB log | 8.5 | 8.5 |
| [0-9]+abc in 4KB | 246.5 | 248.6 |
| anchored ^GET | 3.0 | 3.0 |
| literal miss, dense first bytes | 108.8 | 112.4 |
| literal miss, sparse first bytes | 23.6 | 24.1 |
| literal at start | 6.3 | 6.0 |
| [A-Za-z0-9_]+ in 16KB | 326.6 | 320.7 |
| [a-z]+ icase miss in 8KB digits | 166.8 | 162.1 |
| [a-z]+ icase late in 8KB digits | 171.0 | 169.3 |
| [^0-9]+ in 1KB upper | 26.5 | 26.3 |

The dense-miss case searches for `needle` in 4KB of `n`; the
sparse-miss case uses 4KB of `x`. Buffers and compiled objects are reused,
so these measurements reflect warm caches. Native tuning is workload
dependent: it helps some compilation cases but slows the small
`^(a*)CONTROL` execution case.

Run `taskset -c 2 ./bench` on this machine, or choose a verified
performance core on your machine. Add `--exec-only` for compiled matching.
The harness checks compile and match results and warms each workload
before timing. For frequent calls, prefer the compiled API.

# License

MIT — see [LICENSE](LICENSE).

# Acknowledgements

This project began as a fork of [SLRE](https://github.com/cesanta/slre)
("Super Light Regular Expression library") by Sergey Lyubka and
Cesanta Software. Although the engine, compiler, VMs, prefilters, and
public API have all been rewritten, the original SLRE was the
starting point and inspiration, and the unit-test corpus that
shipped with it remains a useful baseline for regression checking.
Thanks to Sergey and Cesanta for releasing the original 
