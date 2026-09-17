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
make bench       # builds bench with default -O3 -flto -march=native flags
make bench-scalar # builds bench_scalar with HFRE_DISABLE_SIMD
make bench-release test-release # portable -O3 -flto, builds bench_release
make bench-native test-native   # explicit native profile, builds bench_native
make asan CC=clang        # ASAN/UBSAN, including allocation tests
make asan-scalar CC=clang # ASAN/UBSAN without SIMD
make portable-syntax   # -std=c23 -pedantic-errors -fsyntax-only
```

The default is the native profile:
`-O3 -flto -march=native -fomit-frame-pointer`.
It led the aggregate across 30 benchmark workloads in two comparison
batches, with the clearest gains in compilation. Compiled matching was
effectively tied overall. Release builds retain runtime CPU dispatch.
Native builds target the
build machine's instruction set; rebuild on the destination CPU when
using that profile. Both profiles include `-fomit-frame-pointer`.
`RELEASE_CFLAGS` and `NATIVE_CFLAGS` can be overridden independently.
See [performance notes](docs/performance.md) for compiler experiments,
memory usage, SIMD, and threading.

# Benchmarks

Nanoseconds per call on an Intel Core i9-12900K, Linux, GCC 16.2.1,
measured 2026-09-17. Results are medians of ten runs per configuration,
interleaving configurations and running serially with `taskset -c 2`.
CPU 2 was verified as a **P-core** through Linux's `cpu_core` topology
(CPUs 0–15; E-cores are 16–23). AVX2 was active in both builds.

**Release** uses `-std=c23 -O3 -flto -fomit-frame-pointer`.
**Native** adds `-march=native`. These are current performance numbers,
not measurements on AMD or a guarantee for other workloads.

`hfre_match` recompiles on every call:

| Workload | Release (ns) | Native, default (ns) |
| -------- | -----------: | ----------: |
| literal needle in 4KB | 176.2 | 178.8 |
| HTTP request capture | 963.0 | 912.6 |
| [a-z]+ icase 1KB upper | 170.4 | 143.0 |
| ^(a*)CONTROL on CONTROL | 494.9 | 489.3 |
| zzz[0-9]+ late in 16KB | 842.5 | 834.5 |
| (GET\|POST\|PUT\|DELETE) | 940.3 | 927.5 |
| UTF-8 emoji 🦀 | 46.7 | 46.7 |
| fixed HTTP fields with captures | 1409.7 | 1405.5 |

`hfre_exec` reuses a compiled regex:

| Workload | Release (ns) | Native, default (ns) |
| -------- | -----------: | ----------: |
| literal needle in 4KB | 113.2 | 108.8 |
| HTTP request capture | 365.9 | 375.9 |
| [a-z]+ icase 1KB upper | 26.7 | 26.6 |
| ^(a*)CONTROL on CONTROL | 50.2 | 54.1 |
| zzz[0-9]+ late in 16KB | 165.3 | 169.9 |
| (GET\|POST\|PUT\|DELETE) | 43.7 | 47.2 |
| UTF-8 emoji 🦀 | 5.9 | 5.9 |
| [A-Za-z0-9_]+ on words | 8.4 | 7.9 |
| .*error in 8KB log | 8.6 | 8.1 |
| [0-9]+abc in 4KB | 242.9 | 242.2 |
| anchored ^GET | 3.0 | 3.1 |
| literal miss, dense first bytes | 117.2 | 113.1 |
| literal miss, sparse first bytes | 24.1 | 24.1 |
| literal at start | 6.2 | 6.5 |
| [A-Za-z0-9_]+ in 16KB | 322.8 | 321.8 |
| [a-z]+ icase miss in 8KB digits | 166.9 | 165.6 |
| [a-z]+ icase late in 8KB digits | 172.8 | 170.2 |
| [^0-9]+ in 1KB upper | 28.9 | 26.6 |
| fixed HTTP fields with captures | 69.2 | 70.4 |
| 256-byte required literal miss in 16KB | 180.3 | 181.6 |
| icase kx late in 8KB (Kelvin) | 169.2 | 170.2 |
| icase kx miss in 8KB digits | 140.9 | 138.8 |

The dense-miss case searches for `needle` in 4KB of `n`; the
sparse-miss case uses 4KB of `x`. Buffers and compiled objects are reused,
so these measurements reflect warm caches. Native tuning is workload
dependent. The long required-literal case searches for 256 zero digits
in nonmatching text; the case-insensitive prefix tests include the
Unicode Kelvin-sign fold. These expose specific search paths and do
not represent a general application mix.

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
