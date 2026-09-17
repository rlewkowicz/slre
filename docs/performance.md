# Performance notes

The [README](../README.md#benchmarks) lists current benchmark results.
Measurements below use GCC 16.2.1 on an Intel Core i9-12900K,
2026-09-17. Benchmarks and final correctness runs were pinned to CPU 2,
a verified P-core. Benchmark configurations ran serially, with five
rounds and a rotating configuration order.

## Build profiles and compiler flags

The default build uses `-O3 -flto -fomit-frame-pointer`. `make bench-release`
builds `bench_release` with the same flags;
`make bench-native` builds `bench_native` with those flags plus
`-march=native`. Separate filenames prevent accidentally timing a binary
left over from another profile. `make test-release` and `make test-native`
run the same correctness suite under those flags.

Here are current medians in nanoseconds per call. Each configuration
includes `-fomit-frame-pointer` unless indicated otherwise.

| Flags | HTTP capture, exec | 1KB icase class, compile + exec | `^(a*)CONTROL`, exec | 16KB class, exec |
| --- | ---: | ---: | ---: | ---: |
| `-O2` | 393.1 | 283.6 | 57.6 | 321.1 |
| `-O3` | 356.8 | 207.9 | 65.9 | 325.3 |
| `-O3 -march=native` | 356.6 | 196.5 | 68.9 | 321.3 |
| `-O3 -flto` | 370.4 | 215.0 | 49.7 | 326.6 |
| `-O3 -flto -march=native` | 361.1 | 191.3 | 70.8 | 320.7 |
| Native + LTO, `-fno-omit-frame-pointer` | 367.0 | 194.0 | 73.7 | 325.1 |

There is no universally fastest flag combination. LTO permits optimization
across the application/engine boundary; use it at both compilation and
linking when integrating the source. Native tuning enables instructions
for the build CPU throughout the program, beyond the guarded AVX2 functions.
Use the release profile for binaries intended to run on other CPUs.

The release profile is the default because it had the highest geometric
mean of per-workload speed ratios across all 25 cases: 1.086× relative
to `-O2`, versus 1.078× for native LTO. It also led the 18 compiled-matching
cases, at 1.075× versus 1.054×. Each workload receives equal weight in
these aggregates; they do not predict a particular application's mix.
Native LTO led the seven compile-and-match cases. Sub-nanosecond
differences should be treated as timing noise rather than reliable wins.

Adding `-fno-semantic-interposition` to the native LTO benchmark produced
an identical executable `.text` section. This directly linked executable
does not demonstrate its potential benefit for a shared-library build.
The option changes assumptions about interposed symbols and should be
evaluated in that integration context.

The engine has no floating-point arithmetic. Its assembly was identical
under `-O2`, `-O2 -ffast-math`, and `-O2 -fdelete-null-pointer-checks`.
Fast-math relaxes floating-point semantics, including assumptions about
NaNs and infinities; it does not supply the pointer-null-check option.
Neither flag was added. The benchmark's floating-point time conversion
occurs outside the timed loop. See the
[GCC optimization options](https://gcc.gnu.org/onlinedocs/gcc-16.2.0/gcc/Optimize-Options.html).

## SIMD and literal search

Sparse literal candidates use libc's `memchr` followed by `memcmp`.
After several nearby false candidates, the scanner filters two literal
bytes at eight positions per word, or 32 positions per AVX2 vector.
Full verification still determines every match.

Greedy ASCII class repeats use two AVX2 byte shuffles to test arbitrary
ASCII class bitmaps. Non-ASCII bytes return to UTF-8 decoding and Unicode
class matching, including case folds such as Kelvin sign and long s.
Malformed UTF-8 follows the same matching behavior as the VM. Short spans
use scalar code to avoid vector setup costs.

Every vector load stays within the supplied buffer. Tails use scalar code
or an overlapping final vector with consumed lanes masked out. No padding,
special alignment, or caller-owned scratch buffer is required.

The implementation uses intrinsics in functions annotated with
`target("avx2")`, guarded by runtime CPU capability checks. GCC/Clang x86
builds emit the vector comparisons, shuffles, masks, and `vzeroupper`
without handwritten assembly. Other architectures and compilers use the
portable path. Define `HFRE_DISABLE_SIMD` to test that path explicitly.
This disables the engine's explicit SIMD; libc or compiler-generated
vector instructions may still be used.

AVX2 is supported by AMD as well as Intel. For example,
[AMD documents AVX2 support across Zen generations](https://docs.amd.com/r/en-US/57404-AOCL-user-guide/11.4.4.-Run-Time-ISA-Selection).
Dispatch checks capabilities, not vendor names. AMD performance has not
been measured here.

## Memory and allocations

Literal-only patterns and simple greedy rune/class repeats return from
compilation before allocating filters or VM scratch they cannot use.
Other patterns use one checked-size arena for thread lists, capture pools,
generation markers, and capture output. Thompson and Pike execution reuse
thread-list storage. The bounded 64-state DFA cache occupies 9,216 bytes
on this machine, using signed-byte transition indices.

Current requested heap bytes and allocator calls per compile, measured
with `make test-alloc` in the default SIMD-capable build:

| Pattern | Live bytes | Allocation calls |
| --- | ---: | ---: |
| `needle` | 1,086 | 3 |
| `[a-z]+`, ignore case | 1,368 | 3 |
| `[A-Za-z0-9_]+` | 1,368 | 3 |
| `a+` | 1,080 | 2 |
| `[\p{Greek}]+` | 1,368 | 3 |
| `a[0-9]+b` | 11,684 | 15 |
| `(a(b)\|a(c))` | 4,852 | 13 |
| HTTP request with four captures | 9,897 | 17 |

These counts include requested engine allocations, excluding allocator
metadata; peak requested bytes equal live bytes for these examples.
Execution performs no allocations. The allocation test checks cleanup
and injects failure at each allocation call, including optional
accelerator allocations.

## Parallelism

Process independent inputs concurrently with one compiled regex per
worker. A compiled object contains mutable scratch and DFA transitions,
so concurrent execution on the same object is unsupported.

The engine does not create threads for individual matches. Arbitrary
regexes can span buffer divisions and depend on anchors, greediness,
and captures, so dividing one input into independent chunks would change
semantics without additional coordination. Scheduling overhead would also
dominate many of the nanosecond-scale cases above.

## Verification

The 2,668,827-assertion suite passes with SIMD enabled and disabled, under
the release and native profiles, and with Clang ASAN/UBSAN. Tests cover
literal-search alignments and tails against an independent byte-search
oracle, class scans against the capturing VM, Unicode and invalid UTF-8,
and alternating capture/no-capture execution on shared scratch storage.
Allocation accounting and failure injection also pass ASAN/UBSAN.
Strict C23 syntax checks pass with SIMD enabled and disabled.
