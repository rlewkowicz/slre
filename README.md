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
  (Boyer-Moore-Horspool / `memchr`-and-verify hybrid).
* Match-time scratch buffers are pre-allocated at compile time so
  `hfre_exec` is malloc-free on the hot path.
* Builds clean under `-std=c23 -Wall -Wextra -pedantic-errors` and
  runs clean under `-fsanitize=address,undefined`.
* No dependency outside libc.

# Build

```
make             # builds unit_test
make test        # runs the unit tests
make bench       # builds the bench
make run-bench   # runs the bench
make asan        # builds + runs under ASAN/UBSAN (uses CC=clang or
                 # libsan-equipped gcc)
make portable-syntax   # -std=c23 -pedantic-errors -fsyntax-only
```

# Benchmarks

Nanoseconds per call, measured with `gcc-14 -O2 -std=c23` via
`make run-bench`. `v1 baseline` is the original recursive
backtracking engine for reference. `hfre_match` is the one-shot
wrapper (recompiles per call); `hfre_exec` is the same engine called
against a regex compiled once. Higher-frequency call sites should
prefer the compiled API.

| Workload                | v1 baseline | hfre_match | hfre_exec | Δ vs v1 baseline |
| ----------------------- | ----------: | ---------: | --------: | ---------------- |
| literal needle in 4KB   |      63 990 |      3 495 |     2 223 | 28.8× faster     |
| HTTP request capture    |       3 002 |      3 867 |     1 557 | 1.9× faster      |
| [a-z]+ icase 1KB upper  |      23 597 |     45 949 |     1 094 | 21.6× faster     |
| ^(a*)CONTROL on CONTROL |         197 |      1 617 |       165 | 1.2× faster      |
| zzz[0-9]+ late in 16KB  |     234 760 |      3 470 |       634 | 370× faster      |

Workloads not present in the v1 bench:

| Workload                  | hfre_exec |
| ------------------------- | --------: |
| (GET\|POST\|PUT\|DELETE)  |       158 |
| UTF-8 emoji 🦀            |        18 |
| [A-Za-z0-9_]+ on words    |        20 |
| .*error in 8KB log        |        18 |
| [0-9]+abc in 4KB          |       800 |
| anchored ^GET             |       103 |

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
