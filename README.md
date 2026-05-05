SLRE: Super Light Regular Expression library
============================================

Documentation and API reference are at
[docs.cesanta.com/slre](https://docs.cesanta.com/slre)

# Benchmarks

All numbers are nanoseconds per call, measured with `gcc-14 -O2` via
`make run-bench`. `v1 baseline` is the original recursive backtracking
engine; `v1 optimized` is the same engine after the first round of
targeted optimizations; `NEW slre_match` is the rewritten engine
called via the legacy one-shot wrapper (recompiles per call); `NEW
slre_exec` is the rewritten engine called against a regex compiled
once.

| Workload                | v1 baseline | v1 optimized | NEW slre_match | NEW slre_exec | Δ vs v1 baseline |
| ----------------------- | ----------: | -----------: | -------------: | ------------: | ---------------- |
| literal needle in 4KB   |      63 990 |        5 015 |          2 545 |         2 064 | 31.0× faster     |
| HTTP request capture    |       3 002 |        2 913 |          1 855 |           855 | 3.5× faster      |
| [a-z]+ icase 1KB upper  |      23 597 |       22 700 |          1 418 |         1 090 | 21.6× faster     |
| ^(a*)CONTROL on CONTROL |         197 |          211 |            519 |           201 | unchanged        |
| zzz[0-9]+ late in 16KB  |     234 760 |          511 |          1 062 |           611 | 384× faster      |

Plus three new workloads not in the old bench:

| Workload               | NEW slre_exec |
| ---------------------- | ------------: |
| (GET\|POST\|PUT\|DELETE) |     163 ns/op |
| UTF-8 emoji 🦀         |      16 ns/op |
| [A-Za-z0-9_]+ on words |      17 ns/op |

# Contributions

To submit contributions, sign
[Cesanta CLA](https://docs.cesanta.com/contributors_la.shtml)
and send GitHub pull request.

# Licensing

SLRE is released under commercial and
[GNU GPL v.2](http://www.gnu.org/licenses/old-licenses/gpl-2.0.html)
open source licenses.

Commercial Projects:
Once your project becomes commercialised GPLv2 licensing dictates that you need to either open your source fully or purchase a commercial license. Cesanta offer full, royalty-free commercial licenses without any GPL restrictions. If your needs require a custom license, we’d be happy to work on a solution with you. [Contact us for pricing.] (https://www.cesanta.com/contact)
