---
title: "Overview"
---

hfre is a small portable C23 regex engine that implements a useful
subset of Perl-style syntax with UTF-8 support. Highlights:

* Compile-once / exec-many API (`hfre_compile`, `hfre_exec`,
  `hfre_free`); the legacy `hfre_match` is preserved as a one-shot
  wrapper.
* UTF-8 input is supported transparently. Non-ASCII literals, including
  emoji, match their UTF-8 byte sequence; `.` matches one full code
  point. RE2-style Unicode property classes (`\pN`, `\p{Greek}`,
  `\PN`, `\P{Greek}`) are supported both as atoms and inside bracket
  classes using Unicode Character Database 17.0.0 ranges.
* `HFRE_IGNORE_CASE` applies simple single-code-point Unicode folding
  for supported scripts. Multi-code-point folds and Unicode
  normalization are intentionally out of scope.
* Pike VM (with captures) and a no-capture Thompson VM are both
  available — `hfre_exec` picks the cheaper path automatically based
  on whether the caller asked for capture offsets. Both VMs use
  leftmost-first alternation and greedy/lazy quantifier semantics, so
  there's no catastrophic backtracking on nested quantifiers.
* Compile-time analyses produce prefilter metadata used to
  short-circuit the VM whenever possible: anchored-start detection,
  anchored-end finite-length bounds, 256-bit byte-class bitmaps,
  pure-literal extraction, suffix-literal checks, simple greedy
  rune/class-repeat shape detection, single-byte and small-set
  first-byte filters, literal-run and repeat bytecode opcodes,
  top-level multi-literal filters, adaptive literal scanning,
  a bounded lazy-DFA reject cache for eligible no-capture ASCII
  bytecode, and a dominator-based required-literal scan
  (Boyer-Moore-Horspool / memchr with a word-at-a-time or AVX2 filter
  when first-byte candidates are dense). For the common
  shape `.*LIT` (greedy) and `.*?LIT` (lazy) the engine answers
  directly from the literal search without entering the VM at all.
* Runtime AVX2 dispatch on x86 GCC/Clang accelerates long ASCII class
  repeats and dense literal searches on capable Intel and AMD CPUs.
  A portable fallback is always available (`HFRE_DISABLE_SIMD` forces it).
  Vector loads stay inside the supplied buffer; class scans stop at
  non-ASCII bytes for UTF-8 decoding and Unicode folding.
* Case-sensitive literal-only patterns, optionally anchored with `^`
  and/or `$`, and simple greedy rune/class repeats skip VM allocation
  and unrelated compile-time analyses.
  Case-insensitive class analysis traverses the Unicode fold table
  once per class. ASCII folding avoids Unicode table searches.
* Needed match-time scratch buffers share one arena, and Thompson/Pike
  thread lists reuse storage because the VMs execute separately. DFA
  transition indices use one signed byte. `hfre_exec` is allocation-free.
* Explicit unmatched-capture initialization to `{ NULL, 0 }`.
* No dependency outside libc; portable C23 with `-pedantic-errors`.

hfre is well-suited to parsing network requests, configuration files,
log lines, and user input where bringing in a heavier library like
PCRE2 is overkill.

A `struct hfre` is **not** thread-safe (it owns scratch buffers used
by the VM and a mutable DFA cache). Use one compiled regex per thread
when processing independent inputs in parallel. See
[performance notes](performance.md) for build profiles and measurements.
