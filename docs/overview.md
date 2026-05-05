---
title: "Overview"
---

SLRE is a small portable C23 regex engine that implements a useful
subset of Perl-style syntax with UTF-8 support. Highlights:

* Compile-once / exec-many API (`slre_compile`, `slre_exec`,
  `slre_free`); the legacy `slre_match` is preserved as a one-shot
  wrapper.
* UTF-8 input is supported transparently. Non-ASCII literals — including
  emoji — match their UTF-8 byte sequence; `.` matches one full code
  point.
* Pike VM (with captures) and a no-capture Thompson VM are both
  available — `slre_exec` picks the cheaper path automatically based
  on whether the caller asked for capture offsets. Both VMs use
  leftmost-first alternation and greedy/lazy quantifier semantics, so
  there's no catastrophic backtracking on nested quantifiers.
* Compile-time analyses produce prefilter metadata used to
  short-circuit the VM whenever possible: anchored-start detection,
  256-bit byte-class bitmaps, pure-literal extraction, simple
  greedy-class-repeat shape detection, single-byte and small-set
  first-byte filters, and a dominator-based required-literal scan
  (Boyer-Moore-Horspool / memchr-and-verify hybrid). For the common
  shape `.*LIT` (greedy) and `.*?LIT` (lazy) the engine answers
  directly from the literal search without entering the VM at all.
* Match-time scratch buffers are pre-allocated at compile time, so
  `slre_exec` is malloc-free on the hot path.
* Explicit unmatched-capture initialization to `{ NULL, 0 }`.
* No dependency outside libc; portable C23 with `-pedantic-errors`.

SLRE is well-suited to parsing network requests, configuration files,
log lines, and user input where bringing in a heavier library like
PCRE2 is overkill.

A `struct slre` is **not** thread-safe (it owns scratch buffers used
by the VM). Use one compiled regex per thread.
