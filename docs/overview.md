---
title: "Overview"
---

SLRE is a small C regex engine that implements a useful subset of
Perl-style syntax with UTF-8 support. Highlights:

* Compile-once / exec-many API (`slre_compile`, `slre_exec`,
  `slre_free`); the legacy `slre_match` is preserved as a one-shot
  wrapper.
* UTF-8 input is supported transparently. Non-ASCII literals — including
  emoji — are matched as their UTF-8 byte sequence; `.` matches one
  full code point.
* Pike VM with leftmost-first alternation and greedy/lazy quantifier
  semantics — no catastrophic backtracking on nested quantifiers.
* Compile-time prefilters (anchored start, single-byte / first-byte
  set, pure-literal extraction, simple class-repeat detection) and
  fixed-string fast paths short-circuit the VM for common patterns.
* Explicit unmatched-capture initialization to `{ NULL, 0 }`.
* No dependency outside libc.

SLRE is well-suited to parsing network requests, configuration files,
log lines, and user input where bringing in a heavier library like
PCRE2 is overkill.

A `struct slre` is **not** thread-safe (it owns scratch buffers used
by the VM). Use one compiled regex per thread.
