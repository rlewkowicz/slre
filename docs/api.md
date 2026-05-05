---
title: "API"
---

hfre exposes a compile-once / exec-many API plus a one-shot
convenience wrapper.

## Compiled API

```c
struct hfre;            /* opaque, heap-owned */

struct hfre_cap {
  const char *ptr;
  int len;
};

struct hfre_result {
  int start;            /* byte offset of match start */
  int end;              /* byte offset just past the match */
  int ncaps;            /* number of capture groups populated */
};

int hfre_compile(const char *pattern, int flags, struct hfre **out);
int hfre_capture_count(const struct hfre *re);
int hfre_exec(const struct hfre *re, const char *buf, int buf_len,
              struct hfre_cap *caps, int num_caps,
              struct hfre_result *result);
void hfre_free(struct hfre *re);
```

`hfre_compile` parses the pattern, builds bytecode, and pre-allocates
the VM scratch buffers. The returned object is **not thread-safe**:
use one `struct hfre` per thread.

`hfre_exec` searches `buf[0..buf_len)` for the first match. On
success it returns the byte offset just past the match (also written
to `result->end`). On no match it returns `HFRE_NO_MATCH`.

`caps[i].ptr` points into the input buffer; unmatched captures are
left as `{ NULL, 0 }`. If `num_caps` is smaller than the pattern's
capture count, `hfre_exec` returns `HFRE_CAPS_ARRAY_TOO_SMALL`.

`hfre_free(NULL)` is a no-op.

## One-shot wrapper

```c
int hfre_match(const char *regexp, const char *buf, int buf_len,
               struct hfre_cap *caps, int num_caps, int flags);
```

Equivalent to compile + exec + free. Convenient for ad-hoc use; for
repeated matching of the same pattern use the compiled API to avoid
re-parsing.

## Match semantics

- Leftmost-first match selection.
- Regex-order alternation priority: `a|b` prefers `a`.
- Greedy quantifiers (`*`, `+`, `?`) prefer longer valid matches.
- Lazy quantifiers (`*?`, `+?`, `??`) prefer shorter valid matches.
- Captures use byte offsets and byte lengths into the original buffer.
- Empty alternatives are deterministic: `(|.c)` against `"abc"`
  matches the empty string at offset 0 with capture length 0. The
  legacy engine suppressed empty alternatives — the new engine
  follows standard semantics.
- Unmatched captures are explicitly initialized to `{ NULL, 0 }`.

## Unicode

Pattern and buffer bytes are interpreted as UTF-8. Literal code points
in the pattern (including non-ASCII characters and emoji) match the
same UTF-8 byte sequence in the input. `.` matches one full code
point.

Perl shorthand classes (`\d`, `\D`, `\s`, `\S`, `\w`, `\W`) are
ASCII-only by design. Unicode property classes use RE2-style syntax:
`\pN`, `\p{Greek}`, `\PN`, and `\P{Greek}`. Supported property names
are `L`, `N`, `Lu`, `Ll`, `Nd`, `Latin`, `Greek`, `Cyrillic`, `Han`,
`Hiragana`, and `Katakana`, backed by Unicode Character Database
17.0.0 ranges. Unicode matching does not normalize text.

## Flags

- `HFRE_IGNORE_CASE` — simple single-code-point case-insensitive
  matching. Multi-code-point folds are intentionally out of scope.

## Error codes

```c
#define HFRE_NO_MATCH                  -1
#define HFRE_UNEXPECTED_QUANTIFIER     -2
#define HFRE_UNBALANCED_BRACKETS       -3
#define HFRE_INTERNAL_ERROR            -4
#define HFRE_INVALID_CHARACTER_SET     -5
#define HFRE_INVALID_METACHARACTER     -6
#define HFRE_CAPS_ARRAY_TOO_SMALL      -7
#define HFRE_TOO_MANY_BRANCHES         -8
#define HFRE_TOO_MANY_BRACKETS         -9
#define HFRE_OUT_OF_MEMORY            -10
#define HFRE_INVALID_ARGUMENT         -11
#define HFRE_INVALID_UTF8             -12
#define HFRE_INVALID_UNICODE_PROPERTY -13
```
