---
title: "API"
---

SLRE exposes a compile-once / exec-many API plus a one-shot
convenience wrapper.

## Compiled API

```c
struct slre;            /* opaque, heap-owned */

struct slre_cap {
  const char *ptr;
  int len;
};

struct slre_result {
  int start;            /* byte offset of match start */
  int end;              /* byte offset just past the match */
  int ncaps;            /* number of capture groups populated */
};

int slre_compile(const char *pattern, int flags, struct slre **out);
int slre_capture_count(const struct slre *re);
int slre_exec(const struct slre *re, const char *buf, int buf_len,
              struct slre_cap *caps, int num_caps,
              struct slre_result *result);
void slre_free(struct slre *re);
```

`slre_compile` parses the pattern, builds bytecode, and pre-allocates
the VM scratch buffers. The returned object is **not thread-safe**:
use one `struct slre` per thread.

`slre_exec` searches `buf[0..buf_len)` for the first match. On
success it returns the byte offset just past the match (also written
to `result->end`). On no match it returns `SLRE_NO_MATCH`.

`caps[i].ptr` points into the input buffer; unmatched captures are
left as `{ NULL, 0 }`. If `num_caps` is smaller than the pattern's
capture count, `slre_exec` returns `SLRE_CAPS_ARRAY_TOO_SMALL`.

`slre_free(NULL)` is a no-op.

## One-shot wrapper

```c
int slre_match(const char *regexp, const char *buf, int buf_len,
               struct slre_cap *caps, int num_caps, int flags);
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
ASCII-only by design. Unicode property classes (`\p{Greek}`, `\PN`,
etc.) are reserved for a future revision and currently produce
`SLRE_INVALID_UNICODE_PROPERTY` at compile time.

## Flags

- `SLRE_IGNORE_CASE` — ASCII case-insensitive matching for letters.

## Error codes

```c
#define SLRE_NO_MATCH                  -1
#define SLRE_UNEXPECTED_QUANTIFIER     -2
#define SLRE_UNBALANCED_BRACKETS       -3
#define SLRE_INTERNAL_ERROR            -4
#define SLRE_INVALID_CHARACTER_SET     -5
#define SLRE_INVALID_METACHARACTER     -6
#define SLRE_CAPS_ARRAY_TOO_SMALL      -7
#define SLRE_TOO_MANY_BRANCHES         -8
#define SLRE_TOO_MANY_BRACKETS         -9
#define SLRE_OUT_OF_MEMORY            -10
#define SLRE_INVALID_ARGUMENT         -11
#define SLRE_INVALID_UTF8             -12
#define SLRE_INVALID_UNICODE_PROPERTY -13
```
