/*
 * hfre - small regex engine.
 *
 * Public API: an opaque compiled-regex object plus an exec function.
 * The legacy hfre_match() is preserved as a one-shot convenience wrapper.
 *
 * Match semantics: leftmost-first, regex-order alternation priority,
 * greedy quantifiers prefer longer valid matches, lazy quantifiers
 * prefer shorter valid matches.
 *
 * Buffer/offset model: the input is a (char*, byte length) pair; all
 * offsets and lengths reported by the engine are byte counts into that
 * buffer. UTF-8 input is supported transparently. Pattern literals,
 * including non-ASCII code points, are matched as UTF-8 byte
 * sequences, Unicode property classes use RE2-style \p and \P syntax,
 * and HFRE_IGNORE_CASE applies simple single-code-point Unicode folds.
 * Perl shorthand classes (\d, \s, \w, etc.) remain ASCII-only by
 * design.
 */

#ifndef HFRE_HFRE_H_
#define HFRE_HFRE_H_

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

struct hfre;            /* opaque compiled regex (heap-owned) */

struct hfre_cap {
  const char *ptr;
  int len;
};

struct hfre_result {
  int start;            /* byte offset of match start */
  int end;              /* byte offset just past the match */
  int ncaps;            /* number of capture groups populated */
};

/* Flags */
enum {
  HFRE_IGNORE_CASE = 1
};

/*
 * Compile a regex pattern. Returns 0 on success and stores a heap-owned
 * compiled regex in *out (which the caller must release with hfre_free).
 * On failure returns a negative HFRE_* error code; *out is unchanged.
 */
int hfre_compile(const char *pattern, int flags, struct hfre **out);

/*
 * Number of explicit capture groups in the pattern (excluding the
 * implicit whole-match group).
 */
int hfre_capture_count(const struct hfre *re);

/*
 * Search buf[0..buf_len) for the first match of re. caps may be NULL or
 * point to an array of num_caps hfre_cap entries; up to num_caps
 * captures will be filled in. Unmatched captures get { NULL, 0 }.
 * If result is non-NULL, it is filled with start/end/ncaps.
 *
 * On success, returns the byte offset of the end of the match
 * (i.e. result->end). On failure returns HFRE_NO_MATCH or another
 * negative HFRE_* error code.
 */
int hfre_exec(const struct hfre *re, const char *buf, int buf_len,
              struct hfre_cap *caps, int num_caps,
              struct hfre_result *result);

/* Release a compiled regex. Safe to call with NULL. */
void hfre_free(struct hfre *re);

/*
 * One-shot convenience wrapper: compile, exec, free.
 * Behavior is source-compatible with the legacy hfre_match.
 */
int hfre_match(const char *regexp, const char *buf, int buf_len,
               struct hfre_cap *caps, int num_caps, int flags);

/* Error codes (negative values). */
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

#ifdef __cplusplus
}
#endif

#endif /* HFRE_HFRE_H_ */
