/*
 * SLRE - small regex engine.
 *
 * Public API: an opaque compiled-regex object plus an exec function.
 * The legacy slre_match() is preserved as a one-shot convenience wrapper.
 *
 * Match semantics: leftmost-first, regex-order alternation priority,
 * greedy quantifiers prefer longer valid matches, lazy quantifiers
 * prefer shorter valid matches.
 *
 * Buffer/offset model: the input is a (char*, byte length) pair; all
 * offsets and lengths reported by the engine are byte counts into that
 * buffer. UTF-8 input is supported transparently — pattern literals,
 * including non-ASCII code points, are matched as UTF-8 byte
 * sequences. Perl shorthand classes (\d, \s, \w, etc.) remain
 * ASCII-only by design.
 */

#ifndef CS_SLRE_SLRE_H_
#define CS_SLRE_SLRE_H_

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

struct slre;            /* opaque compiled regex (heap-owned) */

struct slre_cap {
  const char *ptr;
  int len;
};

struct slre_result {
  int start;            /* byte offset of match start */
  int end;              /* byte offset just past the match */
  int ncaps;            /* number of capture groups populated */
};

/* Flags */
enum {
  SLRE_IGNORE_CASE = 1
};

/*
 * Compile a regex pattern. Returns 0 on success and stores a heap-owned
 * compiled regex in *out (which the caller must release with slre_free).
 * On failure returns a negative SLRE_* error code; *out is unchanged.
 */
int slre_compile(const char *pattern, int flags, struct slre **out);

/*
 * Number of explicit capture groups in the pattern (excluding the
 * implicit whole-match group).
 */
int slre_capture_count(const struct slre *re);

/*
 * Search buf[0..buf_len) for the first match of re. caps may be NULL or
 * point to an array of num_caps slre_cap entries; up to num_caps
 * captures will be filled in. Unmatched captures get { NULL, 0 }.
 * If result is non-NULL, it is filled with start/end/ncaps.
 *
 * On success, returns the byte offset of the end of the match
 * (i.e. result->end). On failure returns SLRE_NO_MATCH or another
 * negative SLRE_* error code.
 */
int slre_exec(const struct slre *re, const char *buf, int buf_len,
              struct slre_cap *caps, int num_caps,
              struct slre_result *result);

/* Release a compiled regex. Safe to call with NULL. */
void slre_free(struct slre *re);

/*
 * One-shot convenience wrapper: compile, exec, free.
 * Behavior is source-compatible with the legacy slre_match.
 */
int slre_match(const char *regexp, const char *buf, int buf_len,
               struct slre_cap *caps, int num_caps, int flags);

/* Error codes (negative values). */
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

#ifdef __cplusplus
}
#endif

#endif /* CS_SLRE_SLRE_H_ */
