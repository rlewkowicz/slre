#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "hfre.h"

static int static_total_tests = 0;
static int static_failed_tests = 0;

#define FAIL(str, line) do {                      \
  printf("Fail on line %d: [%s]\n", line, str);   \
  static_failed_tests++;                          \
} while (0)

#define ASSERT(expr) do {               \
  static_total_tests++;                 \
  if (!(expr)) FAIL(#expr, __LINE__);   \
} while (0)

/* Regex must have exactly one bracket pair */
static char *hfre_replace(const char *regex, const char *buf,
                          const char *sub) {
  char *s = NULL;
  int n, n1, n2, n3, s_len, len = strlen(buf);
  struct hfre_cap cap = { NULL, 0 };

  do {
    s_len = s == NULL ? 0 : strlen(s);
    if ((n = hfre_match(regex, buf, len, &cap, 1, 0)) > 0) {
      n1 = cap.ptr - buf, n2 = strlen(sub),
         n3 = &buf[n] - &cap.ptr[cap.len];
    } else {
      n1 = len, n2 = 0, n3 = 0;
    }
    s = (char *) realloc(s, s_len + n1 + n2 + n3 + 1);
    memcpy(s + s_len, buf, n1);
    memcpy(s + s_len + n1, sub, n2);
    if (n3 > 0) {
      memcpy(s + s_len + n1 + n2, cap.ptr + cap.len, n3);
    }
    s[s_len + n1 + n2 + n3] = '\0';

    buf += n > 0 ? n : len;
    len -= n > 0 ? n : len;
  } while (len > 0);

  return s;
}

/* Independent byte-search oracle for the adaptive literal scanner. */
static void check_literal_scan(const struct hfre *re, const char *buf, int len,
                                const char *literal, int literal_len) {
  int expected = -1;
  for (int i = 0; i <= len - literal_len; i++) {
    if (memcmp(buf + i, literal, (size_t) literal_len) == 0) {
      expected = i;
      break;
    }
  }
  struct hfre_result res;
  int end = hfre_exec(re, buf, len, NULL, 0, &res);
  ASSERT(expected < 0 ? end == HFRE_NO_MATCH :
         end == expected + literal_len &&
         res.start == expected && res.end == end && res.ncaps == 0);
}

/* Exact-sized allocations let ASAN catch reads past each input end. */
static void test_literal_scans(void) {
  static const struct {
    const char *pattern;
    const char *literal;
    int len;
  } cases[] = {
    { "a", "a", 1 }, { "ab", "ab", 2 }, { "needle", "needle", 6 },
    { "aaaab", "aaaab", 5 }, { "ababa", "ababa", 5 },
    { "aaaa", "aaaa", 4 }, { "🦀", "🦀", 4 },
    { "\\x00a", "\0a", 2 }, { "a\\x00b", "a\0b", 3 },
    { "\\x00\\x01a", "\0\1a", 3 }
  };
  for (size_t c = 0; c < sizeof(cases) / sizeof(cases[0]); c++) {
    struct hfre *re = NULL;
    ASSERT(hfre_compile(cases[c].pattern, 0, &re) == 0);
    if (re == NULL) continue;
    for (int align = 0; align < 32; align++) {
      for (int len = 0; len <= 96; len++) {
        char *storage = malloc((size_t)(align + len + (len == 0)));
        ASSERT(storage != NULL);
        if (storage == NULL) continue;
        char *buf = storage + align;
        int last = len >= cases[c].len ? len - cases[c].len : -1;
        for (int pos = -1; pos <= last; pos++) {
          memset(buf, cases[c].literal[0], (size_t) len);
          if (pos >= 0) {
            memcpy(buf + pos, cases[c].literal, (size_t) cases[c].len);
          }
          check_literal_scan(re, buf, len, cases[c].literal, cases[c].len);
        }
        free(storage);
      }
    }
    /* Mixed candidate bytes exercise pair-filter collisions and the
     * zero-byte arithmetic with NULs, high bits, and adjacent values. */
    uint32_t rng = 1;
    for (int trial = 0; trial < 512; trial++) {
      char buf[128];
      for (size_t i = 0; i < sizeof(buf); i++) {
        rng = rng * UINT32_C(1664525) + UINT32_C(1013904223);
        buf[i] = (trial & 1) ? (char)(rng >> 24) :
          cases[c].literal[(rng >> 16) % (unsigned) cases[c].len];
      }
      if (trial % 3 != 0) {
        int pos = trial % ((int) sizeof(buf) - cases[c].len + 1);
        memcpy(buf + pos, cases[c].literal, (size_t) cases[c].len);
      }
      check_literal_scan(re, buf, (int) sizeof(buf), cases[c].literal, cases[c].len);
    }
    hfre_free(re);
  }

  /* Long needles, overlapping candidates, and an exact end-of-buffer hit. */
  for (int n = 63; n <= 321; n++) {
    char pattern[322], buf[512];
    memset(pattern, 'a', (size_t) n);
    pattern[n / 2] = 'b';
    pattern[n] = '\0';
    memset(buf, 'a', sizeof(buf));
    struct hfre *re = NULL;
    struct hfre_result res;
    ASSERT(hfre_compile(pattern, 0, &re) == 0);
    ASSERT(hfre_exec(re, buf, (int) sizeof(buf), NULL, 0, NULL) == HFRE_NO_MATCH);
    memcpy(buf + sizeof(buf) - n, pattern, (size_t) n);
    ASSERT(hfre_exec(re, buf, (int) sizeof(buf), NULL, 0, &res) ==
           (int) sizeof(buf));
    ASSERT(res.start == (int) sizeof(buf) - n);
    hfre_free(re);
  }
}

/* Capturing the same class forces the Pike VM, an independent oracle
 * for the scalar/SIMD repeat shortcut, including UTF-8 fallback. */
static void check_class_scan(const struct hfre *fast, const struct hfre *vm,
                              const char *buf, int len) {
  struct hfre_result a, b;
  struct hfre_cap unused = { "stale", 5 }, cap;
  int x = hfre_exec(fast, buf, len, &unused, 1, &a);
  int y = hfre_exec(vm, buf, len, &cap, 1, &b);
  ASSERT(x == y);
  ASSERT(unused.ptr == NULL && unused.len == 0);
  if (x >= 0 && y >= 0) {
    ASSERT(a.start == b.start && a.end == b.end);
    ASSERT(a.ncaps == 0 && cap.ptr == buf + a.start && cap.len == x - a.start);
  }
}

static void test_class_scans(void) {
  static const char *patterns[] = {
    "[a-z]+", "[a-z]*", "[^a-z]+", "[^a-z]*", "[A-Za-z0-9_]+",
    "[\\x00-\\x1f\\x7f]+", "[!#%&,.:;=]+", "\\s+", "\\S+",
    "\\d+", "\\w+", "[\\p{Greek}a-z]+"
  };
  static const char *runes[] = { "K", "ſ", "é", "Σ", "🦀", "\xc0", "\x80" };
  for (size_t p = 0; p < sizeof(patterns) / sizeof(patterns[0]); p++) {
    for (int flags = 0; flags <= HFRE_IGNORE_CASE; flags++) {
      char wrapped[80];
      snprintf(wrapped, sizeof(wrapped), "(%s)", patterns[p]);
      struct hfre *fast = NULL, *vm = NULL;
      ASSERT(hfre_compile(patterns[p], flags, &fast) == 0);
      ASSERT(hfre_compile(wrapped, flags, &vm) == 0);
      if (fast == NULL || vm == NULL) {
        hfre_free(fast);
        hfre_free(vm);
        continue;
      }
      /* Every ASCII byte, all alignments, and every vector-tail length.
       * An exact allocation boundary exposes any vector over-read. */
      for (int trial = 0; trial < 256; trial++) {
        int len = 128 + trial % 33, align = trial % 32;
        char *storage = malloc((size_t)(align + len));
        ASSERT(storage != NULL);
        if (storage == NULL) continue;
        char *buf = storage + align;
        memset(buf, trial & 127, (size_t) len);
        check_class_scan(fast, vm, buf, len);
        buf[trial % len] = (trial & 1) ? 'a' : '!';
        check_class_scan(fast, vm, buf, len);
        free(storage);
      }
      /* Stop at each possible position, including the overlapping
       * final vector and short inputs that stay on the scalar path. */
      char buf[160];
      for (int len = 0; len <= (int) sizeof(buf); len++) {
        for (int pos = 0; pos < len; pos++) {
          memset(buf, 'a', (size_t) len);
          buf[pos] = '!';
          check_class_scan(fast, vm, buf, len);
        }
      }
      for (size_t r = 0; r < sizeof(runes) / sizeof(runes[0]); r++) {
        for (int pos = 28; pos <= 132; pos++) {
          memset(buf, 'a', sizeof(buf));
          memcpy(buf + pos, runes[r], strlen(runes[r]));
          check_class_scan(fast, vm, buf, (int) sizeof(buf));
        }
      }
      check_class_scan(fast, vm, "", 0);
      hfre_free(fast);
      hfre_free(vm);
    }
  }
}

int main(void) {
  struct hfre_cap caps[10];

  /* Metacharacters */
  ASSERT(hfre_match("$", "abcd", 4, NULL, 0, 0) == 4);
  ASSERT(hfre_match("^", "abcd", 4, NULL, 0, 0) == 0);
  ASSERT(hfre_match("x|^", "abcd", 4, NULL, 0, 0) == 0);
  ASSERT(hfre_match("x|$", "abcd", 4, NULL, 0, 0) == 4);
  ASSERT(hfre_match("x", "abcd", 4, NULL, 0, 0) == HFRE_NO_MATCH);
  ASSERT(hfre_match(".", "abcd", 4, NULL, 0, 0) == 1);
  ASSERT(hfre_match("^.*\\\\.*$", "c:\\Tools", 8, NULL, 0, HFRE_IGNORE_CASE)
    == 8);
  ASSERT(hfre_match("\\", "a", 1, NULL, 0, 0) == HFRE_INVALID_METACHARACTER);
  ASSERT(hfre_match("\\x", "a", 1, NULL, 0, 0) == HFRE_INVALID_METACHARACTER);
  ASSERT(hfre_match("\\x1", "a", 1, NULL, 0, 0) == HFRE_INVALID_METACHARACTER);
  ASSERT(hfre_match("\\x20", " ", 1, NULL, 0, 0) == 1);

  ASSERT(hfre_match("^.+$", "", 0, NULL, 0, 0) == HFRE_NO_MATCH);
  ASSERT(hfre_match("^(.+)$", "", 0, NULL, 0, 0) == HFRE_NO_MATCH);
  ASSERT(hfre_match("^([\\+-]?)([\\d]+)$", "+", 1,
                    caps, 10, HFRE_IGNORE_CASE) == HFRE_NO_MATCH);
  ASSERT(hfre_match("^([\\+-]?)([\\d]+)$", "+27", 3,
                    caps, 10, HFRE_IGNORE_CASE) == 3);
  ASSERT(caps[0].len == 1);
  ASSERT(caps[0].ptr[0] == '+');
  ASSERT(caps[1].len == 2);
  ASSERT(memcmp(caps[1].ptr, "27", 2) == 0);

  ASSERT(hfre_match("tel:\\+(\\d+[\\d-]+\\d)",
                    "tel:+1-201-555-0123;a=b", 23, caps, 10, 0) == 19);
  ASSERT(caps[0].len == 14);
  ASSERT(memcmp(caps[0].ptr, "1-201-555-0123", 14) == 0);

  /* Character sets */
  ASSERT(hfre_match("[abc]", "1c2", 3, NULL, 0, 0) == 2);
  ASSERT(hfre_match("[abc]", "1C2", 3, NULL, 0, 0) == HFRE_NO_MATCH);
  ASSERT(hfre_match("[abc]", "1C2", 3, NULL, 0, HFRE_IGNORE_CASE) == 2);
  /* Legacy hfre treated '.' inside [] as match-any-byte. The current
   * engine follows standard regex semantics: '.' inside a class is a
   * literal '.'. So [.2] matches only '.' or '2'; in "1C2" the first
   * match is '2' at offset 2 (end offset = 3). */
  ASSERT(hfre_match("[.2]", "1C2", 3, NULL, 0, 0) == 3);
  ASSERT(hfre_match("[.2]", "..2", 3, NULL, 0, 0) == 1);
  ASSERT(hfre_match("[\\S]+", "ab cd", 5, NULL, 0, 0) == 2);
  ASSERT(hfre_match("[\\S]+\\s+[tyc]*", "ab cd", 5, NULL, 0, 0) == 4);
  ASSERT(hfre_match("[\\d]", "ab cd", 5, NULL, 0, 0) == HFRE_NO_MATCH);
  ASSERT(hfre_match("[^\\d]", "ab cd", 5, NULL, 0, 0) == 1);
  ASSERT(hfre_match("[^\\d]+", "abc123", 6, NULL, 0, 0) == 3);
  ASSERT(hfre_match("[1-5]+", "123456789", 9, NULL, 0, 0) == 5);
  ASSERT(hfre_match("[1-5a-c]+", "123abcdef", 9, NULL, 0, 0) == 6);
  ASSERT(hfre_match("[1-5a-]+", "123abcdef", 9, NULL, 0, 0) == 4);
  ASSERT(hfre_match("[1-5a-]+", "123a--2oo", 9, NULL, 0, 0) == 7);
  ASSERT(hfre_match("[htps]+://", "https://", 8, NULL, 0, 0) == 8);
  ASSERT(hfre_match("[^\\s]+", "abc def", 7, NULL, 0, 0) == 3);
  ASSERT(hfre_match("[^fc]+", "abc def", 7, NULL, 0, 0) == 2);
  ASSERT(hfre_match("[^d\\sf]+", "abc def", 7, NULL, 0, 0) == 3);

  /* Flags - case sensitivity */
  ASSERT(hfre_match("FO", "foo", 3, NULL, 0, 0) == HFRE_NO_MATCH);
  ASSERT(hfre_match("FO", "foo", 3, NULL, 0, HFRE_IGNORE_CASE) == 2);
  ASSERT(hfre_match("(?m)FO", "foo", 3, NULL, 0, 0) ==
    HFRE_UNEXPECTED_QUANTIFIER);
  ASSERT(hfre_match("(?m)x", "foo", 3, NULL, 0, 0) ==
    HFRE_UNEXPECTED_QUANTIFIER);

  ASSERT(hfre_match("fo", "foo", 3, NULL, 0, 0) == 2);
  ASSERT(hfre_match(".+", "foo", 3, NULL, 0, 0) == 3);
  ASSERT(hfre_match(".+k", "fooklmn", 7, NULL, 0, 0) == 4);
  ASSERT(hfre_match(".+k.", "fooklmn", 7, NULL, 0, 0) == 5);
  ASSERT(hfre_match("p+", "fooklmn", 7, NULL, 0, 0) == HFRE_NO_MATCH);
  ASSERT(hfre_match("ok", "fooklmn", 7, NULL, 0, 0) == 4);
  ASSERT(hfre_match("lmno", "fooklmn", 7, NULL, 0, 0) == HFRE_NO_MATCH);
  ASSERT(hfre_match("mn.", "fooklmn", 7, NULL, 0, 0) == HFRE_NO_MATCH);
  ASSERT(hfre_match("o", "fooklmn", 7, NULL, 0, 0) == 2);
  ASSERT(hfre_match("^o", "fooklmn", 7, NULL, 0, 0) == HFRE_NO_MATCH);
  ASSERT(hfre_match("^", "fooklmn", 7, NULL, 0, 0) == 0);
  ASSERT(hfre_match("n$", "fooklmn", 7, NULL, 0, 0) == 7);
  ASSERT(hfre_match("n$k", "fooklmn", 7, NULL, 0, 0) == HFRE_NO_MATCH);
  ASSERT(hfre_match("l$", "fooklmn", 7, NULL, 0, 0) == HFRE_NO_MATCH);
  ASSERT(hfre_match(".$", "fooklmn", 7, NULL, 0, 0) == 7);
  ASSERT(hfre_match("a?", "fooklmn", 7, NULL, 0, 0) == 0);
  ASSERT(hfre_match("^a*CONTROL", "CONTROL", 7, NULL, 0, 0) == 7);
  ASSERT(hfre_match("^[a]*CONTROL", "CONTROL", 7, NULL, 0, 0) == 7);
  ASSERT(hfre_match("^(a*)CONTROL", "CONTROL", 7, NULL, 0, 0) == 7);
  ASSERT(hfre_match("^(a*)?CONTROL", "CONTROL", 7, NULL, 0, 0) == 7);

  ASSERT(hfre_match("\\_", "abc", 3, NULL, 0, 0) == HFRE_INVALID_METACHARACTER);
  ASSERT(hfre_match("+", "fooklmn", 7, NULL, 0, 0) == HFRE_UNEXPECTED_QUANTIFIER);
  /* Legacy hfre returned NO_MATCH for "()+". Under standard
   * semantics an empty group can match the empty string, so the
   * leftmost-first match has length 0 at offset 0. */
  ASSERT(hfre_match("()+", "fooklmn", 7, NULL, 0, 0) == 0);
  ASSERT(hfre_match("\\x", "12", 2, NULL, 0, 0) == HFRE_INVALID_METACHARACTER);
  ASSERT(hfre_match("\\xhi", "12", 2, NULL, 0, 0) == HFRE_INVALID_METACHARACTER);
  ASSERT(hfre_match("\\x20", "_ J", 3, NULL, 0, 0) == 2);
  ASSERT(hfre_match("\\x4A", "_ J", 3, NULL, 0, 0) == 3);
  ASSERT(hfre_match("\\d+", "abc123def", 9, NULL, 0, 0) == 6);

  /* Balancing brackets */
  ASSERT(hfre_match("(x))", "fooklmn", 7, NULL, 0, 0) == HFRE_UNBALANCED_BRACKETS);
  ASSERT(hfre_match("(", "fooklmn", 7, NULL, 0, 0) == HFRE_UNBALANCED_BRACKETS);

  ASSERT(hfre_match("klz?mn", "fooklmn", 7, NULL, 0, 0) == 7);
  ASSERT(hfre_match("fa?b", "fooklmn", 7, NULL, 0, 0) == HFRE_NO_MATCH);

  /* Brackets & capturing */
  ASSERT(hfre_match("^(te)", "tenacity subdues all", 20, caps, 10, 0) == 2);
  ASSERT(hfre_match("(bc)", "abcdef", 6, caps, 10, 0) == 3);
  ASSERT(hfre_match(".(d.)", "abcdef", 6, caps, 10, 0) == 5);
  ASSERT(hfre_match(".(d.)\\)?", "abcdef", 6, caps, 10, 0) == 5);
  ASSERT(caps[0].len == 2);
  ASSERT(memcmp(caps[0].ptr, "de", 2) == 0);
  ASSERT(hfre_match("(.+)", "123", 3, caps, 10, 0) == 3);
  ASSERT(hfre_match("(2.+)", "123", 3, caps, 10, 0) == 3);
  ASSERT(caps[0].len == 2);
  ASSERT(memcmp(caps[0].ptr, "23", 2) == 0);
  ASSERT(hfre_match("(.+2)", "123", 3, caps, 10, 0) == 2);
  ASSERT(caps[0].len == 2);
  ASSERT(memcmp(caps[0].ptr, "12", 2) == 0);
  ASSERT(hfre_match("(.*(2.))", "123", 3, caps, 10, 0) == 3);
  ASSERT(hfre_match("(.)(.)", "123", 3, caps, 10, 0) == 2);
  ASSERT(hfre_match("(\\d+)\\s+(\\S+)", "12 hi", 5, caps, 10, 0) == 5);
  ASSERT(hfre_match("ab(cd)+ef", "abcdcdef", 8, NULL, 0, 0) == 8);
  ASSERT(hfre_match("ab(cd)*ef", "abcdcdef", 8, NULL, 0, 0) == 8);
  ASSERT(hfre_match("ab(cd)+?ef", "abcdcdef", 8, NULL, 0, 0) == 8);
  ASSERT(hfre_match("ab(cd)+?.", "abcdcdef", 8, NULL, 0, 0) == 5);
  ASSERT(hfre_match("ab(cd)?", "abcdcdef", 8, NULL, 0, 0) == 4);
  ASSERT(hfre_match("a(b)(cd)", "abcdcdef", 8, caps, 1, 0) ==
      HFRE_CAPS_ARRAY_TOO_SMALL);
  ASSERT(hfre_match("(.+/\\d+\\.\\d+)\\.jpg$", "/foo/bar/12.34.jpg", 18,
                    caps, 1, 0) == 18);
  ASSERT(hfre_match("(ab|cd).*\\.(xx|yy)", "ab.yy", 5, NULL, 0, 0) == 5);
  ASSERT(hfre_match(".*a", "abcdef", 6, NULL, 0, 0) == 1);
  ASSERT(hfre_match("(.+)c", "abcdef", 6, NULL, 0, 0) == 3);
  ASSERT(hfre_match("\\n", "abc\ndef", 7, NULL, 0, 0) == 4);
  ASSERT(hfre_match("b.\\s*\\n", "aa\r\nbb\r\ncc\r\n\r\n", 14,
                    caps, 10, 0) == 8);

  /* Greedy vs non-greedy */
  ASSERT(hfre_match(".+c", "abcabc", 6, NULL, 0, 0) == 6);
  ASSERT(hfre_match(".+?c", "abcabc", 6, NULL, 0, 0) == 3);
  ASSERT(hfre_match(".*?c", "abcabc", 6, NULL, 0, 0) == 3);
  ASSERT(hfre_match(".*c", "abcabc", 6, NULL, 0, 0) == 6);
  ASSERT(hfre_match("bc.d?k?b+", "abcabc", 6, NULL, 0, 0) == 5);

  /* Branching. Note: leftmost-first alternation prefers the first
   * branch that matches, even if it matches the empty string. */
  ASSERT(hfre_match("|", "abc", 3, NULL, 0, 0) == 0);
  /* "|." -> empty branch wins at pos 0 (length 0). Legacy hfre
   * suppressed empty-branch wins, returning 1 (the '.' branch). */
  ASSERT(hfre_match("|.", "abc", 3, NULL, 0, 0) == 0);
  ASSERT(hfre_match("x|y|b", "abc", 3, NULL, 0, 0) == 2);
  ASSERT(hfre_match("k(xx|yy)|ca", "abcabc", 6, NULL, 0, 0) == 4);
  ASSERT(hfre_match("k(xx|yy)|ca|bc", "abcabc", 6, NULL, 0, 0) == 3);
  /* "(|.c)" -> empty alternation wins at pos 0 (length 0). Legacy
   * hfre returned 3 with caps[0]="bc". */
  ASSERT(hfre_match("(|.c)", "abc", 3, caps, 10, 0) == 0);
  ASSERT(caps[0].len == 0);
  ASSERT(hfre_match("a|b|c", "a", 1, NULL, 0, 0) == 1);
  ASSERT(hfre_match("a|b|c", "b", 1, NULL, 0, 0) == 1);
  ASSERT(hfre_match("a|b|c", "c", 1, NULL, 0, 0) == 1);
  ASSERT(hfre_match("a|b|c", "d", 1, NULL, 0, 0) == HFRE_NO_MATCH);

  /* Optional match at the end of the string */
  ASSERT(hfre_match("^.*c.?$", "abc", 3, NULL, 0, 0) == 3);
  ASSERT(hfre_match("^.*C.?$", "abc", 3, NULL, 0, HFRE_IGNORE_CASE) == 3);
  ASSERT(hfre_match("bk?", "ab", 2, NULL, 0, 0) == 2);
  ASSERT(hfre_match("b(k?)", "ab", 2, NULL, 0, 0) == 2);
  ASSERT(hfre_match("b[k-z]*", "ab", 2, NULL, 0, 0) == 2);
  ASSERT(hfre_match("ab(k|z|y)*", "ab", 2, NULL, 0, 0) == 2);
  ASSERT(hfre_match("[b-z].*", "ab", 2, NULL, 0, 0) == 2);
  ASSERT(hfre_match("(b|z|u).*", "ab", 2, NULL, 0, 0) == 2);
  ASSERT(hfre_match("ab(k|z|y)?", "ab", 2, NULL, 0, 0) == 2);
  ASSERT(hfre_match(".*", "ab", 2, NULL, 0, 0) == 2);
  ASSERT(hfre_match(".*$", "ab", 2, NULL, 0, 0) == 2);
  ASSERT(hfre_match("a+$", "aa", 2, NULL, 0, 0) == 2);
  ASSERT(hfre_match("a*$", "aa", 2, NULL, 0, 0) == 2);
  ASSERT(hfre_match( "a+$" ,"Xaa", 3, NULL, 0, 0) == 3);
  ASSERT(hfre_match( "a*$" ,"Xaa", 3, NULL, 0, 0) == 3);

  /* Ignore case flag */
  ASSERT(hfre_match("[a-h]+", "abcdefghxxx", 11, NULL, 0, 0) == 8);
  ASSERT(hfre_match("[A-H]+", "ABCDEFGHyyy", 11, NULL, 0, 0) == 8);
  ASSERT(hfre_match("[a-h]+", "ABCDEFGHyyy", 11, NULL, 0, 0) == HFRE_NO_MATCH);
  ASSERT(hfre_match("[A-H]+", "abcdefghyyy", 11, NULL, 0, 0) == HFRE_NO_MATCH);
  ASSERT(hfre_match("[a-h]+", "ABCDEFGHyyy", 11, NULL, 0, HFRE_IGNORE_CASE) == 8);
  ASSERT(hfre_match("[A-H]+", "abcdefghyyy", 11, NULL, 0, HFRE_IGNORE_CASE) == 8);

  {
    /* Example: HTTP request */
    const char *request = " GET /index.html HTTP/1.0\r\n\r\n";
    struct hfre_cap caps[4];

    if (hfre_match("^\\s*(\\S+)\\s+(\\S+)\\s+HTTP/(\\d)\\.(\\d)",
                   request, strlen(request), caps, 4, 0) > 0) {
      printf("Method: [%.*s], URI: [%.*s]\n",
             caps[0].len, caps[0].ptr,
             caps[1].len, caps[1].ptr);
    } else {
      printf("Error parsing [%s]\n", request);
    }

    ASSERT(caps[1].len == 11);
    ASSERT(memcmp(caps[1].ptr, "/index.html", caps[1].len) == 0);
  }

  {
    /* Example: string replacement */
    char *s = hfre_replace("({{.+?}})",
                           "Good morning, {{foo}}. How are you, {{bar}}?",
                           "Bob");
    printf("%s\n", s);
    ASSERT(strcmp(s, "Good morning, Bob. How are you, Bob?") == 0);
    free(s);
  }

  {
    /* Example: find all URLs in a string */
    static const char *str =
      "<img src=\"HTTPS://FOO.COM/x?b#c=tab1\"/> "
      "  <a href=\"http://example.org\">some link</a>";

    static const char *regex = "((https?://)[^\\s/'\"<>]+/?[^\\s'\"<>]*)";
    struct hfre_cap caps[2];
    int i, j = 0, str_len = (int) strlen(str);

    while (j < str_len &&
           (i = hfre_match(regex, str + j, str_len - j, caps, 2, HFRE_IGNORE_CASE)) > 0) {
      printf("Found URL: [%.*s]\n", caps[0].len, caps[0].ptr);
      j += i;
    }
  }

  {
    /* Example more complex regular expression */
    static const char * str = "aa 1234 xy\nxyz";
    static const char * regex = "aa ([0-9]*) *([x-z]*)\\s+xy([yz])";
    struct hfre_cap caps[3];
    ASSERT(hfre_match(regex, str, strlen(str), caps, 3, 0) > 0);
    ASSERT(caps[0].len == 4);
    ASSERT(caps[1].len == 2);
    ASSERT(caps[2].len == 1);
    ASSERT(caps[2].ptr[0] == 'z');
  }

  /* Compile/exec API. */
  {
    struct hfre *re = NULL;
    ASSERT(hfre_compile("a(b+)c", 0, &re) == 0);
    ASSERT(re != NULL);
    ASSERT(hfre_capture_count(re) == 1);
    struct hfre_cap c[1];
    struct hfre_result r;
    ASSERT(hfre_exec(re, "xxabbbcyy", 9, c, 1, &r) == 7);
    ASSERT(r.start == 2);
    ASSERT(r.end == 7);
    ASSERT(r.ncaps == 1);
    ASSERT(c[0].len == 3);
    ASSERT(memcmp(c[0].ptr, "bbb", 3) == 0);
    /* Re-using the same compiled regex on a different buffer. */
    ASSERT(hfre_exec(re, "ac", 2, c, 1, &r) == HFRE_NO_MATCH);
    ASSERT(hfre_exec(re, "abbc abbbbc", 11, c, 1, &r) == 4);
    ASSERT(c[0].len == 2);
    hfre_free(re);
  }
  /* hfre_free(NULL) is safe. */
  hfre_free(NULL);

  /* New error codes. */
  {
    struct hfre *re = NULL;
    ASSERT(hfre_compile("\\p{NotAProperty}", 0, &re) ==
           HFRE_INVALID_UNICODE_PROPERTY);
    ASSERT(hfre_compile(NULL, 0, &re) == HFRE_INVALID_ARGUMENT);
    /* Invalid UTF-8 in pattern. */
    ASSERT(hfre_compile("\xC0", 0, &re) == HFRE_INVALID_UTF8);
  }

  /* UTF-8 literal matching. */
  {
    /* "ñ" = U+00F1 = 0xC3 0xB1; "中" = U+4E2D = 0xE4 0xB8 0xAD;
     * "🦀" = U+1F980 = 0xF0 0x9F 0xA6 0x80. */
    const char *needle1 = "ñ";
    const char *hay1 = "abc ñ def";
    ASSERT(hfre_match(needle1, hay1, (int) strlen(hay1), NULL, 0, 0)
           == 4 + 2);  /* match ends just past the 2-byte rune */
    const char *needle2 = "中";
    const char *hay2 = "x中y";
    ASSERT(hfre_match(needle2, hay2, (int) strlen(hay2), NULL, 0, 0)
           == 1 + 3);
    const char *needle3 = "🦀";
    const char *hay3 = "love 🦀!";
    ASSERT(hfre_match(needle3, hay3, (int) strlen(hay3), NULL, 0, 0)
           == 5 + 4);
    /* . matches one full code point. */
    ASSERT(hfre_match("a.b", "a🦀b", 6, NULL, 0, 0) == 6);
    /* Multi-rune pattern. */
    struct hfre_cap mc[1];
    ASSERT(hfre_match("(中文)", "hello 中文", 12, mc, 1, 0) == 12);
    ASSERT(mc[0].len == 6);
  }

  /* Unicode property classes. */
  {
    ASSERT(hfre_match("\\pN+", "abc١٢3", (int) strlen("abc١٢3"),
                      NULL, 0, 0) == (int) strlen("abc١٢3"));
    ASSERT(hfre_match("\\p{Greek}+", "xαβγy", (int) strlen("xαβγy"),
                      NULL, 0, 0) == 1 + (int) strlen("αβγ"));
    ASSERT(hfre_match("\\PN+", "123abc", 6, NULL, 0, 0) == 6);
    ASSERT(hfre_match("\\p{Lu}+", "xABCé", (int) strlen("xABCé"),
                      NULL, 0, 0) == 4);
    ASSERT(hfre_match("\\p{Ll}+", "ABCéz", (int) strlen("ABCéz"),
                      NULL, 0, 0) == (int) strlen("ABCéz"));
    ASSERT(hfre_match("\\p{Nd}+", "x٣4", (int) strlen("x٣4"),
                      NULL, 0, 0) == (int) strlen("x٣4"));
    ASSERT(hfre_match("\\P{Greek}+", "αβabc", (int) strlen("αβabc"),
                      NULL, 0, 0) == (int) strlen("αβabc"));
    ASSERT(hfre_match("[\\p{Greek}A]+", "xxAβ!", (int) strlen("xxAβ!"),
                      NULL, 0, 0) == 2 + (int) strlen("Aβ"));
    ASSERT(hfre_match("[\\P{Greek}]+", "αβabc", (int) strlen("αβabc"),
                      NULL, 0, 0) == (int) strlen("αβabc"));
    ASSERT(hfre_match("[^\\p{Greek}]+", "αβabc", (int) strlen("αβabc"),
                      NULL, 0, 0) == (int) strlen("αβabc"));
    ASSERT(hfre_match("\\p{Han}+", "xx中文!", (int) strlen("xx中文!"),
                      NULL, 0, 0) == 2 + (int) strlen("中文"));
  }

  /* Simple Unicode case folding for single-code-point folds. */
  {
    ASSERT(hfre_match("É", "xxéyy", (int) strlen("xxéyy"), NULL, 0,
                      HFRE_IGNORE_CASE) == 2 + (int) strlen("é"));
    ASSERT(hfre_match("Ω", "xω", (int) strlen("xω"), NULL, 0,
                      HFRE_IGNORE_CASE) == (int) strlen("xω"));
    ASSERT(hfre_match("ω", "xΩ", (int) strlen("xΩ"), NULL, 0,
                      HFRE_IGNORE_CASE) == (int) strlen("xΩ"));
    ASSERT(hfre_match("Ж", "xж", (int) strlen("xж"), NULL, 0,
                      HFRE_IGNORE_CASE) == (int) strlen("xж"));
    ASSERT(hfre_match("K", "xK", (int) strlen("xK"), NULL, 0,
                      HFRE_IGNORE_CASE) == (int) strlen("xK"));
    ASSERT(hfre_match("K", "xk", 2, NULL, 0, HFRE_IGNORE_CASE) == 2);
    ASSERT(hfre_match("K+", "KK", (int) strlen("KK"), NULL, 0,
                      HFRE_IGNORE_CASE) == (int) strlen("KK"));
    ASSERT(hfre_match("[K]+", "KK", (int) strlen("KK"), NULL, 0,
                      HFRE_IGNORE_CASE) == (int) strlen("KK"));
    struct hfre *re;
    struct hfre_result res;
    ASSERT(hfre_compile("[K]+", 0, &re) == 0);
    ASSERT(hfre_exec(re, "KK", (int) strlen("KK"), NULL, 0, &res) ==
           (int) strlen("KK"));
    ASSERT(res.start == (int) strlen("K"));
    hfre_free(re);
    ASSERT(hfre_compile("[s]+", 0, &re) == 0);
    ASSERT(hfre_exec(re, "ſs", (int) strlen("ſs"), NULL, 0, &res) ==
           (int) strlen("ſs"));
    ASSERT(res.start == (int) strlen("ſ"));
    hfre_free(re);
  }

  /* Greedy vs lazy alternation under leftmost-first. */
  {
    /* Leftmost-first: prefer the FIRST listed branch when both could
     * match. */
    ASSERT(hfre_match("a|aa", "aa", 2, NULL, 0, 0) == 1);
    ASSERT(hfre_match("aa|a", "aa", 2, NULL, 0, 0) == 2);
  }

  /* Word class \w \W. */
  {
    struct hfre_cap c[1];
    ASSERT(hfre_match("(\\w+)", "  hello_world42 ", 16, c, 1, 0) > 0);
    ASSERT(c[0].len == 13);
    ASSERT(hfre_match("\\W+", "  ;.!  ab", 9, NULL, 0, 0) == 7);
  }

  /* Required-literal prefilter: literal absent -> no match. The
   * filter is tighter than the single-byte first-byte set. */
  {
    /* "abc" is a 3-byte required literal in this regex. */
    ASSERT(hfre_match("[0-9]+abc", "no digits here", 14, NULL, 0, 0)
           == HFRE_NO_MATCH);
    ASSERT(hfre_match("[0-9]+abc", "x12abc!", 7, NULL, 0, 0) == 6);
  }

  /* .*LIT direct shortcut: greedy returns the LAST occurrence. */
  {
    ASSERT(hfre_match(".*error", "ok", 2, NULL, 0, 0) == HFRE_NO_MATCH);
    /* Greedy: prefers the last "error" position. */
    ASSERT(hfre_match(".*error", "first error then second error end",
                      33, NULL, 0, 0) == 29);
    /* Lazy: prefers the first. */
    ASSERT(hfre_match(".*?error", "first error then second error end",
                      33, NULL, 0, 0) == 11);
  }

  /* Required literal as prefix lets the scanner jump straight to the
   * literal's position. */
  {
    static char big[2048];
    for (int i = 0; i < (int) sizeof(big); i++) big[i] = (char) ('a' + (i % 23));
    memcpy(big + 1900, "tel:+1234", 9);
    struct hfre_cap c[1];
    int n = hfre_match("tel:\\+(\\d+)", big, (int) sizeof(big), c, 1, 0);
    ASSERT(n == 1900 + 9);
    ASSERT(c[0].len == 4);
    ASSERT(memcmp(c[0].ptr, "1234", 4) == 0);
  }

  /* Multi-byte first-byte set scan: pattern needs no captures, set
   * has 10 candidate bytes. */
  {
    char buf[1024];
    for (int i = 0; i < (int) sizeof(buf); i++) buf[i] = 'a' + (i % 24);
    /* No digits anywhere: NO_MATCH; the multi-memchr scan should
     * exit fast. */
    ASSERT(hfre_match("[0-9]+x", buf, (int) sizeof(buf), NULL, 0, 0)
           == HFRE_NO_MATCH);
  }

  /* Remaining portable accelerator shapes preserve observable
   * matching: suffix literals, multi-literal filters, pure literals,
   * bounded DFA filtering, and simple rune repeats. */
  {
    struct hfre *re = NULL;
    struct hfre_result res;
    struct hfre_cap c[1];

    ASSERT(hfre_compile("foo$", 0, &re) == 0);
    ASSERT(hfre_exec(re, "xxfoo", 5, NULL, 0, &res) == 5);
    ASSERT(res.start == 2);
    hfre_free(re);

    ASSERT(hfre_compile("^foo$", 0, &re) == 0);
    ASSERT(hfre_exec(re, "xfoo", 4, NULL, 0, NULL) == HFRE_NO_MATCH);
    ASSERT(hfre_exec(re, "foo", 3, NULL, 0, &res) == 3);
    ASSERT(res.start == 0);
    hfre_free(re);

    ASSERT(hfre_match("needle", "haystack needle", 15, NULL, 0, 0) == 15);
    ASSERT(hfre_match("a|bb|cc", "a", 1, NULL, 0, 0) == 1);

    ASSERT(hfre_compile("(foo|bar):", 0, &re) == 0);
    ASSERT(hfre_exec(re, "xxbar:1", 7, c, 1, &res) == 6);
    ASSERT(res.start == 2);
    ASSERT(c[0].len == 3);
    ASSERT(memcmp(c[0].ptr, "bar", 3) == 0);
    hfre_free(re);

    ASSERT(hfre_compile("(\\xC3|z):", 0, &re) == 0);
    ASSERT(hfre_exec(re, "xxÃ:", (int) strlen("xxÃ:"), c, 1, &res) ==
           (int) strlen("xxÃ:"));
    ASSERT(res.start == 2);
    hfre_free(re);

    ASSERT(hfre_match("ab[0-9]c", "xxab7c", 6, NULL, 0, 0) == 6);
    ASSERT(hfre_match("(ab)", "xxab", 4, c, 1, 0) == 4);
    ASSERT(c[0].len == 2);
    ASSERT(memcmp(c[0].ptr, "ab", 2) == 0);
    ASSERT(hfre_match("(ab|)*", "", 0, NULL, 0, 0) == 0);
    ASSERT(hfre_match("é+", "xxéé!", (int) strlen("xxéé!"),
                      NULL, 0, 0) == 2 + (int) strlen("éé"));

    {
      const char bad[] = { (char) 0xc3, (char) 0xc3 };
      ASSERT(hfre_match("\\xC3+", bad, 2, NULL, 0, 0) == HFRE_NO_MATCH);
    }
  }

  /* No-capture Thompson VM correctness. */
  {
    /* Patterns must give the same answer with and without caps. */
    static const char *str = "GET /api/v1/users HTTP/1.1";
    int n_no_caps = hfre_match("GET /\\w+/\\w+/\\w+ HTTP/\\d\\.\\d",
                               str, (int) strlen(str), NULL, 0, 0);
    struct hfre_cap c[1];
    int n_caps = hfre_match("GET /\\w+/\\w+/\\w+ HTTP/\\d\\.\\d",
                            str, (int) strlen(str), c, 1, 0);
    ASSERT(n_no_caps == n_caps);
    ASSERT(n_no_caps == 26);
  }

  /* Pike/Thompson equivalence on edge cases. */
  {
    static const char *patterns[] = {
      "a?|b", "()*", "(a*)?", "^(a|aa)*$", "(|a)b?", "a*b+c?"
    };
    static const char *inputs[] = {
      "", "a", "aa", "abbbc", "b", "c"
    };
    for (int pi = 0; pi < (int)(sizeof(patterns) / sizeof(patterns[0])); pi++) {
      struct hfre *re = NULL;
      ASSERT(hfre_compile(patterns[pi], 0, &re) == 0);
      for (int si = 0; si < (int)(sizeof(inputs) / sizeof(inputs[0])); si++) {
        struct hfre_cap c[4];
        int len = (int) strlen(inputs[si]);
        int n_th = hfre_exec(re, inputs[si], len, NULL, 0, NULL);
        int n_pi = hfre_exec(re, inputs[si], len, c, 4, NULL);
        ASSERT(n_th == n_pi);
      }
      hfre_free(re);
    }

    {
      const char invalid_utf8[] = { (char) 0xc0, 'A', '\0' };
      struct hfre *re = NULL;
      struct hfre_cap c[1];
      ASSERT(hfre_compile(".", 0, &re) == 0);
      ASSERT(hfre_exec(re, invalid_utf8, 2, NULL, 0, NULL) ==
             hfre_exec(re, invalid_utf8, 2, c, 1, NULL));
      hfre_free(re);
    }
  }

  /* Failed alternation branches must not leak stale captures. */
  {
    struct hfre_cap c[3];
    ASSERT(hfre_match("(a(b)|a(c))", "ac", 2, c, 3, 0) == 2);
    ASSERT(c[0].len == 2);
    ASSERT(memcmp(c[0].ptr, "ac", 2) == 0);
    ASSERT(c[1].ptr == NULL);
    ASSERT(c[1].len == 0);
    ASSERT(c[2].len == 1);
    ASSERT(c[2].ptr[0] == 'c');
  }

  /* Zero-length progress and empty matches. */
  {
    ASSERT(hfre_match("()*", "abc", 3, NULL, 0, 0) == 0);
    ASSERT(hfre_match("(|)", "abc", 3, caps, 10, 0) == 0);
    ASSERT(caps[0].len == 0);
    ASSERT(hfre_match("^$", "", 0, NULL, 0, 0) == 0);
    ASSERT(hfre_match("^$", "x", 1, NULL, 0, 0) == HFRE_NO_MATCH);
  }

  /* Required-literal filters and dot-star shortcuts must preserve
   * anchors, greedy/lazy ordering, and leftmost-first behavior. */
  {
    ASSERT(hfre_match("^.*error", "ok error", 8, NULL, 0, 0) == 8);
    ASSERT(hfre_match("^.*error", "ok", 2, NULL, 0, 0) == HFRE_NO_MATCH);
    ASSERT(hfre_match(".*error$", "error then ok", 13, NULL, 0, 0)
           == HFRE_NO_MATCH);
    ASSERT(hfre_match(".*error$", "ok error", 8, NULL, 0, 0) == 8);
    ASSERT(hfre_match("x.*error", "x first error second error", 26,
                      NULL, 0, 0) == 26);
  }

  /* Explicit input lengths must allow NUL bytes in the input buffer. */
  {
    const char nul_buf1[] = { 'a', '\0', 'c' };
    const char nul_buf2[] = { 'x', '\0', 'y' };
    ASSERT(hfre_match("a.c", nul_buf1, 3, NULL, 0, 0) == 3);
    ASSERT(hfre_match("\\x00", nul_buf2, 3, NULL, 0, 0) == 2);
  }

  /* Literal-only compilation omits VM scratch. An unused capture array
   * must still be cleared for all three literal anchor shapes. */
  {
    static const char *patterns[] = { "foo", "^foo", "foo$", "^foo$" };
    for (size_t i = 0; i < sizeof(patterns) / sizeof(patterns[0]); i++) {
      struct hfre *re = NULL;
      struct hfre_result res;
      struct hfre_cap c[2] = { { "stale", 5 }, { "stale", 5 } };
      ASSERT(hfre_compile(patterns[i], 0, &re) == 0);
      ASSERT(hfre_capture_count(re) == 0);
      ASSERT(hfre_exec(re, "foo", 3, c, 2, &res) == 3);
      ASSERT(res.start == 0 && res.end == 3 && res.ncaps == 0);
      ASSERT(c[0].ptr == NULL && c[0].len == 0);
      ASSERT(c[1].ptr == NULL && c[1].len == 0);
      ASSERT(hfre_exec(re, "fo", 2, c, 2, NULL) == HFRE_NO_MATCH);
      hfre_free(re);
    }
    ASSERT(hfre_match("^foo", "xfoo", 4, NULL, 0, 0) == HFRE_NO_MATCH);
    ASSERT(hfre_match("^foo", "foobar", 6, NULL, 0, 0) == 3);
    ASSERT(hfre_match("^🦀", "🦀!", 5, NULL, 0, 0) == 4);
    ASSERT(hfre_match("^foo", "FOO", 3, NULL, 0, HFRE_IGNORE_CASE) == 3);
    ASSERT(hfre_match("^foo|bar", "xbar", 4, NULL, 0, 0) == 4);
    const char buf[] = { '\0', 'a', 'b' };
    ASSERT(hfre_match("^\\x00a", buf, 3, NULL, 0, 0) == 2);
  }

  /* Class first-byte analysis must include reverse Unicode folds after
   * changing from one fold-table traversal per byte to one per class. */
  {
    static const struct {
      const char *pattern;
      const char *input;
    } cases[] = {
      { "([a-z]x)", "Kx" }, { "([A-Z]x)", "ſx" },
      { "([k]x)", "Kx" }, { "([s]x)", "ſx" },
      { "([\\xE0]x)", "Àx" }
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
      struct hfre_cap c[1];
      int len = (int) strlen(cases[i].input);
      ASSERT(hfre_match(cases[i].pattern, cases[i].input, len, c, 1,
                        HFRE_IGNORE_CASE) == len);
      ASSERT(c[0].ptr == cases[i].input && c[0].len == len);
    }
  }

  /* The same literal scanner also seeds the VM and handles lazy dot-star. */
  {
    char buf[128];
    memset(buf, 'n', sizeof(buf));
    memcpy(buf + 101, "needle42", 8);
    struct hfre_cap c[1];
    struct hfre_result res;
    struct hfre *re = NULL;
    ASSERT(hfre_compile("needle(\\d+)", 0, &re) == 0);
    ASSERT(hfre_exec(re, buf, (int) sizeof(buf), c, 1, &res) == 109);
    ASSERT(res.start == 101 && c[0].ptr == buf + 107 && c[0].len == 2);
    hfre_free(re);
    memcpy(buf + 120, "needle", 6);
    ASSERT(hfre_match(".*?needle", buf, (int) sizeof(buf), NULL, 0, 0) == 107);
    ASSERT(hfre_match(".*needle", buf, (int) sizeof(buf), NULL, 0, 0) == 126);
  }

  test_literal_scans();
  test_class_scans();

  /* The two VMs share list storage. Alternate capture/no-capture
   * execution on the same object across successful and failed calls. */
  {
    static const char *patterns[] = {
      "(a|ab)+c", "(a(b)|a(c))", "([a-z]+):(\\d+)", "(ab)[0-9]c",
      "a[0-9]+b", "[a-z]+_[0-9]+"
    };
    static const char *inputs[] = {
      "", "xxababc", "ac", "abc:123", "ab7c", "a123b", "word_456", "!"
    };
    for (size_t p = 0; p < sizeof(patterns) / sizeof(patterns[0]); p++) {
      struct hfre *re = NULL;
      ASSERT(hfre_compile(patterns[p], 0, &re) == 0);
      for (int pass = 0; pass < 8; pass++) {
        for (size_t i = 0; i < sizeof(inputs) / sizeof(inputs[0]); i++) {
          int len = (int) strlen(inputs[i]);
          struct hfre_cap expected[4], actual[4];
          int end = hfre_match(patterns[p], inputs[i], len, expected, 4, 0);
          ASSERT(hfre_exec(re, inputs[i], len, NULL, 0, NULL) == end);
          ASSERT(hfre_exec(re, inputs[i], len, actual, 4, NULL) == end);
          for (int k = 0; k < 4; k++) {
            ASSERT(actual[k].ptr == expected[k].ptr &&
                   actual[k].len == expected[k].len);
          }
        }
      }
      hfre_free(re);
    }
  }

  /* Large alternation/capture pressure should stay inside VM scratch
   * bounds and return a real match or a real internal error, never
   * memory corruption hidden as a miss. */
  {
    static const char *regex =
      "((a)|(b)|(c)|(d)|(e)|(f)|(g)|(h)|(i)|(j)|(k)|(l)|(m)|(n)|(o)|(p))";
    struct hfre_cap c[17];
    int n = hfre_match(regex, "p", 1, c, 17, 0);
    ASSERT(n == 1 || n == HFRE_INTERNAL_ERROR);
    if (n == 1) {
      ASSERT(c[0].len == 1);
      ASSERT(c[16].len == 1);
      ASSERT(c[16].ptr[0] == 'p');
    }
  }

  printf("Unit test %s (total test: %d, failed tests: %d)\n",
         static_failed_tests > 0 ? "FAILED" : "PASSED",
         static_total_tests, static_failed_tests);

  return static_failed_tests == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
