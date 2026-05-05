#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "slre.h"

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
static char *slre_replace(const char *regex, const char *buf,
                          const char *sub) {
  char *s = NULL;
  int n, n1, n2, n3, s_len, len = strlen(buf);
  struct slre_cap cap = { NULL, 0 };

  do {
    s_len = s == NULL ? 0 : strlen(s);
    if ((n = slre_match(regex, buf, len, &cap, 1, 0)) > 0) {
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

int main(void) {
  struct slre_cap caps[10];

  /* Metacharacters */
  ASSERT(slre_match("$", "abcd", 4, NULL, 0, 0) == 4);
  ASSERT(slre_match("^", "abcd", 4, NULL, 0, 0) == 0);
  ASSERT(slre_match("x|^", "abcd", 4, NULL, 0, 0) == 0);
  ASSERT(slre_match("x|$", "abcd", 4, NULL, 0, 0) == 4);
  ASSERT(slre_match("x", "abcd", 4, NULL, 0, 0) == SLRE_NO_MATCH);
  ASSERT(slre_match(".", "abcd", 4, NULL, 0, 0) == 1);
  ASSERT(slre_match("^.*\\\\.*$", "c:\\Tools", 8, NULL, 0, SLRE_IGNORE_CASE)
    == 8);
  ASSERT(slre_match("\\", "a", 1, NULL, 0, 0) == SLRE_INVALID_METACHARACTER);
  ASSERT(slre_match("\\x", "a", 1, NULL, 0, 0) == SLRE_INVALID_METACHARACTER);
  ASSERT(slre_match("\\x1", "a", 1, NULL, 0, 0) == SLRE_INVALID_METACHARACTER);
  ASSERT(slre_match("\\x20", " ", 1, NULL, 0, 0) == 1);

  ASSERT(slre_match("^.+$", "", 0, NULL, 0, 0) == SLRE_NO_MATCH);
  ASSERT(slre_match("^(.+)$", "", 0, NULL, 0, 0) == SLRE_NO_MATCH);
  ASSERT(slre_match("^([\\+-]?)([\\d]+)$", "+", 1,
                    caps, 10, SLRE_IGNORE_CASE) == SLRE_NO_MATCH);
  ASSERT(slre_match("^([\\+-]?)([\\d]+)$", "+27", 3,
                    caps, 10, SLRE_IGNORE_CASE) == 3);
  ASSERT(caps[0].len == 1);
  ASSERT(caps[0].ptr[0] == '+');
  ASSERT(caps[1].len == 2);
  ASSERT(memcmp(caps[1].ptr, "27", 2) == 0);

  ASSERT(slre_match("tel:\\+(\\d+[\\d-]+\\d)",
                    "tel:+1-201-555-0123;a=b", 23, caps, 10, 0) == 19);
  ASSERT(caps[0].len == 14);
  ASSERT(memcmp(caps[0].ptr, "1-201-555-0123", 14) == 0);

  /* Character sets */
  ASSERT(slre_match("[abc]", "1c2", 3, NULL, 0, 0) == 2);
  ASSERT(slre_match("[abc]", "1C2", 3, NULL, 0, 0) == SLRE_NO_MATCH);
  ASSERT(slre_match("[abc]", "1C2", 3, NULL, 0, SLRE_IGNORE_CASE) == 2);
  /* Legacy SLRE treated '.' inside [] as match-any-byte. The current
   * engine follows standard regex semantics: '.' inside a class is a
   * literal '.'. So [.2] matches only '.' or '2'; in "1C2" the first
   * match is '2' at offset 2 (end offset = 3). */
  ASSERT(slre_match("[.2]", "1C2", 3, NULL, 0, 0) == 3);
  ASSERT(slre_match("[.2]", "..2", 3, NULL, 0, 0) == 1);
  ASSERT(slre_match("[\\S]+", "ab cd", 5, NULL, 0, 0) == 2);
  ASSERT(slre_match("[\\S]+\\s+[tyc]*", "ab cd", 5, NULL, 0, 0) == 4);
  ASSERT(slre_match("[\\d]", "ab cd", 5, NULL, 0, 0) == SLRE_NO_MATCH);
  ASSERT(slre_match("[^\\d]", "ab cd", 5, NULL, 0, 0) == 1);
  ASSERT(slre_match("[^\\d]+", "abc123", 6, NULL, 0, 0) == 3);
  ASSERT(slre_match("[1-5]+", "123456789", 9, NULL, 0, 0) == 5);
  ASSERT(slre_match("[1-5a-c]+", "123abcdef", 9, NULL, 0, 0) == 6);
  ASSERT(slre_match("[1-5a-]+", "123abcdef", 9, NULL, 0, 0) == 4);
  ASSERT(slre_match("[1-5a-]+", "123a--2oo", 9, NULL, 0, 0) == 7);
  ASSERT(slre_match("[htps]+://", "https://", 8, NULL, 0, 0) == 8);
  ASSERT(slre_match("[^\\s]+", "abc def", 7, NULL, 0, 0) == 3);
  ASSERT(slre_match("[^fc]+", "abc def", 7, NULL, 0, 0) == 2);
  ASSERT(slre_match("[^d\\sf]+", "abc def", 7, NULL, 0, 0) == 3);

  /* Flags - case sensitivity */
  ASSERT(slre_match("FO", "foo", 3, NULL, 0, 0) == SLRE_NO_MATCH);
  ASSERT(slre_match("FO", "foo", 3, NULL, 0, SLRE_IGNORE_CASE) == 2);
  ASSERT(slre_match("(?m)FO", "foo", 3, NULL, 0, 0) ==
    SLRE_UNEXPECTED_QUANTIFIER);
  ASSERT(slre_match("(?m)x", "foo", 3, NULL, 0, 0) ==
    SLRE_UNEXPECTED_QUANTIFIER);

  ASSERT(slre_match("fo", "foo", 3, NULL, 0, 0) == 2);
  ASSERT(slre_match(".+", "foo", 3, NULL, 0, 0) == 3);
  ASSERT(slre_match(".+k", "fooklmn", 7, NULL, 0, 0) == 4);
  ASSERT(slre_match(".+k.", "fooklmn", 7, NULL, 0, 0) == 5);
  ASSERT(slre_match("p+", "fooklmn", 7, NULL, 0, 0) == SLRE_NO_MATCH);
  ASSERT(slre_match("ok", "fooklmn", 7, NULL, 0, 0) == 4);
  ASSERT(slre_match("lmno", "fooklmn", 7, NULL, 0, 0) == SLRE_NO_MATCH);
  ASSERT(slre_match("mn.", "fooklmn", 7, NULL, 0, 0) == SLRE_NO_MATCH);
  ASSERT(slre_match("o", "fooklmn", 7, NULL, 0, 0) == 2);
  ASSERT(slre_match("^o", "fooklmn", 7, NULL, 0, 0) == SLRE_NO_MATCH);
  ASSERT(slre_match("^", "fooklmn", 7, NULL, 0, 0) == 0);
  ASSERT(slre_match("n$", "fooklmn", 7, NULL, 0, 0) == 7);
  ASSERT(slre_match("n$k", "fooklmn", 7, NULL, 0, 0) == SLRE_NO_MATCH);
  ASSERT(slre_match("l$", "fooklmn", 7, NULL, 0, 0) == SLRE_NO_MATCH);
  ASSERT(slre_match(".$", "fooklmn", 7, NULL, 0, 0) == 7);
  ASSERT(slre_match("a?", "fooklmn", 7, NULL, 0, 0) == 0);
  ASSERT(slre_match("^a*CONTROL", "CONTROL", 7, NULL, 0, 0) == 7);
  ASSERT(slre_match("^[a]*CONTROL", "CONTROL", 7, NULL, 0, 0) == 7);
  ASSERT(slre_match("^(a*)CONTROL", "CONTROL", 7, NULL, 0, 0) == 7);
  ASSERT(slre_match("^(a*)?CONTROL", "CONTROL", 7, NULL, 0, 0) == 7);

  ASSERT(slre_match("\\_", "abc", 3, NULL, 0, 0) == SLRE_INVALID_METACHARACTER);
  ASSERT(slre_match("+", "fooklmn", 7, NULL, 0, 0) == SLRE_UNEXPECTED_QUANTIFIER);
  /* Legacy SLRE returned NO_MATCH for "()+". Under standard
   * semantics an empty group can match the empty string, so the
   * leftmost-first match has length 0 at offset 0. */
  ASSERT(slre_match("()+", "fooklmn", 7, NULL, 0, 0) == 0);
  ASSERT(slre_match("\\x", "12", 2, NULL, 0, 0) == SLRE_INVALID_METACHARACTER);
  ASSERT(slre_match("\\xhi", "12", 2, NULL, 0, 0) == SLRE_INVALID_METACHARACTER);
  ASSERT(slre_match("\\x20", "_ J", 3, NULL, 0, 0) == 2);
  ASSERT(slre_match("\\x4A", "_ J", 3, NULL, 0, 0) == 3);
  ASSERT(slre_match("\\d+", "abc123def", 9, NULL, 0, 0) == 6);

  /* Balancing brackets */
  ASSERT(slre_match("(x))", "fooklmn", 7, NULL, 0, 0) == SLRE_UNBALANCED_BRACKETS);
  ASSERT(slre_match("(", "fooklmn", 7, NULL, 0, 0) == SLRE_UNBALANCED_BRACKETS);

  ASSERT(slre_match("klz?mn", "fooklmn", 7, NULL, 0, 0) == 7);
  ASSERT(slre_match("fa?b", "fooklmn", 7, NULL, 0, 0) == SLRE_NO_MATCH);

  /* Brackets & capturing */
  ASSERT(slre_match("^(te)", "tenacity subdues all", 20, caps, 10, 0) == 2);
  ASSERT(slre_match("(bc)", "abcdef", 6, caps, 10, 0) == 3);
  ASSERT(slre_match(".(d.)", "abcdef", 6, caps, 10, 0) == 5);
  ASSERT(slre_match(".(d.)\\)?", "abcdef", 6, caps, 10, 0) == 5);
  ASSERT(caps[0].len == 2);
  ASSERT(memcmp(caps[0].ptr, "de", 2) == 0);
  ASSERT(slre_match("(.+)", "123", 3, caps, 10, 0) == 3);
  ASSERT(slre_match("(2.+)", "123", 3, caps, 10, 0) == 3);
  ASSERT(caps[0].len == 2);
  ASSERT(memcmp(caps[0].ptr, "23", 2) == 0);
  ASSERT(slre_match("(.+2)", "123", 3, caps, 10, 0) == 2);
  ASSERT(caps[0].len == 2);
  ASSERT(memcmp(caps[0].ptr, "12", 2) == 0);
  ASSERT(slre_match("(.*(2.))", "123", 3, caps, 10, 0) == 3);
  ASSERT(slre_match("(.)(.)", "123", 3, caps, 10, 0) == 2);
  ASSERT(slre_match("(\\d+)\\s+(\\S+)", "12 hi", 5, caps, 10, 0) == 5);
  ASSERT(slre_match("ab(cd)+ef", "abcdcdef", 8, NULL, 0, 0) == 8);
  ASSERT(slre_match("ab(cd)*ef", "abcdcdef", 8, NULL, 0, 0) == 8);
  ASSERT(slre_match("ab(cd)+?ef", "abcdcdef", 8, NULL, 0, 0) == 8);
  ASSERT(slre_match("ab(cd)+?.", "abcdcdef", 8, NULL, 0, 0) == 5);
  ASSERT(slre_match("ab(cd)?", "abcdcdef", 8, NULL, 0, 0) == 4);
  ASSERT(slre_match("a(b)(cd)", "abcdcdef", 8, caps, 1, 0) ==
      SLRE_CAPS_ARRAY_TOO_SMALL);
  ASSERT(slre_match("(.+/\\d+\\.\\d+)\\.jpg$", "/foo/bar/12.34.jpg", 18,
                    caps, 1, 0) == 18);
  ASSERT(slre_match("(ab|cd).*\\.(xx|yy)", "ab.yy", 5, NULL, 0, 0) == 5);
  ASSERT(slre_match(".*a", "abcdef", 6, NULL, 0, 0) == 1);
  ASSERT(slre_match("(.+)c", "abcdef", 6, NULL, 0, 0) == 3);
  ASSERT(slre_match("\\n", "abc\ndef", 7, NULL, 0, 0) == 4);
  ASSERT(slre_match("b.\\s*\\n", "aa\r\nbb\r\ncc\r\n\r\n", 14,
                    caps, 10, 0) == 8);

  /* Greedy vs non-greedy */
  ASSERT(slre_match(".+c", "abcabc", 6, NULL, 0, 0) == 6);
  ASSERT(slre_match(".+?c", "abcabc", 6, NULL, 0, 0) == 3);
  ASSERT(slre_match(".*?c", "abcabc", 6, NULL, 0, 0) == 3);
  ASSERT(slre_match(".*c", "abcabc", 6, NULL, 0, 0) == 6);
  ASSERT(slre_match("bc.d?k?b+", "abcabc", 6, NULL, 0, 0) == 5);

  /* Branching. Note: leftmost-first alternation prefers the first
   * branch that matches, even if it matches the empty string. */
  ASSERT(slre_match("|", "abc", 3, NULL, 0, 0) == 0);
  /* "|." -> empty branch wins at pos 0 (length 0). Legacy SLRE
   * suppressed empty-branch wins, returning 1 (the '.' branch). */
  ASSERT(slre_match("|.", "abc", 3, NULL, 0, 0) == 0);
  ASSERT(slre_match("x|y|b", "abc", 3, NULL, 0, 0) == 2);
  ASSERT(slre_match("k(xx|yy)|ca", "abcabc", 6, NULL, 0, 0) == 4);
  ASSERT(slre_match("k(xx|yy)|ca|bc", "abcabc", 6, NULL, 0, 0) == 3);
  /* "(|.c)" -> empty alternation wins at pos 0 (length 0). Legacy
   * SLRE returned 3 with caps[0]="bc". */
  ASSERT(slre_match("(|.c)", "abc", 3, caps, 10, 0) == 0);
  ASSERT(caps[0].len == 0);
  ASSERT(slre_match("a|b|c", "a", 1, NULL, 0, 0) == 1);
  ASSERT(slre_match("a|b|c", "b", 1, NULL, 0, 0) == 1);
  ASSERT(slre_match("a|b|c", "c", 1, NULL, 0, 0) == 1);
  ASSERT(slre_match("a|b|c", "d", 1, NULL, 0, 0) == SLRE_NO_MATCH);

  /* Optional match at the end of the string */
  ASSERT(slre_match("^.*c.?$", "abc", 3, NULL, 0, 0) == 3);
  ASSERT(slre_match("^.*C.?$", "abc", 3, NULL, 0, SLRE_IGNORE_CASE) == 3);
  ASSERT(slre_match("bk?", "ab", 2, NULL, 0, 0) == 2);
  ASSERT(slre_match("b(k?)", "ab", 2, NULL, 0, 0) == 2);
  ASSERT(slre_match("b[k-z]*", "ab", 2, NULL, 0, 0) == 2);
  ASSERT(slre_match("ab(k|z|y)*", "ab", 2, NULL, 0, 0) == 2);
  ASSERT(slre_match("[b-z].*", "ab", 2, NULL, 0, 0) == 2);
  ASSERT(slre_match("(b|z|u).*", "ab", 2, NULL, 0, 0) == 2);
  ASSERT(slre_match("ab(k|z|y)?", "ab", 2, NULL, 0, 0) == 2);
  ASSERT(slre_match(".*", "ab", 2, NULL, 0, 0) == 2);
  ASSERT(slre_match(".*$", "ab", 2, NULL, 0, 0) == 2);
  ASSERT(slre_match("a+$", "aa", 2, NULL, 0, 0) == 2);
  ASSERT(slre_match("a*$", "aa", 2, NULL, 0, 0) == 2);
  ASSERT(slre_match( "a+$" ,"Xaa", 3, NULL, 0, 0) == 3);
  ASSERT(slre_match( "a*$" ,"Xaa", 3, NULL, 0, 0) == 3);

  /* Ignore case flag */
  ASSERT(slre_match("[a-h]+", "abcdefghxxx", 11, NULL, 0, 0) == 8);
  ASSERT(slre_match("[A-H]+", "ABCDEFGHyyy", 11, NULL, 0, 0) == 8);
  ASSERT(slre_match("[a-h]+", "ABCDEFGHyyy", 11, NULL, 0, 0) == SLRE_NO_MATCH);
  ASSERT(slre_match("[A-H]+", "abcdefghyyy", 11, NULL, 0, 0) == SLRE_NO_MATCH);
  ASSERT(slre_match("[a-h]+", "ABCDEFGHyyy", 11, NULL, 0, SLRE_IGNORE_CASE) == 8);
  ASSERT(slre_match("[A-H]+", "abcdefghyyy", 11, NULL, 0, SLRE_IGNORE_CASE) == 8);

  {
    /* Example: HTTP request */
    const char *request = " GET /index.html HTTP/1.0\r\n\r\n";
    struct slre_cap caps[4];

    if (slre_match("^\\s*(\\S+)\\s+(\\S+)\\s+HTTP/(\\d)\\.(\\d)",
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
    char *s = slre_replace("({{.+?}})",
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
      "  <a href=\"http://cesanta.com\">some link</a>";

    static const char *regex = "((https?://)[^\\s/'\"<>]+/?[^\\s'\"<>]*)";
    struct slre_cap caps[2];
    int i, j = 0, str_len = (int) strlen(str);

    while (j < str_len &&
           (i = slre_match(regex, str + j, str_len - j, caps, 2, SLRE_IGNORE_CASE)) > 0) {
      printf("Found URL: [%.*s]\n", caps[0].len, caps[0].ptr);
      j += i;
    }
  }

  {
    /* Example more complex regular expression */
    static const char * str = "aa 1234 xy\nxyz";
    static const char * regex = "aa ([0-9]*) *([x-z]*)\\s+xy([yz])";
    struct slre_cap caps[3];
    ASSERT(slre_match(regex, str, strlen(str), caps, 3, 0) > 0);
    ASSERT(caps[0].len == 4);
    ASSERT(caps[1].len == 2);
    ASSERT(caps[2].len == 1);
    ASSERT(caps[2].ptr[0] == 'z');
  }

  /* Compile/exec API. */
  {
    struct slre *re = NULL;
    ASSERT(slre_compile("a(b+)c", 0, &re) == 0);
    ASSERT(re != NULL);
    ASSERT(slre_capture_count(re) == 1);
    struct slre_cap c[1];
    struct slre_result r;
    ASSERT(slre_exec(re, "xxabbbcyy", 9, c, 1, &r) == 7);
    ASSERT(r.start == 2);
    ASSERT(r.end == 7);
    ASSERT(r.ncaps == 1);
    ASSERT(c[0].len == 3);
    ASSERT(memcmp(c[0].ptr, "bbb", 3) == 0);
    /* Re-using the same compiled regex on a different buffer. */
    ASSERT(slre_exec(re, "ac", 2, c, 1, &r) == SLRE_NO_MATCH);
    ASSERT(slre_exec(re, "abbc abbbbc", 11, c, 1, &r) == 4);
    ASSERT(c[0].len == 2);
    slre_free(re);
  }
  /* slre_free(NULL) is safe. */
  slre_free(NULL);

  /* New error codes. */
  {
    struct slre *re = NULL;
    ASSERT(slre_compile("\\p{Latin}", 0, &re) == SLRE_INVALID_UNICODE_PROPERTY);
    ASSERT(slre_compile(NULL, 0, &re) == SLRE_INVALID_ARGUMENT);
    /* Invalid UTF-8 in pattern. */
    ASSERT(slre_compile("\xC0", 0, &re) == SLRE_INVALID_UTF8);
  }

  /* UTF-8 literal matching. */
  {
    /* "ñ" = U+00F1 = 0xC3 0xB1; "中" = U+4E2D = 0xE4 0xB8 0xAD;
     * "🦀" = U+1F980 = 0xF0 0x9F 0xA6 0x80. */
    const char *needle1 = "ñ";
    const char *hay1 = "abc ñ def";
    ASSERT(slre_match(needle1, hay1, (int) strlen(hay1), NULL, 0, 0)
           == 4 + 2);  /* match ends just past the 2-byte rune */
    const char *needle2 = "中";
    const char *hay2 = "x中y";
    ASSERT(slre_match(needle2, hay2, (int) strlen(hay2), NULL, 0, 0)
           == 1 + 3);
    const char *needle3 = "🦀";
    const char *hay3 = "love 🦀!";
    ASSERT(slre_match(needle3, hay3, (int) strlen(hay3), NULL, 0, 0)
           == 5 + 4);
    /* . matches one full code point. */
    ASSERT(slre_match("a.b", "a🦀b", 6, NULL, 0, 0) == 6);
    /* Multi-rune pattern. */
    struct slre_cap mc[1];
    ASSERT(slre_match("(中文)", "hello 中文", 12, mc, 1, 0) == 12);
    ASSERT(mc[0].len == 6);
  }

  /* Greedy vs lazy alternation under leftmost-first. */
  {
    /* Leftmost-first: prefer the FIRST listed branch when both could
     * match. */
    ASSERT(slre_match("a|aa", "aa", 2, NULL, 0, 0) == 1);
    ASSERT(slre_match("aa|a", "aa", 2, NULL, 0, 0) == 2);
  }

  /* Word class \w \W. */
  {
    struct slre_cap c[1];
    ASSERT(slre_match("(\\w+)", "  hello_world42 ", 16, c, 1, 0) > 0);
    ASSERT(c[0].len == 13);
    ASSERT(slre_match("\\W+", "  ;.!  ab", 9, NULL, 0, 0) == 7);
  }

  /* Required-literal prefilter: literal absent -> no match. The
   * filter is tighter than the single-byte first-byte set. */
  {
    /* "abc" is a 3-byte required literal in this regex. */
    ASSERT(slre_match("[0-9]+abc", "no digits here", 14, NULL, 0, 0)
           == SLRE_NO_MATCH);
    ASSERT(slre_match("[0-9]+abc", "x12abc!", 7, NULL, 0, 0) == 6);
  }

  /* .*LIT direct shortcut: greedy returns the LAST occurrence. */
  {
    ASSERT(slre_match(".*error", "ok", 2, NULL, 0, 0) == SLRE_NO_MATCH);
    /* Greedy: prefers the last "error" position. */
    ASSERT(slre_match(".*error", "first error then second error end",
                      33, NULL, 0, 0) == 29);
    /* Lazy: prefers the first. */
    ASSERT(slre_match(".*?error", "first error then second error end",
                      33, NULL, 0, 0) == 11);
  }

  /* Required literal as prefix lets the scanner jump straight to the
   * literal's position. */
  {
    static char big[2048];
    for (int i = 0; i < (int) sizeof(big); i++) big[i] = (char) ('a' + (i % 23));
    memcpy(big + 1900, "tel:+1234", 9);
    struct slre_cap c[1];
    int n = slre_match("tel:\\+(\\d+)", big, (int) sizeof(big), c, 1, 0);
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
    ASSERT(slre_match("[0-9]+x", buf, (int) sizeof(buf), NULL, 0, 0)
           == SLRE_NO_MATCH);
  }

  /* No-capture Thompson VM correctness. */
  {
    /* Patterns must give the same answer with and without caps. */
    static const char *str = "GET /api/v1/users HTTP/1.1";
    int n_no_caps = slre_match("GET /\\w+/\\w+/\\w+ HTTP/\\d\\.\\d",
                               str, (int) strlen(str), NULL, 0, 0);
    struct slre_cap c[1];
    int n_caps = slre_match("GET /\\w+/\\w+/\\w+ HTTP/\\d\\.\\d",
                            str, (int) strlen(str), c, 1, 0);
    ASSERT(n_no_caps == n_caps);
    ASSERT(n_no_caps == 26);
  }

  printf("Unit test %s (total test: %d, failed tests: %d)\n",
         static_failed_tests > 0 ? "FAILED" : "PASSED",
         static_total_tests, static_failed_tests);

  return static_failed_tests == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
