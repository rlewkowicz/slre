/*
 * SLRE micro-benchmark harness.
 *
 * Measures both the legacy slre_match() one-shot wrapper (which
 * recompiles the regex on every call) and the compiled-once
 * slre_compile + slre_exec path. Reports nanoseconds per call.
 *
 * Build: make bench
 * Run:   ./bench
 */

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <string.h>
#include <time.h>

#include "slre.h"

static volatile int sink;

static double elapsed_ns(struct timespec a, struct timespec b) {
  return (double)(b.tv_sec - a.tv_sec) * 1e9
       + (double)(b.tv_nsec - a.tv_nsec);
}

#define RUN(label, iters, body)                                          \
  do {                                                                   \
    struct timespec _t0, _t1;                                            \
    int _acc = 0;                                                        \
    clock_gettime(CLOCK_MONOTONIC, &_t0);                                \
    for (int _i = 0; _i < (iters); _i++) { _acc ^= (body); }             \
    clock_gettime(CLOCK_MONOTONIC, &_t1);                                \
    sink ^= _acc;                                                        \
    printf("  %-44s %10.1f ns/op  (%d iters)\n",                         \
           (label), elapsed_ns(_t0, _t1) / (iters), (iters));            \
  } while (0)

/* Static buffers for the workloads. */
static char big_buf[4096];
static int  big_buf_len;
static char upper_buf[1024];
static int  upper_buf_len;
static char long_buf[16384];
static int  long_buf_len;
static const char *http_req = " GET /index.html HTTP/1.0\r\n\r\n";
static int http_req_len;
static const char *unicode_buf = "lorem ipsum dolor sit amet 🦀 consectetur";
static int unicode_buf_len;

int main(void) {
  /* big_buf: 4096 bytes of "abc..." with "needle" placed late. */
  for (int i = 0; i < (int) sizeof(big_buf); i++) {
    big_buf[i] = (char) ('a' + (i % 23));
  }
  memcpy(big_buf + sizeof(big_buf) - 16, "needle", 6);
  big_buf_len = (int) sizeof(big_buf);

  /* upper_buf: 1023 'A'..'Z' cycled, no lowercase. */
  for (int i = 0; i < (int) sizeof(upper_buf); i++) {
    upper_buf[i] = 'A' + (i % 26);
  }
  upper_buf_len = (int) sizeof(upper_buf);

  /* long_buf: filler with "zzz12345" at offset 16000. */
  for (int i = 0; i < (int) sizeof(long_buf); i++) {
    long_buf[i] = (char) ('a' + (i % 25));  /* avoid 'z' */
  }
  memcpy(long_buf + 16000, "zzz12345", 8);
  long_buf_len = (int) sizeof(long_buf);

  http_req_len = (int) strlen(http_req);
  unicode_buf_len = (int) strlen(unicode_buf);

  /* Pre-compile the patterns we'll reuse for the slre_exec path. */
  struct slre *re_lit = NULL, *re_http = NULL, *re_icase = NULL,
              *re_anchored = NULL, *re_late = NULL, *re_alt = NULL,
              *re_unicode = NULL, *re_class_repeat = NULL;
  slre_compile("needle", 0, &re_lit);
  slre_compile("^\\s*(\\S+)\\s+(\\S+)\\s+HTTP/(\\d)\\.(\\d)", 0, &re_http);
  slre_compile("[a-z]+", SLRE_IGNORE_CASE, &re_icase);
  slre_compile("^(a*)CONTROL", 0, &re_anchored);
  slre_compile("zzz[0-9]+", 0, &re_late);
  slre_compile("(GET|POST|PUT|DELETE)", 0, &re_alt);
  slre_compile("🦀", 0, &re_unicode);
  slre_compile("[A-Za-z0-9_]+", 0, &re_class_repeat);

  printf("=== slre_match (compile every call) ===\n");
  RUN("literal 'needle' in 4KB",          200000,
      slre_match("needle", big_buf, big_buf_len, NULL, 0, 0));
  RUN("HTTP request capture",             500000, ({
        struct slre_cap c[4];
        slre_match("^\\s*(\\S+)\\s+(\\S+)\\s+HTTP/(\\d)\\.(\\d)",
                   http_req, http_req_len, c, 4, 0);
      }));
  RUN("[a-z]+ icase 1KB upper",           200000,
      slre_match("[a-z]+", upper_buf, upper_buf_len, NULL, 0,
                 SLRE_IGNORE_CASE));
  RUN("^(a*)CONTROL on CONTROL",          1000000,
      slre_match("^(a*)CONTROL", "CONTROL", 7, NULL, 0, 0));
  RUN("zzz[0-9]+ late in 16KB",           100000,
      slre_match("zzz[0-9]+", long_buf, long_buf_len, NULL, 0, 0));
  RUN("(GET|POST|PUT|DELETE)",           1000000,
      slre_match("(GET|POST|PUT|DELETE)",
                 "x GET /foo", 10, NULL, 0, 0));
  RUN("UTF-8 emoji literal",             1000000,
      slre_match("🦀", unicode_buf, unicode_buf_len, NULL, 0, 0));

  printf("\n=== slre_exec (compile once) ===\n");
  RUN("literal 'needle' in 4KB",         1000000,
      slre_exec(re_lit, big_buf, big_buf_len, NULL, 0, NULL));
  RUN("HTTP request capture",            1000000, ({
        struct slre_cap c[4];
        slre_exec(re_http, http_req, http_req_len, c, 4, NULL);
      }));
  RUN("[a-z]+ icase 1KB upper",           500000,
      slre_exec(re_icase, upper_buf, upper_buf_len, NULL, 0, NULL));
  RUN("^(a*)CONTROL on CONTROL",         2000000,
      slre_exec(re_anchored, "CONTROL", 7, NULL, 0, NULL));
  RUN("zzz[0-9]+ late in 16KB",          200000,
      slre_exec(re_late, long_buf, long_buf_len, NULL, 0, NULL));
  RUN("(GET|POST|PUT|DELETE)",           2000000,
      slre_exec(re_alt, "x GET /foo", 10, NULL, 0, NULL));
  RUN("UTF-8 emoji literal",             2000000,
      slre_exec(re_unicode, unicode_buf, unicode_buf_len, NULL, 0, NULL));
  RUN("[A-Za-z0-9_]+ on words",          1000000,
      slre_exec(re_class_repeat, "abcDEF_123 ", 11, NULL, 0, NULL));

  slre_free(re_lit);
  slre_free(re_http);
  slre_free(re_icase);
  slre_free(re_anchored);
  slre_free(re_late);
  slre_free(re_alt);
  slre_free(re_unicode);
  slre_free(re_class_repeat);

  printf("\n(sink=%d)\n", sink);
  return 0;
}
