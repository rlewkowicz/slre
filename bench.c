/*
 * hfre micro-benchmark harness.
 *
 * Measures both the legacy hfre_match() one-shot wrapper (which
 * recompiles the regex on every call) and the compiled-once
 * hfre_compile + hfre_exec path. Reports nanoseconds per call.
 *
 * Build: make bench
 * Run:   ./bench
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "hfre.h"

static volatile int sink;

static double elapsed_ns(struct timespec a, struct timespec b) {
  return (double) (b.tv_sec - a.tv_sec) * 1e9
       + (double) (b.tv_nsec - a.tv_nsec);
}

/* Static buffers shared across workloads. */
static char big_buf[4096];
static int  big_buf_len;
static char upper_buf[1024];
static int  upper_buf_len;
static char long_buf[16384];
static int  long_buf_len;
static char log_buf[8192];
static int  log_buf_len;
static char dense_buf[4096];
static char sparse_buf[4096];
static char number_buf[8192];
static const char *http_req = " GET /index.html HTTP/1.0\r\n\r\n";
static int  http_req_len;
static const char *unicode_buf = "lorem ipsum dolor sit amet 🦀 consectetur";
static int  unicode_buf_len;

/* Pre-compiled patterns. */
static struct hfre *re_lit, *re_http, *re_icase, *re_anchored, *re_late,
                   *re_alt, *re_unicode, *re_class_repeat, *re_dot_error,
                   *re_digits_abc, *re_anchored_lit, *re_notdigits;

/* Each workload is a function returning an int that gets XOR'd into
 * the sink so the optimizer cannot delete the call. */
typedef int (*work_fn)(int iter);

/* hfre_match (compile every call) workloads. */
static int w_match_lit(int i)       { (void) i; return hfre_match("needle", big_buf, big_buf_len, NULL, 0, 0); }
static int w_match_http(int i)      { (void) i; struct hfre_cap c[4]; return hfre_match("^\\s*(\\S+)\\s+(\\S+)\\s+HTTP/(\\d)\\.(\\d)", http_req, http_req_len, c, 4, 0); }
static int w_match_icase(int i)     { (void) i; return hfre_match("[a-z]+", upper_buf, upper_buf_len, NULL, 0, HFRE_IGNORE_CASE); }
static int w_match_anchored(int i)  { (void) i; return hfre_match("^(a*)CONTROL", "CONTROL", 7, NULL, 0, 0); }
static int w_match_late(int i)      { (void) i; return hfre_match("zzz[0-9]+", long_buf, long_buf_len, NULL, 0, 0); }
static int w_match_alt(int i)       { (void) i; return hfre_match("(GET|POST|PUT|DELETE)", "x GET /foo", 10, NULL, 0, 0); }
static int w_match_unicode(int i)   { (void) i; return hfre_match("🦀", unicode_buf, unicode_buf_len, NULL, 0, 0); }

/* hfre_exec (compile once) workloads. */
static int w_exec_lit(int i)        { (void) i; return hfre_exec(re_lit, big_buf, big_buf_len, NULL, 0, NULL); }
static int w_exec_http(int i)       { (void) i; struct hfre_cap c[4]; return hfre_exec(re_http, http_req, http_req_len, c, 4, NULL); }
static int w_exec_icase(int i)      { (void) i; return hfre_exec(re_icase, upper_buf, upper_buf_len, NULL, 0, NULL); }
static int w_exec_anchored(int i)   { (void) i; return hfre_exec(re_anchored, "CONTROL", 7, NULL, 0, NULL); }
static int w_exec_late(int i)       { (void) i; return hfre_exec(re_late, long_buf, long_buf_len, NULL, 0, NULL); }
static int w_exec_alt(int i)        { (void) i; return hfre_exec(re_alt, "x GET /foo", 10, NULL, 0, NULL); }
static int w_exec_unicode(int i)    { (void) i; return hfre_exec(re_unicode, unicode_buf, unicode_buf_len, NULL, 0, NULL); }
static int w_exec_class(int i)      { (void) i; return hfre_exec(re_class_repeat, "abcDEF_123 ", 11, NULL, 0, NULL); }
static int w_exec_dot_error(int i)  { (void) i; return hfre_exec(re_dot_error, log_buf, log_buf_len, NULL, 0, NULL); }
static int w_exec_digits_abc(int i) { (void) i; return hfre_exec(re_digits_abc, big_buf, big_buf_len, NULL, 0, NULL); }
static int w_exec_anchored_lit(int i) { (void) i; return hfre_exec(re_anchored_lit, "GET /", 5, NULL, 0, NULL); }
static int w_exec_dense_miss(int i) { (void) i; return hfre_exec(re_lit, dense_buf, (int) sizeof(dense_buf), NULL, 0, NULL); }
static int w_exec_sparse_miss(int i) { (void) i; return hfre_exec(re_lit, sparse_buf, (int) sizeof(sparse_buf), NULL, 0, NULL); }
static int w_exec_early_lit(int i)  { (void) i; return hfre_exec(re_lit, "needle at the start", 19, NULL, 0, NULL); }
static int w_exec_class_large(int i) { (void) i; return hfre_exec(re_class_repeat, long_buf, long_buf_len, NULL, 0, NULL); }
static int w_exec_class_miss(int i) { (void) i; return hfre_exec(re_icase, number_buf, (int) sizeof(number_buf) - 3, NULL, 0, NULL); }
static int w_exec_class_late(int i) { (void) i; return hfre_exec(re_icase, number_buf, (int) sizeof(number_buf), NULL, 0, NULL); }
static int w_exec_inverted(int i) { (void) i; return hfre_exec(re_notdigits, upper_buf, upper_buf_len, NULL, 0, NULL); }

static void run(const char *label, int iters, work_fn fn, int expected) {
  struct timespec t0, t1;
  int acc = 0;
  /* Check results and warm up code, data, and lazy DFA transitions. */
  for (int i = 0; i < 32; i++) {
    int actual = fn(i);
    if (actual != expected) {
      fprintf(stderr, "%s: expected %d, got %d\n", label, expected, actual);
      exit(EXIT_FAILURE);
    }
    acc ^= actual;
  }
  clock_gettime(CLOCK_MONOTONIC, &t0);
  for (int i = 0; i < iters; i++) acc ^= fn(i);
  clock_gettime(CLOCK_MONOTONIC, &t1);
  sink ^= acc;
  printf("  %-44s %10.1f ns/op  (%d iters)\n",
         label, elapsed_ns(t0, t1) / iters, iters);
}

static void compile(const char *pattern, int flags, struct hfre **out) {
  int err = hfre_compile(pattern, flags, out);
  if (err != 0) {
    fprintf(stderr, "Cannot compile %s: %d\n", pattern, err);
    exit(EXIT_FAILURE);
  }
}

int main(int argc, char **argv) {
  int exec_only = argc == 2 && strcmp(argv[1], "--exec-only") == 0;
  if (argc > 1 && !exec_only) {
    fprintf(stderr, "Usage: %s [--exec-only]\n", argv[0]);
    return EXIT_FAILURE;
  }
  setvbuf(stdout, NULL, _IOLBF, 0);
  /* big_buf: 4096 bytes of "abc..." with "needle" placed late. */
  for (int i = 0; i < (int) sizeof(big_buf); i++) {
    big_buf[i] = (char) ('a' + (i % 23));
  }
  memcpy(big_buf + sizeof(big_buf) - 16, "needle", 6);
  big_buf_len = (int) sizeof(big_buf);

  /* upper_buf: 1024 bytes of A..Z, no lowercase letters. */
  for (int i = 0; i < (int) sizeof(upper_buf); i++) {
    upper_buf[i] = (char) ('A' + (i % 26));
  }
  upper_buf_len = (int) sizeof(upper_buf);

  /* long_buf: filler with "zzz12345" at offset 16000. */
  for (int i = 0; i < (int) sizeof(long_buf); i++) {
    long_buf[i] = (char) ('a' + (i % 25));  /* avoid 'z' */
  }
  memcpy(long_buf + 16000, "zzz12345", 8);
  long_buf_len = (int) sizeof(long_buf);

  /* log_buf: 8KB of "log line" filler with "error" near the end. */
  for (int i = 0; i < (int) sizeof(log_buf); i++) {
    log_buf[i] = (char) ('a' + (i % 25));
  }
  memcpy(log_buf + sizeof(log_buf) - 24, "fatal error: boom", 17);
  log_buf_len = (int) sizeof(log_buf);
  memset(dense_buf, 'n', sizeof(dense_buf));
  memset(sparse_buf, 'x', sizeof(sparse_buf));
  memset(number_buf, '7', sizeof(number_buf));
  memcpy(number_buf + sizeof(number_buf) - 3, "abc", 3);

  http_req_len = (int) strlen(http_req);
  unicode_buf_len = (int) strlen(unicode_buf);

  compile("needle", 0, &re_lit);
  compile("^\\s*(\\S+)\\s+(\\S+)\\s+HTTP/(\\d)\\.(\\d)", 0, &re_http);
  compile("[a-z]+", HFRE_IGNORE_CASE, &re_icase);
  compile("^(a*)CONTROL", 0, &re_anchored);
  compile("zzz[0-9]+", 0, &re_late);
  compile("(GET|POST|PUT|DELETE)", 0, &re_alt);
  compile("🦀", 0, &re_unicode);
  compile("[A-Za-z0-9_]+", 0, &re_class_repeat);
  compile(".*error", 0, &re_dot_error);
  compile("[0-9]+abc", 0, &re_digits_abc);
  compile("^GET ", 0, &re_anchored_lit);
  compile("[^0-9]+", 0, &re_notdigits);

  if (!exec_only) {
    printf("=== hfre_match (compile every call) ===\n");
    run("literal 'needle' in 4KB",          200000, w_match_lit, 4086);
    run("HTTP request capture",             500000, w_match_http, http_req_len - 4);
    run("[a-z]+ icase 1KB upper",           200000, w_match_icase, upper_buf_len);
    run("^(a*)CONTROL on CONTROL",         1000000, w_match_anchored, 7);
    run("zzz[0-9]+ late in 16KB",           100000, w_match_late, 16008);
    run("(GET|POST|PUT|DELETE)",           1000000, w_match_alt, 5);
    run("UTF-8 emoji literal",             1000000, w_match_unicode, 31);
  }

  printf("\n=== hfre_exec (compile once) ===\n");
  run("literal 'needle' in 4KB",         1000000, w_exec_lit, 4086);
  run("HTTP request capture",            1000000, w_exec_http, http_req_len - 4);
  run("[a-z]+ icase 1KB upper",           500000, w_exec_icase, upper_buf_len);
  run("^(a*)CONTROL on CONTROL",         2000000, w_exec_anchored, 7);
  run("zzz[0-9]+ late in 16KB",           200000, w_exec_late, 16008);
  run("(GET|POST|PUT|DELETE)",           2000000, w_exec_alt, 5);
  run("UTF-8 emoji literal",             2000000, w_exec_unicode, 31);
  run("[A-Za-z0-9_]+ on words",          1000000, w_exec_class, 10);
  run(".*error in 8KB log",              200000, w_exec_dot_error, 8179);
  run("[0-9]+abc in 4KB",                500000, w_exec_digits_abc, HFRE_NO_MATCH);
  run("anchored ^GET ",                  2000000, w_exec_anchored_lit, 4);
  run("literal miss, dense first bytes",  200000, w_exec_dense_miss, HFRE_NO_MATCH);
  run("literal miss, sparse first bytes", 1000000, w_exec_sparse_miss, HFRE_NO_MATCH);
  run("literal at start",               2000000, w_exec_early_lit, 6);
  run("[A-Za-z0-9_]+ in 16KB",            200000, w_exec_class_large, long_buf_len);
  run("[a-z]+ icase miss in 8KB digits",  200000, w_exec_class_miss, HFRE_NO_MATCH);
  run("[a-z]+ icase late in 8KB digits",  200000, w_exec_class_late, (int) sizeof(number_buf));
  run("[^0-9]+ in 1KB upper",            500000, w_exec_inverted, upper_buf_len);

  hfre_free(re_lit);
  hfre_free(re_http);
  hfre_free(re_icase);
  hfre_free(re_anchored);
  hfre_free(re_late);
  hfre_free(re_alt);
  hfre_free(re_unicode);
  hfre_free(re_class_repeat);
  hfre_free(re_dot_error);
  hfre_free(re_digits_abc);
  hfre_free(re_anchored_lit);
  hfre_free(re_notdigits);

  printf("\n(sink=%d)\n", sink);
  return 0;
}
