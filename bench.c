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
static const char *http_req = " GET /index.html HTTP/1.0\r\n\r\n";
static int  http_req_len;
static const char *unicode_buf = "lorem ipsum dolor sit amet 🦀 consectetur";
static int  unicode_buf_len;

/* Pre-compiled patterns. */
static struct hfre *re_lit, *re_http, *re_icase, *re_anchored, *re_late,
                   *re_alt, *re_unicode, *re_class_repeat, *re_dot_error,
                   *re_digits_abc, *re_anchored_lit;

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

static void run(const char *label, int iters, work_fn fn) {
  struct timespec t0, t1;
  int acc = 0;
  clock_gettime(CLOCK_MONOTONIC, &t0);
  for (int i = 0; i < iters; i++) acc ^= fn(i);
  clock_gettime(CLOCK_MONOTONIC, &t1);
  sink ^= acc;
  printf("  %-44s %10.1f ns/op  (%d iters)\n",
         label, elapsed_ns(t0, t1) / iters, iters);
}

int main(void) {
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

  http_req_len = (int) strlen(http_req);
  unicode_buf_len = (int) strlen(unicode_buf);

  hfre_compile("needle", 0, &re_lit);
  hfre_compile("^\\s*(\\S+)\\s+(\\S+)\\s+HTTP/(\\d)\\.(\\d)", 0, &re_http);
  hfre_compile("[a-z]+", HFRE_IGNORE_CASE, &re_icase);
  hfre_compile("^(a*)CONTROL", 0, &re_anchored);
  hfre_compile("zzz[0-9]+", 0, &re_late);
  hfre_compile("(GET|POST|PUT|DELETE)", 0, &re_alt);
  hfre_compile("🦀", 0, &re_unicode);
  hfre_compile("[A-Za-z0-9_]+", 0, &re_class_repeat);
  hfre_compile(".*error", 0, &re_dot_error);
  hfre_compile("[0-9]+abc", 0, &re_digits_abc);
  hfre_compile("^GET ", 0, &re_anchored_lit);

  printf("=== hfre_match (compile every call) ===\n");
  run("literal 'needle' in 4KB",          200000, w_match_lit);
  run("HTTP request capture",             500000, w_match_http);
  run("[a-z]+ icase 1KB upper",           200000, w_match_icase);
  run("^(a*)CONTROL on CONTROL",         1000000, w_match_anchored);
  run("zzz[0-9]+ late in 16KB",           100000, w_match_late);
  run("(GET|POST|PUT|DELETE)",           1000000, w_match_alt);
  run("UTF-8 emoji literal",             1000000, w_match_unicode);

  printf("\n=== hfre_exec (compile once) ===\n");
  run("literal 'needle' in 4KB",         1000000, w_exec_lit);
  run("HTTP request capture",            1000000, w_exec_http);
  run("[a-z]+ icase 1KB upper",           500000, w_exec_icase);
  run("^(a*)CONTROL on CONTROL",         2000000, w_exec_anchored);
  run("zzz[0-9]+ late in 16KB",           200000, w_exec_late);
  run("(GET|POST|PUT|DELETE)",           2000000, w_exec_alt);
  run("UTF-8 emoji literal",             2000000, w_exec_unicode);
  run("[A-Za-z0-9_]+ on words",          1000000, w_exec_class);
  run(".*error in 8KB log",              200000, w_exec_dot_error);
  run("[0-9]+abc in 4KB",                500000, w_exec_digits_abc);
  run("anchored ^GET ",                  2000000, w_exec_anchored_lit);

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

  printf("\n(sink=%d)\n", sink);
  return 0;
}
