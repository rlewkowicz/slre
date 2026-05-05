/*
 * SLRE micro-benchmark harness.
 * Build: make bench
 * Run:   ./bench
 *
 * Reports nanoseconds-per-call for representative workloads.
 * The result of each match is XOR'd into a sink so the optimizer
 * cannot delete the call.
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

static void run(const char *name, int iters,
                int (*body)(int)) {
  struct timespec t0, t1;
  int i, acc = 0;
  clock_gettime(CLOCK_MONOTONIC, &t0);
  for (i = 0; i < iters; i++) acc ^= body(i);
  clock_gettime(CLOCK_MONOTONIC, &t1);
  sink ^= acc;
  printf("  %-40s %10.1f ns/op  (%d iters)\n",
         name, elapsed_ns(t0, t1) / iters, iters);
}

/* Workload 1: literal-prefix unanchored search over 4KB buffer. */
static char big_buf[4096];
static int  big_buf_len;

static int bench_literal(int i) {
  (void) i;
  return slre_match("needle", big_buf, big_buf_len, NULL, 0, 0);
}

/* Workload 2: HTTP request line capture. */
static const char *http_req =
  " GET /index.html HTTP/1.0\r\n\r\n";
static int http_req_len;

static int bench_http(int i) {
  struct slre_cap caps[4];
  (void) i;
  return slre_match(
    "^\\s*(\\S+)\\s+(\\S+)\\s+HTTP/(\\d)\\.(\\d)",
    http_req, http_req_len, caps, 4, 0);
}

/* Workload 3: case-insensitive char-class over uppercase 1KB buffer. */
static char upper_buf[1024];
static int  upper_buf_len;

static int bench_icase_set(int i) {
  (void) i;
  return slre_match("[a-z]+", upper_buf, upper_buf_len,
                    NULL, 0, SLRE_IGNORE_CASE);
}

/* Workload 4: pathological-ish anchored greedy on tiny input
 * (regression canary - should remain very fast). */
static int bench_path(int i) {
  (void) i;
  return slre_match("^(a*)CONTROL", "CONTROL", 7, NULL, 0, 0);
}

/* Workload 5: unanchored search where the match is near the end of
 * a long buffer (stresses the start-position scan). */
static char long_buf[16384];
static int  long_buf_len;

static int bench_late_match(int i) {
  (void) i;
  return slre_match("zzz[0-9]+", long_buf, long_buf_len, NULL, 0, 0);
}

int main(void) {
  int i;

  /* big_buf: 4096 bytes of "abc..." with "needle" placed late. */
  for (i = 0; i < (int) sizeof(big_buf); i++) {
    big_buf[i] = (char) ('a' + (i % 23));
  }
  memcpy(big_buf + sizeof(big_buf) - 16, "needle", 6);
  big_buf_len = (int) sizeof(big_buf);

  /* upper_buf: 1023 'A's + final NUL. No lowercase letters,
   * so case-insensitive [a-z]+ matches all of it. */
  for (i = 0; i < (int) sizeof(upper_buf) - 1; i++) {
    upper_buf[i] = 'A' + (i % 26);
  }
  upper_buf[sizeof(upper_buf) - 1] = 'A';
  upper_buf_len = (int) sizeof(upper_buf);

  /* long_buf: filler with "zzz12345" at offset 16000. */
  for (i = 0; i < (int) sizeof(long_buf); i++) {
    long_buf[i] = (char) ('a' + (i % 25));  /* avoid 'z' */
  }
  memcpy(long_buf + 16000, "zzz12345", 8);
  long_buf_len = (int) sizeof(long_buf);

  http_req_len = (int) strlen(http_req);

  printf("SLRE benchmark\n");
  run("literal 'needle' in 4KB",       200000, bench_literal);
  run("HTTP request capture",         1000000, bench_http);
  run("[a-z]+ icase 1KB upper",        200000, bench_icase_set);
  run("^(a*)CONTROL on CONTROL",      2000000, bench_path);
  run("zzz[0-9]+ late in 16KB",        100000, bench_late_match);

  printf("(sink=%d)\n", sink);
  return 0;
}
