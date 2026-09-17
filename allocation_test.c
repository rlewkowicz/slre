/* Allocation accounting and failure injection. Include the engine in
 * this test translation unit to intercept only its allocator calls. */
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

union allocation_header {
  max_align_t alignment;
  size_t size;
};

static size_t live_bytes, peak_bytes, allocation_calls, fail_at;

static void *counted_malloc(size_t size) {
  allocation_calls++;
  if (allocation_calls == fail_at || size > SIZE_MAX - sizeof(union allocation_header)) {
    return NULL;
  }
  union allocation_header *p = malloc(sizeof(*p) + size);
  if (p == NULL) return NULL;
  p->size = size;
  live_bytes += size;
  if (live_bytes > peak_bytes) peak_bytes = live_bytes;
  return p + 1;
}

static void counted_free(void *ptr) {
  if (ptr == NULL) return;
  union allocation_header *p = (union allocation_header *) ptr - 1;
  live_bytes -= p->size;
  free(p);
}

static void *counted_calloc(size_t count, size_t size) {
  if (size != 0 && count > SIZE_MAX / size) return NULL;
  void *p = counted_malloc(count * size);
  if (p != NULL) memset(p, 0, count * size);
  return p;
}

static void *counted_realloc(void *ptr, size_t size) {
  if (ptr == NULL) return counted_malloc(size);
  allocation_calls++;
  if (allocation_calls == fail_at || size > SIZE_MAX - sizeof(union allocation_header)) {
    return NULL;
  }
  union allocation_header *old = (union allocation_header *) ptr - 1;
  size_t old_size = old->size;
  union allocation_header *p = realloc(old, sizeof(*p) + size);
  if (p == NULL) return NULL;
  p->size = size;
  live_bytes = live_bytes - old_size + size;
  if (live_bytes > peak_bytes) peak_bytes = live_bytes;
  return p + 1;
}

#define malloc counted_malloc
#define calloc counted_calloc
#define realloc counted_realloc
#define free counted_free
#include "hfre.c"
#undef malloc
#undef calloc
#undef realloc
#undef free

static int failures;
static const char *current_pattern;

#define CHECK(expr) do { \
  if (!(expr)) { \
    fprintf(stderr, "Allocation check failed for %s (failure %zu), line %d: %s\n", \
            current_pattern, fail_at, __LINE__, #expr); \
    failures++; \
  } \
} while (0)

static void check_exec(struct hfre *re, const char *buf, int len, int expected) {
  struct hfre_cap caps[4];
  size_t calls = allocation_calls;
  CHECK(hfre_exec(re, buf, len, NULL, 0, NULL) == expected);
  CHECK(hfre_exec(re, buf, len, caps, 4, NULL) == expected);
  CHECK(allocation_calls == calls);
}

int main(void) {
  static const struct {
    const char *pattern;
    const char *input;
    int flags;
    int expected;
  } cases[] = {
    { "needle", "hayneedle", 0, 9 },
    { "[a-z]+", "ABCDEF", HFRE_IGNORE_CASE, 6 },
    { "[A-Za-z0-9_]+", "aBc_123 ", 0, 7 },
    { "a+", "aaaa", 0, 4 },
    { "[\\p{Greek}]+", "ΣΣ!", 0, 4 },
    { "a[0-9]+b", "a123b", 0, 5 },
    { "(a(b)|a(c))", "ac", 0, 2 },
    { "^(ab)[0-9](cd)[0-9](ef)[0-9](gh)ij$", "ab1cd2ef3ghij", 0, 13 },
    { "aaaaaaaaaaaaaaa.", "aaaaaaaaaaaaaaab", 0, 16 },
    { "aaaaaaaaaaaaaaa\\p{Greek}", "aaaaaaaaaaaaaaaΣ", 0, 17 },
    { "^\\s*(\\S+)\\s+(\\S+)\\s+HTTP/(\\d)\\.(\\d)",
      " GET /index.html HTTP/1.0\r\n\r\n", 0, 25 }
  };
  setvbuf(stdout, NULL, _IOLBF, 0);
  puts("Pattern                                       live bytes  peak bytes  alloc calls");
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    current_pattern = cases[i].pattern;
    allocation_calls = peak_bytes = fail_at = 0;
    struct hfre *re = NULL;
    int err = hfre_compile(cases[i].pattern, cases[i].flags, &re);
    CHECK(err == 0);
    if (err != 0) continue;
    size_t calls = allocation_calls;
    printf("%-45s %10zu  %10zu  %11zu\n",
           cases[i].pattern, live_bytes, peak_bytes, calls);
    int len = (int) strlen(cases[i].input);
    check_exec(re, cases[i].input, len, cases[i].expected);
    hfre_free(re);
    CHECK(live_bytes == 0);

    /* Failure of an optional accelerator may still compile successfully;
     * its fallback must match correctly and remain allocation-free. */
    for (size_t fail = 1; fail <= calls; fail++) {
      allocation_calls = peak_bytes = 0;
      fail_at = fail;
      struct hfre *sentinel = (struct hfre *) (uintptr_t) 1;
      re = sentinel;
      err = hfre_compile(cases[i].pattern, cases[i].flags, &re);
      if (err == 0) {
        check_exec(re, cases[i].input, len, cases[i].expected);
        hfre_free(re);
      } else {
        CHECK(err == HFRE_OUT_OF_MEMORY && re == sentinel);
      }
      CHECK(live_bytes == 0);
    }
  }
  printf("Allocation tests %s\n", failures ? "FAILED" : "PASSED");
  return failures ? EXIT_FAILURE : EXIT_SUCCESS;
}
