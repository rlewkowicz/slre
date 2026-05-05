/*
 * SLRE - small regex engine.
 *
 * Pipeline:
 *   pattern (UTF-8) -> bytecode -> Pike VM -> match
 *
 * The compile step parses the pattern into a flat instruction stream
 * (OP_RUNE / OP_CLASS / OP_ANY / OP_BOL / OP_EOL / OP_SAVE / OP_JMP /
 * OP_SPLIT / OP_MATCH) and computes prefilter metadata: whether the
 * regex is anchored at start of buffer, the minimum byte length of any
 * match, the set of bytes that may legally start a match, and a
 * pure-literal extraction when the entire regex is a fixed string.
 *
 * The exec step uses the prefilter metadata to skip non-candidate
 * start positions cheaply (memchr / first-byte set), then runs a Pike
 * VM that steps the input one UTF-8 code point at a time. Threads
 * carry capture offsets and are deduplicated per (PC, generation) so
 * a single step is O(code_len).
 *
 * Match semantics: leftmost-first, regex-order alternation priority,
 * greedy quantifiers prefer longer matches, lazy quantifiers prefer
 * shorter matches. Captures use start/end byte offsets into the input
 * buffer; unmatched captures are reported as { NULL, 0 }.
 *
 * Background: Russ Cox, "Regular expression matching: the virtual
 * machine approach". https://swtch.com/~rsc/regexp/regexp2.html
 */

#include "slre.h"

#include <ctype.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */

static inline int ascii_lower(int c) {
  return (c >= 'A' && c <= 'Z') ? c + 32 : c;
}

static inline int ascii_upper(int c) {
  return (c >= 'a' && c <= 'z') ? c - 32 : c;
}

static inline int is_ascii_letter(int c) {
  return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');
}

/* Decode one UTF-8 code point. *out_len gets the byte length consumed
 * (always >= 1 if max > 0; 0 if max == 0). Returns the code point, or
 * -1 if the bytes don't form valid UTF-8 (in which case *out_len = 1
 * so callers can re-sync byte-by-byte). */
static int utf8_decode(const unsigned char *p, int max, int *out_len) {
  if (max <= 0) { *out_len = 0; return -1; }
  unsigned c0 = p[0];
  if (c0 < 0x80) { *out_len = 1; return (int) c0; }
  unsigned need; unsigned cp;
  if      ((c0 & 0xE0) == 0xC0) { need = 2; cp = c0 & 0x1F; }
  else if ((c0 & 0xF0) == 0xE0) { need = 3; cp = c0 & 0x0F; }
  else if ((c0 & 0xF8) == 0xF0) { need = 4; cp = c0 & 0x07; }
  else                          { *out_len = 1; return -1; }
  if ((int) need > max) { *out_len = 1; return -1; }
  for (unsigned i = 1; i < need; i++) {
    unsigned ci = p[i];
    if ((ci & 0xC0) != 0x80) { *out_len = 1; return -1; }
    cp = (cp << 6) | (ci & 0x3F);
  }
  if ((need == 2 && cp < 0x80) ||
      (need == 3 && cp < 0x800) ||
      (need == 4 && cp < 0x10000) ||
      (cp >= 0xD800 && cp <= 0xDFFF) ||
      cp > 0x10FFFF) {
    *out_len = 1;
    return -1;
  }
  *out_len = (int) need;
  return (int) cp;
}

/* ------------------------------------------------------------------ */
/* Bytecode                                                            */
/* ------------------------------------------------------------------ */

enum {
  OP_MATCH = 1,
  OP_RUNE,        /* match exact code point ins.a */
  OP_RUNE_CI,     /* ASCII case-insensitive: ins.a is lowercased letter */
  OP_CLASS,       /* match byte against classes[ins.a] */
  OP_ANY,         /* match any single code point */
  OP_BOL,
  OP_EOL,
  OP_SAVE,        /* save current pos to caps[ins.a] */
  OP_JMP,         /* pc = ins.a */
  OP_SPLIT        /* try ins.a first, then ins.b */
};

struct insn {
  int32_t op;
  int32_t a;
  int32_t b;
};

struct sclass {
  uint64_t bits[4];   /* 256-bit byte bitmap (post-negation if any) */
};

/* VM thread record (declared up front so struct slre can size its
 * scratch buffers in terms of sizeof(struct thread)). */
struct thread {
  int pc;
  int *caps;     /* length n_save_slots */
};

static inline int sclass_test(const struct sclass *c, unsigned char b) {
  return (int) ((c->bits[b >> 6] >> (b & 63)) & 1ull);
}

static inline void sclass_set(struct sclass *c, unsigned char b) {
  c->bits[b >> 6] |= 1ull << (b & 63);
}

static inline void sclass_negate(struct sclass *c) {
  for (int i = 0; i < 4; i++) c->bits[i] = ~c->bits[i];
}

/* ------------------------------------------------------------------ */
/* Compiled regex                                                      */
/* ------------------------------------------------------------------ */

struct slre {
  int flags;
  int n_groups;          /* user-visible capture groups (excluding implicit 0) */
  int n_save_slots;      /* 2 * (n_groups + 1) */

  struct insn *code;
  int code_len;
  int code_cap;

  struct sclass *classes;
  int n_classes;
  int classes_cap;

  /* Prefilter metadata. */
  int anchored_bol;          /* every match must start at offset 0 */
  int min_match_len;         /* lower bound (in bytes) on a match */

  uint64_t first_byte[4];    /* set of possible first bytes (256-bit) */
  int has_first_byte_set;    /* 0 if unknown / unrestricted */
  int first_byte_count;      /* popcount of first_byte */
  unsigned char single_first_byte;
  /* Materialized list of candidate first bytes — used for the scan
   * loop's multi-memchr fast path when the set is small. */
  unsigned char first_byte_list[16];
  int first_byte_list_len;   /* 0 means "set too large for memchr scan" */

  /* Pure literal pattern (no metacharacters, no captures, no flags
   * beyond the optional ASCII fold). When set, slre_exec uses
   * memchr+memcmp instead of the VM. literal[] is bytewise compared,
   * after both sides are ASCII-folded if SLRE_IGNORE_CASE is set. */
  unsigned char *literal;       /* lowercased if icase, else verbatim */
  int literal_len;
  int is_pure_literal;

  /* Simple greedy single-class repetition: [CLASS]+ or [CLASS]*.
   * 0 = not applicable, 1 = plus, 2 = star. */
  int simple_class_kind;
  int simple_class_idx;

  /* Required literal substring: every successful match must contain
   * these exact bytes in order. Computed from the longest consecutive
   * run of OP_RUNE instructions that dominate OP_MATCH. Used as a
   * cheap reject filter (Boyer-Moore-Horspool search) and, when the
   * regex shape is .*LIT or .*?LIT with no captures, as a direct
   * accept oracle. */
  unsigned char *req_lit;
  int req_lit_len;
  /* When set, the required literal begins at the start of the match
   * (no consumers between PC=0 and the first literal RUNE). In that
   * case slre_exec can skip the per-position scan and seed the VM at
   * the literal's position directly. */
  int req_lit_is_prefix;
  unsigned char bmh_skip[256];   /* BMH bad-character shift table */
  /* Direct match shape: .*LIT (greedy) or .*?LIT (lazy) at the
   * top level, no captures. 0=none, 1=greedy, 2=lazy. */
  int dot_star_lit_kind;

  /* VM scratch: pre-allocated at compile time so slre_exec is
   * malloc-free on the hot path. The struct is therefore NOT
   * thread-safe; callers must use one struct slre per thread. */
  void *vm_clist;          /* struct thread *, length vm_max_per_step */
  void *vm_nlist;          /* struct thread *, length vm_max_per_step */
  int *vm_pool_a;          /* size vm_max_per_step * n_save_slots */
  int *vm_pool_b;
  int *vm_seen_gen;        /* size code_len */
  int *vm_best_caps;       /* size n_save_slots */
  int *vm_cap_ints;        /* size n_save_slots, used by slre_exec */
  /* Thompson (no-capture) lists: each entry is just a PC. */
  int *vm_th_a;            /* size vm_max_per_step */
  int *vm_th_b;
  int vm_max_per_step;
};

/* ------------------------------------------------------------------ */
/* Code emission                                                       */
/* ------------------------------------------------------------------ */

static int code_grow(struct slre *p) {
  int cap = p->code_cap == 0 ? 16 : p->code_cap * 2;
  struct insn *n = (struct insn *) realloc(p->code, (size_t) cap * sizeof(*n));
  if (n == NULL) return SLRE_OUT_OF_MEMORY;
  p->code = n;
  p->code_cap = cap;
  return 0;
}

static int emit(struct slre *p, int op, int a, int b) {
  if (p->code_len == p->code_cap) {
    int e = code_grow(p);
    if (e) return e;
  }
  p->code[p->code_len].op = op;
  p->code[p->code_len].a  = a;
  p->code[p->code_len].b  = b;
  return p->code_len++;
}

/* Insert a new instruction at position pos, shifting [pos..code_len)
 * forward by one slot. Patches every JMP/SPLIT target > pos by +1.
 *
 * Targets equal to pos are NOT shifted: the new instruction takes over
 * pos, so callers that want to address "the splice point itself"
 * (e.g. parse_alt chaining the next SPLIT into the previous SPLIT.b)
 * keep their reference. Targets that point past the splice point shift
 * forward to track the moved code. Internal references inside the
 * displaced region are >= pos+1 originally, so this rule preserves
 * them too. */
static int insert_at(struct slre *p, int pos, int op, int a, int b) {
  if (p->code_len == p->code_cap) {
    int e = code_grow(p);
    if (e) return e;
  }
  for (int i = 0; i < p->code_len; i++) {
    if (p->code[i].op == OP_JMP) {
      if (p->code[i].a > pos) p->code[i].a++;
    } else if (p->code[i].op == OP_SPLIT) {
      if (p->code[i].a > pos) p->code[i].a++;
      if (p->code[i].b > pos) p->code[i].b++;
    }
  }
  memmove(&p->code[pos + 1], &p->code[pos],
          (size_t)(p->code_len - pos) * sizeof(p->code[0]));
  p->code[pos].op = op;
  p->code[pos].a  = a;
  p->code[pos].b  = b;
  p->code_len++;
  return pos;
}

static int alloc_class(struct slre *p) {
  if (p->n_classes == p->classes_cap) {
    int cap = p->classes_cap == 0 ? 4 : p->classes_cap * 2;
    struct sclass *n = (struct sclass *)
      realloc(p->classes, (size_t) cap * sizeof(*n));
    if (n == NULL) return SLRE_OUT_OF_MEMORY;
    p->classes = n;
    p->classes_cap = cap;
  }
  int idx = p->n_classes++;
  memset(&p->classes[idx], 0, sizeof(p->classes[idx]));
  return idx;
}

/* ------------------------------------------------------------------ */
/* Parser                                                              */
/* ------------------------------------------------------------------ */

struct parser {
  const unsigned char *re;
  int re_len;
  int pos;
  int flags;
  int err;
  int group_index;     /* next group number to assign (group 0 implicit) */
  int top_level_alt;
};

static int parse_alt(struct parser *ps, struct slre *p);
static int parse_concat(struct parser *ps, struct slre *p);

static int peek(struct parser *ps) {
  return ps->pos < ps->re_len ? ps->re[ps->pos] : -1;
}

static int emit_rune(struct slre *p, int flags, int cp) {
  if ((flags & SLRE_IGNORE_CASE) && cp < 128 && is_ascii_letter(cp)) {
    return emit(p, OP_RUNE_CI, ascii_lower(cp), 0);
  }
  return emit(p, OP_RUNE, cp, 0);
}

static void class_add_byte(struct sclass *cls, int flags, int byte) {
  sclass_set(cls, (unsigned char) byte);
  if ((flags & SLRE_IGNORE_CASE) && is_ascii_letter(byte)) {
    int other = (byte >= 'A' && byte <= 'Z') ? byte + 32 : byte - 32;
    sclass_set(cls, (unsigned char) other);
  }
}

static void class_add_range(struct sclass *cls, int flags, int lo, int hi) {
  if (lo > hi) { int t = lo; lo = hi; hi = t; }
  for (int b = lo; b <= hi && b <= 0xFF; b++) {
    class_add_byte(cls, flags, b);
  }
}

static void class_add_perl(struct sclass *cls, int kind) {
  switch (kind) {
    case 'd':
      for (int b = '0'; b <= '9'; b++) sclass_set(cls, (unsigned char) b);
      break;
    case 's':
      sclass_set(cls, ' ');
      sclass_set(cls, '\t');
      sclass_set(cls, '\n');
      sclass_set(cls, '\v');
      sclass_set(cls, '\f');
      sclass_set(cls, '\r');
      break;
    case 'w':
      for (int b = '0'; b <= '9'; b++) sclass_set(cls, (unsigned char) b);
      for (int b = 'A'; b <= 'Z'; b++) sclass_set(cls, (unsigned char) b);
      for (int b = 'a'; b <= 'z'; b++) sclass_set(cls, (unsigned char) b);
      sclass_set(cls, '_');
      break;
  }
}

static int parse_hex_byte(struct parser *ps) {
  if (ps->pos + 2 > ps->re_len) {
    ps->err = SLRE_INVALID_METACHARACTER;
    return -1;
  }
  unsigned char h = ps->re[ps->pos];
  unsigned char l = ps->re[ps->pos + 1];
  if (!isxdigit(h) || !isxdigit(l)) {
    ps->err = SLRE_INVALID_METACHARACTER;
    return -1;
  }
  ps->pos += 2;
  int hv = (h >= 'a' ? h - 'a' + 10 : (h >= 'A' ? h - 'A' + 10 : h - '0'));
  int lv = (l >= 'a' ? l - 'a' + 10 : (l >= 'A' ? l - 'A' + 10 : l - '0'));
  return (hv << 4) | lv;
}

/* Consume one class element (character or escape) and return its
 * byte value (0..255). Returns -1 on error. */
static int parse_class_atom(struct parser *ps) {
  int c = peek(ps);
  if (c < 0) { ps->err = SLRE_INVALID_CHARACTER_SET; return -1; }
  if (c != '\\') { ps->pos++; return c; }
  ps->pos++;
  int e = peek(ps);
  if (e < 0) { ps->err = SLRE_INVALID_METACHARACTER; return -1; }
  ps->pos++;
  switch (e) {
    case 'x': return parse_hex_byte(ps);
    case 'n': return '\n';
    case 'r': return '\r';
    case 't': return '\t';
    case 'f': return '\f';
    case 'v': return '\v';
    case 'b': return '\b';
    case '\\': case '^': case '$': case '.': case '|':
    case '(':  case ')': case '[': case ']':
    case '*':  case '+': case '?': case '/': case '-':
      return e;
    case 'p': case 'P':
      ps->err = SLRE_INVALID_UNICODE_PROPERTY;
      return -1;
    default:
      /* Perl shorthand inside a class — handled separately in
       * parse_class. */
      ps->err = SLRE_INVALID_METACHARACTER;
      return -1;
  }
}

/* Parse a class body starting just after '['. Emits one OP_CLASS. */
static int parse_class(struct parser *ps, struct slre *p) {
  int idx = alloc_class(p);
  if (idx < 0) { ps->err = SLRE_OUT_OF_MEMORY; return -1; }
  struct sclass *cls = &p->classes[idx];

  int negated = 0;
  if (peek(ps) == '^') { negated = 1; ps->pos++; }

  if (peek(ps) == ']' || peek(ps) < 0) {
    ps->err = SLRE_INVALID_CHARACTER_SET;
    return -1;
  }

  while (peek(ps) != ']') {
    int c = peek(ps);
    if (c < 0) { ps->err = SLRE_INVALID_CHARACTER_SET; return -1; }

    /* Perl shorthand classes inside [...] — handled specially since
     * they expand to a set rather than a single byte. */
    if (c == '\\' && ps->pos + 1 < ps->re_len) {
      int e = ps->re[ps->pos + 1];
      if (e == 'd' || e == 's' || e == 'w') {
        ps->pos += 2;
        class_add_perl(cls, e);
        continue;
      }
      if (e == 'D' || e == 'S' || e == 'W') {
        ps->pos += 2;
        struct sclass tmp; memset(&tmp, 0, sizeof(tmp));
        class_add_perl(&tmp, e + ('a' - 'A'));
        for (int i = 0; i < 4; i++) cls->bits[i] |= ~tmp.bits[i];
        continue;
      }
    }

    int lo = parse_class_atom(ps);
    if (lo < 0) return -1;

    /* Optional range. */
    if (peek(ps) == '-' && ps->pos + 1 < ps->re_len &&
        ps->re[ps->pos + 1] != ']') {
      ps->pos++; /* consume '-' */
      int hi = parse_class_atom(ps);
      if (hi < 0) return -1;
      class_add_range(cls, ps->flags, lo, hi);
    } else {
      class_add_byte(cls, ps->flags, lo);
    }
  }
  ps->pos++; /* consume ']' */

  if (negated) sclass_negate(cls);
  emit(p, OP_CLASS, idx, 0);
  return 0;
}

/* Apply postfix quantifier to atom code at [start_pc, code_len). */
static int apply_quantifier(struct parser *ps, struct slre *p,
                            int start_pc, int q, int lazy) {
  int end_pc = p->code_len;
  if (start_pc == end_pc) {
    ps->err = SLRE_UNEXPECTED_QUANTIFIER;
    return -1;
  }

  if (q == '?') {
    int a = start_pc + 1;        /* body */
    int b = end_pc + 1;          /* after */
    if (lazy) { int t = a; a = b; b = t; }
    if (insert_at(p, start_pc, OP_SPLIT, a, b) < 0) {
      ps->err = SLRE_OUT_OF_MEMORY; return -1;
    }
    return 0;
  }
  if (q == '*') {
    int a = start_pc + 1;        /* body */
    int b = end_pc + 2;          /* after (SPLIT inserted, JMP appended) */
    if (lazy) { int t = a; a = b; b = t; }
    if (insert_at(p, start_pc, OP_SPLIT, a, b) < 0) {
      ps->err = SLRE_OUT_OF_MEMORY; return -1;
    }
    if (emit(p, OP_JMP, start_pc, 0) < 0) {
      ps->err = SLRE_OUT_OF_MEMORY; return -1;
    }
    return 0;
  }
  if (q == '+') {
    int after = end_pc + 1;
    int a = start_pc;
    int b = after;
    if (lazy) { int t = a; a = b; b = t; }
    if (emit(p, OP_SPLIT, a, b) < 0) {
      ps->err = SLRE_OUT_OF_MEMORY; return -1;
    }
    return 0;
  }
  ps->err = SLRE_INTERNAL_ERROR;
  return -1;
}

static int parse_atom(struct parser *ps, struct slre *p) {
  int c = peek(ps);
  if (c < 0) return 0;
  if (c == '|' || c == ')') return 0;

  int start_pc = p->code_len;

  if (c == '(') {
    ps->pos++;
    int gi = ps->group_index++;
    if (emit(p, OP_SAVE, 2 * gi, 0) < 0) {
      ps->err = SLRE_OUT_OF_MEMORY; return -1;
    }
    if (parse_alt(ps, p) < 0) return -1;
    if (peek(ps) != ')') {
      ps->err = SLRE_UNBALANCED_BRACKETS; return -1;
    }
    ps->pos++;
    if (emit(p, OP_SAVE, 2 * gi + 1, 0) < 0) {
      ps->err = SLRE_OUT_OF_MEMORY; return -1;
    }
  } else if (c == '[') {
    ps->pos++;
    if (parse_class(ps, p) < 0) return -1;
  } else if (c == '.') {
    ps->pos++;
    emit(p, OP_ANY, 0, 0);
  } else if (c == '^') {
    ps->pos++;
    emit(p, OP_BOL, 0, 0);
  } else if (c == '$') {
    ps->pos++;
    emit(p, OP_EOL, 0, 0);
  } else if (c == '\\') {
    ps->pos++;
    int e = peek(ps);
    if (e < 0) { ps->err = SLRE_INVALID_METACHARACTER; return -1; }
    ps->pos++;
    switch (e) {
      case 'd': case 's': case 'w': {
        int idx = alloc_class(p);
        if (idx < 0) { ps->err = SLRE_OUT_OF_MEMORY; return -1; }
        class_add_perl(&p->classes[idx], e);
        emit(p, OP_CLASS, idx, 0);
        break;
      }
      case 'D': case 'S': case 'W': {
        int idx = alloc_class(p);
        if (idx < 0) { ps->err = SLRE_OUT_OF_MEMORY; return -1; }
        struct sclass tmp; memset(&tmp, 0, sizeof(tmp));
        class_add_perl(&tmp, e + ('a' - 'A'));
        for (int i = 0; i < 4; i++) p->classes[idx].bits[i] = ~tmp.bits[i];
        emit(p, OP_CLASS, idx, 0);
        break;
      }
      case 'x': {
        int hb = parse_hex_byte(ps);
        if (hb < 0) return -1;
        emit(p, OP_RUNE, hb, 0);
        break;
      }
      case 'p': case 'P':
        ps->err = SLRE_INVALID_UNICODE_PROPERTY;
        return -1;
      case 'n': emit_rune(p, ps->flags, '\n'); break;
      case 'r': emit_rune(p, ps->flags, '\r'); break;
      case 't': emit_rune(p, ps->flags, '\t'); break;
      case 'f': emit_rune(p, ps->flags, '\f'); break;
      case 'v': emit_rune(p, ps->flags, '\v'); break;
      case 'b': emit_rune(p, ps->flags, '\b'); break;
      case '\\': case '^': case '$': case '.': case '|':
      case '(':  case ')': case '[': case ']':
      case '*':  case '+': case '?': case '/': case '-':
        emit_rune(p, ps->flags, e);
        break;
      default:
        ps->err = SLRE_INVALID_METACHARACTER;
        return -1;
    }
  } else if (c == '*' || c == '+' || c == '?') {
    ps->err = SLRE_UNEXPECTED_QUANTIFIER;
    return -1;
  } else {
    /* Literal byte or UTF-8 leading byte. */
    if (c < 0x80) {
      ps->pos++;
      emit_rune(p, ps->flags, c);
    } else {
      int dec_len;
      int cp = utf8_decode(ps->re + ps->pos, ps->re_len - ps->pos, &dec_len);
      if (cp < 0) { ps->err = SLRE_INVALID_UTF8; return -1; }
      ps->pos += dec_len;
      emit(p, OP_RUNE, cp, 0);
    }
  }

  /* Postfix quantifier? */
  int q = peek(ps);
  if (q == '*' || q == '+' || q == '?') {
    ps->pos++;
    int lazy = 0;
    if (peek(ps) == '?') { lazy = 1; ps->pos++; }
    if (apply_quantifier(ps, p, start_pc, q, lazy) < 0) return -1;
  }

  return 0;
}

static int parse_concat(struct parser *ps, struct slre *p) {
  while (1) {
    int c = peek(ps);
    if (c < 0 || c == '|' || c == ')') return 0;
    if (parse_atom(ps, p) < 0) return -1;
  }
}

/*
 * Right-recursive alternation: for A|B|C we generate
 *   SPLIT A, rest
 *   <A>
 *   JMP end
 *   rest: SPLIT B, C
 *   <B>
 *   JMP end
 *   <C>
 *   end:
 */
static int parse_alt(struct parser *ps, struct slre *p) {
  int L0 = p->code_len;
  if (parse_concat(ps, p) < 0) return -1;
  if (peek(ps) != '|') return 0;
  ps->top_level_alt = 1;
  while (peek(ps) == '|') {
    ps->pos++;
    if (insert_at(p, L0, OP_SPLIT, L0 + 1, /*tmp*/ 0) < 0) {
      ps->err = SLRE_OUT_OF_MEMORY; return -1;
    }
    int jmp_pc = emit(p, OP_JMP, /*tmp*/ 0, 0);
    if (jmp_pc < 0) { ps->err = SLRE_OUT_OF_MEMORY; return -1; }
    int right_start = p->code_len;
    if (parse_concat(ps, p) < 0) return -1;
    int end = p->code_len;
    p->code[L0].b = right_start;
    p->code[jmp_pc].a = end;
    L0 = right_start;
  }
  return 0;
}

/* ------------------------------------------------------------------ */
/* Post-parse analysis                                                 */
/* ------------------------------------------------------------------ */

/*
 * Walk the program collecting bytes that may legally appear at the
 * start of a match, plus a lower bound on match byte length.
 *
 * Returns the popcount of the first-byte set on success, -1 if the
 * set is unrestricted (e.g. the regex begins with OP_ANY or a class
 * with non-ASCII impact).
 */
static int compute_first_set(struct slre *p, uint64_t out[4],
                             int *out_min_len) {
  unsigned char *visited = (unsigned char *) calloc((size_t) p->code_len, 1);
  int *stack_pc = (int *) malloc((size_t) p->code_len * sizeof(int));
  int *stack_d  = (int *) malloc((size_t) p->code_len * sizeof(int));
  if (visited == NULL || stack_pc == NULL || stack_d == NULL) {
    free(visited); free(stack_pc); free(stack_d);
    *out_min_len = 0;
    return -1;
  }
  int sp = 0;
  stack_pc[sp] = 0; stack_d[sp] = 0; sp++;
  memset(out, 0, 4 * sizeof(uint64_t));
  int min_len = INT32_MAX;
  int saw_unbounded = 0;

  while (sp > 0) {
    sp--;
    int pc = stack_pc[sp];
    int d  = stack_d[sp];
    if (pc < 0 || pc >= p->code_len) continue;
    if (visited[pc]) continue;
    visited[pc] = 1;
    struct insn ins = p->code[pc];
    switch (ins.op) {
      case OP_MATCH:
        if (d < min_len) min_len = d;
        break;
      case OP_SAVE:
      case OP_BOL:
      case OP_EOL:
        stack_pc[sp] = pc + 1; stack_d[sp] = d; sp++;
        break;
      case OP_JMP:
        stack_pc[sp] = ins.a; stack_d[sp] = d; sp++;
        break;
      case OP_SPLIT:
        stack_pc[sp] = ins.a; stack_d[sp] = d; sp++;
        if (ins.b >= 0 && ins.b < p->code_len && !visited[ins.b]) {
          stack_pc[sp] = ins.b; stack_d[sp] = d; sp++;
        }
        break;
      case OP_RUNE: {
        int cp = ins.a;
        if (cp < 128) {
          out[cp >> 6] |= 1ull << (cp & 63);
        } else {
          /* multi-byte UTF-8: lead byte is determined by code point. */
          unsigned char lead;
          if (cp < 0x800)        lead = (unsigned char)(0xC0 | (cp >> 6));
          else if (cp < 0x10000) lead = (unsigned char)(0xE0 | (cp >> 12));
          else                   lead = (unsigned char)(0xF0 | (cp >> 18));
          out[lead >> 6] |= 1ull << (lead & 63);
        }
        if (d + 1 < min_len) min_len = d + 1;
        break;
      }
      case OP_RUNE_CI: {
        unsigned lo = (unsigned) ins.a;
        unsigned hi = is_ascii_letter((int) lo)
                      ? (unsigned) ascii_upper((int) lo) : lo;
        out[lo >> 6] |= 1ull << (lo & 63);
        out[hi >> 6] |= 1ull << (hi & 63);
        if (d + 1 < min_len) min_len = d + 1;
        break;
      }
      case OP_CLASS: {
        const struct sclass *cls = &p->classes[ins.a];
        int has_any = 0;
        for (int i = 0; i < 4; i++) {
          out[i] |= cls->bits[i];
          if (cls->bits[i] != 0) has_any = 1;
        }
        if (!has_any) {
          /* class is empty -> nothing matches; min_len stays infinite */
        }
        if (d + 1 < min_len) min_len = d + 1;
        break;
      }
      case OP_ANY:
        saw_unbounded = 1;
        if (d + 1 < min_len) min_len = d + 1;
        break;
    }
  }

  free(visited); free(stack_pc); free(stack_d);
  if (min_len == INT32_MAX) min_len = 0;
  *out_min_len = min_len;
  if (saw_unbounded) return -1;
  int popcnt = 0;
  for (int i = 0; i < 4; i++) {
    uint64_t v = out[i];
    while (v) { v &= v - 1; popcnt++; }
  }
  return popcnt;
}

/*
 * Compute the longest required-literal substring: a sequence of
 * consecutive OP_RUNE instructions, all of which dominate OP_MATCH.
 *
 * A PC dominates MATCH iff every path from PC=0 to OP_MATCH visits
 * it. We compute domination by an O(N^2) reachability test: for each
 * candidate PC, run a BFS from 0 in the bytecode graph that skips
 * the candidate; if MATCH becomes unreachable, the PC dominates.
 *
 * Among the dominating PCs we look for the longest run of
 * consecutive OP_RUNE ops (case-sensitive only — case-insensitive
 * letters complicate byte-level search, so we exclude them). The
 * literal is encoded as a UTF-8 byte string.
 */
static int reaches_match_skipping(const struct slre *p, int skip,
                                  unsigned char *seen, int *stack) {
  /* Returns 1 if any OP_MATCH is reachable from PC=0 without
   * traversing PC=skip. Caller provides seen[] and stack[] scratch
   * sized code_len. */
  memset(seen, 0, (size_t) p->code_len);
  int top = 0;
  if (0 != skip) { stack[top++] = 0; seen[0] = 1; }
  while (top > 0) {
    int pc = stack[--top];
    struct insn ins = p->code[pc];
    if (ins.op == OP_MATCH) return 1;
    /* push successors */
    int succs[2]; int nsucc = 0;
    switch (ins.op) {
      case OP_JMP:
        succs[nsucc++] = ins.a;
        break;
      case OP_SPLIT:
        succs[nsucc++] = ins.a;
        succs[nsucc++] = ins.b;
        break;
      default:
        succs[nsucc++] = pc + 1;
        break;
    }
    for (int i = 0; i < nsucc; i++) {
      int s = succs[i];
      if (s < 0 || s >= p->code_len) continue;
      if (s == skip) continue;
      if (seen[s]) continue;
      seen[s] = 1;
      stack[top++] = s;
    }
  }
  return 0;
}

static void compute_required_literal(struct slre *p) {
  if (p->code_len <= 0) return;
  unsigned char *seen = (unsigned char *) malloc((size_t) p->code_len);
  int *stack = (int *) malloc((size_t) p->code_len * sizeof(int));
  unsigned char *dominates = (unsigned char *) calloc((size_t) p->code_len, 1);
  if (seen == NULL || stack == NULL || dominates == NULL) {
    free(seen); free(stack); free(dominates);
    return;
  }
  for (int pc = 0; pc < p->code_len; pc++) {
    /* PC=0 itself is trivially required if MATCH is reachable, but
     * skipping it disconnects everything. We only care about RUNEs. */
    if (p->code[pc].op != OP_RUNE) continue;
    if (!reaches_match_skipping(p, pc, seen, stack)) {
      dominates[pc] = 1;
    }
  }
  /* Find longest consecutive RUNE run. */
  int best_start = -1, best_len = 0;
  int cur_start = -1, cur_len = 0;
  for (int pc = 0; pc < p->code_len; pc++) {
    if (dominates[pc] && p->code[pc].op == OP_RUNE) {
      if (cur_start < 0) { cur_start = pc; cur_len = 0; }
      cur_len++;
    } else {
      if (cur_len > best_len) {
        best_len = cur_len;
        best_start = cur_start;
      }
      cur_start = -1;
      cur_len = 0;
    }
  }
  if (cur_len > best_len) {
    best_len = cur_len;
    best_start = cur_start;
  }
  free(seen); free(stack); free(dominates);

  if (best_len < 2) return;  /* not worth it; first-byte filter is enough */

  /* Encode the rune sequence as UTF-8 bytes. */
  int bytes = 0;
  for (int i = 0; i < best_len; i++) {
    int cp = p->code[best_start + i].a;
    if (cp < 0x80) bytes += 1;
    else if (cp < 0x800) bytes += 2;
    else if (cp < 0x10000) bytes += 3;
    else bytes += 4;
  }
  unsigned char *lit = (unsigned char *) malloc((size_t) bytes);
  if (lit == NULL) return;
  int off = 0;
  for (int i = 0; i < best_len; i++) {
    int cp = p->code[best_start + i].a;
    if (cp < 0x80) {
      lit[off++] = (unsigned char) cp;
    } else if (cp < 0x800) {
      lit[off++] = (unsigned char) (0xC0 | (cp >> 6));
      lit[off++] = (unsigned char) (0x80 | (cp & 0x3F));
    } else if (cp < 0x10000) {
      lit[off++] = (unsigned char) (0xE0 | (cp >> 12));
      lit[off++] = (unsigned char) (0x80 | ((cp >> 6) & 0x3F));
      lit[off++] = (unsigned char) (0x80 | (cp & 0x3F));
    } else {
      lit[off++] = (unsigned char) (0xF0 | (cp >> 18));
      lit[off++] = (unsigned char) (0x80 | ((cp >> 12) & 0x3F));
      lit[off++] = (unsigned char) (0x80 | ((cp >> 6) & 0x3F));
      lit[off++] = (unsigned char) (0x80 | (cp & 0x3F));
    }
  }
  p->req_lit = lit;
  p->req_lit_len = off;
  /* Is the literal at a fixed offset 0 from match start? It is iff
   * the path from PC=0 to best_start consists of nothing but SAVE
   * instructions. */
  p->req_lit_is_prefix = 1;
  for (int pc = 0; pc < best_start; pc++) {
    if (p->code[pc].op != OP_SAVE) {
      p->req_lit_is_prefix = 0;
      break;
    }
  }
  /* BMH bad-character shift table. */
  for (int i = 0; i < 256; i++) p->bmh_skip[i] = (unsigned char) off;
  for (int i = 0; i < off - 1; i++) {
    int shift = off - 1 - i;
    if (shift > 255) shift = 255;
    p->bmh_skip[lit[i]] = (unsigned char) shift;
  }
}

/* Detect the .*LIT (greedy) or .*?LIT (lazy) shape, where LIT is
 * exactly the required literal computed above. When recognized, the
 * match end is determined directly by the literal search:
 *   greedy: last occurrence + lit_len
 *   lazy:   first occurrence + lit_len
 * and the match start is 0 (offset 0 of the buffer), since .* / .*?
 * can absorb anything between offset 0 and the literal. */
static void compute_dot_star_lit(struct slre *p) {
  /* Shape with greedy .*: SAVE 0(0); SPLIT(2,4)(1); ANY(2); JMP 1(3);
   *   <lit RUNE...>; SAVE 1; MATCH.
   * Shape with lazy  .*?: SAVE 0(0); SPLIT(4,2)(1); ANY(2); JMP 1(3);
   *   <lit RUNE...>; SAVE 1; MATCH.
   */
  if (p->n_groups != 0) return;
  if (p->req_lit_len < 1) return;
  if (p->code_len < 6) return;
  if (p->code[0].op != OP_SAVE || p->code[0].a != 0) return;
  if (p->code[1].op != OP_SPLIT) return;
  if (p->code[2].op != OP_ANY) return;
  if (p->code[3].op != OP_JMP || p->code[3].a != 1) return;
  if (p->code[p->code_len - 1].op != OP_MATCH) return;
  if (p->code[p->code_len - 2].op != OP_SAVE
      || p->code[p->code_len - 2].a != 1) return;
  /* All instructions between PC=4 and PC=code_len-2 must be RUNE
   * (the literal). And the RUNEs must MATCH the bytes already in
   * req_lit (since req_lit was computed from this very dominator
   * chain). */
  int n = p->code_len - 2 - 4;
  if (n <= 0) return;
  for (int i = 0; i < n; i++) {
    if (p->code[4 + i].op != OP_RUNE) return;
  }
  /* Greedy if SPLIT.a points at body=2, lazy if SPLIT.a points at
   * after=4. */
  if (p->code[1].a == 2 && p->code[1].b == 4) p->dot_star_lit_kind = 1;
  else if (p->code[1].a == 4 && p->code[1].b == 2) p->dot_star_lit_kind = 2;
}

/* Detect a pure-literal regex (no metas, no quantifiers, no groups)
 * and record the byte sequence for fast memchr/memcmp matching. */
static void compute_pure_literal(struct slre *p) {
  if (p->n_groups > 0) return;
  if (p->code_len < 3) return;
  if (p->code[0].op != OP_SAVE || p->code[0].a != 0) return;
  if (p->code[p->code_len - 1].op != OP_MATCH) return;
  if (p->code[p->code_len - 2].op != OP_SAVE
      || p->code[p->code_len - 2].a != 1) return;

  int n = p->code_len - 3;
  int icase = 0;
  /* All inner ops must be OP_RUNE (any rune) or OP_RUNE_CI (icase
   * letters). For multi-byte runes we expand to UTF-8 bytes below. */
  int total_bytes = 0;
  for (int i = 1; i <= n; i++) {
    int op = p->code[i].op;
    if (op == OP_RUNE_CI) { icase = 1; total_bytes += 1; continue; }
    if (op != OP_RUNE) return;  /* not pure */
    int cp = p->code[i].a;
    if (cp < 0x80)        total_bytes += 1;
    else if (cp < 0x800)  total_bytes += 2;
    else if (cp < 0x10000) total_bytes += 3;
    else                   total_bytes += 4;
  }
  if (total_bytes == 0) return;  /* empty pattern */
  unsigned char *lit = (unsigned char *) malloc((size_t) total_bytes);
  if (lit == NULL) return;
  int off = 0;
  for (int i = 1; i <= n; i++) {
    int op = p->code[i].op;
    int cp = p->code[i].a;
    if (op == OP_RUNE_CI) {
      lit[off++] = (unsigned char) cp;        /* already lowercase */
      continue;
    }
    /* OP_RUNE: encode as UTF-8 bytes. For icase compares we lowercase
     * ASCII bytes here too so the buffer is uniform. */
    int b0 = cp;
    if (icase && b0 < 128 && is_ascii_letter(b0)) b0 = ascii_lower(b0);
    if (cp < 0x80) {
      lit[off++] = (unsigned char) b0;
    } else if (cp < 0x800) {
      lit[off++] = (unsigned char) (0xC0 | (cp >> 6));
      lit[off++] = (unsigned char) (0x80 | (cp & 0x3F));
    } else if (cp < 0x10000) {
      lit[off++] = (unsigned char) (0xE0 | (cp >> 12));
      lit[off++] = (unsigned char) (0x80 | ((cp >> 6) & 0x3F));
      lit[off++] = (unsigned char) (0x80 | (cp & 0x3F));
    } else {
      lit[off++] = (unsigned char) (0xF0 | (cp >> 18));
      lit[off++] = (unsigned char) (0x80 | ((cp >> 12) & 0x3F));
      lit[off++] = (unsigned char) (0x80 | ((cp >> 6) & 0x3F));
      lit[off++] = (unsigned char) (0x80 | (cp & 0x3F));
    }
  }
  p->literal = lit;
  p->literal_len = off;
  p->is_pure_literal = 1;
  if (icase) p->flags |= SLRE_IGNORE_CASE;
}

/* ------------------------------------------------------------------ */
/* Compile                                                             */
/* ------------------------------------------------------------------ */

void slre_free(struct slre *re) {
  if (re == NULL) return;
  free(re->code);
  free(re->classes);
  free(re->literal);
  free(re->req_lit);
  free(re->vm_clist);
  free(re->vm_nlist);
  free(re->vm_pool_a);
  free(re->vm_pool_b);
  free(re->vm_seen_gen);
  free(re->vm_best_caps);
  free(re->vm_cap_ints);
  free(re->vm_th_a);
  free(re->vm_th_b);
  free(re);
}

int slre_capture_count(const struct slre *re) {
  return re == NULL ? 0 : re->n_groups;
}

int slre_compile(const char *pattern, int flags, struct slre **out) {
  if (pattern == NULL || out == NULL) return SLRE_INVALID_ARGUMENT;
  struct slre *p = (struct slre *) calloc(1, sizeof(*p));
  if (p == NULL) return SLRE_OUT_OF_MEMORY;
  p->flags = flags;

  struct parser ps;
  memset(&ps, 0, sizeof(ps));
  ps.re = (const unsigned char *) pattern;
  ps.re_len = (int) strlen(pattern);
  ps.flags = flags;
  ps.group_index = 1;

  if (emit(p, OP_SAVE, 0, 0) < 0) { slre_free(p); return SLRE_OUT_OF_MEMORY; }
  if (parse_alt(&ps, p) < 0) {
    int err = ps.err ? ps.err : SLRE_INTERNAL_ERROR;
    slre_free(p);
    return err;
  }
  if (ps.pos != ps.re_len) {
    slre_free(p);
    return SLRE_UNBALANCED_BRACKETS;
  }
  if (emit(p, OP_SAVE, 1, 0) < 0) { slre_free(p); return SLRE_OUT_OF_MEMORY; }
  if (emit(p, OP_MATCH, 0, 0) < 0) { slre_free(p); return SLRE_OUT_OF_MEMORY; }

  p->n_groups = ps.group_index - 1;
  p->n_save_slots = 2 * (p->n_groups + 1);

  /* anchored_bol: regex starts with OP_BOL (after SAVE), no top-level
   * alternation. */
  p->anchored_bol = 0;
  if (!ps.top_level_alt) {
    for (int i = 0; i < p->code_len; i++) {
      if (p->code[i].op == OP_SAVE) continue;
      if (p->code[i].op == OP_BOL) p->anchored_bol = 1;
      break;
    }
  }

  uint64_t fb[4] = { 0 };
  int min_len = 0;
  int n = compute_first_set(p, fb, &min_len);
  p->min_match_len = min_len;
  /* The first-byte set is only valid when every reachable accept path
   * consumes at least one byte. min_len == 0 means an empty-string
   * path exists, in which case any starting position is a candidate
   * and the prefilter would falsely skip valid matches. */
  if (n > 0 && min_len > 0) {
    memcpy(p->first_byte, fb, sizeof(fb));
    p->has_first_byte_set = 1;
    p->first_byte_count = n;
    if (n == 1) {
      for (int i = 0; i < 256; i++) {
        if (fb[i >> 6] & (1ull << (i & 63))) {
          p->single_first_byte = (unsigned char) i;
          break;
        }
      }
    }
    /* Materialize the candidate list when the set is small enough
     * for a multi-memchr scan to outperform a per-byte bitmap test.
     * The threshold is set so that the cost of N memchr calls beats
     * the per-byte loop on typical buffers. */
    if (n <= 16) {
      int k = 0;
      for (int i = 0; i < 256; i++) {
        if (fb[i >> 6] & (1ull << (i & 63))) {
          p->first_byte_list[k++] = (unsigned char) i;
        }
      }
      p->first_byte_list_len = k;
    }
  }

  compute_pure_literal(p);
  compute_required_literal(p);
  compute_dot_star_lit(p);

  /* Simple greedy class-repeat detection. [CLASS]+ compiles to:
   *   0: SAVE 0
   *   1: CLASS idx
   *   2: SPLIT 1, 3      (greedy: loop body or escape)
   *   3: SAVE 1
   *   4: MATCH
   * [CLASS]* compiles to:
   *   0: SAVE 0
   *   1: SPLIT 2, 4      (greedy: enter or skip)
   *   2: CLASS idx
   *   3: JMP 1
   *   4: SAVE 1
   *   5: MATCH
   */
  if (p->n_groups == 0 && p->code_len == 5 &&
      p->code[0].op == OP_SAVE && p->code[0].a == 0 &&
      p->code[1].op == OP_CLASS &&
      p->code[2].op == OP_SPLIT && p->code[2].a == 1 && p->code[2].b == 3 &&
      p->code[3].op == OP_SAVE && p->code[3].a == 1 &&
      p->code[4].op == OP_MATCH) {
    p->simple_class_kind = 1;
    p->simple_class_idx = p->code[1].a;
  } else if (p->n_groups == 0 && p->code_len == 6 &&
      p->code[0].op == OP_SAVE && p->code[0].a == 0 &&
      p->code[1].op == OP_SPLIT && p->code[1].a == 2 && p->code[1].b == 4 &&
      p->code[2].op == OP_CLASS &&
      p->code[3].op == OP_JMP && p->code[3].a == 1 &&
      p->code[4].op == OP_SAVE && p->code[4].a == 1 &&
      p->code[5].op == OP_MATCH) {
    p->simple_class_kind = 2;
    p->simple_class_idx = p->code[2].a;
  }

  /* Pre-allocate VM scratch buffers. */
  p->vm_max_per_step = p->code_len * 2 + 8;
  size_t thread_bytes = (size_t) p->vm_max_per_step * sizeof(struct thread);
  size_t pool_ints = (size_t) p->vm_max_per_step * (size_t) p->n_save_slots;
  p->vm_clist     = malloc(thread_bytes);
  p->vm_nlist     = malloc(thread_bytes);
  p->vm_pool_a    = (int *) malloc(pool_ints * sizeof(int));
  p->vm_pool_b    = (int *) malloc(pool_ints * sizeof(int));
  p->vm_seen_gen  = (int *) calloc((size_t) p->code_len, sizeof(int));
  p->vm_best_caps = (int *) malloc((size_t) p->n_save_slots * sizeof(int));
  p->vm_cap_ints  = (int *) malloc((size_t) p->n_save_slots * sizeof(int));
  p->vm_th_a      = (int *) malloc((size_t) p->vm_max_per_step * sizeof(int));
  p->vm_th_b      = (int *) malloc((size_t) p->vm_max_per_step * sizeof(int));
  if (p->vm_clist == NULL || p->vm_nlist == NULL ||
      p->vm_pool_a == NULL || p->vm_pool_b == NULL ||
      p->vm_seen_gen == NULL || p->vm_best_caps == NULL ||
      p->vm_cap_ints == NULL || p->vm_th_a == NULL || p->vm_th_b == NULL) {
    slre_free(p);
    return SLRE_OUT_OF_MEMORY;
  }

  *out = p;
  return 0;
}

/* ------------------------------------------------------------------ */
/* Pike VM                                                             */
/* ------------------------------------------------------------------ */

struct threadlist {
  struct thread *t;
  int n;
};

struct execstate {
  const struct slre *re;
  const unsigned char *buf;
  int buf_len;
  int *cap_pool;
  int cap_pool_used;
  int cap_stride;
  int *seen_gen;
  int gen;
};

static int *cap_alloc(struct execstate *es) {
  int *p = es->cap_pool + es->cap_pool_used;
  es->cap_pool_used += es->cap_stride;
  return p;
}

static void cap_init(int *caps, int n) {
  for (int i = 0; i < n; i++) caps[i] = -1;
}

static void cap_copy(int *dst, const int *src, int n) {
  memcpy(dst, src, (size_t) n * sizeof(int));
}

/* ------------------------------------------------------------------ */
/* Thompson VM (no-capture)                                            */
/* ------------------------------------------------------------------ */

/* Add a PC to a Thompson thread list. SAVE is a no-op (no captures).
 * Per-step (pc, gen) dedup, leftmost-first by add order. */
static void add_thompson(const struct slre *re, int *list, int *n,
                         int pc, int sp, int gen, int *seen_gen,
                         int buf_len) {
  while (1) {
    if (pc < 0 || pc >= re->code_len) return;
    if (seen_gen[pc] == gen) return;
    seen_gen[pc] = gen;
    struct insn ins = re->code[pc];
    switch (ins.op) {
      case OP_JMP:
        pc = ins.a;
        continue;
      case OP_SPLIT:
        add_thompson(re, list, n, ins.a, sp, gen, seen_gen, buf_len);
        pc = ins.b;
        continue;
      case OP_SAVE:
        pc = pc + 1;
        continue;
      case OP_BOL:
        if (sp != 0) return;
        pc = pc + 1;
        continue;
      case OP_EOL:
        if (sp != buf_len) return;
        pc = pc + 1;
        continue;
      default:
        list[(*n)++] = pc;
        return;
    }
  }
}

/* Run the no-capture Thompson VM. On success returns the byte offset
 * just past the match. Caller knows the match start (== start_off for
 * leftmost matches). */
static int run_thompson(struct slre *re, const unsigned char *buf,
                        int buf_len, int start_off) {
  int code_len = re->code_len;
  int *clist = re->vm_th_a;
  int *nlist = re->vm_th_b;
  int n_c = 0, n_n = 0;
  int *seen_gen = re->vm_seen_gen;
  memset(seen_gen, 0, (size_t) code_len * sizeof(int));
  int gen = 1;

  add_thompson(re, clist, &n_c, 0, start_off, gen, seen_gen, buf_len);

  int has_match = 0;
  int best_end = -1;
  int sp = start_off;

  while (1) {
    if (n_c == 0) break;

    int rune_len = 0;
    int cp = -1;
    if (sp < buf_len) {
      cp = utf8_decode(buf + sp, buf_len - sp, &rune_len);
      if (rune_len <= 0) rune_len = 1;
    }

    gen++;
    n_n = 0;

    for (int ti = 0; ti < n_c; ti++) {
      int pc = clist[ti];
      struct insn ins = re->code[pc];

      if (ins.op == OP_MATCH) {
        has_match = 1;
        best_end = sp;
        break;  /* lower-priority threads in clist are killed */
      }
      if (cp < 0) continue;

      int matched = 0;
      switch (ins.op) {
        case OP_RUNE:
          matched = (cp == ins.a);
          break;
        case OP_RUNE_CI:
          matched = (cp < 128 && ascii_lower(cp) == ins.a);
          break;
        case OP_CLASS:
          matched = sclass_test(&re->classes[ins.a], (unsigned char) buf[sp]);
          break;
        case OP_ANY:
          matched = 1;
          break;
        default:
          break;
      }
      if (matched) {
        add_thompson(re, nlist, &n_n, pc + 1, sp + rune_len,
                     gen, seen_gen, buf_len);
      }
    }

    /* Swap. */
    int *tmp = clist; clist = nlist; nlist = tmp;
    n_c = n_n; n_n = 0;

    if (rune_len == 0) break;
    sp += rune_len;
  }

  /* Drain: any remaining MATCH thread fires at the final sp. */
  if (!has_match) {
    for (int ti = 0; ti < n_c; ti++) {
      if (re->code[clist[ti]].op == OP_MATCH) {
        has_match = 1;
        best_end = sp;
        break;
      }
    }
  }

  return has_match ? best_end : SLRE_NO_MATCH;
}

/* ------------------------------------------------------------------ */
/* Pike VM (with captures)                                             */
/* ------------------------------------------------------------------ */

/*
 * Add a thread at pc to list l with the given captures and current
 * input position sp. Follows non-consuming ops (SAVE, JMP, SPLIT,
 * BOL, EOL) immediately and inline. Deduplicates by (pc, generation):
 * the first thread to reach a given pc wins (highest priority).
 */
static void add_thread(struct execstate *es, struct threadlist *l,
                       int pc, int *caps, int sp) {
  while (1) {
    if (pc < 0 || pc >= es->re->code_len) return;
    if (es->seen_gen[pc] == es->gen) return;
    es->seen_gen[pc] = es->gen;
    struct insn ins = es->re->code[pc];
    switch (ins.op) {
      case OP_JMP:
        pc = ins.a;
        continue;
      case OP_SPLIT: {
        /* Higher priority first. We allocate a fresh capture vector
         * for one branch so they don't share state. */
        int *caps_dup = cap_alloc(es);
        cap_copy(caps_dup, caps, es->cap_stride);
        add_thread(es, l, ins.a, caps, sp);
        pc = ins.b;
        caps = caps_dup;
        continue;
      }
      case OP_SAVE:
        caps[ins.a] = sp;
        pc = pc + 1;
        continue;
      case OP_BOL:
        if (sp != 0) return;
        pc = pc + 1;
        continue;
      case OP_EOL:
        if (sp != es->buf_len) return;
        pc = pc + 1;
        continue;
      default:
        l->t[l->n].pc = pc;
        l->t[l->n].caps = caps;
        l->n++;
        return;
    }
  }
}

/*
 * Run the Pike VM starting at byte offset start_off. On success
 * returns the end byte offset and writes capture pairs (pairs of
 * (start, end) byte offsets) into out_caps. On no match returns
 * SLRE_NO_MATCH.
 */
static int run_pike(struct slre *re, const unsigned char *buf,
                    int buf_len, int start_off,
                    int *out_caps, int *out_match_start) {
  int code_len = re->code_len;
  int stride = re->n_save_slots;

  /* Use the scratch buffers preallocated at compile time. seen_gen
   * is reset to zero here; the rest is overwritten in-place. */
  struct thread *ct = (struct thread *) re->vm_clist;
  struct thread *nt = (struct thread *) re->vm_nlist;
  int *cap_pool_a = re->vm_pool_a;
  int *cap_pool_b = re->vm_pool_b;
  int *seen_gen = re->vm_seen_gen;
  int *best_caps = re->vm_best_caps;
  memset(seen_gen, 0, (size_t) code_len * sizeof(int));
  struct threadlist clist = { ct, 0 };
  struct threadlist nlist = { nt, 0 };

  /* es.cap_pool always points at the buffer where NEW thread captures
   * are allocated (i.e. for the list being built). Before the main
   * loop it points at cap_pool_a so the seed allocates there; once
   * the seed populates clist, we set cap_pool to cap_pool_b for the
   * upcoming nlist allocations. */
  struct execstate es;
  es.re = re;
  es.buf = buf;
  es.buf_len = buf_len;
  es.cap_pool = cap_pool_a;
  es.cap_pool_used = 0;
  es.cap_stride = stride;
  es.seen_gen = seen_gen;
  es.gen = 1;

  int has_match = 0;
  int best_end = -1;
  int best_start = -1;

  /* Seed. */
  int *seed = cap_alloc(&es);
  cap_init(seed, stride);
  add_thread(&es, &clist, 0, seed, start_off);

  int sp = start_off;
  while (1) {
    if (clist.n == 0) break;

    /* Decode one rune (or one byte if invalid UTF-8). */
    int rune_len = 0;
    int cp = -1;
    if (sp < buf_len) {
      cp = utf8_decode(buf + sp, buf_len - sp, &rune_len);
      if (rune_len <= 0) rune_len = 1;
    }

    /* Switch allocations to the OTHER pool half for nlist. */
    es.cap_pool = (es.cap_pool == cap_pool_a) ? cap_pool_b : cap_pool_a;
    es.cap_pool_used = 0;
    es.gen++;
    nlist.n = 0;

    for (int ti = 0; ti < clist.n; ti++) {
      struct thread th = clist.t[ti];
      struct insn ins = re->code[th.pc];

      if (ins.op == OP_MATCH) {
        /* Record the match. Higher-priority surviving threads have
         * already been processed and live in nlist; they can still
         * produce a longer/better match in later steps. Lower-priority
         * threads in clist are killed (leftmost-first preempts). */
        has_match = 1;
        best_end = sp;
        best_start = th.caps[0] >= 0 ? th.caps[0] : start_off;
        cap_copy(best_caps, th.caps, stride);
        break;
      }

      if (cp < 0) {
        continue;
      }

      int matched = 0;
      switch (ins.op) {
        case OP_RUNE:
          matched = (cp == ins.a);
          break;
        case OP_RUNE_CI:
          matched = (cp < 128 && ascii_lower(cp) == ins.a);
          break;
        case OP_CLASS:
          /* Class bitmaps are byte-level. For ASCII (cp < 128) the
           * lead byte equals cp. For non-ASCII runes, test the lead
           * byte; this preserves the original SLRE byte-class behavior
           * and lets users target e.g. \xC3 explicitly if needed. */
          matched = sclass_test(&re->classes[ins.a], (unsigned char) buf[sp]);
          break;
        case OP_ANY:
          matched = 1;
          break;
        default:
          break;
      }
      if (matched) {
        int *new_caps = cap_alloc(&es);
        cap_copy(new_caps, th.caps, stride);
        add_thread(&es, &nlist, th.pc + 1, new_caps, sp + rune_len);
      }
    }

    /* Swap clist <-> nlist. Captures stay where they are — clist's
     * captures live in the half that was just-built (where es.cap_pool
     * already points). At the top of the next iteration we'll flip
     * to the OTHER half for nlist allocations. */
    {
      struct thread *tmp = clist.t;
      clist.t = nlist.t;
      nlist.t = tmp;
      clist.n = nlist.n;
      nlist.n = 0;
    }

    if (rune_len == 0) break;  /* end of input */
    sp += rune_len;
  }

  /* If we exited the loop because clist drained (e.g. at end of input)
   * we may still have an OP_MATCH thread among the parked threads. */
  if (!has_match) {
    for (int ti = 0; ti < clist.n; ti++) {
      if (re->code[clist.t[ti].pc].op == OP_MATCH) {
        has_match = 1;
        best_end = sp;
        best_start = clist.t[ti].caps[0] >= 0 ? clist.t[ti].caps[0] : start_off;
        cap_copy(best_caps, clist.t[ti].caps, stride);
        break;
      }
    }
  }

  int result = SLRE_NO_MATCH;
  if (has_match) {
    if (out_caps != NULL) cap_copy(out_caps, best_caps, stride);
    if (out_match_start != NULL) *out_match_start = best_start;
    result = best_end;
  }

  return result;
}

/* ------------------------------------------------------------------ */
/* slre_exec                                                           */
/* ------------------------------------------------------------------ */

static const unsigned char *icase_memchr(const unsigned char *hay, int hlen,
                                          unsigned char needle_lo) {
  unsigned char hi = ascii_upper(needle_lo);
  for (int i = 0; i < hlen; i++) {
    if (hay[i] == needle_lo || hay[i] == hi) return hay + i;
  }
  return NULL;
}

static int find_pure_literal(const struct slre *re,
                             const unsigned char *buf, int buf_len,
                             int *out_start) {
  int icase = (re->flags & SLRE_IGNORE_CASE) != 0;
  int n = re->literal_len;
  if (n == 0) { *out_start = 0; return 0; }
  if (n > buf_len) return SLRE_NO_MATCH;

  if (!icase) {
    unsigned char first = re->literal[0];
    int last = buf_len - n;
    int i = 0;
    while (i <= last) {
      const unsigned char *p =
        (const unsigned char *) memchr(buf + i, first, (size_t)(last - i + 1));
      if (p == NULL) return SLRE_NO_MATCH;
      i = (int) (p - buf);
      if (memcmp(buf + i, re->literal, (size_t) n) == 0) {
        *out_start = i;
        return i + n;
      }
      i++;
    }
    return SLRE_NO_MATCH;
  } else {
    unsigned char first = re->literal[0];   /* lowercased */
    int last = buf_len - n;
    int i = 0;
    while (i <= last) {
      const unsigned char *p = icase_memchr(buf + i, last - i + 1, first);
      if (p == NULL) return SLRE_NO_MATCH;
      i = (int) (p - buf);
      int ok = 1;
      for (int j = 0; j < n; j++) {
        unsigned char b = buf[i + j];
        unsigned char lo = (unsigned char) ascii_lower((int) b);
        if (lo != re->literal[j]) { ok = 0; break; }
      }
      if (ok) {
        *out_start = i;
        return i + n;
      }
      i++;
    }
    return SLRE_NO_MATCH;
  }
}

/*
 * Substring search returning the leftmost match offset, or -1.
 *
 * Strategy: for short needles (the common case for required regex
 * literals), memchr is heavily vectorized in libc and dominates a
 * scalar Boyer-Moore-Horspool inner loop. We use memchr to find the
 * first-byte candidate, verify with memcmp, and slide. For longer
 * needles (>= 8 bytes) we fall through to BMH whose bad-character
 * shift becomes worth the inner-loop overhead.
 */
static int find_lit(const unsigned char *haystack, int hlen,
                    const unsigned char *needle, int nlen,
                    const unsigned char *skip) {
  if (nlen <= 0 || hlen < nlen) return -1;
  if (nlen == 1) {
    const unsigned char *p =
      (const unsigned char *) memchr(haystack, needle[0], (size_t) hlen);
    return p == NULL ? -1 : (int)(p - haystack);
  }
  int last = hlen - nlen;
  if (nlen < 8) {
    int i = 0;
    while (i <= last) {
      const unsigned char *p = (const unsigned char *)
        memchr(haystack + i, needle[0], (size_t)(last - i + 1));
      if (p == NULL) return -1;
      i = (int)(p - haystack);
      if (memcmp(haystack + i, needle, (size_t) nlen) == 0) return i;
      i++;
    }
    return -1;
  }
  /* BMH for longer needles. */
  int i = 0;
  while (i <= last) {
    int j = nlen - 1;
    while (j >= 0 && haystack[i + j] == needle[j]) j--;
    if (j < 0) return i;
    int shift = skip[haystack[i + nlen - 1]];
    i += shift > 0 ? shift : 1;
  }
  return -1;
}

/* Rightmost match — used by the greedy .*LIT shortcut. */
static int find_lit_last(const unsigned char *haystack, int hlen,
                         const unsigned char *needle, int nlen) {
  if (nlen <= 0 || hlen < nlen) return -1;
  for (int i = hlen - nlen; i >= 0; i--) {
    if (haystack[i] == needle[0] &&
        memcmp(haystack + i, needle, (size_t) nlen) == 0) {
      return i;
    }
  }
  return -1;
}

int slre_exec(const struct slre *re, const char *buf_, int buf_len,
              struct slre_cap *caps, int num_caps,
              struct slre_result *result) {
  if (re == NULL || buf_ == NULL || buf_len < 0) return SLRE_INVALID_ARGUMENT;
  if (num_caps < 0) return SLRE_INVALID_ARGUMENT;
  if (num_caps > 0 && caps == NULL) return SLRE_INVALID_ARGUMENT;
  if (num_caps > 0 && num_caps < re->n_groups) return SLRE_CAPS_ARRAY_TOO_SMALL;

  const unsigned char *buf = (const unsigned char *) buf_;

  if (caps != NULL) {
    for (int i = 0; i < num_caps; i++) {
      caps[i].ptr = NULL;
      caps[i].len = 0;
    }
  }

  if (re->is_pure_literal) {
    int start = 0;
    int end = find_pure_literal(re, buf, buf_len, &start);
    if (end < 0) return end;
    if (result != NULL) {
      result->start = start;
      result->end = end;
      result->ncaps = 0;
    }
    return end;
  }

  /* .*LIT / .*?LIT direct-accept shortcut (no captures). */
  if (re->dot_star_lit_kind != 0 && num_caps == 0) {
    int pos;
    if (re->dot_star_lit_kind == 1) {
      pos = find_lit_last(buf, buf_len, re->req_lit, re->req_lit_len);
    } else {
      pos = find_lit(buf, buf_len, re->req_lit, re->req_lit_len,
                     re->bmh_skip);
    }
    if (pos < 0) return SLRE_NO_MATCH;
    int end = pos + re->req_lit_len;
    if (result != NULL) {
      result->start = 0;
      result->end = end;
      result->ncaps = 0;
    }
    return end;
  }

  /* Required-literal reject filter: if there's a literal substring
   * that every match must contain, and it isn't anywhere in the
   * input, we can return NO_MATCH without running the VM. We only
   * apply this when the literal is NOT the prefix — when it is the
   * prefix we'll use it for candidate scanning below, which already
   * subsumes this filter. */
  if (re->req_lit_len >= 2 && !re->req_lit_is_prefix) {
    int found = find_lit(buf, buf_len, re->req_lit, re->req_lit_len,
                         re->bmh_skip);
    if (found < 0) return SLRE_NO_MATCH;
  }

  /* Greedy single-class repeat fast path. */
  if (re->simple_class_kind != 0) {
    const struct sclass *cls = &re->classes[re->simple_class_idx];
    int kind = re->simple_class_kind;  /* 1 plus, 2 star */
    if (kind == 2) {
      /* [CLASS]* — leftmost match is at offset 0; greedy length is the
       * longest run of in-class bytes from offset 0. */
      int j = 0;
      while (j < buf_len && sclass_test(cls, (unsigned char) buf[j])) j++;
      if (result != NULL) {
        result->start = 0;
        result->end = j;
        result->ncaps = 0;
      }
      return j;
    }
    /* kind == 1, [CLASS]+ — leftmost in-class byte starts the match. */
    for (int i = 0; i < buf_len; i++) {
      if (sclass_test(cls, (unsigned char) buf[i])) {
        int j = i + 1;
        while (j < buf_len && sclass_test(cls, (unsigned char) buf[j])) j++;
        if (result != NULL) {
          result->start = i;
          result->end = j;
          result->ncaps = 0;
        }
        return j;
      }
    }
    return SLRE_NO_MATCH;
  }

  int min_len = re->min_match_len;
  int last_start = buf_len - min_len;
  if (last_start < 0) {
    /* Min length exceeds buffer. The only way it could still match is
     * if the regex matches the empty string, in which case min_len
     * == 0 — handled below — OR the regex has anchors / lookarounds
     * that we approximate. We bail conservatively. */
    return SLRE_NO_MATCH;
  }
  if (re->anchored_bol) last_start = 0;

  /* Use the slre struct's preallocated scratch (not thread-safe). */
  struct slre *re_mut = (struct slre *) re;
  int *cap_ints = re_mut->vm_cap_ints;

  int ret = SLRE_NO_MATCH;
  int start_pos = 0;
  int icase = (re->flags & SLRE_IGNORE_CASE) != 0;

  int p = 0;
  while (p <= last_start) {
    /* Find next candidate start position using the most precise
     * filter available. The required-literal-prefix filter is
     * tightest: a multi-byte literal that must begin at the match
     * start. Falling back: single-byte first-byte memchr, then a
     * 256-bit byte set scan. */
    if (re->req_lit_is_prefix && re->req_lit_len >= 2) {
      int remaining = buf_len - p;
      int found = find_lit(buf + p, remaining,
                           re->req_lit, re->req_lit_len,
                           re->bmh_skip);
      if (found < 0) break;
      p += found;
      if (p > last_start) break;
    } else if (re->has_first_byte_set) {
      int found = -1;
      const unsigned char *bp = buf + p;
      int remaining = last_start - p + 1;
      if (re->first_byte_count == 1 && !icase) {
        const unsigned char *q = (const unsigned char *)
          memchr(bp, re->single_first_byte, (size_t) remaining);
        if (q == NULL) break;
        found = (int)(q - buf);
      } else if (re->first_byte_list_len > 0 && !icase) {
        /* Multi-memchr scan: search for each candidate byte and keep
         * the leftmost. We bound the second and subsequent searches
         * by the current best so they don't re-scan past it. */
        int best = remaining;
        for (int k = 0; k < re->first_byte_list_len; k++) {
          if (best == 0) break;
          const unsigned char *q = (const unsigned char *)
            memchr(bp, re->first_byte_list[k], (size_t) best);
          if (q != NULL) {
            int pos = (int)(q - bp);
            if (pos < best) best = pos;
          }
        }
        if (best == remaining) break;
        found = p + best;
      } else {
        for (int i = 0; i < remaining; i++) {
          unsigned b = bp[i];
          if (re->first_byte[b >> 6] & (1ull << (b & 63))) {
            found = p + i;
            break;
          }
        }
        if (found < 0) break;
      }
      p = found;
    }

    int s = -1;
    int end;
    /* Thompson VM is sufficient when the caller doesn't request
     * captures. The match start is the seed position p; the engine
     * just reports the end offset. */
    if (num_caps == 0 && (result == NULL || re->n_groups == 0)) {
      end = run_thompson(re_mut, buf, buf_len, p);
      s = p;
    } else {
      end = run_pike(re_mut, buf, buf_len, p, cap_ints, &s);
    }
    if (end == SLRE_OUT_OF_MEMORY) { ret = SLRE_OUT_OF_MEMORY; break; }
    if (end >= 0) {
      ret = end;
      start_pos = (s >= 0) ? s : p;
      break;
    }

    int rl;
    int cp = utf8_decode(buf + p, buf_len - p, &rl);
    (void) cp;
    if (rl <= 0) rl = 1;
    p += rl;
    if (re->anchored_bol) break;
  }

  if (ret >= 0) {
    if (caps != NULL) {
      int filled = re->n_groups < num_caps ? re->n_groups : num_caps;
      for (int i = 0; i < filled; i++) {
        int s = cap_ints[2 * (i + 1)];
        int e = cap_ints[2 * (i + 1) + 1];
        if (s < 0 || e < 0) {
          caps[i].ptr = NULL;
          caps[i].len = 0;
        } else {
          caps[i].ptr = buf_ + s;
          caps[i].len = e - s;
        }
      }
    }
    if (result != NULL) {
      result->start = start_pos;
      result->end = ret;
      result->ncaps = re->n_groups;
    }
  }

  return ret;
}

/* ------------------------------------------------------------------ */
/* slre_match (legacy convenience wrapper)                             */
/* ------------------------------------------------------------------ */

int slre_match(const char *regexp, const char *buf, int buf_len,
               struct slre_cap *caps, int num_caps, int flags) {
  struct slre *re = NULL;
  int err = slre_compile(regexp, flags, &re);
  if (err) return err;
  int rc = slre_exec(re, buf, buf_len, caps, num_caps, NULL);
  slre_free(re);
  return rc;
}
