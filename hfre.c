/*
 * hfre - small regex engine.
 *
 * Pipeline:
 *   pattern (UTF-8) -> bytecode -> Pike VM -> match
 *
 * The compile step parses the pattern into a flat instruction stream
 * (OP_RUNE / OP_RUNE_CI / OP_LIT / OP_REPEAT_RUNE / OP_CLASS /
 * OP_UPROP / OP_ANY / OP_BOL / OP_EOL / OP_SAVE / OP_JMP / OP_SPLIT /
 * OP_MATCH) and computes prefilter metadata: whether the
 * regex is anchored at start of buffer, the minimum byte length of any
 * match, the set of bytes that may legally start a match, and a
 * pure-literal extraction when the entire regex is a fixed string.
 *
 * The exec step uses the prefilter metadata to skip non-candidate
 * start positions cheaply (memchr / first-byte set), then runs a Pike
 * VM that steps the input one UTF-8 code point at a time. Unicode
 * property classes are represented as property tests, not expanded
 * into byte classes. Threads carry capture offsets and are
 * deduplicated per (PC, generation) so a single step is O(code_len).
 *
 * Match semantics: leftmost-first, regex-order alternation priority,
 * greedy quantifiers prefer longer matches, lazy quantifiers prefer
 * shorter matches. Captures use start/end byte offsets into the input
 * buffer; unmatched captures are reported as { NULL, 0 }.
 *
 * Background: Russ Cox, "Regular expression matching: the virtual
 * machine approach". https://swtch.com/~rsc/regexp/regexp2.html
 */

#include "hfre.h"

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
static inline int utf8_decode(const unsigned char *p, int max, int *out_len) {
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

static int utf8_encode(int cp, unsigned char out[4]) {
  if (cp < 0 || cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff)) return 0;
  if (cp < 0x80) {
    out[0] = (unsigned char) cp;
    return 1;
  }
  if (cp < 0x800) {
    out[0] = (unsigned char) (0xc0 | (cp >> 6));
    out[1] = (unsigned char) (0x80 | (cp & 0x3f));
    return 2;
  }
  if (cp < 0x10000) {
    out[0] = (unsigned char) (0xe0 | (cp >> 12));
    out[1] = (unsigned char) (0x80 | ((cp >> 6) & 0x3f));
    out[2] = (unsigned char) (0x80 | (cp & 0x3f));
    return 3;
  }
  out[0] = (unsigned char) (0xf0 | (cp >> 18));
  out[1] = (unsigned char) (0x80 | ((cp >> 12) & 0x3f));
  out[2] = (unsigned char) (0x80 | ((cp >> 6) & 0x3f));
  out[3] = (unsigned char) (0x80 | (cp & 0x3f));
  return 4;
}

static int utf8_width_for_cp(int cp) {
  if (cp < 0 || cp > 0x10ffff) return 1;
  if (cp < 0x80) return 1;
  if (cp < 0x800) return 2;
  if (cp < 0x10000) return 3;
  return 4;
}

struct urange { int32_t lo, hi; };
struct fold_pair { int32_t from, to; };

static int urange_contains(const struct urange *ranges, int n, int cp) {
  int lo = 0, hi = n - 1;
  while (lo <= hi) {
    int mid = lo + (hi - lo) / 2;
    if (cp < ranges[mid].lo) hi = mid - 1;
    else if (cp > ranges[mid].hi) lo = mid + 1;
    else return 1;
  }
  return 0;
}

/* Generated from Unicode Character Database 17.0.0:
 * UnicodeData.txt, Scripts.txt, and CaseFolding.txt. */
static const struct fold_pair unicode_folds[] = {
  {0x0041, 0x0061}, {0x0042, 0x0062}, {0x0043, 0x0063}, {0x0044, 0x0064},
  {0x0045, 0x0065}, {0x0046, 0x0066}, {0x0047, 0x0067}, {0x0048, 0x0068},
  {0x0049, 0x0069}, {0x004a, 0x006a}, {0x004b, 0x006b}, {0x004c, 0x006c},
  {0x004d, 0x006d}, {0x004e, 0x006e}, {0x004f, 0x006f}, {0x0050, 0x0070},
  {0x0051, 0x0071}, {0x0052, 0x0072}, {0x0053, 0x0073}, {0x0054, 0x0074},
  {0x0055, 0x0075}, {0x0056, 0x0076}, {0x0057, 0x0077}, {0x0058, 0x0078},
  {0x0059, 0x0079}, {0x005a, 0x007a}, {0x00b5, 0x03bc}, {0x00c0, 0x00e0},
  {0x00c1, 0x00e1}, {0x00c2, 0x00e2}, {0x00c3, 0x00e3}, {0x00c4, 0x00e4},
  {0x00c5, 0x00e5}, {0x00c6, 0x00e6}, {0x00c7, 0x00e7}, {0x00c8, 0x00e8},
  {0x00c9, 0x00e9}, {0x00ca, 0x00ea}, {0x00cb, 0x00eb}, {0x00cc, 0x00ec},
  {0x00cd, 0x00ed}, {0x00ce, 0x00ee}, {0x00cf, 0x00ef}, {0x00d0, 0x00f0},
  {0x00d1, 0x00f1}, {0x00d2, 0x00f2}, {0x00d3, 0x00f3}, {0x00d4, 0x00f4},
  {0x00d5, 0x00f5}, {0x00d6, 0x00f6}, {0x00d8, 0x00f8}, {0x00d9, 0x00f9},
  {0x00da, 0x00fa}, {0x00db, 0x00fb}, {0x00dc, 0x00fc}, {0x00dd, 0x00fd},
  {0x00de, 0x00fe}, {0x0100, 0x0101}, {0x0102, 0x0103}, {0x0104, 0x0105},
  {0x0106, 0x0107}, {0x0108, 0x0109}, {0x010a, 0x010b}, {0x010c, 0x010d},
  {0x010e, 0x010f}, {0x0110, 0x0111}, {0x0112, 0x0113}, {0x0114, 0x0115},
  {0x0116, 0x0117}, {0x0118, 0x0119}, {0x011a, 0x011b}, {0x011c, 0x011d},
  {0x011e, 0x011f}, {0x0120, 0x0121}, {0x0122, 0x0123}, {0x0124, 0x0125},
  {0x0126, 0x0127}, {0x0128, 0x0129}, {0x012a, 0x012b}, {0x012c, 0x012d},
  {0x012e, 0x012f}, {0x0132, 0x0133}, {0x0134, 0x0135}, {0x0136, 0x0137},
  {0x0139, 0x013a}, {0x013b, 0x013c}, {0x013d, 0x013e}, {0x013f, 0x0140},
  {0x0141, 0x0142}, {0x0143, 0x0144}, {0x0145, 0x0146}, {0x0147, 0x0148},
  {0x014a, 0x014b}, {0x014c, 0x014d}, {0x014e, 0x014f}, {0x0150, 0x0151},
  {0x0152, 0x0153}, {0x0154, 0x0155}, {0x0156, 0x0157}, {0x0158, 0x0159},
  {0x015a, 0x015b}, {0x015c, 0x015d}, {0x015e, 0x015f}, {0x0160, 0x0161},
  {0x0162, 0x0163}, {0x0164, 0x0165}, {0x0166, 0x0167}, {0x0168, 0x0169},
  {0x016a, 0x016b}, {0x016c, 0x016d}, {0x016e, 0x016f}, {0x0170, 0x0171},
  {0x0172, 0x0173}, {0x0174, 0x0175}, {0x0176, 0x0177}, {0x0178, 0x00ff},
  {0x0179, 0x017a}, {0x017b, 0x017c}, {0x017d, 0x017e}, {0x017f, 0x0073},
  {0x0181, 0x0253}, {0x0182, 0x0183}, {0x0184, 0x0185}, {0x0186, 0x0254},
  {0x0187, 0x0188}, {0x0189, 0x0256}, {0x018a, 0x0257}, {0x018b, 0x018c},
  {0x018e, 0x01dd}, {0x018f, 0x0259}, {0x0190, 0x025b}, {0x0191, 0x0192},
  {0x0193, 0x0260}, {0x0194, 0x0263}, {0x0196, 0x0269}, {0x0197, 0x0268},
  {0x0198, 0x0199}, {0x019c, 0x026f}, {0x019d, 0x0272}, {0x019f, 0x0275},
  {0x01a0, 0x01a1}, {0x01a2, 0x01a3}, {0x01a4, 0x01a5}, {0x01a6, 0x0280},
  {0x01a7, 0x01a8}, {0x01a9, 0x0283}, {0x01ac, 0x01ad}, {0x01ae, 0x0288},
  {0x01af, 0x01b0}, {0x01b1, 0x028a}, {0x01b2, 0x028b}, {0x01b3, 0x01b4},
  {0x01b5, 0x01b6}, {0x01b7, 0x0292}, {0x01b8, 0x01b9}, {0x01bc, 0x01bd},
  {0x01c4, 0x01c6}, {0x01c5, 0x01c6}, {0x01c7, 0x01c9}, {0x01c8, 0x01c9},
  {0x01ca, 0x01cc}, {0x01cb, 0x01cc}, {0x01cd, 0x01ce}, {0x01cf, 0x01d0},
  {0x01d1, 0x01d2}, {0x01d3, 0x01d4}, {0x01d5, 0x01d6}, {0x01d7, 0x01d8},
  {0x01d9, 0x01da}, {0x01db, 0x01dc}, {0x01de, 0x01df}, {0x01e0, 0x01e1},
  {0x01e2, 0x01e3}, {0x01e4, 0x01e5}, {0x01e6, 0x01e7}, {0x01e8, 0x01e9},
  {0x01ea, 0x01eb}, {0x01ec, 0x01ed}, {0x01ee, 0x01ef}, {0x01f1, 0x01f3},
  {0x01f2, 0x01f3}, {0x01f4, 0x01f5}, {0x01f6, 0x0195}, {0x01f7, 0x01bf},
  {0x01f8, 0x01f9}, {0x01fa, 0x01fb}, {0x01fc, 0x01fd}, {0x01fe, 0x01ff},
  {0x0200, 0x0201}, {0x0202, 0x0203}, {0x0204, 0x0205}, {0x0206, 0x0207},
  {0x0208, 0x0209}, {0x020a, 0x020b}, {0x020c, 0x020d}, {0x020e, 0x020f},
  {0x0210, 0x0211}, {0x0212, 0x0213}, {0x0214, 0x0215}, {0x0216, 0x0217},
  {0x0218, 0x0219}, {0x021a, 0x021b}, {0x021c, 0x021d}, {0x021e, 0x021f},
  {0x0220, 0x019e}, {0x0222, 0x0223}, {0x0224, 0x0225}, {0x0226, 0x0227},
  {0x0228, 0x0229}, {0x022a, 0x022b}, {0x022c, 0x022d}, {0x022e, 0x022f},
  {0x0230, 0x0231}, {0x0232, 0x0233}, {0x023a, 0x2c65}, {0x023b, 0x023c},
  {0x023d, 0x019a}, {0x023e, 0x2c66}, {0x0241, 0x0242}, {0x0243, 0x0180},
  {0x0244, 0x0289}, {0x0245, 0x028c}, {0x0246, 0x0247}, {0x0248, 0x0249},
  {0x024a, 0x024b}, {0x024c, 0x024d}, {0x024e, 0x024f}, {0x0345, 0x03b9},
  {0x0370, 0x0371}, {0x0372, 0x0373}, {0x0376, 0x0377}, {0x037f, 0x03f3},
  {0x0386, 0x03ac}, {0x0388, 0x03ad}, {0x0389, 0x03ae}, {0x038a, 0x03af},
  {0x038c, 0x03cc}, {0x038e, 0x03cd}, {0x038f, 0x03ce}, {0x0391, 0x03b1},
  {0x0392, 0x03b2}, {0x0393, 0x03b3}, {0x0394, 0x03b4}, {0x0395, 0x03b5},
  {0x0396, 0x03b6}, {0x0397, 0x03b7}, {0x0398, 0x03b8}, {0x0399, 0x03b9},
  {0x039a, 0x03ba}, {0x039b, 0x03bb}, {0x039c, 0x03bc}, {0x039d, 0x03bd},
  {0x039e, 0x03be}, {0x039f, 0x03bf}, {0x03a0, 0x03c0}, {0x03a1, 0x03c1},
  {0x03a3, 0x03c3}, {0x03a4, 0x03c4}, {0x03a5, 0x03c5}, {0x03a6, 0x03c6},
  {0x03a7, 0x03c7}, {0x03a8, 0x03c8}, {0x03a9, 0x03c9}, {0x03aa, 0x03ca},
  {0x03ab, 0x03cb}, {0x03c2, 0x03c3}, {0x03cf, 0x03d7}, {0x03d0, 0x03b2},
  {0x03d1, 0x03b8}, {0x03d5, 0x03c6}, {0x03d6, 0x03c0}, {0x03d8, 0x03d9},
  {0x03da, 0x03db}, {0x03dc, 0x03dd}, {0x03de, 0x03df}, {0x03e0, 0x03e1},
  {0x03e2, 0x03e3}, {0x03e4, 0x03e5}, {0x03e6, 0x03e7}, {0x03e8, 0x03e9},
  {0x03ea, 0x03eb}, {0x03ec, 0x03ed}, {0x03ee, 0x03ef}, {0x03f0, 0x03ba},
  {0x03f1, 0x03c1}, {0x03f4, 0x03b8}, {0x03f5, 0x03b5}, {0x03f7, 0x03f8},
  {0x03f9, 0x03f2}, {0x03fa, 0x03fb}, {0x03fd, 0x037b}, {0x03fe, 0x037c},
  {0x03ff, 0x037d}, {0x0400, 0x0450}, {0x0401, 0x0451}, {0x0402, 0x0452},
  {0x0403, 0x0453}, {0x0404, 0x0454}, {0x0405, 0x0455}, {0x0406, 0x0456},
  {0x0407, 0x0457}, {0x0408, 0x0458}, {0x0409, 0x0459}, {0x040a, 0x045a},
  {0x040b, 0x045b}, {0x040c, 0x045c}, {0x040d, 0x045d}, {0x040e, 0x045e},
  {0x040f, 0x045f}, {0x0410, 0x0430}, {0x0411, 0x0431}, {0x0412, 0x0432},
  {0x0413, 0x0433}, {0x0414, 0x0434}, {0x0415, 0x0435}, {0x0416, 0x0436},
  {0x0417, 0x0437}, {0x0418, 0x0438}, {0x0419, 0x0439}, {0x041a, 0x043a},
  {0x041b, 0x043b}, {0x041c, 0x043c}, {0x041d, 0x043d}, {0x041e, 0x043e},
  {0x041f, 0x043f}, {0x0420, 0x0440}, {0x0421, 0x0441}, {0x0422, 0x0442},
  {0x0423, 0x0443}, {0x0424, 0x0444}, {0x0425, 0x0445}, {0x0426, 0x0446},
  {0x0427, 0x0447}, {0x0428, 0x0448}, {0x0429, 0x0449}, {0x042a, 0x044a},
  {0x042b, 0x044b}, {0x042c, 0x044c}, {0x042d, 0x044d}, {0x042e, 0x044e},
  {0x042f, 0x044f}, {0x0460, 0x0461}, {0x0462, 0x0463}, {0x0464, 0x0465},
  {0x0466, 0x0467}, {0x0468, 0x0469}, {0x046a, 0x046b}, {0x046c, 0x046d},
  {0x046e, 0x046f}, {0x0470, 0x0471}, {0x0472, 0x0473}, {0x0474, 0x0475},
  {0x0476, 0x0477}, {0x0478, 0x0479}, {0x047a, 0x047b}, {0x047c, 0x047d},
  {0x047e, 0x047f}, {0x0480, 0x0481}, {0x048a, 0x048b}, {0x048c, 0x048d},
  {0x048e, 0x048f}, {0x0490, 0x0491}, {0x0492, 0x0493}, {0x0494, 0x0495},
  {0x0496, 0x0497}, {0x0498, 0x0499}, {0x049a, 0x049b}, {0x049c, 0x049d},
  {0x049e, 0x049f}, {0x04a0, 0x04a1}, {0x04a2, 0x04a3}, {0x04a4, 0x04a5},
  {0x04a6, 0x04a7}, {0x04a8, 0x04a9}, {0x04aa, 0x04ab}, {0x04ac, 0x04ad},
  {0x04ae, 0x04af}, {0x04b0, 0x04b1}, {0x04b2, 0x04b3}, {0x04b4, 0x04b5},
  {0x04b6, 0x04b7}, {0x04b8, 0x04b9}, {0x04ba, 0x04bb}, {0x04bc, 0x04bd},
  {0x04be, 0x04bf}, {0x04c0, 0x04cf}, {0x04c1, 0x04c2}, {0x04c3, 0x04c4},
  {0x04c5, 0x04c6}, {0x04c7, 0x04c8}, {0x04c9, 0x04ca}, {0x04cb, 0x04cc},
  {0x04cd, 0x04ce}, {0x04d0, 0x04d1}, {0x04d2, 0x04d3}, {0x04d4, 0x04d5},
  {0x04d6, 0x04d7}, {0x04d8, 0x04d9}, {0x04da, 0x04db}, {0x04dc, 0x04dd},
  {0x04de, 0x04df}, {0x04e0, 0x04e1}, {0x04e2, 0x04e3}, {0x04e4, 0x04e5},
  {0x04e6, 0x04e7}, {0x04e8, 0x04e9}, {0x04ea, 0x04eb}, {0x04ec, 0x04ed},
  {0x04ee, 0x04ef}, {0x04f0, 0x04f1}, {0x04f2, 0x04f3}, {0x04f4, 0x04f5},
  {0x04f6, 0x04f7}, {0x04f8, 0x04f9}, {0x04fa, 0x04fb}, {0x04fc, 0x04fd},
  {0x04fe, 0x04ff}, {0x0500, 0x0501}, {0x0502, 0x0503}, {0x0504, 0x0505},
  {0x0506, 0x0507}, {0x0508, 0x0509}, {0x050a, 0x050b}, {0x050c, 0x050d},
  {0x050e, 0x050f}, {0x0510, 0x0511}, {0x0512, 0x0513}, {0x0514, 0x0515},
  {0x0516, 0x0517}, {0x0518, 0x0519}, {0x051a, 0x051b}, {0x051c, 0x051d},
  {0x051e, 0x051f}, {0x0520, 0x0521}, {0x0522, 0x0523}, {0x0524, 0x0525},
  {0x0526, 0x0527}, {0x0528, 0x0529}, {0x052a, 0x052b}, {0x052c, 0x052d},
  {0x052e, 0x052f}, {0x0531, 0x0561}, {0x0532, 0x0562}, {0x0533, 0x0563},
  {0x0534, 0x0564}, {0x0535, 0x0565}, {0x0536, 0x0566}, {0x0537, 0x0567},
  {0x0538, 0x0568}, {0x0539, 0x0569}, {0x053a, 0x056a}, {0x053b, 0x056b},
  {0x053c, 0x056c}, {0x053d, 0x056d}, {0x053e, 0x056e}, {0x053f, 0x056f},
  {0x0540, 0x0570}, {0x0541, 0x0571}, {0x0542, 0x0572}, {0x0543, 0x0573},
  {0x0544, 0x0574}, {0x0545, 0x0575}, {0x0546, 0x0576}, {0x0547, 0x0577},
  {0x0548, 0x0578}, {0x0549, 0x0579}, {0x054a, 0x057a}, {0x054b, 0x057b},
  {0x054c, 0x057c}, {0x054d, 0x057d}, {0x054e, 0x057e}, {0x054f, 0x057f},
  {0x0550, 0x0580}, {0x0551, 0x0581}, {0x0552, 0x0582}, {0x0553, 0x0583},
  {0x0554, 0x0584}, {0x0555, 0x0585}, {0x0556, 0x0586}, {0x10a0, 0x2d00},
  {0x10a1, 0x2d01}, {0x10a2, 0x2d02}, {0x10a3, 0x2d03}, {0x10a4, 0x2d04},
  {0x10a5, 0x2d05}, {0x10a6, 0x2d06}, {0x10a7, 0x2d07}, {0x10a8, 0x2d08},
  {0x10a9, 0x2d09}, {0x10aa, 0x2d0a}, {0x10ab, 0x2d0b}, {0x10ac, 0x2d0c},
  {0x10ad, 0x2d0d}, {0x10ae, 0x2d0e}, {0x10af, 0x2d0f}, {0x10b0, 0x2d10},
  {0x10b1, 0x2d11}, {0x10b2, 0x2d12}, {0x10b3, 0x2d13}, {0x10b4, 0x2d14},
  {0x10b5, 0x2d15}, {0x10b6, 0x2d16}, {0x10b7, 0x2d17}, {0x10b8, 0x2d18},
  {0x10b9, 0x2d19}, {0x10ba, 0x2d1a}, {0x10bb, 0x2d1b}, {0x10bc, 0x2d1c},
  {0x10bd, 0x2d1d}, {0x10be, 0x2d1e}, {0x10bf, 0x2d1f}, {0x10c0, 0x2d20},
  {0x10c1, 0x2d21}, {0x10c2, 0x2d22}, {0x10c3, 0x2d23}, {0x10c4, 0x2d24},
  {0x10c5, 0x2d25}, {0x10c7, 0x2d27}, {0x10cd, 0x2d2d}, {0x13f8, 0x13f0},
  {0x13f9, 0x13f1}, {0x13fa, 0x13f2}, {0x13fb, 0x13f3}, {0x13fc, 0x13f4},
  {0x13fd, 0x13f5}, {0x1c80, 0x0432}, {0x1c81, 0x0434}, {0x1c82, 0x043e},
  {0x1c83, 0x0441}, {0x1c84, 0x0442}, {0x1c85, 0x0442}, {0x1c86, 0x044a},
  {0x1c87, 0x0463}, {0x1c88, 0xa64b}, {0x1c89, 0x1c8a}, {0x1c90, 0x10d0},
  {0x1c91, 0x10d1}, {0x1c92, 0x10d2}, {0x1c93, 0x10d3}, {0x1c94, 0x10d4},
  {0x1c95, 0x10d5}, {0x1c96, 0x10d6}, {0x1c97, 0x10d7}, {0x1c98, 0x10d8},
  {0x1c99, 0x10d9}, {0x1c9a, 0x10da}, {0x1c9b, 0x10db}, {0x1c9c, 0x10dc},
  {0x1c9d, 0x10dd}, {0x1c9e, 0x10de}, {0x1c9f, 0x10df}, {0x1ca0, 0x10e0},
  {0x1ca1, 0x10e1}, {0x1ca2, 0x10e2}, {0x1ca3, 0x10e3}, {0x1ca4, 0x10e4},
  {0x1ca5, 0x10e5}, {0x1ca6, 0x10e6}, {0x1ca7, 0x10e7}, {0x1ca8, 0x10e8},
  {0x1ca9, 0x10e9}, {0x1caa, 0x10ea}, {0x1cab, 0x10eb}, {0x1cac, 0x10ec},
  {0x1cad, 0x10ed}, {0x1cae, 0x10ee}, {0x1caf, 0x10ef}, {0x1cb0, 0x10f0},
  {0x1cb1, 0x10f1}, {0x1cb2, 0x10f2}, {0x1cb3, 0x10f3}, {0x1cb4, 0x10f4},
  {0x1cb5, 0x10f5}, {0x1cb6, 0x10f6}, {0x1cb7, 0x10f7}, {0x1cb8, 0x10f8},
  {0x1cb9, 0x10f9}, {0x1cba, 0x10fa}, {0x1cbd, 0x10fd}, {0x1cbe, 0x10fe},
  {0x1cbf, 0x10ff}, {0x1e00, 0x1e01}, {0x1e02, 0x1e03}, {0x1e04, 0x1e05},
  {0x1e06, 0x1e07}, {0x1e08, 0x1e09}, {0x1e0a, 0x1e0b}, {0x1e0c, 0x1e0d},
  {0x1e0e, 0x1e0f}, {0x1e10, 0x1e11}, {0x1e12, 0x1e13}, {0x1e14, 0x1e15},
  {0x1e16, 0x1e17}, {0x1e18, 0x1e19}, {0x1e1a, 0x1e1b}, {0x1e1c, 0x1e1d},
  {0x1e1e, 0x1e1f}, {0x1e20, 0x1e21}, {0x1e22, 0x1e23}, {0x1e24, 0x1e25},
  {0x1e26, 0x1e27}, {0x1e28, 0x1e29}, {0x1e2a, 0x1e2b}, {0x1e2c, 0x1e2d},
  {0x1e2e, 0x1e2f}, {0x1e30, 0x1e31}, {0x1e32, 0x1e33}, {0x1e34, 0x1e35},
  {0x1e36, 0x1e37}, {0x1e38, 0x1e39}, {0x1e3a, 0x1e3b}, {0x1e3c, 0x1e3d},
  {0x1e3e, 0x1e3f}, {0x1e40, 0x1e41}, {0x1e42, 0x1e43}, {0x1e44, 0x1e45},
  {0x1e46, 0x1e47}, {0x1e48, 0x1e49}, {0x1e4a, 0x1e4b}, {0x1e4c, 0x1e4d},
  {0x1e4e, 0x1e4f}, {0x1e50, 0x1e51}, {0x1e52, 0x1e53}, {0x1e54, 0x1e55},
  {0x1e56, 0x1e57}, {0x1e58, 0x1e59}, {0x1e5a, 0x1e5b}, {0x1e5c, 0x1e5d},
  {0x1e5e, 0x1e5f}, {0x1e60, 0x1e61}, {0x1e62, 0x1e63}, {0x1e64, 0x1e65},
  {0x1e66, 0x1e67}, {0x1e68, 0x1e69}, {0x1e6a, 0x1e6b}, {0x1e6c, 0x1e6d},
  {0x1e6e, 0x1e6f}, {0x1e70, 0x1e71}, {0x1e72, 0x1e73}, {0x1e74, 0x1e75},
  {0x1e76, 0x1e77}, {0x1e78, 0x1e79}, {0x1e7a, 0x1e7b}, {0x1e7c, 0x1e7d},
  {0x1e7e, 0x1e7f}, {0x1e80, 0x1e81}, {0x1e82, 0x1e83}, {0x1e84, 0x1e85},
  {0x1e86, 0x1e87}, {0x1e88, 0x1e89}, {0x1e8a, 0x1e8b}, {0x1e8c, 0x1e8d},
  {0x1e8e, 0x1e8f}, {0x1e90, 0x1e91}, {0x1e92, 0x1e93}, {0x1e94, 0x1e95},
  {0x1e9b, 0x1e61}, {0x1e9e, 0x00df}, {0x1ea0, 0x1ea1}, {0x1ea2, 0x1ea3},
  {0x1ea4, 0x1ea5}, {0x1ea6, 0x1ea7}, {0x1ea8, 0x1ea9}, {0x1eaa, 0x1eab},
  {0x1eac, 0x1ead}, {0x1eae, 0x1eaf}, {0x1eb0, 0x1eb1}, {0x1eb2, 0x1eb3},
  {0x1eb4, 0x1eb5}, {0x1eb6, 0x1eb7}, {0x1eb8, 0x1eb9}, {0x1eba, 0x1ebb},
  {0x1ebc, 0x1ebd}, {0x1ebe, 0x1ebf}, {0x1ec0, 0x1ec1}, {0x1ec2, 0x1ec3},
  {0x1ec4, 0x1ec5}, {0x1ec6, 0x1ec7}, {0x1ec8, 0x1ec9}, {0x1eca, 0x1ecb},
  {0x1ecc, 0x1ecd}, {0x1ece, 0x1ecf}, {0x1ed0, 0x1ed1}, {0x1ed2, 0x1ed3},
  {0x1ed4, 0x1ed5}, {0x1ed6, 0x1ed7}, {0x1ed8, 0x1ed9}, {0x1eda, 0x1edb},
  {0x1edc, 0x1edd}, {0x1ede, 0x1edf}, {0x1ee0, 0x1ee1}, {0x1ee2, 0x1ee3},
  {0x1ee4, 0x1ee5}, {0x1ee6, 0x1ee7}, {0x1ee8, 0x1ee9}, {0x1eea, 0x1eeb},
  {0x1eec, 0x1eed}, {0x1eee, 0x1eef}, {0x1ef0, 0x1ef1}, {0x1ef2, 0x1ef3},
  {0x1ef4, 0x1ef5}, {0x1ef6, 0x1ef7}, {0x1ef8, 0x1ef9}, {0x1efa, 0x1efb},
  {0x1efc, 0x1efd}, {0x1efe, 0x1eff}, {0x1f08, 0x1f00}, {0x1f09, 0x1f01},
  {0x1f0a, 0x1f02}, {0x1f0b, 0x1f03}, {0x1f0c, 0x1f04}, {0x1f0d, 0x1f05},
  {0x1f0e, 0x1f06}, {0x1f0f, 0x1f07}, {0x1f18, 0x1f10}, {0x1f19, 0x1f11},
  {0x1f1a, 0x1f12}, {0x1f1b, 0x1f13}, {0x1f1c, 0x1f14}, {0x1f1d, 0x1f15},
  {0x1f28, 0x1f20}, {0x1f29, 0x1f21}, {0x1f2a, 0x1f22}, {0x1f2b, 0x1f23},
  {0x1f2c, 0x1f24}, {0x1f2d, 0x1f25}, {0x1f2e, 0x1f26}, {0x1f2f, 0x1f27},
  {0x1f38, 0x1f30}, {0x1f39, 0x1f31}, {0x1f3a, 0x1f32}, {0x1f3b, 0x1f33},
  {0x1f3c, 0x1f34}, {0x1f3d, 0x1f35}, {0x1f3e, 0x1f36}, {0x1f3f, 0x1f37},
  {0x1f48, 0x1f40}, {0x1f49, 0x1f41}, {0x1f4a, 0x1f42}, {0x1f4b, 0x1f43},
  {0x1f4c, 0x1f44}, {0x1f4d, 0x1f45}, {0x1f59, 0x1f51}, {0x1f5b, 0x1f53},
  {0x1f5d, 0x1f55}, {0x1f5f, 0x1f57}, {0x1f68, 0x1f60}, {0x1f69, 0x1f61},
  {0x1f6a, 0x1f62}, {0x1f6b, 0x1f63}, {0x1f6c, 0x1f64}, {0x1f6d, 0x1f65},
  {0x1f6e, 0x1f66}, {0x1f6f, 0x1f67}, {0x1f88, 0x1f80}, {0x1f89, 0x1f81},
  {0x1f8a, 0x1f82}, {0x1f8b, 0x1f83}, {0x1f8c, 0x1f84}, {0x1f8d, 0x1f85},
  {0x1f8e, 0x1f86}, {0x1f8f, 0x1f87}, {0x1f98, 0x1f90}, {0x1f99, 0x1f91},
  {0x1f9a, 0x1f92}, {0x1f9b, 0x1f93}, {0x1f9c, 0x1f94}, {0x1f9d, 0x1f95},
  {0x1f9e, 0x1f96}, {0x1f9f, 0x1f97}, {0x1fa8, 0x1fa0}, {0x1fa9, 0x1fa1},
  {0x1faa, 0x1fa2}, {0x1fab, 0x1fa3}, {0x1fac, 0x1fa4}, {0x1fad, 0x1fa5},
  {0x1fae, 0x1fa6}, {0x1faf, 0x1fa7}, {0x1fb8, 0x1fb0}, {0x1fb9, 0x1fb1},
  {0x1fba, 0x1f70}, {0x1fbb, 0x1f71}, {0x1fbc, 0x1fb3}, {0x1fbe, 0x03b9},
  {0x1fc8, 0x1f72}, {0x1fc9, 0x1f73}, {0x1fca, 0x1f74}, {0x1fcb, 0x1f75},
  {0x1fcc, 0x1fc3}, {0x1fd3, 0x0390}, {0x1fd8, 0x1fd0}, {0x1fd9, 0x1fd1},
  {0x1fda, 0x1f76}, {0x1fdb, 0x1f77}, {0x1fe3, 0x03b0}, {0x1fe8, 0x1fe0},
  {0x1fe9, 0x1fe1}, {0x1fea, 0x1f7a}, {0x1feb, 0x1f7b}, {0x1fec, 0x1fe5},
  {0x1ff8, 0x1f78}, {0x1ff9, 0x1f79}, {0x1ffa, 0x1f7c}, {0x1ffb, 0x1f7d},
  {0x1ffc, 0x1ff3}, {0x2126, 0x03c9}, {0x212a, 0x006b}, {0x212b, 0x00e5},
  {0x2132, 0x214e}, {0x2160, 0x2170}, {0x2161, 0x2171}, {0x2162, 0x2172},
  {0x2163, 0x2173}, {0x2164, 0x2174}, {0x2165, 0x2175}, {0x2166, 0x2176},
  {0x2167, 0x2177}, {0x2168, 0x2178}, {0x2169, 0x2179}, {0x216a, 0x217a},
  {0x216b, 0x217b}, {0x216c, 0x217c}, {0x216d, 0x217d}, {0x216e, 0x217e},
  {0x216f, 0x217f}, {0x2183, 0x2184}, {0x24b6, 0x24d0}, {0x24b7, 0x24d1},
  {0x24b8, 0x24d2}, {0x24b9, 0x24d3}, {0x24ba, 0x24d4}, {0x24bb, 0x24d5},
  {0x24bc, 0x24d6}, {0x24bd, 0x24d7}, {0x24be, 0x24d8}, {0x24bf, 0x24d9},
  {0x24c0, 0x24da}, {0x24c1, 0x24db}, {0x24c2, 0x24dc}, {0x24c3, 0x24dd},
  {0x24c4, 0x24de}, {0x24c5, 0x24df}, {0x24c6, 0x24e0}, {0x24c7, 0x24e1},
  {0x24c8, 0x24e2}, {0x24c9, 0x24e3}, {0x24ca, 0x24e4}, {0x24cb, 0x24e5},
  {0x24cc, 0x24e6}, {0x24cd, 0x24e7}, {0x24ce, 0x24e8}, {0x24cf, 0x24e9},
  {0x2c00, 0x2c30}, {0x2c01, 0x2c31}, {0x2c02, 0x2c32}, {0x2c03, 0x2c33},
  {0x2c04, 0x2c34}, {0x2c05, 0x2c35}, {0x2c06, 0x2c36}, {0x2c07, 0x2c37},
  {0x2c08, 0x2c38}, {0x2c09, 0x2c39}, {0x2c0a, 0x2c3a}, {0x2c0b, 0x2c3b},
  {0x2c0c, 0x2c3c}, {0x2c0d, 0x2c3d}, {0x2c0e, 0x2c3e}, {0x2c0f, 0x2c3f},
  {0x2c10, 0x2c40}, {0x2c11, 0x2c41}, {0x2c12, 0x2c42}, {0x2c13, 0x2c43},
  {0x2c14, 0x2c44}, {0x2c15, 0x2c45}, {0x2c16, 0x2c46}, {0x2c17, 0x2c47},
  {0x2c18, 0x2c48}, {0x2c19, 0x2c49}, {0x2c1a, 0x2c4a}, {0x2c1b, 0x2c4b},
  {0x2c1c, 0x2c4c}, {0x2c1d, 0x2c4d}, {0x2c1e, 0x2c4e}, {0x2c1f, 0x2c4f},
  {0x2c20, 0x2c50}, {0x2c21, 0x2c51}, {0x2c22, 0x2c52}, {0x2c23, 0x2c53},
  {0x2c24, 0x2c54}, {0x2c25, 0x2c55}, {0x2c26, 0x2c56}, {0x2c27, 0x2c57},
  {0x2c28, 0x2c58}, {0x2c29, 0x2c59}, {0x2c2a, 0x2c5a}, {0x2c2b, 0x2c5b},
  {0x2c2c, 0x2c5c}, {0x2c2d, 0x2c5d}, {0x2c2e, 0x2c5e}, {0x2c2f, 0x2c5f},
  {0x2c60, 0x2c61}, {0x2c62, 0x026b}, {0x2c63, 0x1d7d}, {0x2c64, 0x027d},
  {0x2c67, 0x2c68}, {0x2c69, 0x2c6a}, {0x2c6b, 0x2c6c}, {0x2c6d, 0x0251},
  {0x2c6e, 0x0271}, {0x2c6f, 0x0250}, {0x2c70, 0x0252}, {0x2c72, 0x2c73},
  {0x2c75, 0x2c76}, {0x2c7e, 0x023f}, {0x2c7f, 0x0240}, {0x2c80, 0x2c81},
  {0x2c82, 0x2c83}, {0x2c84, 0x2c85}, {0x2c86, 0x2c87}, {0x2c88, 0x2c89},
  {0x2c8a, 0x2c8b}, {0x2c8c, 0x2c8d}, {0x2c8e, 0x2c8f}, {0x2c90, 0x2c91},
  {0x2c92, 0x2c93}, {0x2c94, 0x2c95}, {0x2c96, 0x2c97}, {0x2c98, 0x2c99},
  {0x2c9a, 0x2c9b}, {0x2c9c, 0x2c9d}, {0x2c9e, 0x2c9f}, {0x2ca0, 0x2ca1},
  {0x2ca2, 0x2ca3}, {0x2ca4, 0x2ca5}, {0x2ca6, 0x2ca7}, {0x2ca8, 0x2ca9},
  {0x2caa, 0x2cab}, {0x2cac, 0x2cad}, {0x2cae, 0x2caf}, {0x2cb0, 0x2cb1},
  {0x2cb2, 0x2cb3}, {0x2cb4, 0x2cb5}, {0x2cb6, 0x2cb7}, {0x2cb8, 0x2cb9},
  {0x2cba, 0x2cbb}, {0x2cbc, 0x2cbd}, {0x2cbe, 0x2cbf}, {0x2cc0, 0x2cc1},
  {0x2cc2, 0x2cc3}, {0x2cc4, 0x2cc5}, {0x2cc6, 0x2cc7}, {0x2cc8, 0x2cc9},
  {0x2cca, 0x2ccb}, {0x2ccc, 0x2ccd}, {0x2cce, 0x2ccf}, {0x2cd0, 0x2cd1},
  {0x2cd2, 0x2cd3}, {0x2cd4, 0x2cd5}, {0x2cd6, 0x2cd7}, {0x2cd8, 0x2cd9},
  {0x2cda, 0x2cdb}, {0x2cdc, 0x2cdd}, {0x2cde, 0x2cdf}, {0x2ce0, 0x2ce1},
  {0x2ce2, 0x2ce3}, {0x2ceb, 0x2cec}, {0x2ced, 0x2cee}, {0x2cf2, 0x2cf3},
  {0xa640, 0xa641}, {0xa642, 0xa643}, {0xa644, 0xa645}, {0xa646, 0xa647},
  {0xa648, 0xa649}, {0xa64a, 0xa64b}, {0xa64c, 0xa64d}, {0xa64e, 0xa64f},
  {0xa650, 0xa651}, {0xa652, 0xa653}, {0xa654, 0xa655}, {0xa656, 0xa657},
  {0xa658, 0xa659}, {0xa65a, 0xa65b}, {0xa65c, 0xa65d}, {0xa65e, 0xa65f},
  {0xa660, 0xa661}, {0xa662, 0xa663}, {0xa664, 0xa665}, {0xa666, 0xa667},
  {0xa668, 0xa669}, {0xa66a, 0xa66b}, {0xa66c, 0xa66d}, {0xa680, 0xa681},
  {0xa682, 0xa683}, {0xa684, 0xa685}, {0xa686, 0xa687}, {0xa688, 0xa689},
  {0xa68a, 0xa68b}, {0xa68c, 0xa68d}, {0xa68e, 0xa68f}, {0xa690, 0xa691},
  {0xa692, 0xa693}, {0xa694, 0xa695}, {0xa696, 0xa697}, {0xa698, 0xa699},
  {0xa69a, 0xa69b}, {0xa722, 0xa723}, {0xa724, 0xa725}, {0xa726, 0xa727},
  {0xa728, 0xa729}, {0xa72a, 0xa72b}, {0xa72c, 0xa72d}, {0xa72e, 0xa72f},
  {0xa732, 0xa733}, {0xa734, 0xa735}, {0xa736, 0xa737}, {0xa738, 0xa739},
  {0xa73a, 0xa73b}, {0xa73c, 0xa73d}, {0xa73e, 0xa73f}, {0xa740, 0xa741},
  {0xa742, 0xa743}, {0xa744, 0xa745}, {0xa746, 0xa747}, {0xa748, 0xa749},
  {0xa74a, 0xa74b}, {0xa74c, 0xa74d}, {0xa74e, 0xa74f}, {0xa750, 0xa751},
  {0xa752, 0xa753}, {0xa754, 0xa755}, {0xa756, 0xa757}, {0xa758, 0xa759},
  {0xa75a, 0xa75b}, {0xa75c, 0xa75d}, {0xa75e, 0xa75f}, {0xa760, 0xa761},
  {0xa762, 0xa763}, {0xa764, 0xa765}, {0xa766, 0xa767}, {0xa768, 0xa769},
  {0xa76a, 0xa76b}, {0xa76c, 0xa76d}, {0xa76e, 0xa76f}, {0xa779, 0xa77a},
  {0xa77b, 0xa77c}, {0xa77d, 0x1d79}, {0xa77e, 0xa77f}, {0xa780, 0xa781},
  {0xa782, 0xa783}, {0xa784, 0xa785}, {0xa786, 0xa787}, {0xa78b, 0xa78c},
  {0xa78d, 0x0265}, {0xa790, 0xa791}, {0xa792, 0xa793}, {0xa796, 0xa797},
  {0xa798, 0xa799}, {0xa79a, 0xa79b}, {0xa79c, 0xa79d}, {0xa79e, 0xa79f},
  {0xa7a0, 0xa7a1}, {0xa7a2, 0xa7a3}, {0xa7a4, 0xa7a5}, {0xa7a6, 0xa7a7},
  {0xa7a8, 0xa7a9}, {0xa7aa, 0x0266}, {0xa7ab, 0x025c}, {0xa7ac, 0x0261},
  {0xa7ad, 0x026c}, {0xa7ae, 0x026a}, {0xa7b0, 0x029e}, {0xa7b1, 0x0287},
  {0xa7b2, 0x029d}, {0xa7b3, 0xab53}, {0xa7b4, 0xa7b5}, {0xa7b6, 0xa7b7},
  {0xa7b8, 0xa7b9}, {0xa7ba, 0xa7bb}, {0xa7bc, 0xa7bd}, {0xa7be, 0xa7bf},
  {0xa7c0, 0xa7c1}, {0xa7c2, 0xa7c3}, {0xa7c4, 0xa794}, {0xa7c5, 0x0282},
  {0xa7c6, 0x1d8e}, {0xa7c7, 0xa7c8}, {0xa7c9, 0xa7ca}, {0xa7cb, 0x0264},
  {0xa7cc, 0xa7cd}, {0xa7ce, 0xa7cf}, {0xa7d0, 0xa7d1}, {0xa7d2, 0xa7d3},
  {0xa7d4, 0xa7d5}, {0xa7d6, 0xa7d7}, {0xa7d8, 0xa7d9}, {0xa7da, 0xa7db},
  {0xa7dc, 0x019b}, {0xa7f5, 0xa7f6}, {0xab70, 0x13a0}, {0xab71, 0x13a1},
  {0xab72, 0x13a2}, {0xab73, 0x13a3}, {0xab74, 0x13a4}, {0xab75, 0x13a5},
  {0xab76, 0x13a6}, {0xab77, 0x13a7}, {0xab78, 0x13a8}, {0xab79, 0x13a9},
  {0xab7a, 0x13aa}, {0xab7b, 0x13ab}, {0xab7c, 0x13ac}, {0xab7d, 0x13ad},
  {0xab7e, 0x13ae}, {0xab7f, 0x13af}, {0xab80, 0x13b0}, {0xab81, 0x13b1},
  {0xab82, 0x13b2}, {0xab83, 0x13b3}, {0xab84, 0x13b4}, {0xab85, 0x13b5},
  {0xab86, 0x13b6}, {0xab87, 0x13b7}, {0xab88, 0x13b8}, {0xab89, 0x13b9},
  {0xab8a, 0x13ba}, {0xab8b, 0x13bb}, {0xab8c, 0x13bc}, {0xab8d, 0x13bd},
  {0xab8e, 0x13be}, {0xab8f, 0x13bf}, {0xab90, 0x13c0}, {0xab91, 0x13c1},
  {0xab92, 0x13c2}, {0xab93, 0x13c3}, {0xab94, 0x13c4}, {0xab95, 0x13c5},
  {0xab96, 0x13c6}, {0xab97, 0x13c7}, {0xab98, 0x13c8}, {0xab99, 0x13c9},
  {0xab9a, 0x13ca}, {0xab9b, 0x13cb}, {0xab9c, 0x13cc}, {0xab9d, 0x13cd},
  {0xab9e, 0x13ce}, {0xab9f, 0x13cf}, {0xaba0, 0x13d0}, {0xaba1, 0x13d1},
  {0xaba2, 0x13d2}, {0xaba3, 0x13d3}, {0xaba4, 0x13d4}, {0xaba5, 0x13d5},
  {0xaba6, 0x13d6}, {0xaba7, 0x13d7}, {0xaba8, 0x13d8}, {0xaba9, 0x13d9},
  {0xabaa, 0x13da}, {0xabab, 0x13db}, {0xabac, 0x13dc}, {0xabad, 0x13dd},
  {0xabae, 0x13de}, {0xabaf, 0x13df}, {0xabb0, 0x13e0}, {0xabb1, 0x13e1},
  {0xabb2, 0x13e2}, {0xabb3, 0x13e3}, {0xabb4, 0x13e4}, {0xabb5, 0x13e5},
  {0xabb6, 0x13e6}, {0xabb7, 0x13e7}, {0xabb8, 0x13e8}, {0xabb9, 0x13e9},
  {0xabba, 0x13ea}, {0xabbb, 0x13eb}, {0xabbc, 0x13ec}, {0xabbd, 0x13ed},
  {0xabbe, 0x13ee}, {0xabbf, 0x13ef}, {0xfb05, 0xfb06}, {0xff21, 0xff41},
  {0xff22, 0xff42}, {0xff23, 0xff43}, {0xff24, 0xff44}, {0xff25, 0xff45},
  {0xff26, 0xff46}, {0xff27, 0xff47}, {0xff28, 0xff48}, {0xff29, 0xff49},
  {0xff2a, 0xff4a}, {0xff2b, 0xff4b}, {0xff2c, 0xff4c}, {0xff2d, 0xff4d},
  {0xff2e, 0xff4e}, {0xff2f, 0xff4f}, {0xff30, 0xff50}, {0xff31, 0xff51},
  {0xff32, 0xff52}, {0xff33, 0xff53}, {0xff34, 0xff54}, {0xff35, 0xff55},
  {0xff36, 0xff56}, {0xff37, 0xff57}, {0xff38, 0xff58}, {0xff39, 0xff59},
  {0xff3a, 0xff5a}, {0x010400, 0x010428}, {0x010401, 0x010429},
  {0x010402, 0x01042a}, {0x010403, 0x01042b}, {0x010404, 0x01042c},
  {0x010405, 0x01042d}, {0x010406, 0x01042e}, {0x010407, 0x01042f},
  {0x010408, 0x010430}, {0x010409, 0x010431}, {0x01040a, 0x010432},
  {0x01040b, 0x010433}, {0x01040c, 0x010434}, {0x01040d, 0x010435},
  {0x01040e, 0x010436}, {0x01040f, 0x010437}, {0x010410, 0x010438},
  {0x010411, 0x010439}, {0x010412, 0x01043a}, {0x010413, 0x01043b},
  {0x010414, 0x01043c}, {0x010415, 0x01043d}, {0x010416, 0x01043e},
  {0x010417, 0x01043f}, {0x010418, 0x010440}, {0x010419, 0x010441},
  {0x01041a, 0x010442}, {0x01041b, 0x010443}, {0x01041c, 0x010444},
  {0x01041d, 0x010445}, {0x01041e, 0x010446}, {0x01041f, 0x010447},
  {0x010420, 0x010448}, {0x010421, 0x010449}, {0x010422, 0x01044a},
  {0x010423, 0x01044b}, {0x010424, 0x01044c}, {0x010425, 0x01044d},
  {0x010426, 0x01044e}, {0x010427, 0x01044f}, {0x0104b0, 0x0104d8},
  {0x0104b1, 0x0104d9}, {0x0104b2, 0x0104da}, {0x0104b3, 0x0104db},
  {0x0104b4, 0x0104dc}, {0x0104b5, 0x0104dd}, {0x0104b6, 0x0104de},
  {0x0104b7, 0x0104df}, {0x0104b8, 0x0104e0}, {0x0104b9, 0x0104e1},
  {0x0104ba, 0x0104e2}, {0x0104bb, 0x0104e3}, {0x0104bc, 0x0104e4},
  {0x0104bd, 0x0104e5}, {0x0104be, 0x0104e6}, {0x0104bf, 0x0104e7},
  {0x0104c0, 0x0104e8}, {0x0104c1, 0x0104e9}, {0x0104c2, 0x0104ea},
  {0x0104c3, 0x0104eb}, {0x0104c4, 0x0104ec}, {0x0104c5, 0x0104ed},
  {0x0104c6, 0x0104ee}, {0x0104c7, 0x0104ef}, {0x0104c8, 0x0104f0},
  {0x0104c9, 0x0104f1}, {0x0104ca, 0x0104f2}, {0x0104cb, 0x0104f3},
  {0x0104cc, 0x0104f4}, {0x0104cd, 0x0104f5}, {0x0104ce, 0x0104f6},
  {0x0104cf, 0x0104f7}, {0x0104d0, 0x0104f8}, {0x0104d1, 0x0104f9},
  {0x0104d2, 0x0104fa}, {0x0104d3, 0x0104fb}, {0x010570, 0x010597},
  {0x010571, 0x010598}, {0x010572, 0x010599}, {0x010573, 0x01059a},
  {0x010574, 0x01059b}, {0x010575, 0x01059c}, {0x010576, 0x01059d},
  {0x010577, 0x01059e}, {0x010578, 0x01059f}, {0x010579, 0x0105a0},
  {0x01057a, 0x0105a1}, {0x01057c, 0x0105a3}, {0x01057d, 0x0105a4},
  {0x01057e, 0x0105a5}, {0x01057f, 0x0105a6}, {0x010580, 0x0105a7},
  {0x010581, 0x0105a8}, {0x010582, 0x0105a9}, {0x010583, 0x0105aa},
  {0x010584, 0x0105ab}, {0x010585, 0x0105ac}, {0x010586, 0x0105ad},
  {0x010587, 0x0105ae}, {0x010588, 0x0105af}, {0x010589, 0x0105b0},
  {0x01058a, 0x0105b1}, {0x01058c, 0x0105b3}, {0x01058d, 0x0105b4},
  {0x01058e, 0x0105b5}, {0x01058f, 0x0105b6}, {0x010590, 0x0105b7},
  {0x010591, 0x0105b8}, {0x010592, 0x0105b9}, {0x010594, 0x0105bb},
  {0x010595, 0x0105bc}, {0x010c80, 0x010cc0}, {0x010c81, 0x010cc1},
  {0x010c82, 0x010cc2}, {0x010c83, 0x010cc3}, {0x010c84, 0x010cc4},
  {0x010c85, 0x010cc5}, {0x010c86, 0x010cc6}, {0x010c87, 0x010cc7},
  {0x010c88, 0x010cc8}, {0x010c89, 0x010cc9}, {0x010c8a, 0x010cca},
  {0x010c8b, 0x010ccb}, {0x010c8c, 0x010ccc}, {0x010c8d, 0x010ccd},
  {0x010c8e, 0x010cce}, {0x010c8f, 0x010ccf}, {0x010c90, 0x010cd0},
  {0x010c91, 0x010cd1}, {0x010c92, 0x010cd2}, {0x010c93, 0x010cd3},
  {0x010c94, 0x010cd4}, {0x010c95, 0x010cd5}, {0x010c96, 0x010cd6},
  {0x010c97, 0x010cd7}, {0x010c98, 0x010cd8}, {0x010c99, 0x010cd9},
  {0x010c9a, 0x010cda}, {0x010c9b, 0x010cdb}, {0x010c9c, 0x010cdc},
  {0x010c9d, 0x010cdd}, {0x010c9e, 0x010cde}, {0x010c9f, 0x010cdf},
  {0x010ca0, 0x010ce0}, {0x010ca1, 0x010ce1}, {0x010ca2, 0x010ce2},
  {0x010ca3, 0x010ce3}, {0x010ca4, 0x010ce4}, {0x010ca5, 0x010ce5},
  {0x010ca6, 0x010ce6}, {0x010ca7, 0x010ce7}, {0x010ca8, 0x010ce8},
  {0x010ca9, 0x010ce9}, {0x010caa, 0x010cea}, {0x010cab, 0x010ceb},
  {0x010cac, 0x010cec}, {0x010cad, 0x010ced}, {0x010cae, 0x010cee},
  {0x010caf, 0x010cef}, {0x010cb0, 0x010cf0}, {0x010cb1, 0x010cf1},
  {0x010cb2, 0x010cf2}, {0x010d50, 0x010d70}, {0x010d51, 0x010d71},
  {0x010d52, 0x010d72}, {0x010d53, 0x010d73}, {0x010d54, 0x010d74},
  {0x010d55, 0x010d75}, {0x010d56, 0x010d76}, {0x010d57, 0x010d77},
  {0x010d58, 0x010d78}, {0x010d59, 0x010d79}, {0x010d5a, 0x010d7a},
  {0x010d5b, 0x010d7b}, {0x010d5c, 0x010d7c}, {0x010d5d, 0x010d7d},
  {0x010d5e, 0x010d7e}, {0x010d5f, 0x010d7f}, {0x010d60, 0x010d80},
  {0x010d61, 0x010d81}, {0x010d62, 0x010d82}, {0x010d63, 0x010d83},
  {0x010d64, 0x010d84}, {0x010d65, 0x010d85}, {0x0118a0, 0x0118c0},
  {0x0118a1, 0x0118c1}, {0x0118a2, 0x0118c2}, {0x0118a3, 0x0118c3},
  {0x0118a4, 0x0118c4}, {0x0118a5, 0x0118c5}, {0x0118a6, 0x0118c6},
  {0x0118a7, 0x0118c7}, {0x0118a8, 0x0118c8}, {0x0118a9, 0x0118c9},
  {0x0118aa, 0x0118ca}, {0x0118ab, 0x0118cb}, {0x0118ac, 0x0118cc},
  {0x0118ad, 0x0118cd}, {0x0118ae, 0x0118ce}, {0x0118af, 0x0118cf},
  {0x0118b0, 0x0118d0}, {0x0118b1, 0x0118d1}, {0x0118b2, 0x0118d2},
  {0x0118b3, 0x0118d3}, {0x0118b4, 0x0118d4}, {0x0118b5, 0x0118d5},
  {0x0118b6, 0x0118d6}, {0x0118b7, 0x0118d7}, {0x0118b8, 0x0118d8},
  {0x0118b9, 0x0118d9}, {0x0118ba, 0x0118da}, {0x0118bb, 0x0118db},
  {0x0118bc, 0x0118dc}, {0x0118bd, 0x0118dd}, {0x0118be, 0x0118de},
  {0x0118bf, 0x0118df}, {0x016e40, 0x016e60}, {0x016e41, 0x016e61},
  {0x016e42, 0x016e62}, {0x016e43, 0x016e63}, {0x016e44, 0x016e64},
  {0x016e45, 0x016e65}, {0x016e46, 0x016e66}, {0x016e47, 0x016e67},
  {0x016e48, 0x016e68}, {0x016e49, 0x016e69}, {0x016e4a, 0x016e6a},
  {0x016e4b, 0x016e6b}, {0x016e4c, 0x016e6c}, {0x016e4d, 0x016e6d},
  {0x016e4e, 0x016e6e}, {0x016e4f, 0x016e6f}, {0x016e50, 0x016e70},
  {0x016e51, 0x016e71}, {0x016e52, 0x016e72}, {0x016e53, 0x016e73},
  {0x016e54, 0x016e74}, {0x016e55, 0x016e75}, {0x016e56, 0x016e76},
  {0x016e57, 0x016e77}, {0x016e58, 0x016e78}, {0x016e59, 0x016e79},
  {0x016e5a, 0x016e7a}, {0x016e5b, 0x016e7b}, {0x016e5c, 0x016e7c},
  {0x016e5d, 0x016e7d}, {0x016e5e, 0x016e7e}, {0x016e5f, 0x016e7f},
  {0x016ea0, 0x016ebb}, {0x016ea1, 0x016ebc}, {0x016ea2, 0x016ebd},
  {0x016ea3, 0x016ebe}, {0x016ea4, 0x016ebf}, {0x016ea5, 0x016ec0},
  {0x016ea6, 0x016ec1}, {0x016ea7, 0x016ec2}, {0x016ea8, 0x016ec3},
  {0x016ea9, 0x016ec4}, {0x016eaa, 0x016ec5}, {0x016eab, 0x016ec6},
  {0x016eac, 0x016ec7}, {0x016ead, 0x016ec8}, {0x016eae, 0x016ec9},
  {0x016eaf, 0x016eca}, {0x016eb0, 0x016ecb}, {0x016eb1, 0x016ecc},
  {0x016eb2, 0x016ecd}, {0x016eb3, 0x016ece}, {0x016eb4, 0x016ecf},
  {0x016eb5, 0x016ed0}, {0x016eb6, 0x016ed1}, {0x016eb7, 0x016ed2},
  {0x016eb8, 0x016ed3}, {0x01e900, 0x01e922}, {0x01e901, 0x01e923},
  {0x01e902, 0x01e924}, {0x01e903, 0x01e925}, {0x01e904, 0x01e926},
  {0x01e905, 0x01e927}, {0x01e906, 0x01e928}, {0x01e907, 0x01e929},
  {0x01e908, 0x01e92a}, {0x01e909, 0x01e92b}, {0x01e90a, 0x01e92c},
  {0x01e90b, 0x01e92d}, {0x01e90c, 0x01e92e}, {0x01e90d, 0x01e92f},
  {0x01e90e, 0x01e930}, {0x01e90f, 0x01e931}, {0x01e910, 0x01e932},
  {0x01e911, 0x01e933}, {0x01e912, 0x01e934}, {0x01e913, 0x01e935},
  {0x01e914, 0x01e936}, {0x01e915, 0x01e937}, {0x01e916, 0x01e938},
  {0x01e917, 0x01e939}, {0x01e918, 0x01e93a}, {0x01e919, 0x01e93b},
  {0x01e91a, 0x01e93c}, {0x01e91b, 0x01e93d}, {0x01e91c, 0x01e93e},
  {0x01e91d, 0x01e93f}, {0x01e91e, 0x01e940}, {0x01e91f, 0x01e941},
  {0x01e920, 0x01e942}, {0x01e921, 0x01e943},
};

static int unicode_simple_fold(int cp) {
  if (cp >= 'A' && cp <= 'Z') return cp + 32;
  int lo = 0;
  int hi = (int)(sizeof(unicode_folds) / sizeof(unicode_folds[0])) - 1;
  while (lo <= hi) {
    int mid = lo + (hi - lo) / 2;
    if (cp < unicode_folds[mid].from) hi = mid - 1;
    else if (cp > unicode_folds[mid].from) lo = mid + 1;
    else return unicode_folds[mid].to;
  }
  return cp;
}

static void first_set_add_cp(uint64_t out[4], int cp) {
  unsigned char buf[4];
  int n = utf8_encode(cp, buf);
  if (n > 0) out[buf[0] >> 6] |= 1ull << (buf[0] & 63);
}

static void first_set_add_folded_cp(uint64_t out[4], int folded_cp) {
  first_set_add_cp(out, folded_cp);
  int n = (int)(sizeof(unicode_folds) / sizeof(unicode_folds[0]));
  for (int i = 0; i < n; i++) {
    if (unicode_folds[i].to == folded_cp) {
      first_set_add_cp(out, unicode_folds[i].from);
    }
  }
}

enum {
  UPROP_L = 0,
  UPROP_N,
  UPROP_ND,
  UPROP_LU,
  UPROP_LL,
  UPROP_GREEK,
  UPROP_LATIN,
  UPROP_CYRILLIC,
  UPROP_HAN,
  UPROP_HIRAGANA,
  UPROP_KATAKANA,
  UPROP_COUNT
};

static const struct urange uprop_l_ranges[] = {
  {0x0041, 0x005a}, {0x0061, 0x007a}, {0x00aa, 0x00aa}, {0x00b5, 0x00b5},
  {0x00ba, 0x00ba}, {0x00c0, 0x00d6}, {0x00d8, 0x00f6}, {0x00f8, 0x02c1},
  {0x02c6, 0x02d1}, {0x02e0, 0x02e4}, {0x02ec, 0x02ec}, {0x02ee, 0x02ee},
  {0x0370, 0x0374}, {0x0376, 0x0377}, {0x037a, 0x037d}, {0x037f, 0x037f},
  {0x0386, 0x0386}, {0x0388, 0x038a}, {0x038c, 0x038c}, {0x038e, 0x03a1},
  {0x03a3, 0x03f5}, {0x03f7, 0x0481}, {0x048a, 0x052f}, {0x0531, 0x0556},
  {0x0559, 0x0559}, {0x0560, 0x0588}, {0x05d0, 0x05ea}, {0x05ef, 0x05f2},
  {0x0620, 0x064a}, {0x066e, 0x066f}, {0x0671, 0x06d3}, {0x06d5, 0x06d5},
  {0x06e5, 0x06e6}, {0x06ee, 0x06ef}, {0x06fa, 0x06fc}, {0x06ff, 0x06ff},
  {0x0710, 0x0710}, {0x0712, 0x072f}, {0x074d, 0x07a5}, {0x07b1, 0x07b1},
  {0x07ca, 0x07ea}, {0x07f4, 0x07f5}, {0x07fa, 0x07fa}, {0x0800, 0x0815},
  {0x081a, 0x081a}, {0x0824, 0x0824}, {0x0828, 0x0828}, {0x0840, 0x0858},
  {0x0860, 0x086a}, {0x0870, 0x0887}, {0x0889, 0x088f}, {0x08a0, 0x08c9},
  {0x0904, 0x0939}, {0x093d, 0x093d}, {0x0950, 0x0950}, {0x0958, 0x0961},
  {0x0971, 0x0980}, {0x0985, 0x098c}, {0x098f, 0x0990}, {0x0993, 0x09a8},
  {0x09aa, 0x09b0}, {0x09b2, 0x09b2}, {0x09b6, 0x09b9}, {0x09bd, 0x09bd},
  {0x09ce, 0x09ce}, {0x09dc, 0x09dd}, {0x09df, 0x09e1}, {0x09f0, 0x09f1},
  {0x09fc, 0x09fc}, {0x0a05, 0x0a0a}, {0x0a0f, 0x0a10}, {0x0a13, 0x0a28},
  {0x0a2a, 0x0a30}, {0x0a32, 0x0a33}, {0x0a35, 0x0a36}, {0x0a38, 0x0a39},
  {0x0a59, 0x0a5c}, {0x0a5e, 0x0a5e}, {0x0a72, 0x0a74}, {0x0a85, 0x0a8d},
  {0x0a8f, 0x0a91}, {0x0a93, 0x0aa8}, {0x0aaa, 0x0ab0}, {0x0ab2, 0x0ab3},
  {0x0ab5, 0x0ab9}, {0x0abd, 0x0abd}, {0x0ad0, 0x0ad0}, {0x0ae0, 0x0ae1},
  {0x0af9, 0x0af9}, {0x0b05, 0x0b0c}, {0x0b0f, 0x0b10}, {0x0b13, 0x0b28},
  {0x0b2a, 0x0b30}, {0x0b32, 0x0b33}, {0x0b35, 0x0b39}, {0x0b3d, 0x0b3d},
  {0x0b5c, 0x0b5d}, {0x0b5f, 0x0b61}, {0x0b71, 0x0b71}, {0x0b83, 0x0b83},
  {0x0b85, 0x0b8a}, {0x0b8e, 0x0b90}, {0x0b92, 0x0b95}, {0x0b99, 0x0b9a},
  {0x0b9c, 0x0b9c}, {0x0b9e, 0x0b9f}, {0x0ba3, 0x0ba4}, {0x0ba8, 0x0baa},
  {0x0bae, 0x0bb9}, {0x0bd0, 0x0bd0}, {0x0c05, 0x0c0c}, {0x0c0e, 0x0c10},
  {0x0c12, 0x0c28}, {0x0c2a, 0x0c39}, {0x0c3d, 0x0c3d}, {0x0c58, 0x0c5a},
  {0x0c5c, 0x0c5d}, {0x0c60, 0x0c61}, {0x0c80, 0x0c80}, {0x0c85, 0x0c8c},
  {0x0c8e, 0x0c90}, {0x0c92, 0x0ca8}, {0x0caa, 0x0cb3}, {0x0cb5, 0x0cb9},
  {0x0cbd, 0x0cbd}, {0x0cdc, 0x0cde}, {0x0ce0, 0x0ce1}, {0x0cf1, 0x0cf2},
  {0x0d04, 0x0d0c}, {0x0d0e, 0x0d10}, {0x0d12, 0x0d3a}, {0x0d3d, 0x0d3d},
  {0x0d4e, 0x0d4e}, {0x0d54, 0x0d56}, {0x0d5f, 0x0d61}, {0x0d7a, 0x0d7f},
  {0x0d85, 0x0d96}, {0x0d9a, 0x0db1}, {0x0db3, 0x0dbb}, {0x0dbd, 0x0dbd},
  {0x0dc0, 0x0dc6}, {0x0e01, 0x0e30}, {0x0e32, 0x0e33}, {0x0e40, 0x0e46},
  {0x0e81, 0x0e82}, {0x0e84, 0x0e84}, {0x0e86, 0x0e8a}, {0x0e8c, 0x0ea3},
  {0x0ea5, 0x0ea5}, {0x0ea7, 0x0eb0}, {0x0eb2, 0x0eb3}, {0x0ebd, 0x0ebd},
  {0x0ec0, 0x0ec4}, {0x0ec6, 0x0ec6}, {0x0edc, 0x0edf}, {0x0f00, 0x0f00},
  {0x0f40, 0x0f47}, {0x0f49, 0x0f6c}, {0x0f88, 0x0f8c}, {0x1000, 0x102a},
  {0x103f, 0x103f}, {0x1050, 0x1055}, {0x105a, 0x105d}, {0x1061, 0x1061},
  {0x1065, 0x1066}, {0x106e, 0x1070}, {0x1075, 0x1081}, {0x108e, 0x108e},
  {0x10a0, 0x10c5}, {0x10c7, 0x10c7}, {0x10cd, 0x10cd}, {0x10d0, 0x10fa},
  {0x10fc, 0x1248}, {0x124a, 0x124d}, {0x1250, 0x1256}, {0x1258, 0x1258},
  {0x125a, 0x125d}, {0x1260, 0x1288}, {0x128a, 0x128d}, {0x1290, 0x12b0},
  {0x12b2, 0x12b5}, {0x12b8, 0x12be}, {0x12c0, 0x12c0}, {0x12c2, 0x12c5},
  {0x12c8, 0x12d6}, {0x12d8, 0x1310}, {0x1312, 0x1315}, {0x1318, 0x135a},
  {0x1380, 0x138f}, {0x13a0, 0x13f5}, {0x13f8, 0x13fd}, {0x1401, 0x166c},
  {0x166f, 0x167f}, {0x1681, 0x169a}, {0x16a0, 0x16ea}, {0x16f1, 0x16f8},
  {0x1700, 0x1711}, {0x171f, 0x1731}, {0x1740, 0x1751}, {0x1760, 0x176c},
  {0x176e, 0x1770}, {0x1780, 0x17b3}, {0x17d7, 0x17d7}, {0x17dc, 0x17dc},
  {0x1820, 0x1878}, {0x1880, 0x1884}, {0x1887, 0x18a8}, {0x18aa, 0x18aa},
  {0x18b0, 0x18f5}, {0x1900, 0x191e}, {0x1950, 0x196d}, {0x1970, 0x1974},
  {0x1980, 0x19ab}, {0x19b0, 0x19c9}, {0x1a00, 0x1a16}, {0x1a20, 0x1a54},
  {0x1aa7, 0x1aa7}, {0x1b05, 0x1b33}, {0x1b45, 0x1b4c}, {0x1b83, 0x1ba0},
  {0x1bae, 0x1baf}, {0x1bba, 0x1be5}, {0x1c00, 0x1c23}, {0x1c4d, 0x1c4f},
  {0x1c5a, 0x1c7d}, {0x1c80, 0x1c8a}, {0x1c90, 0x1cba}, {0x1cbd, 0x1cbf},
  {0x1ce9, 0x1cec}, {0x1cee, 0x1cf3}, {0x1cf5, 0x1cf6}, {0x1cfa, 0x1cfa},
  {0x1d00, 0x1dbf}, {0x1e00, 0x1f15}, {0x1f18, 0x1f1d}, {0x1f20, 0x1f45},
  {0x1f48, 0x1f4d}, {0x1f50, 0x1f57}, {0x1f59, 0x1f59}, {0x1f5b, 0x1f5b},
  {0x1f5d, 0x1f5d}, {0x1f5f, 0x1f7d}, {0x1f80, 0x1fb4}, {0x1fb6, 0x1fbc},
  {0x1fbe, 0x1fbe}, {0x1fc2, 0x1fc4}, {0x1fc6, 0x1fcc}, {0x1fd0, 0x1fd3},
  {0x1fd6, 0x1fdb}, {0x1fe0, 0x1fec}, {0x1ff2, 0x1ff4}, {0x1ff6, 0x1ffc},
  {0x2071, 0x2071}, {0x207f, 0x207f}, {0x2090, 0x209c}, {0x2102, 0x2102},
  {0x2107, 0x2107}, {0x210a, 0x2113}, {0x2115, 0x2115}, {0x2119, 0x211d},
  {0x2124, 0x2124}, {0x2126, 0x2126}, {0x2128, 0x2128}, {0x212a, 0x212d},
  {0x212f, 0x2139}, {0x213c, 0x213f}, {0x2145, 0x2149}, {0x214e, 0x214e},
  {0x2183, 0x2184}, {0x2c00, 0x2ce4}, {0x2ceb, 0x2cee}, {0x2cf2, 0x2cf3},
  {0x2d00, 0x2d25}, {0x2d27, 0x2d27}, {0x2d2d, 0x2d2d}, {0x2d30, 0x2d67},
  {0x2d6f, 0x2d6f}, {0x2d80, 0x2d96}, {0x2da0, 0x2da6}, {0x2da8, 0x2dae},
  {0x2db0, 0x2db6}, {0x2db8, 0x2dbe}, {0x2dc0, 0x2dc6}, {0x2dc8, 0x2dce},
  {0x2dd0, 0x2dd6}, {0x2dd8, 0x2dde}, {0x2e2f, 0x2e2f}, {0x3005, 0x3006},
  {0x3031, 0x3035}, {0x303b, 0x303c}, {0x3041, 0x3096}, {0x309d, 0x309f},
  {0x30a1, 0x30fa}, {0x30fc, 0x30ff}, {0x3105, 0x312f}, {0x3131, 0x318e},
  {0x31a0, 0x31bf}, {0x31f0, 0x31ff}, {0x3400, 0x4dbf}, {0x4e00, 0xa48c},
  {0xa4d0, 0xa4fd}, {0xa500, 0xa60c}, {0xa610, 0xa61f}, {0xa62a, 0xa62b},
  {0xa640, 0xa66e}, {0xa67f, 0xa69d}, {0xa6a0, 0xa6e5}, {0xa717, 0xa71f},
  {0xa722, 0xa788}, {0xa78b, 0xa7dc}, {0xa7f1, 0xa801}, {0xa803, 0xa805},
  {0xa807, 0xa80a}, {0xa80c, 0xa822}, {0xa840, 0xa873}, {0xa882, 0xa8b3},
  {0xa8f2, 0xa8f7}, {0xa8fb, 0xa8fb}, {0xa8fd, 0xa8fe}, {0xa90a, 0xa925},
  {0xa930, 0xa946}, {0xa960, 0xa97c}, {0xa984, 0xa9b2}, {0xa9cf, 0xa9cf},
  {0xa9e0, 0xa9e4}, {0xa9e6, 0xa9ef}, {0xa9fa, 0xa9fe}, {0xaa00, 0xaa28},
  {0xaa40, 0xaa42}, {0xaa44, 0xaa4b}, {0xaa60, 0xaa76}, {0xaa7a, 0xaa7a},
  {0xaa7e, 0xaaaf}, {0xaab1, 0xaab1}, {0xaab5, 0xaab6}, {0xaab9, 0xaabd},
  {0xaac0, 0xaac0}, {0xaac2, 0xaac2}, {0xaadb, 0xaadd}, {0xaae0, 0xaaea},
  {0xaaf2, 0xaaf4}, {0xab01, 0xab06}, {0xab09, 0xab0e}, {0xab11, 0xab16},
  {0xab20, 0xab26}, {0xab28, 0xab2e}, {0xab30, 0xab5a}, {0xab5c, 0xab69},
  {0xab70, 0xabe2}, {0xac00, 0xd7a3}, {0xd7b0, 0xd7c6}, {0xd7cb, 0xd7fb},
  {0xf900, 0xfa6d}, {0xfa70, 0xfad9}, {0xfb00, 0xfb06}, {0xfb13, 0xfb17},
  {0xfb1d, 0xfb1d}, {0xfb1f, 0xfb28}, {0xfb2a, 0xfb36}, {0xfb38, 0xfb3c},
  {0xfb3e, 0xfb3e}, {0xfb40, 0xfb41}, {0xfb43, 0xfb44}, {0xfb46, 0xfbb1},
  {0xfbd3, 0xfd3d}, {0xfd50, 0xfd8f}, {0xfd92, 0xfdc7}, {0xfdf0, 0xfdfb},
  {0xfe70, 0xfe74}, {0xfe76, 0xfefc}, {0xff21, 0xff3a}, {0xff41, 0xff5a},
  {0xff66, 0xffbe}, {0xffc2, 0xffc7}, {0xffca, 0xffcf}, {0xffd2, 0xffd7},
  {0xffda, 0xffdc}, {0x010000, 0x01000b}, {0x01000d, 0x010026},
  {0x010028, 0x01003a}, {0x01003c, 0x01003d}, {0x01003f, 0x01004d},
  {0x010050, 0x01005d}, {0x010080, 0x0100fa}, {0x010280, 0x01029c},
  {0x0102a0, 0x0102d0}, {0x010300, 0x01031f}, {0x01032d, 0x010340},
  {0x010342, 0x010349}, {0x010350, 0x010375}, {0x010380, 0x01039d},
  {0x0103a0, 0x0103c3}, {0x0103c8, 0x0103cf}, {0x010400, 0x01049d},
  {0x0104b0, 0x0104d3}, {0x0104d8, 0x0104fb}, {0x010500, 0x010527},
  {0x010530, 0x010563}, {0x010570, 0x01057a}, {0x01057c, 0x01058a},
  {0x01058c, 0x010592}, {0x010594, 0x010595}, {0x010597, 0x0105a1},
  {0x0105a3, 0x0105b1}, {0x0105b3, 0x0105b9}, {0x0105bb, 0x0105bc},
  {0x0105c0, 0x0105f3}, {0x010600, 0x010736}, {0x010740, 0x010755},
  {0x010760, 0x010767}, {0x010780, 0x010785}, {0x010787, 0x0107b0},
  {0x0107b2, 0x0107ba}, {0x010800, 0x010805}, {0x010808, 0x010808},
  {0x01080a, 0x010835}, {0x010837, 0x010838}, {0x01083c, 0x01083c},
  {0x01083f, 0x010855}, {0x010860, 0x010876}, {0x010880, 0x01089e},
  {0x0108e0, 0x0108f2}, {0x0108f4, 0x0108f5}, {0x010900, 0x010915},
  {0x010920, 0x010939}, {0x010940, 0x010959}, {0x010980, 0x0109b7},
  {0x0109be, 0x0109bf}, {0x010a00, 0x010a00}, {0x010a10, 0x010a13},
  {0x010a15, 0x010a17}, {0x010a19, 0x010a35}, {0x010a60, 0x010a7c},
  {0x010a80, 0x010a9c}, {0x010ac0, 0x010ac7}, {0x010ac9, 0x010ae4},
  {0x010b00, 0x010b35}, {0x010b40, 0x010b55}, {0x010b60, 0x010b72},
  {0x010b80, 0x010b91}, {0x010c00, 0x010c48}, {0x010c80, 0x010cb2},
  {0x010cc0, 0x010cf2}, {0x010d00, 0x010d23}, {0x010d4a, 0x010d65},
  {0x010d6f, 0x010d85}, {0x010e80, 0x010ea9}, {0x010eb0, 0x010eb1},
  {0x010ec2, 0x010ec7}, {0x010f00, 0x010f1c}, {0x010f27, 0x010f27},
  {0x010f30, 0x010f45}, {0x010f70, 0x010f81}, {0x010fb0, 0x010fc4},
  {0x010fe0, 0x010ff6}, {0x011003, 0x011037}, {0x011071, 0x011072},
  {0x011075, 0x011075}, {0x011083, 0x0110af}, {0x0110d0, 0x0110e8},
  {0x011103, 0x011126}, {0x011144, 0x011144}, {0x011147, 0x011147},
  {0x011150, 0x011172}, {0x011176, 0x011176}, {0x011183, 0x0111b2},
  {0x0111c1, 0x0111c4}, {0x0111da, 0x0111da}, {0x0111dc, 0x0111dc},
  {0x011200, 0x011211}, {0x011213, 0x01122b}, {0x01123f, 0x011240},
  {0x011280, 0x011286}, {0x011288, 0x011288}, {0x01128a, 0x01128d},
  {0x01128f, 0x01129d}, {0x01129f, 0x0112a8}, {0x0112b0, 0x0112de},
  {0x011305, 0x01130c}, {0x01130f, 0x011310}, {0x011313, 0x011328},
  {0x01132a, 0x011330}, {0x011332, 0x011333}, {0x011335, 0x011339},
  {0x01133d, 0x01133d}, {0x011350, 0x011350}, {0x01135d, 0x011361},
  {0x011380, 0x011389}, {0x01138b, 0x01138b}, {0x01138e, 0x01138e},
  {0x011390, 0x0113b5}, {0x0113b7, 0x0113b7}, {0x0113d1, 0x0113d1},
  {0x0113d3, 0x0113d3}, {0x011400, 0x011434}, {0x011447, 0x01144a},
  {0x01145f, 0x011461}, {0x011480, 0x0114af}, {0x0114c4, 0x0114c5},
  {0x0114c7, 0x0114c7}, {0x011580, 0x0115ae}, {0x0115d8, 0x0115db},
  {0x011600, 0x01162f}, {0x011644, 0x011644}, {0x011680, 0x0116aa},
  {0x0116b8, 0x0116b8}, {0x011700, 0x01171a}, {0x011740, 0x011746},
  {0x011800, 0x01182b}, {0x0118a0, 0x0118df}, {0x0118ff, 0x011906},
  {0x011909, 0x011909}, {0x01190c, 0x011913}, {0x011915, 0x011916},
  {0x011918, 0x01192f}, {0x01193f, 0x01193f}, {0x011941, 0x011941},
  {0x0119a0, 0x0119a7}, {0x0119aa, 0x0119d0}, {0x0119e1, 0x0119e1},
  {0x0119e3, 0x0119e3}, {0x011a00, 0x011a00}, {0x011a0b, 0x011a32},
  {0x011a3a, 0x011a3a}, {0x011a50, 0x011a50}, {0x011a5c, 0x011a89},
  {0x011a9d, 0x011a9d}, {0x011ab0, 0x011af8}, {0x011bc0, 0x011be0},
  {0x011c00, 0x011c08}, {0x011c0a, 0x011c2e}, {0x011c40, 0x011c40},
  {0x011c72, 0x011c8f}, {0x011d00, 0x011d06}, {0x011d08, 0x011d09},
  {0x011d0b, 0x011d30}, {0x011d46, 0x011d46}, {0x011d60, 0x011d65},
  {0x011d67, 0x011d68}, {0x011d6a, 0x011d89}, {0x011d98, 0x011d98},
  {0x011db0, 0x011ddb}, {0x011ee0, 0x011ef2}, {0x011f02, 0x011f02},
  {0x011f04, 0x011f10}, {0x011f12, 0x011f33}, {0x011fb0, 0x011fb0},
  {0x012000, 0x012399}, {0x012480, 0x012543}, {0x012f90, 0x012ff0},
  {0x013000, 0x01342f}, {0x013441, 0x013446}, {0x013460, 0x0143fa},
  {0x014400, 0x014646}, {0x016100, 0x01611d}, {0x016800, 0x016a38},
  {0x016a40, 0x016a5e}, {0x016a70, 0x016abe}, {0x016ad0, 0x016aed},
  {0x016b00, 0x016b2f}, {0x016b40, 0x016b43}, {0x016b63, 0x016b77},
  {0x016b7d, 0x016b8f}, {0x016d40, 0x016d6c}, {0x016e40, 0x016e7f},
  {0x016ea0, 0x016eb8}, {0x016ebb, 0x016ed3}, {0x016f00, 0x016f4a},
  {0x016f50, 0x016f50}, {0x016f93, 0x016f9f}, {0x016fe0, 0x016fe1},
  {0x016fe3, 0x016fe3}, {0x016ff2, 0x016ff3}, {0x017000, 0x018cd5},
  {0x018cff, 0x018d1e}, {0x018d80, 0x018df2}, {0x01aff0, 0x01aff3},
  {0x01aff5, 0x01affb}, {0x01affd, 0x01affe}, {0x01b000, 0x01b122},
  {0x01b132, 0x01b132}, {0x01b150, 0x01b152}, {0x01b155, 0x01b155},
  {0x01b164, 0x01b167}, {0x01b170, 0x01b2fb}, {0x01bc00, 0x01bc6a},
  {0x01bc70, 0x01bc7c}, {0x01bc80, 0x01bc88}, {0x01bc90, 0x01bc99},
  {0x01d400, 0x01d454}, {0x01d456, 0x01d49c}, {0x01d49e, 0x01d49f},
  {0x01d4a2, 0x01d4a2}, {0x01d4a5, 0x01d4a6}, {0x01d4a9, 0x01d4ac},
  {0x01d4ae, 0x01d4b9}, {0x01d4bb, 0x01d4bb}, {0x01d4bd, 0x01d4c3},
  {0x01d4c5, 0x01d505}, {0x01d507, 0x01d50a}, {0x01d50d, 0x01d514},
  {0x01d516, 0x01d51c}, {0x01d51e, 0x01d539}, {0x01d53b, 0x01d53e},
  {0x01d540, 0x01d544}, {0x01d546, 0x01d546}, {0x01d54a, 0x01d550},
  {0x01d552, 0x01d6a5}, {0x01d6a8, 0x01d6c0}, {0x01d6c2, 0x01d6da},
  {0x01d6dc, 0x01d6fa}, {0x01d6fc, 0x01d714}, {0x01d716, 0x01d734},
  {0x01d736, 0x01d74e}, {0x01d750, 0x01d76e}, {0x01d770, 0x01d788},
  {0x01d78a, 0x01d7a8}, {0x01d7aa, 0x01d7c2}, {0x01d7c4, 0x01d7cb},
  {0x01df00, 0x01df1e}, {0x01df25, 0x01df2a}, {0x01e030, 0x01e06d},
  {0x01e100, 0x01e12c}, {0x01e137, 0x01e13d}, {0x01e14e, 0x01e14e},
  {0x01e290, 0x01e2ad}, {0x01e2c0, 0x01e2eb}, {0x01e4d0, 0x01e4eb},
  {0x01e5d0, 0x01e5ed}, {0x01e5f0, 0x01e5f0}, {0x01e6c0, 0x01e6de},
  {0x01e6e0, 0x01e6e2}, {0x01e6e4, 0x01e6e5}, {0x01e6e7, 0x01e6ed},
  {0x01e6f0, 0x01e6f4}, {0x01e6fe, 0x01e6ff}, {0x01e7e0, 0x01e7e6},
  {0x01e7e8, 0x01e7eb}, {0x01e7ed, 0x01e7ee}, {0x01e7f0, 0x01e7fe},
  {0x01e800, 0x01e8c4}, {0x01e900, 0x01e943}, {0x01e94b, 0x01e94b},
  {0x01ee00, 0x01ee03}, {0x01ee05, 0x01ee1f}, {0x01ee21, 0x01ee22},
  {0x01ee24, 0x01ee24}, {0x01ee27, 0x01ee27}, {0x01ee29, 0x01ee32},
  {0x01ee34, 0x01ee37}, {0x01ee39, 0x01ee39}, {0x01ee3b, 0x01ee3b},
  {0x01ee42, 0x01ee42}, {0x01ee47, 0x01ee47}, {0x01ee49, 0x01ee49},
  {0x01ee4b, 0x01ee4b}, {0x01ee4d, 0x01ee4f}, {0x01ee51, 0x01ee52},
  {0x01ee54, 0x01ee54}, {0x01ee57, 0x01ee57}, {0x01ee59, 0x01ee59},
  {0x01ee5b, 0x01ee5b}, {0x01ee5d, 0x01ee5d}, {0x01ee5f, 0x01ee5f},
  {0x01ee61, 0x01ee62}, {0x01ee64, 0x01ee64}, {0x01ee67, 0x01ee6a},
  {0x01ee6c, 0x01ee72}, {0x01ee74, 0x01ee77}, {0x01ee79, 0x01ee7c},
  {0x01ee7e, 0x01ee7e}, {0x01ee80, 0x01ee89}, {0x01ee8b, 0x01ee9b},
  {0x01eea1, 0x01eea3}, {0x01eea5, 0x01eea9}, {0x01eeab, 0x01eebb},
  {0x020000, 0x02a6df}, {0x02a700, 0x02b81d}, {0x02b820, 0x02cead},
  {0x02ceb0, 0x02ebe0}, {0x02ebf0, 0x02ee5d}, {0x02f800, 0x02fa1d},
  {0x030000, 0x03134a}, {0x031350, 0x033479},
};

static const struct urange uprop_n_ranges[] = {
  {0x0030, 0x0039}, {0x00b2, 0x00b3}, {0x00b9, 0x00b9}, {0x00bc, 0x00be},
  {0x0660, 0x0669}, {0x06f0, 0x06f9}, {0x07c0, 0x07c9}, {0x0966, 0x096f},
  {0x09e6, 0x09ef}, {0x09f4, 0x09f9}, {0x0a66, 0x0a6f}, {0x0ae6, 0x0aef},
  {0x0b66, 0x0b6f}, {0x0b72, 0x0b77}, {0x0be6, 0x0bf2}, {0x0c66, 0x0c6f},
  {0x0c78, 0x0c7e}, {0x0ce6, 0x0cef}, {0x0d58, 0x0d5e}, {0x0d66, 0x0d78},
  {0x0de6, 0x0def}, {0x0e50, 0x0e59}, {0x0ed0, 0x0ed9}, {0x0f20, 0x0f33},
  {0x1040, 0x1049}, {0x1090, 0x1099}, {0x1369, 0x137c}, {0x16ee, 0x16f0},
  {0x17e0, 0x17e9}, {0x17f0, 0x17f9}, {0x1810, 0x1819}, {0x1946, 0x194f},
  {0x19d0, 0x19da}, {0x1a80, 0x1a89}, {0x1a90, 0x1a99}, {0x1b50, 0x1b59},
  {0x1bb0, 0x1bb9}, {0x1c40, 0x1c49}, {0x1c50, 0x1c59}, {0x2070, 0x2070},
  {0x2074, 0x2079}, {0x2080, 0x2089}, {0x2150, 0x2182}, {0x2185, 0x2189},
  {0x2460, 0x249b}, {0x24ea, 0x24ff}, {0x2776, 0x2793}, {0x2cfd, 0x2cfd},
  {0x3007, 0x3007}, {0x3021, 0x3029}, {0x3038, 0x303a}, {0x3192, 0x3195},
  {0x3220, 0x3229}, {0x3248, 0x324f}, {0x3251, 0x325f}, {0x3280, 0x3289},
  {0x32b1, 0x32bf}, {0xa620, 0xa629}, {0xa6e6, 0xa6ef}, {0xa830, 0xa835},
  {0xa8d0, 0xa8d9}, {0xa900, 0xa909}, {0xa9d0, 0xa9d9}, {0xa9f0, 0xa9f9},
  {0xaa50, 0xaa59}, {0xabf0, 0xabf9}, {0xff10, 0xff19},
  {0x010107, 0x010133}, {0x010140, 0x010178}, {0x01018a, 0x01018b},
  {0x0102e1, 0x0102fb}, {0x010320, 0x010323}, {0x010341, 0x010341},
  {0x01034a, 0x01034a}, {0x0103d1, 0x0103d5}, {0x0104a0, 0x0104a9},
  {0x010858, 0x01085f}, {0x010879, 0x01087f}, {0x0108a7, 0x0108af},
  {0x0108fb, 0x0108ff}, {0x010916, 0x01091b}, {0x0109bc, 0x0109bd},
  {0x0109c0, 0x0109cf}, {0x0109d2, 0x0109ff}, {0x010a40, 0x010a48},
  {0x010a7d, 0x010a7e}, {0x010a9d, 0x010a9f}, {0x010aeb, 0x010aef},
  {0x010b58, 0x010b5f}, {0x010b78, 0x010b7f}, {0x010ba9, 0x010baf},
  {0x010cfa, 0x010cff}, {0x010d30, 0x010d39}, {0x010d40, 0x010d49},
  {0x010e60, 0x010e7e}, {0x010f1d, 0x010f26}, {0x010f51, 0x010f54},
  {0x010fc5, 0x010fcb}, {0x011052, 0x01106f}, {0x0110f0, 0x0110f9},
  {0x011136, 0x01113f}, {0x0111d0, 0x0111d9}, {0x0111e1, 0x0111f4},
  {0x0112f0, 0x0112f9}, {0x011450, 0x011459}, {0x0114d0, 0x0114d9},
  {0x011650, 0x011659}, {0x0116c0, 0x0116c9}, {0x0116d0, 0x0116e3},
  {0x011730, 0x01173b}, {0x0118e0, 0x0118f2}, {0x011950, 0x011959},
  {0x011bf0, 0x011bf9}, {0x011c50, 0x011c6c}, {0x011d50, 0x011d59},
  {0x011da0, 0x011da9}, {0x011de0, 0x011de9}, {0x011f50, 0x011f59},
  {0x011fc0, 0x011fd4}, {0x012400, 0x01246e}, {0x016130, 0x016139},
  {0x016a60, 0x016a69}, {0x016ac0, 0x016ac9}, {0x016b50, 0x016b59},
  {0x016b5b, 0x016b61}, {0x016d70, 0x016d79}, {0x016e80, 0x016e96},
  {0x016ff4, 0x016ff6}, {0x01ccf0, 0x01ccf9}, {0x01d2c0, 0x01d2d3},
  {0x01d2e0, 0x01d2f3}, {0x01d360, 0x01d378}, {0x01d7ce, 0x01d7ff},
  {0x01e140, 0x01e149}, {0x01e2f0, 0x01e2f9}, {0x01e4f0, 0x01e4f9},
  {0x01e5f1, 0x01e5fa}, {0x01e8c7, 0x01e8cf}, {0x01e950, 0x01e959},
  {0x01ec71, 0x01ecab}, {0x01ecad, 0x01ecaf}, {0x01ecb1, 0x01ecb4},
  {0x01ed01, 0x01ed2d}, {0x01ed2f, 0x01ed3d}, {0x01f100, 0x01f10c},
  {0x01fbf0, 0x01fbf9},
};

static const struct urange uprop_nd_ranges[] = {
  {0x0030, 0x0039}, {0x0660, 0x0669}, {0x06f0, 0x06f9}, {0x07c0, 0x07c9},
  {0x0966, 0x096f}, {0x09e6, 0x09ef}, {0x0a66, 0x0a6f}, {0x0ae6, 0x0aef},
  {0x0b66, 0x0b6f}, {0x0be6, 0x0bef}, {0x0c66, 0x0c6f}, {0x0ce6, 0x0cef},
  {0x0d66, 0x0d6f}, {0x0de6, 0x0def}, {0x0e50, 0x0e59}, {0x0ed0, 0x0ed9},
  {0x0f20, 0x0f29}, {0x1040, 0x1049}, {0x1090, 0x1099}, {0x17e0, 0x17e9},
  {0x1810, 0x1819}, {0x1946, 0x194f}, {0x19d0, 0x19d9}, {0x1a80, 0x1a89},
  {0x1a90, 0x1a99}, {0x1b50, 0x1b59}, {0x1bb0, 0x1bb9}, {0x1c40, 0x1c49},
  {0x1c50, 0x1c59}, {0xa620, 0xa629}, {0xa8d0, 0xa8d9}, {0xa900, 0xa909},
  {0xa9d0, 0xa9d9}, {0xa9f0, 0xa9f9}, {0xaa50, 0xaa59}, {0xabf0, 0xabf9},
  {0xff10, 0xff19}, {0x0104a0, 0x0104a9}, {0x010d30, 0x010d39},
  {0x010d40, 0x010d49}, {0x011066, 0x01106f}, {0x0110f0, 0x0110f9},
  {0x011136, 0x01113f}, {0x0111d0, 0x0111d9}, {0x0112f0, 0x0112f9},
  {0x011450, 0x011459}, {0x0114d0, 0x0114d9}, {0x011650, 0x011659},
  {0x0116c0, 0x0116c9}, {0x0116d0, 0x0116e3}, {0x011730, 0x011739},
  {0x0118e0, 0x0118e9}, {0x011950, 0x011959}, {0x011bf0, 0x011bf9},
  {0x011c50, 0x011c59}, {0x011d50, 0x011d59}, {0x011da0, 0x011da9},
  {0x011de0, 0x011de9}, {0x011f50, 0x011f59}, {0x016130, 0x016139},
  {0x016a60, 0x016a69}, {0x016ac0, 0x016ac9}, {0x016b50, 0x016b59},
  {0x016d70, 0x016d79}, {0x01ccf0, 0x01ccf9}, {0x01d7ce, 0x01d7ff},
  {0x01e140, 0x01e149}, {0x01e2f0, 0x01e2f9}, {0x01e4f0, 0x01e4f9},
  {0x01e5f1, 0x01e5fa}, {0x01e950, 0x01e959}, {0x01fbf0, 0x01fbf9},
};

static const struct urange uprop_lu_ranges[] = {
  {0x0041, 0x005a}, {0x00c0, 0x00d6}, {0x00d8, 0x00de}, {0x0100, 0x0100},
  {0x0102, 0x0102}, {0x0104, 0x0104}, {0x0106, 0x0106}, {0x0108, 0x0108},
  {0x010a, 0x010a}, {0x010c, 0x010c}, {0x010e, 0x010e}, {0x0110, 0x0110},
  {0x0112, 0x0112}, {0x0114, 0x0114}, {0x0116, 0x0116}, {0x0118, 0x0118},
  {0x011a, 0x011a}, {0x011c, 0x011c}, {0x011e, 0x011e}, {0x0120, 0x0120},
  {0x0122, 0x0122}, {0x0124, 0x0124}, {0x0126, 0x0126}, {0x0128, 0x0128},
  {0x012a, 0x012a}, {0x012c, 0x012c}, {0x012e, 0x012e}, {0x0130, 0x0130},
  {0x0132, 0x0132}, {0x0134, 0x0134}, {0x0136, 0x0136}, {0x0139, 0x0139},
  {0x013b, 0x013b}, {0x013d, 0x013d}, {0x013f, 0x013f}, {0x0141, 0x0141},
  {0x0143, 0x0143}, {0x0145, 0x0145}, {0x0147, 0x0147}, {0x014a, 0x014a},
  {0x014c, 0x014c}, {0x014e, 0x014e}, {0x0150, 0x0150}, {0x0152, 0x0152},
  {0x0154, 0x0154}, {0x0156, 0x0156}, {0x0158, 0x0158}, {0x015a, 0x015a},
  {0x015c, 0x015c}, {0x015e, 0x015e}, {0x0160, 0x0160}, {0x0162, 0x0162},
  {0x0164, 0x0164}, {0x0166, 0x0166}, {0x0168, 0x0168}, {0x016a, 0x016a},
  {0x016c, 0x016c}, {0x016e, 0x016e}, {0x0170, 0x0170}, {0x0172, 0x0172},
  {0x0174, 0x0174}, {0x0176, 0x0176}, {0x0178, 0x0179}, {0x017b, 0x017b},
  {0x017d, 0x017d}, {0x0181, 0x0182}, {0x0184, 0x0184}, {0x0186, 0x0187},
  {0x0189, 0x018b}, {0x018e, 0x0191}, {0x0193, 0x0194}, {0x0196, 0x0198},
  {0x019c, 0x019d}, {0x019f, 0x01a0}, {0x01a2, 0x01a2}, {0x01a4, 0x01a4},
  {0x01a6, 0x01a7}, {0x01a9, 0x01a9}, {0x01ac, 0x01ac}, {0x01ae, 0x01af},
  {0x01b1, 0x01b3}, {0x01b5, 0x01b5}, {0x01b7, 0x01b8}, {0x01bc, 0x01bc},
  {0x01c4, 0x01c4}, {0x01c7, 0x01c7}, {0x01ca, 0x01ca}, {0x01cd, 0x01cd},
  {0x01cf, 0x01cf}, {0x01d1, 0x01d1}, {0x01d3, 0x01d3}, {0x01d5, 0x01d5},
  {0x01d7, 0x01d7}, {0x01d9, 0x01d9}, {0x01db, 0x01db}, {0x01de, 0x01de},
  {0x01e0, 0x01e0}, {0x01e2, 0x01e2}, {0x01e4, 0x01e4}, {0x01e6, 0x01e6},
  {0x01e8, 0x01e8}, {0x01ea, 0x01ea}, {0x01ec, 0x01ec}, {0x01ee, 0x01ee},
  {0x01f1, 0x01f1}, {0x01f4, 0x01f4}, {0x01f6, 0x01f8}, {0x01fa, 0x01fa},
  {0x01fc, 0x01fc}, {0x01fe, 0x01fe}, {0x0200, 0x0200}, {0x0202, 0x0202},
  {0x0204, 0x0204}, {0x0206, 0x0206}, {0x0208, 0x0208}, {0x020a, 0x020a},
  {0x020c, 0x020c}, {0x020e, 0x020e}, {0x0210, 0x0210}, {0x0212, 0x0212},
  {0x0214, 0x0214}, {0x0216, 0x0216}, {0x0218, 0x0218}, {0x021a, 0x021a},
  {0x021c, 0x021c}, {0x021e, 0x021e}, {0x0220, 0x0220}, {0x0222, 0x0222},
  {0x0224, 0x0224}, {0x0226, 0x0226}, {0x0228, 0x0228}, {0x022a, 0x022a},
  {0x022c, 0x022c}, {0x022e, 0x022e}, {0x0230, 0x0230}, {0x0232, 0x0232},
  {0x023a, 0x023b}, {0x023d, 0x023e}, {0x0241, 0x0241}, {0x0243, 0x0246},
  {0x0248, 0x0248}, {0x024a, 0x024a}, {0x024c, 0x024c}, {0x024e, 0x024e},
  {0x0370, 0x0370}, {0x0372, 0x0372}, {0x0376, 0x0376}, {0x037f, 0x037f},
  {0x0386, 0x0386}, {0x0388, 0x038a}, {0x038c, 0x038c}, {0x038e, 0x038f},
  {0x0391, 0x03a1}, {0x03a3, 0x03ab}, {0x03cf, 0x03cf}, {0x03d2, 0x03d4},
  {0x03d8, 0x03d8}, {0x03da, 0x03da}, {0x03dc, 0x03dc}, {0x03de, 0x03de},
  {0x03e0, 0x03e0}, {0x03e2, 0x03e2}, {0x03e4, 0x03e4}, {0x03e6, 0x03e6},
  {0x03e8, 0x03e8}, {0x03ea, 0x03ea}, {0x03ec, 0x03ec}, {0x03ee, 0x03ee},
  {0x03f4, 0x03f4}, {0x03f7, 0x03f7}, {0x03f9, 0x03fa}, {0x03fd, 0x042f},
  {0x0460, 0x0460}, {0x0462, 0x0462}, {0x0464, 0x0464}, {0x0466, 0x0466},
  {0x0468, 0x0468}, {0x046a, 0x046a}, {0x046c, 0x046c}, {0x046e, 0x046e},
  {0x0470, 0x0470}, {0x0472, 0x0472}, {0x0474, 0x0474}, {0x0476, 0x0476},
  {0x0478, 0x0478}, {0x047a, 0x047a}, {0x047c, 0x047c}, {0x047e, 0x047e},
  {0x0480, 0x0480}, {0x048a, 0x048a}, {0x048c, 0x048c}, {0x048e, 0x048e},
  {0x0490, 0x0490}, {0x0492, 0x0492}, {0x0494, 0x0494}, {0x0496, 0x0496},
  {0x0498, 0x0498}, {0x049a, 0x049a}, {0x049c, 0x049c}, {0x049e, 0x049e},
  {0x04a0, 0x04a0}, {0x04a2, 0x04a2}, {0x04a4, 0x04a4}, {0x04a6, 0x04a6},
  {0x04a8, 0x04a8}, {0x04aa, 0x04aa}, {0x04ac, 0x04ac}, {0x04ae, 0x04ae},
  {0x04b0, 0x04b0}, {0x04b2, 0x04b2}, {0x04b4, 0x04b4}, {0x04b6, 0x04b6},
  {0x04b8, 0x04b8}, {0x04ba, 0x04ba}, {0x04bc, 0x04bc}, {0x04be, 0x04be},
  {0x04c0, 0x04c1}, {0x04c3, 0x04c3}, {0x04c5, 0x04c5}, {0x04c7, 0x04c7},
  {0x04c9, 0x04c9}, {0x04cb, 0x04cb}, {0x04cd, 0x04cd}, {0x04d0, 0x04d0},
  {0x04d2, 0x04d2}, {0x04d4, 0x04d4}, {0x04d6, 0x04d6}, {0x04d8, 0x04d8},
  {0x04da, 0x04da}, {0x04dc, 0x04dc}, {0x04de, 0x04de}, {0x04e0, 0x04e0},
  {0x04e2, 0x04e2}, {0x04e4, 0x04e4}, {0x04e6, 0x04e6}, {0x04e8, 0x04e8},
  {0x04ea, 0x04ea}, {0x04ec, 0x04ec}, {0x04ee, 0x04ee}, {0x04f0, 0x04f0},
  {0x04f2, 0x04f2}, {0x04f4, 0x04f4}, {0x04f6, 0x04f6}, {0x04f8, 0x04f8},
  {0x04fa, 0x04fa}, {0x04fc, 0x04fc}, {0x04fe, 0x04fe}, {0x0500, 0x0500},
  {0x0502, 0x0502}, {0x0504, 0x0504}, {0x0506, 0x0506}, {0x0508, 0x0508},
  {0x050a, 0x050a}, {0x050c, 0x050c}, {0x050e, 0x050e}, {0x0510, 0x0510},
  {0x0512, 0x0512}, {0x0514, 0x0514}, {0x0516, 0x0516}, {0x0518, 0x0518},
  {0x051a, 0x051a}, {0x051c, 0x051c}, {0x051e, 0x051e}, {0x0520, 0x0520},
  {0x0522, 0x0522}, {0x0524, 0x0524}, {0x0526, 0x0526}, {0x0528, 0x0528},
  {0x052a, 0x052a}, {0x052c, 0x052c}, {0x052e, 0x052e}, {0x0531, 0x0556},
  {0x10a0, 0x10c5}, {0x10c7, 0x10c7}, {0x10cd, 0x10cd}, {0x13a0, 0x13f5},
  {0x1c89, 0x1c89}, {0x1c90, 0x1cba}, {0x1cbd, 0x1cbf}, {0x1e00, 0x1e00},
  {0x1e02, 0x1e02}, {0x1e04, 0x1e04}, {0x1e06, 0x1e06}, {0x1e08, 0x1e08},
  {0x1e0a, 0x1e0a}, {0x1e0c, 0x1e0c}, {0x1e0e, 0x1e0e}, {0x1e10, 0x1e10},
  {0x1e12, 0x1e12}, {0x1e14, 0x1e14}, {0x1e16, 0x1e16}, {0x1e18, 0x1e18},
  {0x1e1a, 0x1e1a}, {0x1e1c, 0x1e1c}, {0x1e1e, 0x1e1e}, {0x1e20, 0x1e20},
  {0x1e22, 0x1e22}, {0x1e24, 0x1e24}, {0x1e26, 0x1e26}, {0x1e28, 0x1e28},
  {0x1e2a, 0x1e2a}, {0x1e2c, 0x1e2c}, {0x1e2e, 0x1e2e}, {0x1e30, 0x1e30},
  {0x1e32, 0x1e32}, {0x1e34, 0x1e34}, {0x1e36, 0x1e36}, {0x1e38, 0x1e38},
  {0x1e3a, 0x1e3a}, {0x1e3c, 0x1e3c}, {0x1e3e, 0x1e3e}, {0x1e40, 0x1e40},
  {0x1e42, 0x1e42}, {0x1e44, 0x1e44}, {0x1e46, 0x1e46}, {0x1e48, 0x1e48},
  {0x1e4a, 0x1e4a}, {0x1e4c, 0x1e4c}, {0x1e4e, 0x1e4e}, {0x1e50, 0x1e50},
  {0x1e52, 0x1e52}, {0x1e54, 0x1e54}, {0x1e56, 0x1e56}, {0x1e58, 0x1e58},
  {0x1e5a, 0x1e5a}, {0x1e5c, 0x1e5c}, {0x1e5e, 0x1e5e}, {0x1e60, 0x1e60},
  {0x1e62, 0x1e62}, {0x1e64, 0x1e64}, {0x1e66, 0x1e66}, {0x1e68, 0x1e68},
  {0x1e6a, 0x1e6a}, {0x1e6c, 0x1e6c}, {0x1e6e, 0x1e6e}, {0x1e70, 0x1e70},
  {0x1e72, 0x1e72}, {0x1e74, 0x1e74}, {0x1e76, 0x1e76}, {0x1e78, 0x1e78},
  {0x1e7a, 0x1e7a}, {0x1e7c, 0x1e7c}, {0x1e7e, 0x1e7e}, {0x1e80, 0x1e80},
  {0x1e82, 0x1e82}, {0x1e84, 0x1e84}, {0x1e86, 0x1e86}, {0x1e88, 0x1e88},
  {0x1e8a, 0x1e8a}, {0x1e8c, 0x1e8c}, {0x1e8e, 0x1e8e}, {0x1e90, 0x1e90},
  {0x1e92, 0x1e92}, {0x1e94, 0x1e94}, {0x1e9e, 0x1e9e}, {0x1ea0, 0x1ea0},
  {0x1ea2, 0x1ea2}, {0x1ea4, 0x1ea4}, {0x1ea6, 0x1ea6}, {0x1ea8, 0x1ea8},
  {0x1eaa, 0x1eaa}, {0x1eac, 0x1eac}, {0x1eae, 0x1eae}, {0x1eb0, 0x1eb0},
  {0x1eb2, 0x1eb2}, {0x1eb4, 0x1eb4}, {0x1eb6, 0x1eb6}, {0x1eb8, 0x1eb8},
  {0x1eba, 0x1eba}, {0x1ebc, 0x1ebc}, {0x1ebe, 0x1ebe}, {0x1ec0, 0x1ec0},
  {0x1ec2, 0x1ec2}, {0x1ec4, 0x1ec4}, {0x1ec6, 0x1ec6}, {0x1ec8, 0x1ec8},
  {0x1eca, 0x1eca}, {0x1ecc, 0x1ecc}, {0x1ece, 0x1ece}, {0x1ed0, 0x1ed0},
  {0x1ed2, 0x1ed2}, {0x1ed4, 0x1ed4}, {0x1ed6, 0x1ed6}, {0x1ed8, 0x1ed8},
  {0x1eda, 0x1eda}, {0x1edc, 0x1edc}, {0x1ede, 0x1ede}, {0x1ee0, 0x1ee0},
  {0x1ee2, 0x1ee2}, {0x1ee4, 0x1ee4}, {0x1ee6, 0x1ee6}, {0x1ee8, 0x1ee8},
  {0x1eea, 0x1eea}, {0x1eec, 0x1eec}, {0x1eee, 0x1eee}, {0x1ef0, 0x1ef0},
  {0x1ef2, 0x1ef2}, {0x1ef4, 0x1ef4}, {0x1ef6, 0x1ef6}, {0x1ef8, 0x1ef8},
  {0x1efa, 0x1efa}, {0x1efc, 0x1efc}, {0x1efe, 0x1efe}, {0x1f08, 0x1f0f},
  {0x1f18, 0x1f1d}, {0x1f28, 0x1f2f}, {0x1f38, 0x1f3f}, {0x1f48, 0x1f4d},
  {0x1f59, 0x1f59}, {0x1f5b, 0x1f5b}, {0x1f5d, 0x1f5d}, {0x1f5f, 0x1f5f},
  {0x1f68, 0x1f6f}, {0x1fb8, 0x1fbb}, {0x1fc8, 0x1fcb}, {0x1fd8, 0x1fdb},
  {0x1fe8, 0x1fec}, {0x1ff8, 0x1ffb}, {0x2102, 0x2102}, {0x2107, 0x2107},
  {0x210b, 0x210d}, {0x2110, 0x2112}, {0x2115, 0x2115}, {0x2119, 0x211d},
  {0x2124, 0x2124}, {0x2126, 0x2126}, {0x2128, 0x2128}, {0x212a, 0x212d},
  {0x2130, 0x2133}, {0x213e, 0x213f}, {0x2145, 0x2145}, {0x2183, 0x2183},
  {0x2c00, 0x2c2f}, {0x2c60, 0x2c60}, {0x2c62, 0x2c64}, {0x2c67, 0x2c67},
  {0x2c69, 0x2c69}, {0x2c6b, 0x2c6b}, {0x2c6d, 0x2c70}, {0x2c72, 0x2c72},
  {0x2c75, 0x2c75}, {0x2c7e, 0x2c80}, {0x2c82, 0x2c82}, {0x2c84, 0x2c84},
  {0x2c86, 0x2c86}, {0x2c88, 0x2c88}, {0x2c8a, 0x2c8a}, {0x2c8c, 0x2c8c},
  {0x2c8e, 0x2c8e}, {0x2c90, 0x2c90}, {0x2c92, 0x2c92}, {0x2c94, 0x2c94},
  {0x2c96, 0x2c96}, {0x2c98, 0x2c98}, {0x2c9a, 0x2c9a}, {0x2c9c, 0x2c9c},
  {0x2c9e, 0x2c9e}, {0x2ca0, 0x2ca0}, {0x2ca2, 0x2ca2}, {0x2ca4, 0x2ca4},
  {0x2ca6, 0x2ca6}, {0x2ca8, 0x2ca8}, {0x2caa, 0x2caa}, {0x2cac, 0x2cac},
  {0x2cae, 0x2cae}, {0x2cb0, 0x2cb0}, {0x2cb2, 0x2cb2}, {0x2cb4, 0x2cb4},
  {0x2cb6, 0x2cb6}, {0x2cb8, 0x2cb8}, {0x2cba, 0x2cba}, {0x2cbc, 0x2cbc},
  {0x2cbe, 0x2cbe}, {0x2cc0, 0x2cc0}, {0x2cc2, 0x2cc2}, {0x2cc4, 0x2cc4},
  {0x2cc6, 0x2cc6}, {0x2cc8, 0x2cc8}, {0x2cca, 0x2cca}, {0x2ccc, 0x2ccc},
  {0x2cce, 0x2cce}, {0x2cd0, 0x2cd0}, {0x2cd2, 0x2cd2}, {0x2cd4, 0x2cd4},
  {0x2cd6, 0x2cd6}, {0x2cd8, 0x2cd8}, {0x2cda, 0x2cda}, {0x2cdc, 0x2cdc},
  {0x2cde, 0x2cde}, {0x2ce0, 0x2ce0}, {0x2ce2, 0x2ce2}, {0x2ceb, 0x2ceb},
  {0x2ced, 0x2ced}, {0x2cf2, 0x2cf2}, {0xa640, 0xa640}, {0xa642, 0xa642},
  {0xa644, 0xa644}, {0xa646, 0xa646}, {0xa648, 0xa648}, {0xa64a, 0xa64a},
  {0xa64c, 0xa64c}, {0xa64e, 0xa64e}, {0xa650, 0xa650}, {0xa652, 0xa652},
  {0xa654, 0xa654}, {0xa656, 0xa656}, {0xa658, 0xa658}, {0xa65a, 0xa65a},
  {0xa65c, 0xa65c}, {0xa65e, 0xa65e}, {0xa660, 0xa660}, {0xa662, 0xa662},
  {0xa664, 0xa664}, {0xa666, 0xa666}, {0xa668, 0xa668}, {0xa66a, 0xa66a},
  {0xa66c, 0xa66c}, {0xa680, 0xa680}, {0xa682, 0xa682}, {0xa684, 0xa684},
  {0xa686, 0xa686}, {0xa688, 0xa688}, {0xa68a, 0xa68a}, {0xa68c, 0xa68c},
  {0xa68e, 0xa68e}, {0xa690, 0xa690}, {0xa692, 0xa692}, {0xa694, 0xa694},
  {0xa696, 0xa696}, {0xa698, 0xa698}, {0xa69a, 0xa69a}, {0xa722, 0xa722},
  {0xa724, 0xa724}, {0xa726, 0xa726}, {0xa728, 0xa728}, {0xa72a, 0xa72a},
  {0xa72c, 0xa72c}, {0xa72e, 0xa72e}, {0xa732, 0xa732}, {0xa734, 0xa734},
  {0xa736, 0xa736}, {0xa738, 0xa738}, {0xa73a, 0xa73a}, {0xa73c, 0xa73c},
  {0xa73e, 0xa73e}, {0xa740, 0xa740}, {0xa742, 0xa742}, {0xa744, 0xa744},
  {0xa746, 0xa746}, {0xa748, 0xa748}, {0xa74a, 0xa74a}, {0xa74c, 0xa74c},
  {0xa74e, 0xa74e}, {0xa750, 0xa750}, {0xa752, 0xa752}, {0xa754, 0xa754},
  {0xa756, 0xa756}, {0xa758, 0xa758}, {0xa75a, 0xa75a}, {0xa75c, 0xa75c},
  {0xa75e, 0xa75e}, {0xa760, 0xa760}, {0xa762, 0xa762}, {0xa764, 0xa764},
  {0xa766, 0xa766}, {0xa768, 0xa768}, {0xa76a, 0xa76a}, {0xa76c, 0xa76c},
  {0xa76e, 0xa76e}, {0xa779, 0xa779}, {0xa77b, 0xa77b}, {0xa77d, 0xa77e},
  {0xa780, 0xa780}, {0xa782, 0xa782}, {0xa784, 0xa784}, {0xa786, 0xa786},
  {0xa78b, 0xa78b}, {0xa78d, 0xa78d}, {0xa790, 0xa790}, {0xa792, 0xa792},
  {0xa796, 0xa796}, {0xa798, 0xa798}, {0xa79a, 0xa79a}, {0xa79c, 0xa79c},
  {0xa79e, 0xa79e}, {0xa7a0, 0xa7a0}, {0xa7a2, 0xa7a2}, {0xa7a4, 0xa7a4},
  {0xa7a6, 0xa7a6}, {0xa7a8, 0xa7a8}, {0xa7aa, 0xa7ae}, {0xa7b0, 0xa7b4},
  {0xa7b6, 0xa7b6}, {0xa7b8, 0xa7b8}, {0xa7ba, 0xa7ba}, {0xa7bc, 0xa7bc},
  {0xa7be, 0xa7be}, {0xa7c0, 0xa7c0}, {0xa7c2, 0xa7c2}, {0xa7c4, 0xa7c7},
  {0xa7c9, 0xa7c9}, {0xa7cb, 0xa7cc}, {0xa7ce, 0xa7ce}, {0xa7d0, 0xa7d0},
  {0xa7d2, 0xa7d2}, {0xa7d4, 0xa7d4}, {0xa7d6, 0xa7d6}, {0xa7d8, 0xa7d8},
  {0xa7da, 0xa7da}, {0xa7dc, 0xa7dc}, {0xa7f5, 0xa7f5}, {0xff21, 0xff3a},
  {0x010400, 0x010427}, {0x0104b0, 0x0104d3}, {0x010570, 0x01057a},
  {0x01057c, 0x01058a}, {0x01058c, 0x010592}, {0x010594, 0x010595},
  {0x010c80, 0x010cb2}, {0x010d50, 0x010d65}, {0x0118a0, 0x0118bf},
  {0x016e40, 0x016e5f}, {0x016ea0, 0x016eb8}, {0x01d400, 0x01d419},
  {0x01d434, 0x01d44d}, {0x01d468, 0x01d481}, {0x01d49c, 0x01d49c},
  {0x01d49e, 0x01d49f}, {0x01d4a2, 0x01d4a2}, {0x01d4a5, 0x01d4a6},
  {0x01d4a9, 0x01d4ac}, {0x01d4ae, 0x01d4b5}, {0x01d4d0, 0x01d4e9},
  {0x01d504, 0x01d505}, {0x01d507, 0x01d50a}, {0x01d50d, 0x01d514},
  {0x01d516, 0x01d51c}, {0x01d538, 0x01d539}, {0x01d53b, 0x01d53e},
  {0x01d540, 0x01d544}, {0x01d546, 0x01d546}, {0x01d54a, 0x01d550},
  {0x01d56c, 0x01d585}, {0x01d5a0, 0x01d5b9}, {0x01d5d4, 0x01d5ed},
  {0x01d608, 0x01d621}, {0x01d63c, 0x01d655}, {0x01d670, 0x01d689},
  {0x01d6a8, 0x01d6c0}, {0x01d6e2, 0x01d6fa}, {0x01d71c, 0x01d734},
  {0x01d756, 0x01d76e}, {0x01d790, 0x01d7a8}, {0x01d7ca, 0x01d7ca},
  {0x01e900, 0x01e921},
};

static const struct urange uprop_ll_ranges[] = {
  {0x0061, 0x007a}, {0x00b5, 0x00b5}, {0x00df, 0x00f6}, {0x00f8, 0x00ff},
  {0x0101, 0x0101}, {0x0103, 0x0103}, {0x0105, 0x0105}, {0x0107, 0x0107},
  {0x0109, 0x0109}, {0x010b, 0x010b}, {0x010d, 0x010d}, {0x010f, 0x010f},
  {0x0111, 0x0111}, {0x0113, 0x0113}, {0x0115, 0x0115}, {0x0117, 0x0117},
  {0x0119, 0x0119}, {0x011b, 0x011b}, {0x011d, 0x011d}, {0x011f, 0x011f},
  {0x0121, 0x0121}, {0x0123, 0x0123}, {0x0125, 0x0125}, {0x0127, 0x0127},
  {0x0129, 0x0129}, {0x012b, 0x012b}, {0x012d, 0x012d}, {0x012f, 0x012f},
  {0x0131, 0x0131}, {0x0133, 0x0133}, {0x0135, 0x0135}, {0x0137, 0x0138},
  {0x013a, 0x013a}, {0x013c, 0x013c}, {0x013e, 0x013e}, {0x0140, 0x0140},
  {0x0142, 0x0142}, {0x0144, 0x0144}, {0x0146, 0x0146}, {0x0148, 0x0149},
  {0x014b, 0x014b}, {0x014d, 0x014d}, {0x014f, 0x014f}, {0x0151, 0x0151},
  {0x0153, 0x0153}, {0x0155, 0x0155}, {0x0157, 0x0157}, {0x0159, 0x0159},
  {0x015b, 0x015b}, {0x015d, 0x015d}, {0x015f, 0x015f}, {0x0161, 0x0161},
  {0x0163, 0x0163}, {0x0165, 0x0165}, {0x0167, 0x0167}, {0x0169, 0x0169},
  {0x016b, 0x016b}, {0x016d, 0x016d}, {0x016f, 0x016f}, {0x0171, 0x0171},
  {0x0173, 0x0173}, {0x0175, 0x0175}, {0x0177, 0x0177}, {0x017a, 0x017a},
  {0x017c, 0x017c}, {0x017e, 0x0180}, {0x0183, 0x0183}, {0x0185, 0x0185},
  {0x0188, 0x0188}, {0x018c, 0x018d}, {0x0192, 0x0192}, {0x0195, 0x0195},
  {0x0199, 0x019b}, {0x019e, 0x019e}, {0x01a1, 0x01a1}, {0x01a3, 0x01a3},
  {0x01a5, 0x01a5}, {0x01a8, 0x01a8}, {0x01aa, 0x01ab}, {0x01ad, 0x01ad},
  {0x01b0, 0x01b0}, {0x01b4, 0x01b4}, {0x01b6, 0x01b6}, {0x01b9, 0x01ba},
  {0x01bd, 0x01bf}, {0x01c6, 0x01c6}, {0x01c9, 0x01c9}, {0x01cc, 0x01cc},
  {0x01ce, 0x01ce}, {0x01d0, 0x01d0}, {0x01d2, 0x01d2}, {0x01d4, 0x01d4},
  {0x01d6, 0x01d6}, {0x01d8, 0x01d8}, {0x01da, 0x01da}, {0x01dc, 0x01dd},
  {0x01df, 0x01df}, {0x01e1, 0x01e1}, {0x01e3, 0x01e3}, {0x01e5, 0x01e5},
  {0x01e7, 0x01e7}, {0x01e9, 0x01e9}, {0x01eb, 0x01eb}, {0x01ed, 0x01ed},
  {0x01ef, 0x01f0}, {0x01f3, 0x01f3}, {0x01f5, 0x01f5}, {0x01f9, 0x01f9},
  {0x01fb, 0x01fb}, {0x01fd, 0x01fd}, {0x01ff, 0x01ff}, {0x0201, 0x0201},
  {0x0203, 0x0203}, {0x0205, 0x0205}, {0x0207, 0x0207}, {0x0209, 0x0209},
  {0x020b, 0x020b}, {0x020d, 0x020d}, {0x020f, 0x020f}, {0x0211, 0x0211},
  {0x0213, 0x0213}, {0x0215, 0x0215}, {0x0217, 0x0217}, {0x0219, 0x0219},
  {0x021b, 0x021b}, {0x021d, 0x021d}, {0x021f, 0x021f}, {0x0221, 0x0221},
  {0x0223, 0x0223}, {0x0225, 0x0225}, {0x0227, 0x0227}, {0x0229, 0x0229},
  {0x022b, 0x022b}, {0x022d, 0x022d}, {0x022f, 0x022f}, {0x0231, 0x0231},
  {0x0233, 0x0239}, {0x023c, 0x023c}, {0x023f, 0x0240}, {0x0242, 0x0242},
  {0x0247, 0x0247}, {0x0249, 0x0249}, {0x024b, 0x024b}, {0x024d, 0x024d},
  {0x024f, 0x0293}, {0x0296, 0x02af}, {0x0371, 0x0371}, {0x0373, 0x0373},
  {0x0377, 0x0377}, {0x037b, 0x037d}, {0x0390, 0x0390}, {0x03ac, 0x03ce},
  {0x03d0, 0x03d1}, {0x03d5, 0x03d7}, {0x03d9, 0x03d9}, {0x03db, 0x03db},
  {0x03dd, 0x03dd}, {0x03df, 0x03df}, {0x03e1, 0x03e1}, {0x03e3, 0x03e3},
  {0x03e5, 0x03e5}, {0x03e7, 0x03e7}, {0x03e9, 0x03e9}, {0x03eb, 0x03eb},
  {0x03ed, 0x03ed}, {0x03ef, 0x03f3}, {0x03f5, 0x03f5}, {0x03f8, 0x03f8},
  {0x03fb, 0x03fc}, {0x0430, 0x045f}, {0x0461, 0x0461}, {0x0463, 0x0463},
  {0x0465, 0x0465}, {0x0467, 0x0467}, {0x0469, 0x0469}, {0x046b, 0x046b},
  {0x046d, 0x046d}, {0x046f, 0x046f}, {0x0471, 0x0471}, {0x0473, 0x0473},
  {0x0475, 0x0475}, {0x0477, 0x0477}, {0x0479, 0x0479}, {0x047b, 0x047b},
  {0x047d, 0x047d}, {0x047f, 0x047f}, {0x0481, 0x0481}, {0x048b, 0x048b},
  {0x048d, 0x048d}, {0x048f, 0x048f}, {0x0491, 0x0491}, {0x0493, 0x0493},
  {0x0495, 0x0495}, {0x0497, 0x0497}, {0x0499, 0x0499}, {0x049b, 0x049b},
  {0x049d, 0x049d}, {0x049f, 0x049f}, {0x04a1, 0x04a1}, {0x04a3, 0x04a3},
  {0x04a5, 0x04a5}, {0x04a7, 0x04a7}, {0x04a9, 0x04a9}, {0x04ab, 0x04ab},
  {0x04ad, 0x04ad}, {0x04af, 0x04af}, {0x04b1, 0x04b1}, {0x04b3, 0x04b3},
  {0x04b5, 0x04b5}, {0x04b7, 0x04b7}, {0x04b9, 0x04b9}, {0x04bb, 0x04bb},
  {0x04bd, 0x04bd}, {0x04bf, 0x04bf}, {0x04c2, 0x04c2}, {0x04c4, 0x04c4},
  {0x04c6, 0x04c6}, {0x04c8, 0x04c8}, {0x04ca, 0x04ca}, {0x04cc, 0x04cc},
  {0x04ce, 0x04cf}, {0x04d1, 0x04d1}, {0x04d3, 0x04d3}, {0x04d5, 0x04d5},
  {0x04d7, 0x04d7}, {0x04d9, 0x04d9}, {0x04db, 0x04db}, {0x04dd, 0x04dd},
  {0x04df, 0x04df}, {0x04e1, 0x04e1}, {0x04e3, 0x04e3}, {0x04e5, 0x04e5},
  {0x04e7, 0x04e7}, {0x04e9, 0x04e9}, {0x04eb, 0x04eb}, {0x04ed, 0x04ed},
  {0x04ef, 0x04ef}, {0x04f1, 0x04f1}, {0x04f3, 0x04f3}, {0x04f5, 0x04f5},
  {0x04f7, 0x04f7}, {0x04f9, 0x04f9}, {0x04fb, 0x04fb}, {0x04fd, 0x04fd},
  {0x04ff, 0x04ff}, {0x0501, 0x0501}, {0x0503, 0x0503}, {0x0505, 0x0505},
  {0x0507, 0x0507}, {0x0509, 0x0509}, {0x050b, 0x050b}, {0x050d, 0x050d},
  {0x050f, 0x050f}, {0x0511, 0x0511}, {0x0513, 0x0513}, {0x0515, 0x0515},
  {0x0517, 0x0517}, {0x0519, 0x0519}, {0x051b, 0x051b}, {0x051d, 0x051d},
  {0x051f, 0x051f}, {0x0521, 0x0521}, {0x0523, 0x0523}, {0x0525, 0x0525},
  {0x0527, 0x0527}, {0x0529, 0x0529}, {0x052b, 0x052b}, {0x052d, 0x052d},
  {0x052f, 0x052f}, {0x0560, 0x0588}, {0x10d0, 0x10fa}, {0x10fd, 0x10ff},
  {0x13f8, 0x13fd}, {0x1c80, 0x1c88}, {0x1c8a, 0x1c8a}, {0x1d00, 0x1d2b},
  {0x1d6b, 0x1d77}, {0x1d79, 0x1d9a}, {0x1e01, 0x1e01}, {0x1e03, 0x1e03},
  {0x1e05, 0x1e05}, {0x1e07, 0x1e07}, {0x1e09, 0x1e09}, {0x1e0b, 0x1e0b},
  {0x1e0d, 0x1e0d}, {0x1e0f, 0x1e0f}, {0x1e11, 0x1e11}, {0x1e13, 0x1e13},
  {0x1e15, 0x1e15}, {0x1e17, 0x1e17}, {0x1e19, 0x1e19}, {0x1e1b, 0x1e1b},
  {0x1e1d, 0x1e1d}, {0x1e1f, 0x1e1f}, {0x1e21, 0x1e21}, {0x1e23, 0x1e23},
  {0x1e25, 0x1e25}, {0x1e27, 0x1e27}, {0x1e29, 0x1e29}, {0x1e2b, 0x1e2b},
  {0x1e2d, 0x1e2d}, {0x1e2f, 0x1e2f}, {0x1e31, 0x1e31}, {0x1e33, 0x1e33},
  {0x1e35, 0x1e35}, {0x1e37, 0x1e37}, {0x1e39, 0x1e39}, {0x1e3b, 0x1e3b},
  {0x1e3d, 0x1e3d}, {0x1e3f, 0x1e3f}, {0x1e41, 0x1e41}, {0x1e43, 0x1e43},
  {0x1e45, 0x1e45}, {0x1e47, 0x1e47}, {0x1e49, 0x1e49}, {0x1e4b, 0x1e4b},
  {0x1e4d, 0x1e4d}, {0x1e4f, 0x1e4f}, {0x1e51, 0x1e51}, {0x1e53, 0x1e53},
  {0x1e55, 0x1e55}, {0x1e57, 0x1e57}, {0x1e59, 0x1e59}, {0x1e5b, 0x1e5b},
  {0x1e5d, 0x1e5d}, {0x1e5f, 0x1e5f}, {0x1e61, 0x1e61}, {0x1e63, 0x1e63},
  {0x1e65, 0x1e65}, {0x1e67, 0x1e67}, {0x1e69, 0x1e69}, {0x1e6b, 0x1e6b},
  {0x1e6d, 0x1e6d}, {0x1e6f, 0x1e6f}, {0x1e71, 0x1e71}, {0x1e73, 0x1e73},
  {0x1e75, 0x1e75}, {0x1e77, 0x1e77}, {0x1e79, 0x1e79}, {0x1e7b, 0x1e7b},
  {0x1e7d, 0x1e7d}, {0x1e7f, 0x1e7f}, {0x1e81, 0x1e81}, {0x1e83, 0x1e83},
  {0x1e85, 0x1e85}, {0x1e87, 0x1e87}, {0x1e89, 0x1e89}, {0x1e8b, 0x1e8b},
  {0x1e8d, 0x1e8d}, {0x1e8f, 0x1e8f}, {0x1e91, 0x1e91}, {0x1e93, 0x1e93},
  {0x1e95, 0x1e9d}, {0x1e9f, 0x1e9f}, {0x1ea1, 0x1ea1}, {0x1ea3, 0x1ea3},
  {0x1ea5, 0x1ea5}, {0x1ea7, 0x1ea7}, {0x1ea9, 0x1ea9}, {0x1eab, 0x1eab},
  {0x1ead, 0x1ead}, {0x1eaf, 0x1eaf}, {0x1eb1, 0x1eb1}, {0x1eb3, 0x1eb3},
  {0x1eb5, 0x1eb5}, {0x1eb7, 0x1eb7}, {0x1eb9, 0x1eb9}, {0x1ebb, 0x1ebb},
  {0x1ebd, 0x1ebd}, {0x1ebf, 0x1ebf}, {0x1ec1, 0x1ec1}, {0x1ec3, 0x1ec3},
  {0x1ec5, 0x1ec5}, {0x1ec7, 0x1ec7}, {0x1ec9, 0x1ec9}, {0x1ecb, 0x1ecb},
  {0x1ecd, 0x1ecd}, {0x1ecf, 0x1ecf}, {0x1ed1, 0x1ed1}, {0x1ed3, 0x1ed3},
  {0x1ed5, 0x1ed5}, {0x1ed7, 0x1ed7}, {0x1ed9, 0x1ed9}, {0x1edb, 0x1edb},
  {0x1edd, 0x1edd}, {0x1edf, 0x1edf}, {0x1ee1, 0x1ee1}, {0x1ee3, 0x1ee3},
  {0x1ee5, 0x1ee5}, {0x1ee7, 0x1ee7}, {0x1ee9, 0x1ee9}, {0x1eeb, 0x1eeb},
  {0x1eed, 0x1eed}, {0x1eef, 0x1eef}, {0x1ef1, 0x1ef1}, {0x1ef3, 0x1ef3},
  {0x1ef5, 0x1ef5}, {0x1ef7, 0x1ef7}, {0x1ef9, 0x1ef9}, {0x1efb, 0x1efb},
  {0x1efd, 0x1efd}, {0x1eff, 0x1f07}, {0x1f10, 0x1f15}, {0x1f20, 0x1f27},
  {0x1f30, 0x1f37}, {0x1f40, 0x1f45}, {0x1f50, 0x1f57}, {0x1f60, 0x1f67},
  {0x1f70, 0x1f7d}, {0x1f80, 0x1f87}, {0x1f90, 0x1f97}, {0x1fa0, 0x1fa7},
  {0x1fb0, 0x1fb4}, {0x1fb6, 0x1fb7}, {0x1fbe, 0x1fbe}, {0x1fc2, 0x1fc4},
  {0x1fc6, 0x1fc7}, {0x1fd0, 0x1fd3}, {0x1fd6, 0x1fd7}, {0x1fe0, 0x1fe7},
  {0x1ff2, 0x1ff4}, {0x1ff6, 0x1ff7}, {0x210a, 0x210a}, {0x210e, 0x210f},
  {0x2113, 0x2113}, {0x212f, 0x212f}, {0x2134, 0x2134}, {0x2139, 0x2139},
  {0x213c, 0x213d}, {0x2146, 0x2149}, {0x214e, 0x214e}, {0x2184, 0x2184},
  {0x2c30, 0x2c5f}, {0x2c61, 0x2c61}, {0x2c65, 0x2c66}, {0x2c68, 0x2c68},
  {0x2c6a, 0x2c6a}, {0x2c6c, 0x2c6c}, {0x2c71, 0x2c71}, {0x2c73, 0x2c74},
  {0x2c76, 0x2c7b}, {0x2c81, 0x2c81}, {0x2c83, 0x2c83}, {0x2c85, 0x2c85},
  {0x2c87, 0x2c87}, {0x2c89, 0x2c89}, {0x2c8b, 0x2c8b}, {0x2c8d, 0x2c8d},
  {0x2c8f, 0x2c8f}, {0x2c91, 0x2c91}, {0x2c93, 0x2c93}, {0x2c95, 0x2c95},
  {0x2c97, 0x2c97}, {0x2c99, 0x2c99}, {0x2c9b, 0x2c9b}, {0x2c9d, 0x2c9d},
  {0x2c9f, 0x2c9f}, {0x2ca1, 0x2ca1}, {0x2ca3, 0x2ca3}, {0x2ca5, 0x2ca5},
  {0x2ca7, 0x2ca7}, {0x2ca9, 0x2ca9}, {0x2cab, 0x2cab}, {0x2cad, 0x2cad},
  {0x2caf, 0x2caf}, {0x2cb1, 0x2cb1}, {0x2cb3, 0x2cb3}, {0x2cb5, 0x2cb5},
  {0x2cb7, 0x2cb7}, {0x2cb9, 0x2cb9}, {0x2cbb, 0x2cbb}, {0x2cbd, 0x2cbd},
  {0x2cbf, 0x2cbf}, {0x2cc1, 0x2cc1}, {0x2cc3, 0x2cc3}, {0x2cc5, 0x2cc5},
  {0x2cc7, 0x2cc7}, {0x2cc9, 0x2cc9}, {0x2ccb, 0x2ccb}, {0x2ccd, 0x2ccd},
  {0x2ccf, 0x2ccf}, {0x2cd1, 0x2cd1}, {0x2cd3, 0x2cd3}, {0x2cd5, 0x2cd5},
  {0x2cd7, 0x2cd7}, {0x2cd9, 0x2cd9}, {0x2cdb, 0x2cdb}, {0x2cdd, 0x2cdd},
  {0x2cdf, 0x2cdf}, {0x2ce1, 0x2ce1}, {0x2ce3, 0x2ce4}, {0x2cec, 0x2cec},
  {0x2cee, 0x2cee}, {0x2cf3, 0x2cf3}, {0x2d00, 0x2d25}, {0x2d27, 0x2d27},
  {0x2d2d, 0x2d2d}, {0xa641, 0xa641}, {0xa643, 0xa643}, {0xa645, 0xa645},
  {0xa647, 0xa647}, {0xa649, 0xa649}, {0xa64b, 0xa64b}, {0xa64d, 0xa64d},
  {0xa64f, 0xa64f}, {0xa651, 0xa651}, {0xa653, 0xa653}, {0xa655, 0xa655},
  {0xa657, 0xa657}, {0xa659, 0xa659}, {0xa65b, 0xa65b}, {0xa65d, 0xa65d},
  {0xa65f, 0xa65f}, {0xa661, 0xa661}, {0xa663, 0xa663}, {0xa665, 0xa665},
  {0xa667, 0xa667}, {0xa669, 0xa669}, {0xa66b, 0xa66b}, {0xa66d, 0xa66d},
  {0xa681, 0xa681}, {0xa683, 0xa683}, {0xa685, 0xa685}, {0xa687, 0xa687},
  {0xa689, 0xa689}, {0xa68b, 0xa68b}, {0xa68d, 0xa68d}, {0xa68f, 0xa68f},
  {0xa691, 0xa691}, {0xa693, 0xa693}, {0xa695, 0xa695}, {0xa697, 0xa697},
  {0xa699, 0xa699}, {0xa69b, 0xa69b}, {0xa723, 0xa723}, {0xa725, 0xa725},
  {0xa727, 0xa727}, {0xa729, 0xa729}, {0xa72b, 0xa72b}, {0xa72d, 0xa72d},
  {0xa72f, 0xa731}, {0xa733, 0xa733}, {0xa735, 0xa735}, {0xa737, 0xa737},
  {0xa739, 0xa739}, {0xa73b, 0xa73b}, {0xa73d, 0xa73d}, {0xa73f, 0xa73f},
  {0xa741, 0xa741}, {0xa743, 0xa743}, {0xa745, 0xa745}, {0xa747, 0xa747},
  {0xa749, 0xa749}, {0xa74b, 0xa74b}, {0xa74d, 0xa74d}, {0xa74f, 0xa74f},
  {0xa751, 0xa751}, {0xa753, 0xa753}, {0xa755, 0xa755}, {0xa757, 0xa757},
  {0xa759, 0xa759}, {0xa75b, 0xa75b}, {0xa75d, 0xa75d}, {0xa75f, 0xa75f},
  {0xa761, 0xa761}, {0xa763, 0xa763}, {0xa765, 0xa765}, {0xa767, 0xa767},
  {0xa769, 0xa769}, {0xa76b, 0xa76b}, {0xa76d, 0xa76d}, {0xa76f, 0xa76f},
  {0xa771, 0xa778}, {0xa77a, 0xa77a}, {0xa77c, 0xa77c}, {0xa77f, 0xa77f},
  {0xa781, 0xa781}, {0xa783, 0xa783}, {0xa785, 0xa785}, {0xa787, 0xa787},
  {0xa78c, 0xa78c}, {0xa78e, 0xa78e}, {0xa791, 0xa791}, {0xa793, 0xa795},
  {0xa797, 0xa797}, {0xa799, 0xa799}, {0xa79b, 0xa79b}, {0xa79d, 0xa79d},
  {0xa79f, 0xa79f}, {0xa7a1, 0xa7a1}, {0xa7a3, 0xa7a3}, {0xa7a5, 0xa7a5},
  {0xa7a7, 0xa7a7}, {0xa7a9, 0xa7a9}, {0xa7af, 0xa7af}, {0xa7b5, 0xa7b5},
  {0xa7b7, 0xa7b7}, {0xa7b9, 0xa7b9}, {0xa7bb, 0xa7bb}, {0xa7bd, 0xa7bd},
  {0xa7bf, 0xa7bf}, {0xa7c1, 0xa7c1}, {0xa7c3, 0xa7c3}, {0xa7c8, 0xa7c8},
  {0xa7ca, 0xa7ca}, {0xa7cd, 0xa7cd}, {0xa7cf, 0xa7cf}, {0xa7d1, 0xa7d1},
  {0xa7d3, 0xa7d3}, {0xa7d5, 0xa7d5}, {0xa7d7, 0xa7d7}, {0xa7d9, 0xa7d9},
  {0xa7db, 0xa7db}, {0xa7f6, 0xa7f6}, {0xa7fa, 0xa7fa}, {0xab30, 0xab5a},
  {0xab60, 0xab68}, {0xab70, 0xabbf}, {0xfb00, 0xfb06}, {0xfb13, 0xfb17},
  {0xff41, 0xff5a}, {0x010428, 0x01044f}, {0x0104d8, 0x0104fb},
  {0x010597, 0x0105a1}, {0x0105a3, 0x0105b1}, {0x0105b3, 0x0105b9},
  {0x0105bb, 0x0105bc}, {0x010cc0, 0x010cf2}, {0x010d70, 0x010d85},
  {0x0118c0, 0x0118df}, {0x016e60, 0x016e7f}, {0x016ebb, 0x016ed3},
  {0x01d41a, 0x01d433}, {0x01d44e, 0x01d454}, {0x01d456, 0x01d467},
  {0x01d482, 0x01d49b}, {0x01d4b6, 0x01d4b9}, {0x01d4bb, 0x01d4bb},
  {0x01d4bd, 0x01d4c3}, {0x01d4c5, 0x01d4cf}, {0x01d4ea, 0x01d503},
  {0x01d51e, 0x01d537}, {0x01d552, 0x01d56b}, {0x01d586, 0x01d59f},
  {0x01d5ba, 0x01d5d3}, {0x01d5ee, 0x01d607}, {0x01d622, 0x01d63b},
  {0x01d656, 0x01d66f}, {0x01d68a, 0x01d6a5}, {0x01d6c2, 0x01d6da},
  {0x01d6dc, 0x01d6e1}, {0x01d6fc, 0x01d714}, {0x01d716, 0x01d71b},
  {0x01d736, 0x01d74e}, {0x01d750, 0x01d755}, {0x01d770, 0x01d788},
  {0x01d78a, 0x01d78f}, {0x01d7aa, 0x01d7c2}, {0x01d7c4, 0x01d7c9},
  {0x01d7cb, 0x01d7cb}, {0x01df00, 0x01df09}, {0x01df0b, 0x01df1e},
  {0x01df25, 0x01df2a}, {0x01e922, 0x01e943},
};

static const struct urange uprop_greek_ranges[] = {
  {0x0370, 0x0373}, {0x0375, 0x0377}, {0x037a, 0x037d}, {0x037f, 0x037f},
  {0x0384, 0x0384}, {0x0386, 0x0386}, {0x0388, 0x038a}, {0x038c, 0x038c},
  {0x038e, 0x03a1}, {0x03a3, 0x03e1}, {0x03f0, 0x03ff}, {0x1d26, 0x1d2a},
  {0x1d5d, 0x1d61}, {0x1d66, 0x1d6a}, {0x1dbf, 0x1dbf}, {0x1f00, 0x1f15},
  {0x1f18, 0x1f1d}, {0x1f20, 0x1f45}, {0x1f48, 0x1f4d}, {0x1f50, 0x1f57},
  {0x1f59, 0x1f59}, {0x1f5b, 0x1f5b}, {0x1f5d, 0x1f5d}, {0x1f5f, 0x1f7d},
  {0x1f80, 0x1fb4}, {0x1fb6, 0x1fc4}, {0x1fc6, 0x1fd3}, {0x1fd6, 0x1fdb},
  {0x1fdd, 0x1fef}, {0x1ff2, 0x1ff4}, {0x1ff6, 0x1ffe}, {0x2126, 0x2126},
  {0xab65, 0xab65}, {0x010140, 0x01018e}, {0x0101a0, 0x0101a0},
  {0x01d200, 0x01d245},
};

static const struct urange uprop_latin_ranges[] = {
  {0x0041, 0x005a}, {0x0061, 0x007a}, {0x00aa, 0x00aa}, {0x00ba, 0x00ba},
  {0x00c0, 0x00d6}, {0x00d8, 0x00f6}, {0x00f8, 0x02b8}, {0x02e0, 0x02e4},
  {0x1d00, 0x1d25}, {0x1d2c, 0x1d5c}, {0x1d62, 0x1d65}, {0x1d6b, 0x1d77},
  {0x1d79, 0x1dbe}, {0x1e00, 0x1eff}, {0x2071, 0x2071}, {0x207f, 0x207f},
  {0x2090, 0x209c}, {0x212a, 0x212b}, {0x2132, 0x2132}, {0x214e, 0x214e},
  {0x2160, 0x2188}, {0x2c60, 0x2c7f}, {0xa722, 0xa787}, {0xa78b, 0xa7dc},
  {0xa7f1, 0xa7ff}, {0xab30, 0xab5a}, {0xab5c, 0xab64}, {0xab66, 0xab69},
  {0xfb00, 0xfb06}, {0xff21, 0xff3a}, {0xff41, 0xff5a},
  {0x010780, 0x010785}, {0x010787, 0x0107b0}, {0x0107b2, 0x0107ba},
  {0x01df00, 0x01df1e}, {0x01df25, 0x01df2a},
};

static const struct urange uprop_cyrillic_ranges[] = {
  {0x0400, 0x0484}, {0x0487, 0x052f}, {0x1c80, 0x1c8a}, {0x1d2b, 0x1d2b},
  {0x1d78, 0x1d78}, {0x2de0, 0x2dff}, {0xa640, 0xa69f}, {0xfe2e, 0xfe2f},
  {0x01e030, 0x01e06d}, {0x01e08f, 0x01e08f},
};

static const struct urange uprop_han_ranges[] = {
  {0x2e80, 0x2e99}, {0x2e9b, 0x2ef3}, {0x2f00, 0x2fd5}, {0x3005, 0x3005},
  {0x3007, 0x3007}, {0x3021, 0x3029}, {0x3038, 0x303b}, {0x3400, 0x4dbf},
  {0x4e00, 0x9fff}, {0xf900, 0xfa6d}, {0xfa70, 0xfad9},
  {0x016fe2, 0x016fe3}, {0x016ff0, 0x016ff6}, {0x020000, 0x02a6df},
  {0x02a700, 0x02b81d}, {0x02b820, 0x02cead}, {0x02ceb0, 0x02ebe0},
  {0x02ebf0, 0x02ee5d}, {0x02f800, 0x02fa1d}, {0x030000, 0x03134a},
  {0x031350, 0x033479},
};

static const struct urange uprop_hiragana_ranges[] = {
  {0x3041, 0x3096}, {0x309d, 0x309f}, {0x01b001, 0x01b11f},
  {0x01b132, 0x01b132}, {0x01b150, 0x01b152}, {0x01f200, 0x01f200},
};

static const struct urange uprop_katakana_ranges[] = {
  {0x30a1, 0x30fa}, {0x30fd, 0x30ff}, {0x31f0, 0x31ff}, {0x32d0, 0x32fe},
  {0x3300, 0x3357}, {0xff66, 0xff6f}, {0xff71, 0xff9d},
  {0x01aff0, 0x01aff3}, {0x01aff5, 0x01affb}, {0x01affd, 0x01affe},
  {0x01b000, 0x01b000}, {0x01b120, 0x01b122}, {0x01b155, 0x01b155},
  {0x01b164, 0x01b167},
};

struct uprop_table {
  const struct urange *ranges;
  int n;
};

static const struct uprop_table unicode_props[UPROP_COUNT] = {
  { uprop_l_ranges, (int)(sizeof(uprop_l_ranges) / sizeof(uprop_l_ranges[0])) },
  { uprop_n_ranges, (int)(sizeof(uprop_n_ranges) / sizeof(uprop_n_ranges[0])) },
  { uprop_nd_ranges, (int)(sizeof(uprop_nd_ranges) / sizeof(uprop_nd_ranges[0])) },
  { uprop_lu_ranges, (int)(sizeof(uprop_lu_ranges) / sizeof(uprop_lu_ranges[0])) },
  { uprop_ll_ranges, (int)(sizeof(uprop_ll_ranges) / sizeof(uprop_ll_ranges[0])) },
  { uprop_greek_ranges, (int)(sizeof(uprop_greek_ranges) / sizeof(uprop_greek_ranges[0])) },
  { uprop_latin_ranges, (int)(sizeof(uprop_latin_ranges) / sizeof(uprop_latin_ranges[0])) },
  { uprop_cyrillic_ranges, (int)(sizeof(uprop_cyrillic_ranges) / sizeof(uprop_cyrillic_ranges[0])) },
  { uprop_han_ranges, (int)(sizeof(uprop_han_ranges) / sizeof(uprop_han_ranges[0])) },
  { uprop_hiragana_ranges, (int)(sizeof(uprop_hiragana_ranges) / sizeof(uprop_hiragana_ranges[0])) },
  { uprop_katakana_ranges, (int)(sizeof(uprop_katakana_ranges) / sizeof(uprop_katakana_ranges[0])) },
};

static int unicode_prop_match(int prop, int cp) {
  if (prop < 0 || prop >= UPROP_COUNT || cp < 0 || cp > 0x10ffff) return 0;
  return urange_contains(unicode_props[prop].ranges,
                         unicode_props[prop].n, cp);
}

/* ------------------------------------------------------------------ */
/* Bytecode                                                            */
/* ------------------------------------------------------------------ */

enum {
  OP_MATCH = 1,
  OP_RUNE,        /* match exact code point ins.a */
  OP_RUNE_CI,     /* simple case-insensitive: ins.a is folded code point */
  OP_LIT,         /* match literal byte run lits[ins.a] */
  OP_REPEAT_RUNE, /* whole-pattern greedy rune repeat */
  OP_CLASS,       /* match byte against classes[ins.a] */
  OP_UPROP,       /* match Unicode property ins.a, negated if ins.b */
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
  uint64_t bits[4];   /* 256-bit byte bitmap */
  uint64_t prop_pos;  /* Unicode properties that match positively */
  uint64_t prop_neg;  /* Unicode properties that match when absent */
  int inverted;
};

#define HFRE_MAX_MULTI_LITS 16
#define HFRE_DFA_MAX_STATES 64

struct multi_lit {
  unsigned char *s;
  int len;
};

struct litop {
  unsigned char *s;
  int len;
};

struct dfa_state {
  uint64_t bits;
  int trans[128];     /* -2 unknown, -1 dead, >=0 state index */
  int is_match;
};

/* VM thread record (declared up front so struct hfre can size its
 * scratch buffers in terms of sizeof(struct thread)). */
struct thread {
  int pc;
  int sp;
  int *caps;     /* length n_save_slots */
};

static inline int sclass_byte_raw(const struct sclass *c, unsigned char b) {
  return (int) ((c->bits[b >> 6] >> (b & 63)) & 1ull);
}

static int sclass_match(const struct sclass *c, int flags,
                        int cp, unsigned char lead) {
  int raw = sclass_byte_raw(c, lead);
  if (!raw && (flags & HFRE_IGNORE_CASE) && cp >= 0x80) {
    int folded = unicode_simple_fold(cp);
    if (folded >= 0 && folded <= 0xff) {
      raw = sclass_byte_raw(c, (unsigned char) folded);
    }
  }
  /* Skip the property loop entirely when the class has no Unicode
   * property tests — that's the common case for byte-level classes
   * like \s, \S, [a-z], [0-9], etc. */
  if ((c->prop_pos | c->prop_neg) != 0) {
    for (int i = 0; i < UPROP_COUNT; i++) {
      uint64_t bit = 1ull << i;
      if ((c->prop_pos & bit) && unicode_prop_match(i, cp)) raw = 1;
      if ((c->prop_neg & bit) && !unicode_prop_match(i, cp)) raw = 1;
    }
  }
  return c->inverted ? !raw : raw;
}

static int sclass_has_high_byte(const struct sclass *c) {
  for (int b = 128; b < 256; b++) {
    if (sclass_byte_raw(c, (unsigned char) b)) return 1;
  }
  return 0;
}

static inline void sclass_set(struct sclass *c, unsigned char b) {
  c->bits[b >> 6] |= 1ull << (b & 63);
}

static inline void sclass_negate(struct sclass *c) {
  c->inverted = !c->inverted;
}

/* ------------------------------------------------------------------ */
/* Compiled regex                                                      */
/* ------------------------------------------------------------------ */

struct hfre {
  int flags;
  int n_groups;          /* user-visible capture groups (excluding implicit 0) */
  int n_save_slots;      /* 2 * (n_groups + 1) */

  struct insn *code;
  int code_len;
  int code_cap;

  struct sclass *classes;
  int n_classes;
  int classes_cap;

  struct litop *lits;
  int n_lits;
  int lits_cap;

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

  /* Pure literal pattern (no metacharacters, no captures, case-sensitive).
   * When set, hfre_exec uses memchr+memcmp instead of the VM. */
  unsigned char *literal;
  int literal_len;
  int is_pure_literal;
  int has_litop;

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
   * case hfre_exec can skip the per-position scan and seed the VM at
   * the literal's position directly. */
  int req_lit_is_prefix;
  unsigned char bmh_skip[256];   /* BMH bad-character shift table */
  /* Direct match shape: .*LIT (greedy) or .*?LIT (lazy) at the
   * top level, no captures. 0=none, 1=greedy, 2=lazy. */
  int dot_star_lit_kind;

  int has_max_match_len;
  int max_match_len;        /* finite upper bound in bytes */
  int anchored_eol;         /* every match must pass through OP_EOL */

  unsigned char *suffix_lit;
  int suffix_lit_len;
  int suffix_lit_full;      /* ^LIT$ shape */

  struct multi_lit multi_lits[HFRE_MAX_MULTI_LITS];
  int multi_lit_count;
  int multi_lit_is_prefix;
  uint64_t multi_first[4];

  uint64_t shift_or_mask[256];
  int has_shift_or;
  int shift_or_len;

  int simple_rune_kind;     /* 0 none, 1 plus, 2 star */
  int simple_rune_cp;
  int simple_rune_icase;

  int dfa_eligible;
  int dfa_state_count;
  struct dfa_state *dfa_states;

  /* VM scratch: pre-allocated at compile time so hfre_exec is
   * malloc-free on the hot path. The struct is therefore NOT
   * thread-safe; callers must use one struct hfre per thread. */
  void *vm_clist;          /* struct thread *, length vm_max_per_step */
  void *vm_nlist;          /* struct thread *, length vm_max_per_step */
  int *vm_pool_a;          /* size vm_max_per_step * n_save_slots */
  int *vm_pool_b;
  int *vm_seen_gen;        /* size code_len */
  int *vm_best_caps;       /* size n_save_slots */
  int *vm_cap_ints;        /* size n_save_slots, used by hfre_exec */
  /* Thompson (no-capture) lists: each entry is just a PC. */
  int *vm_th_a;            /* size vm_max_per_step */
  int *vm_th_b;
  int vm_max_per_step;
};

/* ------------------------------------------------------------------ */
/* Code emission                                                       */
/* ------------------------------------------------------------------ */

static int code_grow(struct hfre *p) {
  int cap = p->code_cap == 0 ? 16 : p->code_cap * 2;
  struct insn *n = (struct insn *) realloc(p->code, (size_t) cap * sizeof(*n));
  if (n == NULL) return HFRE_OUT_OF_MEMORY;
  p->code = n;
  p->code_cap = cap;
  return 0;
}

static int emit(struct hfre *p, int op, int a, int b) {
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
static int insert_at(struct hfre *p, int pos, int op, int a, int b) {
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

static int alloc_class(struct hfre *p) {
  if (p->n_classes == p->classes_cap) {
    int cap = p->classes_cap == 0 ? 4 : p->classes_cap * 2;
    struct sclass *n = (struct sclass *)
      realloc(p->classes, (size_t) cap * sizeof(*n));
    if (n == NULL) return HFRE_OUT_OF_MEMORY;
    p->classes = n;
    p->classes_cap = cap;
  }
  int idx = p->n_classes++;
  memset(&p->classes[idx], 0, sizeof(p->classes[idx]));
  return idx;
}

static int alloc_litop(struct hfre *p, const unsigned char *s, int len) {
  if (p->n_lits == p->lits_cap) {
    int cap = p->lits_cap == 0 ? 4 : p->lits_cap * 2;
    struct litop *n = (struct litop *)
      realloc(p->lits, (size_t) cap * sizeof(*n));
    if (n == NULL) return HFRE_OUT_OF_MEMORY;
    p->lits = n;
    p->lits_cap = cap;
  }
  unsigned char *copy = (unsigned char *) malloc((size_t) len);
  if (copy == NULL) return HFRE_OUT_OF_MEMORY;
  memcpy(copy, s, (size_t) len);
  int idx = p->n_lits++;
  p->lits[idx].s = copy;
  p->lits[idx].len = len;
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

static int parse_alt(struct parser *ps, struct hfre *p);
static int parse_concat(struct parser *ps, struct hfre *p);

static int peek(struct parser *ps) {
  return ps->pos < ps->re_len ? ps->re[ps->pos] : -1;
}

static int emit_rune(struct hfre *p, int flags, int cp) {
  if (flags & HFRE_IGNORE_CASE) {
    return emit(p, OP_RUNE_CI, unicode_simple_fold(cp), 0);
  }
  return emit(p, OP_RUNE, cp, 0);
}

static void class_add_byte(struct sclass *cls, int flags, int byte) {
  sclass_set(cls, (unsigned char) byte);
  if ((flags & HFRE_IGNORE_CASE) && is_ascii_letter(byte)) {
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

static void class_add_prop(struct sclass *cls, int prop, int negated) {
  uint64_t bit = 1ull << prop;
  if (negated) cls->prop_neg |= bit;
  else cls->prop_pos |= bit;
}

static int prop_name_eq(const char *name, int len, const char *lit) {
  int i = 0, j = 0;
  while (i < len || lit[j] != '\0') {
    while (i < len &&
           (name[i] == '_' || name[i] == '-' || name[i] == ' ')) i++;
    while (lit[j] == '_' || lit[j] == '-' || lit[j] == ' ') j++;
    if (i >= len || lit[j] == '\0') break;
    int a = name[i];
    int b = lit[j];
    if (a >= 'A' && a <= 'Z') a += 32;
    if (b >= 'A' && b <= 'Z') b += 32;
    if (a != b) return 0;
    i++;
    j++;
  }
  while (i < len &&
         (name[i] == '_' || name[i] == '-' || name[i] == ' ')) i++;
  while (lit[j] == '_' || lit[j] == '-' || lit[j] == ' ') j++;
  return i == len && lit[j] == '\0';
}

static int lookup_prop(const char *name, int len) {
  if (prop_name_eq(name, len, "L") ||
      prop_name_eq(name, len, "Letter") ||
      prop_name_eq(name, len, "Letters")) return UPROP_L;
  if (prop_name_eq(name, len, "Lu") ||
      prop_name_eq(name, len, "Uppercase_Letter") ||
      prop_name_eq(name, len, "UppercaseLetter")) return UPROP_LU;
  if (prop_name_eq(name, len, "Ll") ||
      prop_name_eq(name, len, "Lowercase_Letter") ||
      prop_name_eq(name, len, "LowercaseLetter")) return UPROP_LL;
  if (prop_name_eq(name, len, "N") ||
      prop_name_eq(name, len, "Number")) return UPROP_N;
  if (prop_name_eq(name, len, "Nd") ||
      prop_name_eq(name, len, "Digit") ||
      prop_name_eq(name, len, "Decimal_Number") ||
      prop_name_eq(name, len, "DecimalNumber")) return UPROP_ND;
  if (prop_name_eq(name, len, "Greek")) return UPROP_GREEK;
  if (prop_name_eq(name, len, "Latin")) return UPROP_LATIN;
  if (prop_name_eq(name, len, "Cyrillic")) return UPROP_CYRILLIC;
  if (prop_name_eq(name, len, "Han")) return UPROP_HAN;
  if (prop_name_eq(name, len, "Hiragana")) return UPROP_HIRAGANA;
  if (prop_name_eq(name, len, "Katakana")) return UPROP_KATAKANA;
  return -1;
}

static int parse_unicode_property(struct parser *ps, int *prop) {
  char name[32];
  int len = 0;
  if (peek(ps) == '{') {
    ps->pos++;
    while (peek(ps) >= 0 && peek(ps) != '}') {
      if (len >= (int) sizeof(name)) {
        ps->err = HFRE_INVALID_UNICODE_PROPERTY;
        return -1;
      }
      name[len++] = (char) ps->re[ps->pos++];
    }
    if (peek(ps) != '}' || len == 0) {
      ps->err = HFRE_INVALID_UNICODE_PROPERTY;
      return -1;
    }
    ps->pos++;
  } else {
    int c = peek(ps);
    if (c < 0) {
      ps->err = HFRE_INVALID_UNICODE_PROPERTY;
      return -1;
    }
    name[len++] = (char) c;
    ps->pos++;
  }
  int p = lookup_prop(name, len);
  if (p < 0) {
    ps->err = HFRE_INVALID_UNICODE_PROPERTY;
    return -1;
  }
  *prop = p;
  return 0;
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
    ps->err = HFRE_INVALID_METACHARACTER;
    return -1;
  }
  unsigned char h = ps->re[ps->pos];
  unsigned char l = ps->re[ps->pos + 1];
  if (!isxdigit(h) || !isxdigit(l)) {
    ps->err = HFRE_INVALID_METACHARACTER;
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
  if (c < 0) { ps->err = HFRE_INVALID_CHARACTER_SET; return -1; }
  if (c != '\\') { ps->pos++; return c; }
  ps->pos++;
  int e = peek(ps);
  if (e < 0) { ps->err = HFRE_INVALID_METACHARACTER; return -1; }
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
      ps->err = HFRE_INVALID_UNICODE_PROPERTY;
      return -1;
    default:
      /* Perl shorthand inside a class — handled separately in
       * parse_class. */
      ps->err = HFRE_INVALID_METACHARACTER;
      return -1;
  }
}

/* Parse a class body starting just after '['. Emits one OP_CLASS. */
static int parse_class(struct parser *ps, struct hfre *p) {
  int idx = alloc_class(p);
  if (idx < 0) { ps->err = HFRE_OUT_OF_MEMORY; return -1; }
  struct sclass *cls = &p->classes[idx];

  int negated = 0;
  if (peek(ps) == '^') { negated = 1; ps->pos++; }

  if (peek(ps) == ']' || peek(ps) < 0) {
    ps->err = HFRE_INVALID_CHARACTER_SET;
    return -1;
  }

  while (peek(ps) != ']') {
    int c = peek(ps);
    if (c < 0) { ps->err = HFRE_INVALID_CHARACTER_SET; return -1; }

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
      if (e == 'p' || e == 'P') {
        int prop;
        ps->pos += 2;
        if (parse_unicode_property(ps, &prop) < 0) return -1;
        class_add_prop(cls, prop, e == 'P');
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
static int apply_quantifier(struct parser *ps, struct hfre *p,
                            int start_pc, int q, int lazy) {
  int end_pc = p->code_len;
  if (start_pc == end_pc) {
    ps->err = HFRE_UNEXPECTED_QUANTIFIER;
    return -1;
  }

  if (q == '?') {
    int a = start_pc + 1;        /* body */
    int b = end_pc + 1;          /* after */
    if (lazy) { int t = a; a = b; b = t; }
    if (insert_at(p, start_pc, OP_SPLIT, a, b) < 0) {
      ps->err = HFRE_OUT_OF_MEMORY; return -1;
    }
    return 0;
  }
  if (q == '*') {
    int a = start_pc + 1;        /* body */
    int b = end_pc + 2;          /* after (SPLIT inserted, JMP appended) */
    if (lazy) { int t = a; a = b; b = t; }
    if (insert_at(p, start_pc, OP_SPLIT, a, b) < 0) {
      ps->err = HFRE_OUT_OF_MEMORY; return -1;
    }
    if (emit(p, OP_JMP, start_pc, 0) < 0) {
      ps->err = HFRE_OUT_OF_MEMORY; return -1;
    }
    return 0;
  }
  if (q == '+') {
    int after = end_pc + 1;
    int a = start_pc;
    int b = after;
    if (lazy) { int t = a; a = b; b = t; }
    if (emit(p, OP_SPLIT, a, b) < 0) {
      ps->err = HFRE_OUT_OF_MEMORY; return -1;
    }
    return 0;
  }
  ps->err = HFRE_INTERNAL_ERROR;
  return -1;
}

static int parse_atom(struct parser *ps, struct hfre *p) {
  int c = peek(ps);
  if (c < 0) return 0;
  if (c == '|' || c == ')') return 0;

  int start_pc = p->code_len;

  if (c == '(') {
    ps->pos++;
    int gi = ps->group_index++;
    if (emit(p, OP_SAVE, 2 * gi, 0) < 0) {
      ps->err = HFRE_OUT_OF_MEMORY; return -1;
    }
    if (parse_alt(ps, p) < 0) return -1;
    if (peek(ps) != ')') {
      ps->err = HFRE_UNBALANCED_BRACKETS; return -1;
    }
    ps->pos++;
    if (emit(p, OP_SAVE, 2 * gi + 1, 0) < 0) {
      ps->err = HFRE_OUT_OF_MEMORY; return -1;
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
    if (e < 0) { ps->err = HFRE_INVALID_METACHARACTER; return -1; }
    ps->pos++;
    switch (e) {
      case 'd': case 's': case 'w': {
        int idx = alloc_class(p);
        if (idx < 0) { ps->err = HFRE_OUT_OF_MEMORY; return -1; }
        class_add_perl(&p->classes[idx], e);
        emit(p, OP_CLASS, idx, 0);
        break;
      }
      case 'D': case 'S': case 'W': {
        int idx = alloc_class(p);
        if (idx < 0) { ps->err = HFRE_OUT_OF_MEMORY; return -1; }
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
      case 'p': case 'P': {
        int prop;
        if (parse_unicode_property(ps, &prop) < 0) return -1;
        emit(p, OP_UPROP, prop, e == 'P');
        break;
      }
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
        ps->err = HFRE_INVALID_METACHARACTER;
        return -1;
    }
  } else if (c == '*' || c == '+' || c == '?') {
    ps->err = HFRE_UNEXPECTED_QUANTIFIER;
    return -1;
  } else {
    /* Literal byte or UTF-8 leading byte. */
    if (c < 0x80) {
      ps->pos++;
      emit_rune(p, ps->flags, c);
    } else {
      int dec_len;
      int cp = utf8_decode(ps->re + ps->pos, ps->re_len - ps->pos, &dec_len);
      if (cp < 0) { ps->err = HFRE_INVALID_UTF8; return -1; }
      ps->pos += dec_len;
      emit_rune(p, ps->flags, cp);
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

static int parse_concat(struct parser *ps, struct hfre *p) {
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
static int parse_alt(struct parser *ps, struct hfre *p) {
  int L0 = p->code_len;
  if (parse_concat(ps, p) < 0) return -1;
  if (peek(ps) != '|') return 0;
  ps->top_level_alt = 1;
  while (peek(ps) == '|') {
    ps->pos++;
    if (insert_at(p, L0, OP_SPLIT, L0 + 1, /*tmp*/ 0) < 0) {
      ps->err = HFRE_OUT_OF_MEMORY; return -1;
    }
    int jmp_pc = emit(p, OP_JMP, /*tmp*/ 0, 0);
    if (jmp_pc < 0) { ps->err = HFRE_OUT_OF_MEMORY; return -1; }
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
static int compute_first_set(struct hfre *p, uint64_t out[4],
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
      case OP_LIT: {
        const struct litop *lit = &p->lits[ins.a];
        if (lit->len > 0) {
          unsigned b = lit->s[0];
          out[b >> 6] |= 1ull << (b & 63);
          if (d + lit->len < min_len) min_len = d + lit->len;
        }
        break;
      }
      case OP_REPEAT_RUNE:
        saw_unbounded = 1;
        if ((ins.b & 0xff) == 2 && d < min_len) min_len = d;
        else if (d + 1 < min_len) min_len = d + 1;
        break;
      case OP_RUNE_CI: {
        first_set_add_folded_cp(out, ins.a);
        if (d + 1 < min_len) min_len = d + 1;
        break;
      }
      case OP_CLASS: {
        const struct sclass *cls = &p->classes[ins.a];
        int has_any = 0;
        for (int i = 0; i < 4; i++) {
          uint64_t bits = cls->inverted ? ~cls->bits[i] : cls->bits[i];
          out[i] |= bits;
          if (bits != 0) has_any = 1;
        }
        if (p->flags & HFRE_IGNORE_CASE) {
          for (int b = 0; b < 256; b++) {
            if (sclass_byte_raw(cls, (unsigned char) b)) {
              first_set_add_folded_cp(out, b);
            }
          }
        }
        if (cls->prop_pos || cls->prop_neg) saw_unbounded = 1;
        if (!has_any) {
          /* class is empty -> nothing matches; min_len stays infinite */
        }
        if (d + 1 < min_len) min_len = d + 1;
        break;
      }
      case OP_UPROP:
        saw_unbounded = 1;
        if (d + 1 < min_len) min_len = d + 1;
        break;
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
static int reaches_match_skipping(const struct hfre *p, int skip,
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

static int max_len_width(const struct hfre *p, struct insn ins) {
  switch (ins.op) {
    case OP_RUNE:
      return utf8_width_for_cp(ins.a);
    case OP_RUNE_CI:
    case OP_CLASS:
    case OP_UPROP:
    case OP_ANY:
      (void) p;
      return 4;
    case OP_LIT:
      return p->lits[ins.a].len;
    default:
      return 0;
  }
}

static int max_len_dfs(const struct hfre *p, int pc, unsigned char *state,
                       int *memo, int *unbounded) {
  if (*unbounded) return 0;
  if (pc < 0 || pc >= p->code_len) {
    *unbounded = 1;
    return 0;
  }
  if (state[pc] == 1) {
    *unbounded = 1;
    return 0;
  }
  if (state[pc] == 2) return memo[pc];

  state[pc] = 1;
  struct insn ins = p->code[pc];
  int out = 0;
  switch (ins.op) {
    case OP_MATCH:
      out = 0;
      break;
    case OP_JMP:
      out = max_len_dfs(p, ins.a, state, memo, unbounded);
      break;
    case OP_SPLIT: {
      int a = max_len_dfs(p, ins.a, state, memo, unbounded);
      int b = max_len_dfs(p, ins.b, state, memo, unbounded);
      out = a > b ? a : b;
      break;
    }
    case OP_SAVE:
    case OP_BOL:
    case OP_EOL:
      out = max_len_dfs(p, pc + 1, state, memo, unbounded);
      break;
    default: {
      int tail = max_len_dfs(p, pc + 1, state, memo, unbounded);
      int width = max_len_width(p, ins);
      if (tail > INT32_MAX - width) {
        *unbounded = 1;
        out = 0;
      } else {
        out = tail + width;
      }
      break;
    }
  }
  state[pc] = 2;
  memo[pc] = out;
  return out;
}

static void compute_match_bounds(struct hfre *p) {
  unsigned char *state = (unsigned char *) calloc((size_t) p->code_len, 1);
  int *memo = (int *) calloc((size_t) p->code_len, sizeof(int));
  if (state != NULL && memo != NULL) {
    int unbounded = 0;
    int max_len = max_len_dfs(p, 0, state, memo, &unbounded);
    if (!unbounded) {
      p->has_max_match_len = 1;
      p->max_match_len = max_len;
    }
  }
  free(state);
  free(memo);

  unsigned char *seen = (unsigned char *) malloc((size_t) p->code_len);
  int *stack = (int *) malloc((size_t) p->code_len * sizeof(int));
  if (seen == NULL || stack == NULL) {
    free(seen);
    free(stack);
    return;
  }
  for (int pc = 0; pc < p->code_len; pc++) {
    if (p->code[pc].op == OP_EOL &&
        !reaches_match_skipping(p, pc, seen, stack)) {
      p->anchored_eol = 1;
      break;
    }
  }
  free(seen);
  free(stack);
}

static void compute_required_literal(struct hfre *p) {
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
static void compute_dot_star_lit(struct hfre *p) {
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

static int append_cp_bytes(unsigned char *dst, int off, int cp) {
  unsigned char tmp[4];
  int n = utf8_encode(cp, tmp);
  if (n <= 0) return -1;
  memcpy(dst + off, tmp, (size_t) n);
  return off + n;
}

static int encode_rune_run(const struct hfre *p, int start, int count,
                           unsigned char **out, int *out_len) {
  int bytes = 0;
  for (int i = 0; i < count; i++) {
    bytes += utf8_width_for_cp(p->code[start + i].a);
  }
  unsigned char *buf = (unsigned char *) malloc((size_t) bytes);
  if (buf == NULL) return 0;
  int off = 0;
  for (int i = 0; i < count; i++) {
    off = append_cp_bytes(buf, off, p->code[start + i].a);
    if (off < 0) {
      free(buf);
      return 0;
    }
  }
  *out = buf;
  *out_len = off;
  return 1;
}

static void patch_targets_after_delete(struct hfre *p, int delete_from,
                                       int deleted) {
  for (int i = 0; i < p->code_len; i++) {
    if (p->code[i].op == OP_JMP) {
      if (p->code[i].a >= delete_from) p->code[i].a -= deleted;
    } else if (p->code[i].op == OP_SPLIT) {
      if (p->code[i].a >= delete_from) p->code[i].a -= deleted;
      if (p->code[i].b >= delete_from) p->code[i].b -= deleted;
    }
  }
}

static void compute_literal_run_opcodes(struct hfre *p) {
  /* OP_LIT advances by a byte run in one VM transition. Keep it to
   * straight-line programs so Pike's per-thread position handling
   * never has to deduplicate epsilon cycles by (pc, sp). */
  for (int pc = 0; pc < p->code_len; pc++) {
    if (p->code[pc].op == OP_JMP || p->code[pc].op == OP_SPLIT) {
      return;
    }
  }

  if (p->code_len <= 0) return;
  unsigned char *targeted = (unsigned char *) calloc((size_t) p->code_len, 1);
  if (targeted == NULL) return;
  for (int pc = 0; pc < p->code_len; pc++) {
    if (p->code[pc].op == OP_JMP) {
      if (p->code[pc].a >= 0 && p->code[pc].a < p->code_len) {
        targeted[p->code[pc].a] = 1;
      }
    } else if (p->code[pc].op == OP_SPLIT) {
      if (p->code[pc].a >= 0 && p->code[pc].a < p->code_len) {
        targeted[p->code[pc].a] = 1;
      }
      if (p->code[pc].b >= 0 && p->code[pc].b < p->code_len) {
        targeted[p->code[pc].b] = 1;
      }
    }
  }

  for (int pc = 0; pc < p->code_len; pc++) {
    if (p->code[pc].op != OP_RUNE) continue;
    int end = pc + 1;
    while (end < p->code_len && p->code[end].op == OP_RUNE && !targeted[end]) {
      end++;
    }
    int count = end - pc;
    if (count >= 2) {
      unsigned char *bytes = NULL;
      int len = 0;
      if (encode_rune_run(p, pc, count, &bytes, &len)) {
        int idx = alloc_litop(p, bytes, len);
        free(bytes);
        if (idx >= 0) {
          int deleted = count - 1;
          p->code[pc].op = OP_LIT;
          p->code[pc].a = idx;
          p->code[pc].b = 0;
          p->has_litop = 1;
          memmove(&p->code[pc + 1], &p->code[end],
                  (size_t)(p->code_len - end) * sizeof(p->code[0]));
          p->code_len -= deleted;
          patch_targets_after_delete(p, end, deleted);
          free(targeted);
          compute_literal_run_opcodes(p);
          return;
        }
      }
    }
    pc = end - 1;
  }
  free(targeted);
}

static void compute_suffix_literal(struct hfre *p) {
  if (p->n_groups != 0) return;
  if (p->flags & HFRE_IGNORE_CASE) return;
  if (p->code_len < 5) return;
  if (p->code[0].op != OP_SAVE || p->code[0].a != 0) return;
  if (p->code[p->code_len - 1].op != OP_MATCH) return;
  if (p->code[p->code_len - 2].op != OP_SAVE ||
      p->code[p->code_len - 2].a != 1) return;

  int pc = 1;
  int full = 0;
  if (p->code[pc].op == OP_BOL) {
    full = 1;
    pc++;
  }
  int lit_start = pc;
  int bytes = 0;
  while (pc < p->code_len && p->code[pc].op == OP_RUNE) {
    bytes += utf8_width_for_cp(p->code[pc].a);
    pc++;
  }
  if (bytes <= 0) return;
  if (pc >= p->code_len || p->code[pc].op != OP_EOL) return;
  if (pc + 3 != p->code_len) return;

  unsigned char *lit = (unsigned char *) malloc((size_t) bytes);
  if (lit == NULL) return;
  int off = 0;
  for (int i = lit_start; i < pc; i++) {
    off = append_cp_bytes(lit, off, p->code[i].a);
    if (off < 0) {
      free(lit);
      return;
    }
  }
  p->suffix_lit = lit;
  p->suffix_lit_len = off;
  p->suffix_lit_full = full;
}

/* Detect a pure-literal regex (no metas, no quantifiers, no groups)
 * and record the byte sequence for fast memchr/memcmp matching. */
static void compute_pure_literal(struct hfre *p) {
  if (p->n_groups > 0) return;
  if (p->flags & HFRE_IGNORE_CASE) return;
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
    if (op == OP_RUNE_CI) {
      if (p->code[i].a >= 128) return;
      icase = 1;
      total_bytes += 1;
      continue;
    }
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
  if (icase) p->flags |= HFRE_IGNORE_CASE;
}

static void compute_shift_or(struct hfre *p) {
  if (!p->is_pure_literal) return;
  if (p->flags & HFRE_IGNORE_CASE) return;
  if (p->literal_len <= 0 || p->literal_len > 63) return;
  for (int i = 0; i < 256; i++) p->shift_or_mask[i] = ~0ull;
  for (int i = 0; i < p->literal_len; i++) {
    p->shift_or_mask[p->literal[i]] &= ~(1ull << i);
  }
  p->has_shift_or = 1;
  p->shift_or_len = p->literal_len;
}

static int hex_value(int c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

static int literal_segment_bytes(const unsigned char *re, int start, int end,
                                 unsigned char **out, int *out_len) {
  unsigned char *buf = (unsigned char *) malloc((size_t)(4 * (end - start + 1)));
  if (buf == NULL) return 0;
  int n = 0;
  for (int i = start; i < end; i++) {
    unsigned char c = re[i];
    if (c == '\\') {
      if (++i >= end) { free(buf); return 0; }
      c = re[i];
      switch (c) {
        case 'x': {
          if (i + 2 >= end) { free(buf); return 0; }
          int h = hex_value(re[i + 1]);
          int l = hex_value(re[i + 2]);
          if (h < 0 || l < 0) { free(buf); return 0; }
          int cp = (h << 4) | l;
          n = append_cp_bytes(buf, n, cp);
          if (n < 0) { free(buf); return 0; }
          i += 2;
          break;
        }
        case 'n': buf[n++] = '\n'; break;
        case 'r': buf[n++] = '\r'; break;
        case 't': buf[n++] = '\t'; break;
        case 'f': buf[n++] = '\f'; break;
        case 'v': buf[n++] = '\v'; break;
        case 'b': buf[n++] = '\b'; break;
        case '\\': case '^': case '$': case '.': case '|':
        case '(':  case ')': case '[': case ']':
        case '*':  case '+': case '?': case '/': case '-':
          buf[n++] = c;
          break;
        default:
          free(buf);
          return 0;
      }
    } else {
      if (c == '^' || c == '$' || c == '.' || c == '[' || c == ']' ||
          c == '(' || c == ')' || c == '|' || c == '*' || c == '+' ||
          c == '?') {
        free(buf);
        return 0;
      }
      buf[n++] = c;
    }
  }
  if (n == 0) { free(buf); return 0; }
  *out = buf;
  *out_len = n;
  return 1;
}

static int add_multi_literal(struct hfre *p, const unsigned char *a, int na,
                             const unsigned char *b, int nb) {
  if (p->multi_lit_count >= HFRE_MAX_MULTI_LITS) return 0;
  if (na + nb < 2) return 0;
  unsigned char *s = (unsigned char *) malloc((size_t)(na + nb));
  if (s == NULL) return 0;
  memcpy(s, a, (size_t) na);
  if (nb > 0) memcpy(s + na, b, (size_t) nb);
  p->multi_lits[p->multi_lit_count].s = s;
  p->multi_lits[p->multi_lit_count].len = na + nb;
  p->multi_first[s[0] >> 6] |= 1ull << (s[0] & 63);
  p->multi_lit_count++;
  return 1;
}

static int find_group_close(const unsigned char *re, int len) {
  for (int i = 1; i < len; i++) {
    if (re[i] == '\\') {
      i++;
      continue;
    }
    if (re[i] == '(' || re[i] == '[') return -1;
    if (re[i] == ')') return i;
  }
  return -1;
}

static int next_alt_end(const unsigned char *re, int start, int end) {
  for (int i = start; i < end; i++) {
    if (re[i] == '\\') {
      i++;
      continue;
    }
    if (re[i] == '|') return i;
    if (re[i] == '(' || re[i] == ')' || re[i] == '[' || re[i] == ']') {
      return -1;
    }
  }
  return end;
}

static void discard_multi_literals(struct hfre *p) {
  for (int i = 0; i < p->multi_lit_count; i++) {
    free(p->multi_lits[i].s);
    p->multi_lits[i].s = NULL;
    p->multi_lits[i].len = 0;
  }
  p->multi_lit_count = 0;
  p->multi_lit_is_prefix = 0;
  memset(p->multi_first, 0, sizeof(p->multi_first));
}

static void compute_multi_literals(struct hfre *p, const unsigned char *re,
                                   int len) {
  if (p->flags & HFRE_IGNORE_CASE) return;
  int body_start = 0, body_end = len, suffix_start = len;
  if (len >= 3 && re[0] == '(') {
    int close = find_group_close(re, len);
    if (close < 0) return;
    body_start = 1;
    body_end = close;
    suffix_start = close + 1;
  }

  unsigned char *suffix = NULL;
  int suffix_len = 0;
  if (suffix_start < len &&
      !literal_segment_bytes(re, suffix_start, len, &suffix, &suffix_len)) {
    return;
  }

  int pos = body_start;
  int branches = 0;
  while (pos < body_end) {
    int alt_end = next_alt_end(re, pos, body_end);
    if (alt_end < 0) break;
    unsigned char *branch = NULL;
    int branch_len = 0;
    if (!literal_segment_bytes(re, pos, alt_end, &branch, &branch_len)) {
      free(branch);
      break;
    }
    if (!add_multi_literal(p, branch, branch_len, suffix, suffix_len)) {
      free(branch);
      break;
    }
    branches++;
    free(branch);
    pos = alt_end + 1;
    if (alt_end == body_end) break;
  }

  free(suffix);
  if (branches < 2 || p->multi_lit_count < 2 || pos < body_end) {
    discard_multi_literals(p);
    return;
  }
  p->multi_lit_is_prefix = 1;
}

static void compute_simple_rune_repeat(struct hfre *p) {
  if (p->n_groups != 0) return;
  if (p->code_len == 5 &&
      p->code[0].op == OP_SAVE && p->code[0].a == 0 &&
      (p->code[1].op == OP_RUNE || p->code[1].op == OP_RUNE_CI) &&
      p->code[2].op == OP_SPLIT && p->code[2].a == 1 && p->code[2].b == 3 &&
      p->code[3].op == OP_SAVE && p->code[3].a == 1 &&
      p->code[4].op == OP_MATCH) {
    p->simple_rune_kind = 1;
    p->simple_rune_cp = p->code[1].a;
    p->simple_rune_icase = p->code[1].op == OP_RUNE_CI;
    p->code[1].op = OP_REPEAT_RUNE;
    p->code[1].a = p->simple_rune_cp;
    p->code[1].b = p->simple_rune_kind | (p->simple_rune_icase ? 0x100 : 0);
    p->code[2] = p->code[3];
    p->code[3] = p->code[4];
    p->code_len = 4;
  } else if (p->code_len == 6 &&
      p->code[0].op == OP_SAVE && p->code[0].a == 0 &&
      p->code[1].op == OP_SPLIT && p->code[1].a == 2 && p->code[1].b == 4 &&
      (p->code[2].op == OP_RUNE || p->code[2].op == OP_RUNE_CI) &&
      p->code[3].op == OP_JMP && p->code[3].a == 1 &&
      p->code[4].op == OP_SAVE && p->code[4].a == 1 &&
      p->code[5].op == OP_MATCH) {
    p->simple_rune_kind = 2;
    p->simple_rune_cp = p->code[2].a;
    p->simple_rune_icase = p->code[2].op == OP_RUNE_CI;
    p->code[1].op = OP_REPEAT_RUNE;
    p->code[1].a = p->simple_rune_cp;
    p->code[1].b = p->simple_rune_kind | (p->simple_rune_icase ? 0x100 : 0);
    p->code[2] = p->code[4];
    p->code[3] = p->code[5];
    p->code_len = 4;
  }
}

static int dfa_supported_class(const struct sclass *cls) {
  return cls->prop_pos == 0 && cls->prop_neg == 0;
}

static int dfa_supported_program(const struct hfre *p) {
  if (p->n_groups != 0 || p->code_len <= 0 || p->code_len > 63) return 0;
  for (int pc = 0; pc < p->code_len; pc++) {
    struct insn ins = p->code[pc];
    switch (ins.op) {
      case OP_MATCH:
      case OP_SAVE:
      case OP_JMP:
      case OP_SPLIT:
      case OP_ANY:
        break;
      case OP_LIT:
      case OP_REPEAT_RUNE:
        return 0;
      case OP_RUNE:
        if (ins.a < 0 || ins.a >= 128) return 0;
        break;
      case OP_RUNE_CI:
        if (ins.a < 0 || ins.a >= 128) return 0;
        break;
      case OP_CLASS:
        if (!dfa_supported_class(&p->classes[ins.a])) return 0;
        break;
      default:
        return 0;
    }
  }
  return 1;
}

static void dfa_closure_add(const struct hfre *p, uint64_t *bits, int pc) {
  int stack[128];
  int sp = 0;
  uint64_t seen = 0;
  stack[sp++] = pc;
  while (sp > 0) {
    pc = stack[--sp];
    if (pc < 0 || pc >= p->code_len) continue;
    uint64_t bit = 1ull << pc;
    if (seen & bit) continue;
    seen |= bit;
    if (*bits & bit) continue;
    struct insn ins = p->code[pc];
    switch (ins.op) {
      case OP_JMP:
        if (sp < (int)(sizeof(stack) / sizeof(stack[0]))) stack[sp++] = ins.a;
        break;
      case OP_SPLIT:
        if (sp < (int)(sizeof(stack) / sizeof(stack[0]))) stack[sp++] = ins.b;
        if (sp < (int)(sizeof(stack) / sizeof(stack[0]))) stack[sp++] = ins.a;
        break;
      case OP_SAVE:
        if (sp < (int)(sizeof(stack) / sizeof(stack[0]))) stack[sp++] = pc + 1;
        break;
      default:
        *bits |= bit;
        break;
    }
  }
}

static int dfa_add_state(struct hfre *p, uint64_t bits) {
  for (int i = 0; i < p->dfa_state_count; i++) {
    if (p->dfa_states[i].bits == bits) return i;
  }
  if (p->dfa_state_count >= HFRE_DFA_MAX_STATES) return -1;
  int id = p->dfa_state_count++;
  p->dfa_states[id].bits = bits;
  p->dfa_states[id].is_match = 0;
  for (int i = 0; i < 128; i++) p->dfa_states[id].trans[i] = -2;
  for (int pc = 0; pc < p->code_len; pc++) {
    if ((bits & (1ull << pc)) && p->code[pc].op == OP_MATCH) {
      p->dfa_states[id].is_match = 1;
      break;
    }
  }
  return id;
}

static void compute_lazy_dfa(struct hfre *p) {
  if (!dfa_supported_program(p)) return;
  p->dfa_states = (struct dfa_state *)
    calloc(HFRE_DFA_MAX_STATES, sizeof(p->dfa_states[0]));
  if (p->dfa_states == NULL) return;
  uint64_t start = 0;
  dfa_closure_add(p, &start, 0);
  if (dfa_add_state(p, start) != 0) {
    free(p->dfa_states);
    p->dfa_states = NULL;
    p->dfa_state_count = 0;
    return;
  }
  p->dfa_eligible = 1;
}

/* ------------------------------------------------------------------ */
/* Compile                                                             */
/* ------------------------------------------------------------------ */

void hfre_free(struct hfre *re) {
  if (re == NULL) return;
  free(re->code);
  free(re->classes);
  for (int i = 0; i < re->n_lits; i++) {
    free(re->lits[i].s);
  }
  free(re->lits);
  free(re->literal);
  free(re->req_lit);
  free(re->suffix_lit);
  for (int i = 0; i < re->multi_lit_count; i++) {
    free(re->multi_lits[i].s);
  }
  free(re->dfa_states);
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

int hfre_capture_count(const struct hfre *re) {
  return re == NULL ? 0 : re->n_groups;
}

int hfre_compile(const char *pattern, int flags, struct hfre **out) {
  if (pattern == NULL || out == NULL) return HFRE_INVALID_ARGUMENT;
  struct hfre *p = (struct hfre *) calloc(1, sizeof(*p));
  if (p == NULL) return HFRE_OUT_OF_MEMORY;
  p->flags = flags;

  struct parser ps;
  memset(&ps, 0, sizeof(ps));
  ps.re = (const unsigned char *) pattern;
  ps.re_len = (int) strlen(pattern);
  ps.flags = flags;
  ps.group_index = 1;

  if (emit(p, OP_SAVE, 0, 0) < 0) { hfre_free(p); return HFRE_OUT_OF_MEMORY; }
  if (parse_alt(&ps, p) < 0) {
    int err = ps.err ? ps.err : HFRE_INTERNAL_ERROR;
    hfre_free(p);
    return err;
  }
  if (ps.pos != ps.re_len) {
    hfre_free(p);
    return HFRE_UNBALANCED_BRACKETS;
  }
  if (emit(p, OP_SAVE, 1, 0) < 0) { hfre_free(p); return HFRE_OUT_OF_MEMORY; }
  if (emit(p, OP_MATCH, 0, 0) < 0) { hfre_free(p); return HFRE_OUT_OF_MEMORY; }

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

  compute_match_bounds(p);
  compute_pure_literal(p);
  compute_shift_or(p);
  compute_required_literal(p);
  compute_dot_star_lit(p);
  compute_suffix_literal(p);
  compute_multi_literals(p, ps.re, ps.re_len);
  compute_literal_run_opcodes(p);

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
    const struct sclass *cls = &p->classes[p->code[1].a];
    if (cls->prop_pos || cls->prop_neg || !sclass_has_high_byte(cls)) {
      p->simple_class_kind = 1;
      p->simple_class_idx = p->code[1].a;
    }
  } else if (p->n_groups == 0 && p->code_len == 6 &&
      p->code[0].op == OP_SAVE && p->code[0].a == 0 &&
      p->code[1].op == OP_SPLIT && p->code[1].a == 2 && p->code[1].b == 4 &&
      p->code[2].op == OP_CLASS &&
      p->code[3].op == OP_JMP && p->code[3].a == 1 &&
      p->code[4].op == OP_SAVE && p->code[4].a == 1 &&
      p->code[5].op == OP_MATCH) {
    const struct sclass *cls = &p->classes[p->code[2].a];
    if (cls->prop_pos || cls->prop_neg || !sclass_has_high_byte(cls)) {
      p->simple_class_kind = 2;
      p->simple_class_idx = p->code[2].a;
    }
  }
  compute_simple_rune_repeat(p);
  compute_lazy_dfa(p);

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
    hfre_free(p);
    return HFRE_OUT_OF_MEMORY;
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
  const struct hfre *re;
  const unsigned char *buf;
  int buf_len;
  int *cap_pool;
  int cap_pool_used;
  int cap_pool_cap;
  int cap_stride;
  int *seen_gen;
  int gen;
  int max_threads;
  int failed;
};

static int *cap_alloc(struct execstate *es) {
  if (es->cap_pool_used + es->cap_stride > es->cap_pool_cap) {
    es->failed = 1;
    return NULL;
  }
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
static void add_thompson(const struct hfre *re, int *list, int *n,
                         int pc, int sp, int gen, int *seen_gen,
                         int buf_len, int max_threads, int *failed) {
  while (1) {
    if (*failed) return;
    if (pc < 0 || pc >= re->code_len) return;
    if (seen_gen[pc] == gen) return;
    seen_gen[pc] = gen;
    struct insn ins = re->code[pc];
    switch (ins.op) {
      case OP_JMP:
        pc = ins.a;
        continue;
      case OP_SPLIT:
        add_thompson(re, list, n, ins.a, sp, gen, seen_gen, buf_len,
                     max_threads, failed);
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
        if (*n >= max_threads) {
          *failed = 1;
          return;
        }
        list[(*n)++] = pc;
        return;
    }
  }
}

/* Run the no-capture Thompson VM. On success returns the byte offset
 * just past the match. Caller knows the match start (== start_off for
 * leftmost matches). */
static int run_thompson(struct hfre *re, const unsigned char *buf,
                        int buf_len, int start_off) {
  int code_len = re->code_len;
  int *clist = re->vm_th_a;
  int *nlist = re->vm_th_b;
  int n_c = 0, n_n = 0;
  int *seen_gen = re->vm_seen_gen;
  memset(seen_gen, 0, (size_t) code_len * sizeof(int));
  int gen = 1;
  int failed = 0;

  add_thompson(re, clist, &n_c, 0, start_off, gen, seen_gen, buf_len,
               re->vm_max_per_step, &failed);
  if (failed) return HFRE_INTERNAL_ERROR;

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
          matched = (unicode_simple_fold(cp) == ins.a);
          break;
        case OP_LIT: {
          const struct litop *lit = &re->lits[ins.a];
          matched = lit->len <= buf_len - sp &&
                    memcmp(buf + sp, lit->s, (size_t) lit->len) == 0;
          if (matched) {
            add_thompson(re, nlist, &n_n, pc + 1, sp + lit->len,
                         gen, seen_gen, buf_len, re->vm_max_per_step, &failed);
            if (failed) return HFRE_INTERNAL_ERROR;
            matched = 0;
          }
          break;
        }
        case OP_CLASS:
          matched = sclass_match(&re->classes[ins.a], re->flags, cp,
                                 (unsigned char) buf[sp]);
          break;
        case OP_UPROP:
          matched = unicode_prop_match(ins.a, cp);
          if (ins.b) matched = !matched;
          break;
        case OP_ANY:
          matched = 1;
          break;
        default:
          break;
      }
      if (matched) {
        add_thompson(re, nlist, &n_n, pc + 1, sp + rune_len,
                     gen, seen_gen, buf_len, re->vm_max_per_step, &failed);
        if (failed) return HFRE_INTERNAL_ERROR;
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

  return has_match ? best_end : HFRE_NO_MATCH;
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
    if (es->failed) return;
    if (pc < 0 || pc >= es->re->code_len) return;
    if (!es->re->has_litop) {
      if (es->seen_gen[pc] == es->gen) return;
      es->seen_gen[pc] = es->gen;
    }
    struct insn ins = es->re->code[pc];
    switch (ins.op) {
      case OP_JMP:
        pc = ins.a;
        continue;
      case OP_SPLIT: {
        /* Higher priority first. We allocate a fresh capture vector
         * for one branch so they don't share state. */
        int *caps_dup = cap_alloc(es);
        if (caps_dup == NULL) return;
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
        if (l->n >= es->max_threads) {
          es->failed = 1;
          return;
        }
        l->t[l->n].pc = pc;
        l->t[l->n].sp = sp;
        l->t[l->n].caps = caps;
        l->n++;
        return;
    }
  }
}

/*
 * Fast Pike VM for programs that don't use OP_LIT. All threads in
 * clist share the global sp (they advance by rune_len per outer
 * step), so we decode the rune once instead of once per thread, and
 * dedupe by (pc, gen) which is sufficient when all threads are at
 * the same sp. Empirically this is ~2x faster than the per-thread-sp
 * path on capture-heavy patterns like the HTTP request line.
 *
 * Programs that contain OP_LIT (literal byte runs) need per-thread
 * sp because OP_LIT can advance multiple bytes in one VM step,
 * desynchronizing threads from each other. Those callers fall
 * through to run_pike_general below.
 */
static int run_pike_global_sp(struct hfre *re, const unsigned char *buf,
                              int buf_len, int start_off,
                              int *out_caps, int *out_match_start) {
  int code_len = re->code_len;
  int stride = re->n_save_slots;

  struct thread *ct = (struct thread *) re->vm_clist;
  struct thread *nt = (struct thread *) re->vm_nlist;
  int *cap_pool_a = re->vm_pool_a;
  int *cap_pool_b = re->vm_pool_b;
  int *seen_gen = re->vm_seen_gen;
  int *best_caps = re->vm_best_caps;
  memset(seen_gen, 0, (size_t) code_len * sizeof(int));
  struct threadlist clist = { ct, 0 };
  struct threadlist nlist = { nt, 0 };

  struct execstate es;
  es.re = re;
  es.buf = buf;
  es.buf_len = buf_len;
  es.cap_pool = cap_pool_a;
  es.cap_pool_used = 0;
  es.cap_pool_cap = re->vm_max_per_step * stride;
  es.cap_stride = stride;
  es.seen_gen = seen_gen;
  es.gen = 1;
  es.max_threads = re->vm_max_per_step;
  es.failed = 0;

  int has_match = 0;
  int best_end = -1;
  int best_start = -1;

  int *seed = cap_alloc(&es);
  if (seed == NULL) return HFRE_INTERNAL_ERROR;
  cap_init(seed, stride);
  add_thread(&es, &clist, 0, seed, start_off);
  if (es.failed) return HFRE_INTERNAL_ERROR;

  int sp = start_off;
  while (clist.n > 0) {
    /* Decode one rune at the shared sp. */
    int rune_len = 0;
    int cp = -1;
    if (sp < buf_len) {
      cp = utf8_decode(buf + sp, buf_len - sp, &rune_len);
      if (rune_len <= 0) rune_len = 1;
    }

    es.cap_pool = (es.cap_pool == cap_pool_a) ? cap_pool_b : cap_pool_a;
    es.cap_pool_used = 0;
    es.gen++;
    nlist.n = 0;

    for (int ti = 0; ti < clist.n; ti++) {
      struct thread th = clist.t[ti];
      struct insn ins = re->code[th.pc];

      if (ins.op == OP_MATCH) {
        has_match = 1;
        best_end = sp;
        best_start = th.caps[0] >= 0 ? th.caps[0] : start_off;
        cap_copy(best_caps, th.caps, stride);
        break;
      }
      if (cp < 0) continue;

      int matched = 0;
      switch (ins.op) {
        case OP_RUNE:
          matched = (cp == ins.a);
          break;
        case OP_RUNE_CI:
          matched = (unicode_simple_fold(cp) == ins.a);
          break;
        case OP_CLASS:
          matched = sclass_match(&re->classes[ins.a], re->flags, cp,
                                 (unsigned char) buf[sp]);
          break;
        case OP_UPROP:
          matched = unicode_prop_match(ins.a, cp);
          if (ins.b) matched = !matched;
          break;
        case OP_ANY:
          matched = 1;
          break;
        default:
          break;
      }
      if (matched) {
        int *new_caps = cap_alloc(&es);
        if (new_caps == NULL) return HFRE_INTERNAL_ERROR;
        cap_copy(new_caps, th.caps, stride);
        add_thread(&es, &nlist, th.pc + 1, new_caps, sp + rune_len);
        if (es.failed) return HFRE_INTERNAL_ERROR;
      }
    }

    {
      struct thread *tmp = clist.t;
      clist.t = nlist.t;
      nlist.t = tmp;
      clist.n = nlist.n;
      nlist.n = 0;
    }

    if (rune_len == 0) break;
    sp += rune_len;
  }

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

  if (has_match) {
    if (out_caps != NULL) cap_copy(out_caps, best_caps, stride);
    if (out_match_start != NULL) *out_match_start = best_start;
    return best_end;
  }
  return HFRE_NO_MATCH;
}

/*
 * Run the Pike VM starting at byte offset start_off. On success
 * returns the end byte offset and writes capture pairs (pairs of
 * (start, end) byte offsets) into out_caps. On no match returns
 * HFRE_NO_MATCH.
 */
static int run_pike(struct hfre *re, const unsigned char *buf,
                    int buf_len, int start_off,
                    int *out_caps, int *out_match_start) {
  if (!re->has_litop) {
    return run_pike_global_sp(re, buf, buf_len, start_off,
                              out_caps, out_match_start);
  }
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
  es.cap_pool_cap = re->vm_max_per_step * stride;
  es.cap_stride = stride;
  es.seen_gen = seen_gen;
  es.gen = 1;
  es.max_threads = re->vm_max_per_step;
  es.failed = 0;

  int has_match = 0;
  int best_end = -1;
  int best_start = -1;

  /* Seed. */
  int *seed = cap_alloc(&es);
  if (seed == NULL) return HFRE_INTERNAL_ERROR;
  cap_init(seed, stride);
  add_thread(&es, &clist, 0, seed, start_off);
  if (es.failed) return HFRE_INTERNAL_ERROR;

  while (1) {
    if (clist.n == 0) break;

    /* Switch allocations to the OTHER pool half for nlist. */
    es.cap_pool = (es.cap_pool == cap_pool_a) ? cap_pool_b : cap_pool_a;
    es.cap_pool_used = 0;
    es.gen++;
    nlist.n = 0;

    for (int ti = 0; ti < clist.n; ti++) {
      struct thread th = clist.t[ti];
      int sp = th.sp;
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

      /* Decode one rune (or one byte if invalid UTF-8). */
      int rune_len = 0;
      int cp = -1;
      if (sp < buf_len) {
        cp = utf8_decode(buf + sp, buf_len - sp, &rune_len);
        if (rune_len <= 0) rune_len = 1;
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
          matched = (unicode_simple_fold(cp) == ins.a);
          break;
        case OP_LIT: {
          const struct litop *lit = &re->lits[ins.a];
          matched = lit->len <= buf_len - sp &&
                    memcmp(buf + sp, lit->s, (size_t) lit->len) == 0;
          if (matched) {
            int *new_caps = cap_alloc(&es);
            if (new_caps == NULL) return HFRE_INTERNAL_ERROR;
            cap_copy(new_caps, th.caps, stride);
            add_thread(&es, &nlist, th.pc + 1, new_caps, sp + lit->len);
            if (es.failed) return HFRE_INTERNAL_ERROR;
            matched = 0;
          }
          break;
        }
        case OP_CLASS:
          /* Class bitmaps are byte-level. For ASCII (cp < 128) the
           * lead byte equals cp. For non-ASCII runes, test the lead
           * byte; this preserves the original hfre byte-class behavior
           * and lets users target e.g. \xC3 explicitly if needed. */
          matched = sclass_match(&re->classes[ins.a], re->flags, cp,
                                 (unsigned char) buf[sp]);
          break;
        case OP_UPROP:
          matched = unicode_prop_match(ins.a, cp);
          if (ins.b) matched = !matched;
          break;
        case OP_ANY:
          matched = 1;
          break;
        default:
          break;
      }
      if (matched) {
        int *new_caps = cap_alloc(&es);
        if (new_caps == NULL) return HFRE_INTERNAL_ERROR;
        cap_copy(new_caps, th.caps, stride);
        add_thread(&es, &nlist, th.pc + 1, new_caps, sp + rune_len);
        if (es.failed) return HFRE_INTERNAL_ERROR;
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

  }

  /* If we exited the loop because clist drained (e.g. at end of input)
   * we may still have an OP_MATCH thread among the parked threads. */
  if (!has_match) {
    for (int ti = 0; ti < clist.n; ti++) {
      if (re->code[clist.t[ti].pc].op == OP_MATCH) {
        has_match = 1;
        best_end = clist.t[ti].sp;
        best_start = clist.t[ti].caps[0] >= 0 ? clist.t[ti].caps[0] : start_off;
        cap_copy(best_caps, clist.t[ti].caps, stride);
        break;
      }
    }
  }

  int result = HFRE_NO_MATCH;
  if (has_match) {
    if (out_caps != NULL) cap_copy(out_caps, best_caps, stride);
    if (out_match_start != NULL) *out_match_start = best_start;
    result = best_end;
  }

  return result;
}

/* ------------------------------------------------------------------ */
/* hfre_exec                                                           */
/* ------------------------------------------------------------------ */

static const unsigned char *icase_memchr(const unsigned char *hay, int hlen,
                                          unsigned char needle_lo) {
  unsigned char hi = ascii_upper(needle_lo);
  for (int i = 0; i < hlen; i++) {
    if (hay[i] == needle_lo || hay[i] == hi) return hay + i;
  }
  return NULL;
}

static int find_pure_literal(const struct hfre *re,
                             const unsigned char *buf, int buf_len,
                             int *out_start) {
  int icase = (re->flags & HFRE_IGNORE_CASE) != 0;
  int n = re->literal_len;
  if (n == 0) { *out_start = 0; return 0; }
  if (n > buf_len) return HFRE_NO_MATCH;

  if (!icase) {
    /* memchr+memcmp wins decisively over a scalar Shift-Or loop on
     * realistic buffers because libc's memchr is vectorized; the
     * Shift-Or path here was costing 4-8x on short literals in big
     * buffers. Shift-Or remains compiled for callers who need
     * worst-case-linear behavior, but find_pure_literal defaults to
     * the faster memchr-and-verify scan. */
    unsigned char first = re->literal[0];
    int last = buf_len - n;
    int i = 0;
    while (i <= last) {
      const unsigned char *p =
        (const unsigned char *) memchr(buf + i, first, (size_t)(last - i + 1));
      if (p == NULL) return HFRE_NO_MATCH;
      i = (int) (p - buf);
      if (memcmp(buf + i, re->literal, (size_t) n) == 0) {
        *out_start = i;
        return i + n;
      }
      i++;
    }
    return HFRE_NO_MATCH;
  } else {
    unsigned char first = re->literal[0];   /* lowercased */
    int last = buf_len - n;
    int i = 0;
    while (i <= last) {
      const unsigned char *p = icase_memchr(buf + i, last - i + 1, first);
      if (p == NULL) return HFRE_NO_MATCH;
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
    return HFRE_NO_MATCH;
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

static int find_multi_lit(const struct hfre *re, const unsigned char *hay,
                          int hlen, int start) {
  for (int i = start; i < hlen; i++) {
    unsigned char b = hay[i];
    if ((re->multi_first[b >> 6] & (1ull << (b & 63))) == 0) continue;
    for (int k = 0; k < re->multi_lit_count; k++) {
      const struct multi_lit *m = &re->multi_lits[k];
      if (m->len <= hlen - i &&
          memcmp(hay + i, m->s, (size_t) m->len) == 0) {
        return i;
      }
    }
  }
  return -1;
}

static int simple_rune_matches(const struct hfre *re, int cp) {
  if (re->simple_rune_icase) {
    return unicode_simple_fold(cp) == re->simple_rune_cp;
  }
  return cp == re->simple_rune_cp;
}

static int run_simple_rune_repeat(const struct hfre *re,
                                  const unsigned char *buf, int buf_len,
                                  struct hfre_result *result) {
  int kind = re->simple_rune_kind;
  if (kind == 2) {
    int j = 0;
    while (j < buf_len) {
      int w;
      int cp = utf8_decode(buf + j, buf_len - j, &w);
      if (w <= 0) w = 1;
      if (cp < 0) break;
      if (!simple_rune_matches(re, cp)) break;
      j += w;
    }
    if (result != NULL) {
      result->start = 0;
      result->end = j;
      result->ncaps = 0;
    }
    return j;
  }

  for (int i = 0; i < buf_len; ) {
    int w;
    int cp = utf8_decode(buf + i, buf_len - i, &w);
    if (w <= 0) w = 1;
    if (cp >= 0 && simple_rune_matches(re, cp)) {
      int j = i + w;
      while (j < buf_len) {
        cp = utf8_decode(buf + j, buf_len - j, &w);
        if (w <= 0) w = 1;
        if (cp < 0) break;
        if (!simple_rune_matches(re, cp)) break;
        j += w;
      }
      if (result != NULL) {
        result->start = i;
        result->end = j;
        result->ncaps = 0;
      }
      return j;
    }
    i += w;
  }
  return HFRE_NO_MATCH;
}

static int class_match_at(const struct sclass *cls, int flags,
                          const unsigned char *buf, int buf_len,
                          int pos, int *width) {
  int w = 0;
  int cp = utf8_decode(buf + pos, buf_len - pos, &w);
  if (w <= 0) w = 1;
  *width = w;
  if (cp < 0) return 0;
  return sclass_match(cls, flags, cp, buf[pos]);
}

static int dfa_byte_matches(const struct hfre *re, int pc, unsigned char b) {
  struct insn ins = re->code[pc];
  switch (ins.op) {
    case OP_RUNE:
      return b == (unsigned char) ins.a;
    case OP_RUNE_CI:
      return unicode_simple_fold(b) == ins.a;
    case OP_CLASS: {
      const struct sclass *cls = &re->classes[ins.a];
      int raw = sclass_byte_raw(cls, b);
      return cls->inverted ? !raw : raw;
    }
    case OP_ANY:
      return 1;
    default:
      return 0;
  }
}

static int dfa_step_state(struct hfre *re, int state_id, unsigned char b) {
  struct dfa_state *st = &re->dfa_states[state_id];
  if (st->trans[b] != -2) return st->trans[b];

  uint64_t next = 0;
  for (int pc = 0; pc < re->code_len; pc++) {
    if ((st->bits & (1ull << pc)) && dfa_byte_matches(re, pc, b)) {
      dfa_closure_add(re, &next, pc + 1);
    }
  }
  if (next == 0) {
    st->trans[b] = -1;
    return -1;
  }
  int id = dfa_add_state(re, next);
  if (id < 0) return -2;
  st->trans[b] = id;
  return id;
}

static int dfa_can_match_from(struct hfre *re, const unsigned char *buf,
                              int buf_len, int start) {
  if (!re->dfa_eligible || re->dfa_state_count <= 0) return -2;
  int state = 0;
  if (re->dfa_states[state].is_match) return start;
  for (int pos = start; pos < buf_len; pos++) {
    unsigned char b = buf[pos];
    if (b >= 128) return -2;
    state = dfa_step_state(re, state, b);
    if (state == -1) return -1;
    if (state < 0) return -2;
    if (re->dfa_states[state].is_match) return pos + 1;
  }
  return -1;
}

int hfre_exec(const struct hfre *re, const char *buf_, int buf_len,
              struct hfre_cap *caps, int num_caps,
              struct hfre_result *result) {
  if (re == NULL || buf_ == NULL || buf_len < 0) return HFRE_INVALID_ARGUMENT;
  if (num_caps < 0) return HFRE_INVALID_ARGUMENT;
  if (num_caps > 0 && caps == NULL) return HFRE_INVALID_ARGUMENT;
  if (num_caps > 0 && num_caps < re->n_groups) return HFRE_CAPS_ARRAY_TOO_SMALL;

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

  if (re->suffix_lit_len > 0 && num_caps == 0) {
    if (buf_len < re->suffix_lit_len) return HFRE_NO_MATCH;
    int start = buf_len - re->suffix_lit_len;
    if (re->suffix_lit_full && start != 0) return HFRE_NO_MATCH;
    if (memcmp(buf + start, re->suffix_lit,
               (size_t) re->suffix_lit_len) != 0) {
      return HFRE_NO_MATCH;
    }
    if (result != NULL) {
      result->start = start;
      result->end = buf_len;
      result->ncaps = 0;
    }
    return buf_len;
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
    if (pos < 0) return HFRE_NO_MATCH;
    int end = pos + re->req_lit_len;
    if (result != NULL) {
      result->start = 0;
      result->end = end;
      result->ncaps = 0;
    }
    return end;
  }

  if (re->multi_lit_count > 0 && find_multi_lit(re, buf, buf_len, 0) < 0) {
    return HFRE_NO_MATCH;
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
    if (found < 0) return HFRE_NO_MATCH;
  }

  if (re->simple_rune_kind != 0) {
    return run_simple_rune_repeat(re, buf, buf_len, result);
  }

  /* Greedy single-class repeat fast path. */
  if (re->simple_class_kind != 0) {
    const struct sclass *cls = &re->classes[re->simple_class_idx];
    int kind = re->simple_class_kind;  /* 1 plus, 2 star */
    /* Pure-byte fast path: when the class has no Unicode property
     * tests, every match decision is a single bitmap lookup on the
     * current byte. This dominates the icase-class workload and is
     * the lion's share of the cost when [a-z]+ runs over a kilobyte
     * of input. */
    int byte_only = (cls->prop_pos == 0 && cls->prop_neg == 0);
    if (byte_only) {
      if (kind == 2) {
        int j = 0;
        if (cls->inverted) {
          while (j < buf_len && !sclass_byte_raw(cls, (unsigned char) buf[j])) j++;
        } else {
          while (j < buf_len && sclass_byte_raw(cls, (unsigned char) buf[j])) j++;
        }
        if (result != NULL) {
          result->start = 0; result->end = j; result->ncaps = 0;
        }
        return j;
      }
      /* kind == 1, [CLASS]+ */
      int i = 0;
      if (cls->inverted) {
        while (i < buf_len && sclass_byte_raw(cls, (unsigned char) buf[i])) i++;
        if (i >= buf_len) return HFRE_NO_MATCH;
        int j = i;
        while (j < buf_len && !sclass_byte_raw(cls, (unsigned char) buf[j])) j++;
        if (result != NULL) {
          result->start = i; result->end = j; result->ncaps = 0;
        }
        return j;
      }
      while (i < buf_len && !sclass_byte_raw(cls, (unsigned char) buf[i])) i++;
      if (i >= buf_len) return HFRE_NO_MATCH;
      int j = i;
      while (j < buf_len && sclass_byte_raw(cls, (unsigned char) buf[j])) j++;
      if (result != NULL) {
        result->start = i; result->end = j; result->ncaps = 0;
      }
      return j;
    }
    if (kind == 2) {
      /* [CLASS]* — leftmost match is at offset 0; greedy length is the
       * longest run of in-class bytes from offset 0. */
      int j = 0;
      while (j < buf_len) {
        int w;
        if (!class_match_at(cls, re->flags, buf, buf_len, j, &w)) break;
        j += w;
      }
      if (result != NULL) {
        result->start = 0;
        result->end = j;
        result->ncaps = 0;
      }
      return j;
    }
    /* kind == 1, [CLASS]+ — leftmost in-class byte starts the match. */
    for (int i = 0; i < buf_len; ) {
      int w;
      if (class_match_at(cls, re->flags, buf, buf_len, i, &w)) {
        int j = i + w;
        while (j < buf_len) {
          if (!class_match_at(cls, re->flags, buf, buf_len, j, &w)) break;
          j += w;
        }
        if (result != NULL) {
          result->start = i;
          result->end = j;
          result->ncaps = 0;
        }
        return j;
      }
      if (w <= 0) w = 1;
      i += w;
    }
    return HFRE_NO_MATCH;
  }

  int min_len = re->min_match_len;
  int last_start = buf_len - min_len;
  if (last_start < 0) {
    /* Min length exceeds buffer. The only way it could still match is
     * if the regex matches the empty string, in which case min_len
     * == 0 — handled below — OR the regex has anchors / lookarounds
     * that we approximate. We bail conservatively. */
    return HFRE_NO_MATCH;
  }
  if (re->anchored_bol) last_start = 0;

  /* Use the hfre struct's preallocated scratch (not thread-safe). */
  struct hfre *re_mut = (struct hfre *) re;
  int *cap_ints = re_mut->vm_cap_ints;

  int ret = HFRE_NO_MATCH;
  int start_pos = 0;
  int icase = (re->flags & HFRE_IGNORE_CASE) != 0;

  int p = 0;
  if (re->anchored_eol && re->has_max_match_len &&
      buf_len > re->max_match_len) {
    p = buf_len - re->max_match_len;
  }
  while (p <= last_start) {
    /* Find next candidate start position using the most precise
     * filter available. The required-literal-prefix filter is
     * tightest: a multi-byte literal that must begin at the match
     * start. Falling back: single-byte first-byte memchr, then a
     * 256-bit byte set scan. */
    if (re->multi_lit_is_prefix && re->multi_lit_count > 0) {
      int found = find_multi_lit(re, buf, buf_len, p);
      if (found < 0) break;
      p = found;
      if (p > last_start) break;
    } else if (re->req_lit_is_prefix && re->req_lit_len >= 2) {
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

    if (re_mut->dfa_eligible && num_caps == 0) {
      int possible = dfa_can_match_from(re_mut, buf, buf_len, p);
      if (possible == -1) {
        int rl;
        int cp = utf8_decode(buf + p, buf_len - p, &rl);
        (void) cp;
        if (rl <= 0) rl = 1;
        p += rl;
        if (re->anchored_bol) break;
        continue;
      }
    }

    int s = -1;
    int end;
    /* Thompson VM is sufficient when the caller doesn't request
     * captures. The match start is the seed position p; the engine
     * just reports the end offset. */
    if (!re->has_litop && num_caps == 0 &&
        (result == NULL || re->n_groups == 0)) {
      end = run_thompson(re_mut, buf, buf_len, p);
      s = p;
    } else {
      end = run_pike(re_mut, buf, buf_len, p, cap_ints, &s);
    }
    if (end < 0 && end != HFRE_NO_MATCH) { ret = end; break; }
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
/* hfre_match (legacy convenience wrapper)                             */
/* ------------------------------------------------------------------ */

int hfre_match(const char *regexp, const char *buf, int buf_len,
               struct hfre_cap *caps, int num_caps, int flags) {
  struct hfre *re = NULL;
  int err = hfre_compile(regexp, flags, &re);
  if (err) return err;
  int rc = hfre_exec(re, buf, buf_len, caps, num_caps, NULL);
  hfre_free(re);
  return rc;
}
