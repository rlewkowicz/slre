---
title: "Syntax"
---

```
^       Match beginning of a buffer
$       Match end of a buffer
.       Match any single UTF-8 code point
()      Grouping and substring capturing

\s \S   Match (non-)whitespace (ASCII)
\d \D   Match (non-)decimal digit (ASCII)
\w \W   Match (non-)word character: [A-Za-z0-9_] (ASCII)
\n \r \f \v \t \b
        Match the corresponding control character
\xHH    Match byte with hex value 0xHH (e.g. \x4a)
\pN \p{Greek}
        Match a Unicode property or script
\PN \P{Greek}
        Match a code point outside a Unicode property or script
\meta   Match one of the meta characters: ^$().[]*+?|\

+       Match one or more times (greedy)
+?      Match one or more times (lazy)
*       Match zero or more times (greedy)
*?      Match zero or more times (lazy)
?       Match zero or one time (greedy)
??      Match zero or one time (lazy)
x|y     Match x or y (alternation; leftmost-first priority)

[...]   Match any byte from the set. Ranges like [a-z] supported.
        Inside a class, `\d \D \s \S \w \W` expand to their byte
        sets, `\p...` and `\P...` add Unicode property tests, and
        `\xHH` selects a literal byte. `.` is a literal period.
        The first character may be `^` to negate the set.
[^...]  Negated class.
```

Non-ASCII literals in the pattern (including emoji) match the same
UTF-8 byte sequence in the input.

Supported Unicode property names are `L`, `N`, `Lu`, `Ll`, `Nd`,
`Latin`, `Greek`, `Cyrillic`, `Han`, `Hiragana`, and `Katakana`,
backed by Unicode Character Database 17.0.0 ranges. Matching uses
code points directly and does not normalize text.
