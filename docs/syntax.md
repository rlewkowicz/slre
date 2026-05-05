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
        sets, and `\xHH` selects a literal byte. `.` is a literal
        period. The first character may be `^` to negate the set.
[^...]  Negated class.
```

Non-ASCII literals in the pattern (including emoji) match the same
UTF-8 byte sequence in the input.

Unicode property classes (`\p{Greek}`, `\PN`, etc.) are reserved for
a future revision and currently produce
`SLRE_INVALID_UNICODE_PROPERTY` at compile time.
