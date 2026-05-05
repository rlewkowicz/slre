---
title: "Find all URLs in a string"
---

```c
static const char *str =
  "<img src=\"HTTPS://FOO.COM/x?b#c=tab1\"/> "
  "  <a href=\"http://example.org\">some link</a>";

static const char *regex = "((https?://)[^\\s/'\"<>]+/?[^\\s'\"<>]*)";
struct hfre_cap caps[2];
int i, j = 0, str_len = strlen(str);

while (j < str_len &&
       (i = hfre_match(regex, str + j, str_len - j, caps, 2, HFRE_IGNORE_CASE)) > 0) {
  printf("Found URL: [%.*s]\n", caps[0].len, caps[0].ptr);
  j += i;
}
```

Output:

```
Found URL: [HTTPS://FOO.COM/x?b#c=tab1]
Found URL: [http://example.org]
```
