#ifndef __STRING_MACROS_H
#define __STRING_MACROS_H

#define STRINGS_MATCH(a, b) strcmp((a), (b)) == 0
#define STRINGS_MATCH_NO_CASE_N(a, b, n) strncasecmp((a), (b), (n)) == 0
#define ENDSWITH(s, c) (s)[strlen((s)) - 1] == (c)

#endif /* __STRING_MACROS_H */
