#ifndef __COOKIES_H
#define __COOKIES_H

#include <stdbool.h>

typedef struct cookie_t {
    char *name;
    char *value;
    int expires;
    int max_age;
    char *domain;
    char *path;
    bool secure;
    bool http_only;
    char *same_site;
} cwf_cookie;

cwf_cookie *new_cookie(char *name, char *value);
void free_cookie(cwf_cookie *cookie);
cwf_cookie *get_cookie();

#endif /* __COOKIES_H */
