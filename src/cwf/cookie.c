#include "cookie.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "string_macros.h"

#include "../3dparty/ccgi-1.2/ccgi.h"

cwf_cookie *new_cookie(char *name, char *value) {
    cwf_cookie *v = calloc(1, sizeof(cwf_cookie));
    v->name = strdup(name);
    v->value = strdup(value);
    return v;
}

void free_cookie(cwf_cookie *cookie) {
    if(!cookie)
        return;
    free(cookie->name);
    free(cookie->value);
    free(cookie->path);
    free(cookie->domain);
    free(cookie->same_site);
}

cwf_cookie *get_cookie() {

    const char *env;

    if((env = getenv("HTTP_COOKIE")) == 0) {
        return NULL;
    }

    char *buf, *p, *cookie_data[2];

    cwf_cookie *v = calloc(1, sizeof(cwf_cookie));

    buf = (char *)malloc(strlen(env) + 1);

    p = strcpy(buf, env); //We need to keep a pointer to buf to be able to free it

    while((p = CGI_scanattr(p, cookie_data)) != 0) {
        if(v->name == NULL) {
            v->name = strdup(cookie_data[0]);
            v->value = strdup(cookie_data[1]);
        } else if(STRINGS_MATCH_NO_CASE_N(cookie_data[0], "Expires", 7)) {
            v->expires = (int)strtol(cookie_data[1], NULL, 10);
        } else if(STRINGS_MATCH_NO_CASE_N(cookie_data[0], "Max-Age", 7)) {
            v->max_age = (int)strtol(cookie_data[1], NULL, 10);
        } else if(STRINGS_MATCH_NO_CASE_N(cookie_data[0], "Domain", 6)) {
            v->domain = strdup(cookie_data[1]);

        } else if(STRINGS_MATCH_NO_CASE_N(cookie_data[0], "Path", 4)) {
            v->path = strdup(cookie_data[1]);
        } else if(STRINGS_MATCH_NO_CASE_N(cookie_data[0], "Secure", 6)) {
            v->secure = true;
        } else if(STRINGS_MATCH_NO_CASE_N(cookie_data[0], "HttpOnly", 8)) {
            v->http_only = true;
        } else if(STRINGS_MATCH_NO_CASE_N(cookie_data[0], "SameSite", 8)) {
            if(STRINGS_MATCH_NO_CASE_N(cookie_data[0], "Strict", 6)) {
                v->same_site = strdup("Strict");
            } else if(STRINGS_MATCH_NO_CASE_N(cookie_data[0], "Lax", 3)) {
                v->same_site = strdup("Lax");
            }
        }
    }
    free(buf);
    return v;
}
