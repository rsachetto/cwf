#include "http.h"
#include "../3dparty/sds/sds.h"
#include "../3dparty/stb/stb_ds.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

// TODO: for now redirects are always absolute
void cwf_redirect(const char *url, http_header *headers) {
    char *tmp = (char *)url;

    sds value = NULL;

    if(strlen(url) > 1) {
        if(url[0] == '/') {
            tmp = tmp + 1;
        }

        value = sdscatfmt(sdsempty(), "%s://%s/%s", getenv("REQUEST_SCHEME"), getenv("HTTP_HOST"), tmp);
    } else if(strlen(url) == 1 && *url == '/') {
        value = sdscatfmt(sdsempty(), "%s://%s/", getenv("REQUEST_SCHEME"), getenv("HTTP_HOST"));
    }

    add_custom_header("Location", value, headers);
}

void write_http_headers(http_header header) {
    int h_len = shlen(header);
    for(int i = 0; i < h_len; i++) {
        if(i == h_len - 1) {
            fprintf(stdout, "%s: %s\r\n\r\n", header[i].key, header[i].value);
        } else {
            fprintf(stdout, "%s: %s\r\n", header[i].key, header[i].value);
        }
    }
    fflush(stdout);
}

http_header new_empty_header() {
    http_header header = NULL;
    sh_new_arena(header);
    shdefault(header, NULL);
    return header;
}

void add_custom_header(const char *name, const char *value, http_header *header) {
    if(value)
        shput(*header, name, strdup(value));
}

void add_cookie_to_header(cwf_cookie *c, http_header *header) {

    if(!c || !c->name || !c->value)
        return;

    sds cookie_str = sdsnew(c->name);

    cookie_str = sdscatfmt(cookie_str, "=%s;", c->value);

    char buf[64];
    time_t cookie_date = c->expires + time(NULL);
    struct tm tm = *gmtime(&cookie_date);
    strftime(buf, sizeof buf, "%a, %d %b %Y %H:%M:%S %Z", &tm);

    cookie_str = sdscatfmt(cookie_str, "Expires=%s;", buf);

    if(c->max_age > 0) {
        cookie_str = sdscatfmt(cookie_str, "Max-Age=%i;", c->max_age);
    }

    if(c->domain) {
        cookie_str = sdscatfmt(cookie_str, "Domain=%s;", c->domain);
    }

    if(c->path) {
        cookie_str = sdscatfmt(cookie_str, "Path=%s;", c->path);
    }

    if(c->same_site) {
        cookie_str = sdscatfmt(cookie_str, "SameSite;");
    }

    if(c->secure) {
        cookie_str = sdscatfmt(cookie_str, "Secure;");
    }

    if(c->http_only) {
        cookie_str = sdscatfmt(cookie_str, "HttpOnly;");
    }

    add_custom_header("Set-Cookie", cookie_str, header);

    sdsfree(cookie_str);
}

void cwf_generate_default_404_header(http_header *headers) {
    add_custom_header("Status", "404 Not Found", headers);
    add_custom_header("Content-type", "text/html", headers);
}

void free_cwf_headers(http_header header) {
    int len = shlen(header);

    for(int i = 0; i < len; i++) {
        free(header[i].value);
    }

    shfree(header);
}
