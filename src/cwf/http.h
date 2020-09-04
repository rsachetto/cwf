#ifndef __HTTP_H
#define __HTTP_H

#include "common_data_structures.h"
#include "cookie.h"

typedef string_hash http_header;

http_header new_empty_header();

void add_custom_header(const char *name, const char *value, http_header *header);

void write_http_headers(http_header header);
void add_cookie_to_header(cwf_cookie *c, http_header *header);

void cwf_generate_default_404_header(http_header *headers);

void cwf_redirect(const char *url, http_header *headers);
void free_cwf_headers(http_header header);

#endif /* __HTTP_H */
