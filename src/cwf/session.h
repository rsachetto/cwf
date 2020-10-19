#ifndef __SESSION_H
#define __SESSION_H

#include "common_data_structures.h"
#include "cookie.h"
#include "http.h"
#include "../3dparty/sds/sds.h"


typedef struct cwf_session_t {
    cwf_cookie *cookie;
    string_hash data;
    sds session_filename;
} cwf_session;

void cwf_session_start(cwf_session **session, http_header *headers, char *session_files_path, int expires);
void cwf_session_destroy(cwf_session **session, http_header *headers);
void cwf_save_session(cwf_session *session);
char *cwf_session_get(cwf_session *session, const char *key);
void cwf_session_put(cwf_session *session, const char *key, const char *value);
char *SHA256_from_char_input(char *input);

#endif /* __SESSION_H */
