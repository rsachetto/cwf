#ifndef __SESSION_H
#define __SESSION_H

#include "common_data_structures.h"
#include "cookie.h"
#include "http.h"

typedef struct cwf_session_t {
    cwf_cookie *cookie;
    string_hash data;
    char *db_filename;
} cwf_session;

#define session_start() cwf_session_start(&(cwf_vars->session), &(cwf_vars->headers), cwf_vars->session_files_path)
void cwf_session_start(cwf_session **session, http_header *headers, char *session_files_path);

#define session_destroy() cwf_session_destroy(&(cwf_vars->session), &(cwf_vars->headers), cwf_vars->session_files_path)
void cwf_session_destroy(cwf_session **session, http_header *headers, char *session_files_path);

void cwf_save_session(cwf_session *session);

char *cwf_session_get(cwf_session *session, const char *key);

void cwf_session_put(cwf_session *session, const char *key, const char *value);

#endif /* __SESSION_H */
