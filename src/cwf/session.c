#include <stdio.h>
#include <stdlib.h>

#include "../3dparty/ccgi-1.2/ccgi.h"
#include "../3dparty/sqlite/sqlite3.h"
#include "../3dparty/stb/stb_ds.h"
#include "session.h"
#include <openssl/sha.h>
#include <time.h>

static void rand_str(char *dest, size_t length) {
    srand(time(NULL));
    char charset[] = "0123456789"
                     "abcdefghijklmnopqrstuvwxyz"
                     "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                     ":;?@[\\]^_`{|}";

    while(length-- > 0) {
        size_t index = (double)rand() / RAND_MAX * (sizeof charset - 1);
        *dest++ = charset[index];
    }

    *dest = '\0';
}

static bool simpleSHA256(void *input, unsigned long length, unsigned char *md) {
    SHA256_CTX context;
    if(!SHA256_Init(&context))
        return false;

    if(!SHA256_Update(&context, (unsigned char *)input, length))
        return false;

    if(!SHA256_Final(md, &context))
        return false;

    return true;
}

static char *generate_session_id() {

    char buf[33];

    rand_str(buf, 32);

    unsigned char sha[33];
    simpleSHA256(buf, strlen(buf), sha);

    char *b64 = CGI_encode_base64(sha, 32);

    size_t len = strlen(b64);

    for(size_t i = 0; i < len; i++) {
        if(b64[i] == '/' || b64[i] == '=' || b64[i] == '+') {
            b64[i] = '_';
        }
    }

    return (b64);
}

static inline void hash_bin2hex(char *out, const unsigned char *in, size_t in_len) {
    static const char hexits[17] = "0123456789abcdef";
    size_t i;

    for(i = 0; i < in_len; i++) {
        out[i * 2] = hexits[in[i] >> 4];
        out[(i * 2) + 1] = hexits[in[i] & 0x0F];
    }
}

char *SHA256_from_char_input(char *input) {

    unsigned char sha[32];

    if(!simpleSHA256(input, strlen(input), sha)) {
        fprintf(stderr, "Error on %s, Line :%d\n", __FILE__, __LINE__);
        return NULL;
    }

    char *out = (char *)malloc(65);

    hash_bin2hex(out, sha, 32);

    out[64] = '\0';

    return out;
}

static int sqlite_callback_for_session(void *data, int num_results, char **column_values, char **column_names) {

    if(num_results) {

        string_hash *line = (string_hash *)data;

        for(int i = 0; i < num_results; i += 2) {
            shput(*line, strdup(column_values[i]), strdup(column_values[i + 1]));
        }
    }

    return 0;
}

static int execute_query_for_session(const char *query, sqlite3 *db, string_hash *data, char **error) {

    // TODO We will have to free all records
    if(*data) {
        arrfree(*data);
        *data = NULL;
        sh_new_arena(*data);
        shdefault(*data, NULL);
    }

    int rc = sqlite3_exec(db, query, sqlite_callback_for_session, (void *)data, error);

    return rc;
}

void cwf_session_start(cwf_session **session, http_header *headers, char *session_files_path, int expires) {

    char *error;

    // TODO section needs to have a lock to access the session file. I thing we will need a semaphore here to handle simultaneous connections. If a section is
    // readonly we don't need to bother with the lockfile
    if(*session == NULL) {

        *session = calloc(1, sizeof(struct cwf_session_t));
        (*session)->session_filename = sdscatfmt(sdsempty(), "%s/%s", session_files_path, "sessions.sqlite");

        sqlite3 *session_file;
        int rc = sqlite3_open_v2((*session)->session_filename, &session_file, SQLITE_OPEN_CREATE | SQLITE_OPEN_READWRITE, NULL);

        if(rc != SQLITE_OK) {
            error = (char *)sqlite3_errmsg(session_file);
            fprintf(stderr, "[SQLITE-ERROR] File %s - Line %d - %s\n", __FILE__, __LINE__, error);
            sqlite3_close(session_file);
            return;
        }

        (*session)->cookie = get_cookie();

        if(!(*session)->cookie) {
            (*session)->cookie = new_cookie("sid", generate_session_id());
            (*session)->cookie->expires = expires;
            (*session)->cookie->domain = getenv("SERVER_NAME");
            add_cookie_to_header((*session)->cookie, headers);
        }

        sds sql;
        char *sid = (*session)->cookie->value;

        sql = sdscatfmt(sdsempty(), "CREATE TABLE IF NOT EXISTS \"session_data_%s\" (key TEXT PRIMARY KEY, value TEXT);", sid);
        rc = sqlite3_exec(session_file, sql, NULL, NULL, &error);

        if(rc != SQLITE_OK) {
            sqlite3_close(session_file);
            fprintf(stderr, "[SQLITE-ERROR] File %s - Line %d - %s - query %s\n", __FILE__, __LINE__, error, sql);
            sqlite3_free(error);
            sdsfree(sql);
            return;
        }
        sdsfree(sql);

        sql = sdscatfmt(sdsempty(), "SELECT key, value FROM \"session_data_%s\";", sid);
        rc = execute_query_for_session(sql, session_file, &(*session)->data, &error);

        if(rc != SQLITE_OK) {
            fprintf(stderr, "[SQLITE-ERROR] File %s - Line %d - %s-  query %s\n", __FILE__, __LINE__, error, sql);
            sqlite3_close(session_file);
            sqlite3_free(error);
            sdsfree(sql);
            return;
        }

        sdsfree(sql);

        sqlite3_close(session_file);
    } else {
        // TODO: and do not think this will ever happen
    }
}

void cwf_session_destroy(cwf_session **session, http_header *headers) {

    if(*session == NULL) {
        return;
    } else {

        char *error;
        sqlite3 *session_file;
        int rc = sqlite3_open_v2((*session)->session_filename, &session_file, SQLITE_OPEN_CREATE | SQLITE_OPEN_READWRITE, NULL);

        if(rc != SQLITE_OK) {
            error = (char *)sqlite3_errmsg(session_file);
            fprintf(stderr, "[SQLITE-ERROR] File %s - Line %d - %s\n", __FILE__, __LINE__, error);
            sqlite3_close(session_file);
            return;
        }

        (*session)->cookie->expires = -3600 * 24;
        add_cookie_to_header((*session)->cookie, headers);

        sds sql = sdscatfmt(sdsempty(), "DROP TABLE \"session_data_%s\";", (*session)->cookie->value);
        rc = sqlite3_exec(session_file, sql, NULL, NULL, &error);
        sdsfree(sql);

        if(rc != SQLITE_OK) {
            fprintf(stderr, "[SQLITE-ERROR] File %s - Line %d - %s\n", __FILE__, __LINE__, error);
            sqlite3_close(session_file);
            sqlite3_free(error);
            return;
        }

        sqlite3_close(session_file);

        free_cookie((*session)->cookie);
        sdsfree((*session)->session_filename);

        free(*session);
        *session = NULL;
    }
}

void cwf_save_session(cwf_session *session) {
   
    if(!session)
        return;

    sqlite3 *session_file;
    int rc = sqlite3_open(session->session_filename, &session_file);

    if(rc != SQLITE_OK) {
        char *error = (char *)sqlite3_errmsg(session_file);
        fprintf(stderr, "[SQLITE-ERROR] File %s - Line %d - %s\n", __FILE__, __LINE__, error);
        sqlite3_close(session_file);
        return;
    }

    int len = shlen(session->data);

    sds query = sdsempty();

    for(int i = 0; i < len; i++) {
        query = sdscatfmt(
            query, "INSERT INTO \"session_data_%s\" (key, value) VALUES ('%s', '%s') ON CONFLICT(key) DO UPDATE SET key = '%s', value = '%s' WHERE value <> '%s';",
            session->cookie->value, session->data[i].key, session->data[i].value, session->data[i].key, session->data[i].value, session->data[i].value);
    }

    char *error;
    rc = sqlite3_exec(session_file, query, NULL, NULL, &error);
   
    // TODO handle session errors
    if(rc != SQLITE_OK) {
        fprintf(stderr, "[SQLITE-ERROR] File %s - Line %d - %s\n", __FILE__, __LINE__, error);
        sqlite3_close(session_file);
        sdsfree(query);
        return;
    }

    sdsfree(query);
    sqlite3_close(session_file);
}

char *cwf_session_get(cwf_session *session, const char *key) {
    return shget(session->data, key);
}

void cwf_session_put(cwf_session *session, const char *key, const char *value) {
    shput(session->data, key, strdup(value));
}

