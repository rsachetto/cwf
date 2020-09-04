#include <stdio.h>
#include <stdlib.h>

#include "../3dparty/ccgi-1.2/ccgi.h"
#include "../3dparty/sds/sds.h"
#include "../3dparty/sqlite/sqlite3.h"
#include "../3dparty/stb/stb_ds.h"
#include "session.h"
#include <openssl/sha.h>
#include <time.h>

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
    char buf[40];
    sprintf(buf, "%ld", time(NULL));

    unsigned char sha[32];
    simpleSHA256(buf, strlen(buf), sha);

    char *b64 = CGI_encode_base64(sha, 32);

    size_t len = strlen(b64);

    for(size_t i = 0; i < len; i++) {
        if(b64[i] == '/')
            b64[i] = '_';
    }

    return (b64);
}

static int sqlite_callback_for_session(void *data, int num_results, char **column_values, char **column_names) {
    if(num_results) {
        string_hash *line = (string_hash *)data;

        int num_records = 0;

        for(int i = 0; i < num_results; i += 2) {
            shput(*line, strdup(column_values[i]), strdup(column_values[i + 1]));
        }
    }

    return 0;
}

static void execute_query_for_session(const char *query, sqlite3 *db, string_hash *data) {
    char *errmsg;

    // TODO We will have to free all records
    if(*data) {
        arrfree(*data);
        *data = NULL;
        sh_new_arena(*data);
        shdefault(*data, NULL);
    }

    int rc = sqlite3_exec(db, query, sqlite_callback_for_session, (void *)data, &errmsg);

    // TODO handle error
    if(rc != SQLITE_OK) {
    }
}

#define SESSION_NAME_TEMPLATE "%s/session_%s.session"
void cwf_session_start(cwf_session **session, http_header *headers, char *session_files_path) {
    // TODO section needs to have a lock to access the session file. I thing we will need a semaphore here to handle simultaneous connections. If a section is
    // readonly we don't need to bother with the lockfile
    if(*session == NULL) {
        *session = calloc(1, sizeof(session));

        (*session)->cookie = get_cookie();

        if(!(*session)->cookie) {
            char *sid = generate_session_id();
            (*session)->cookie = new_cookie("sid", sid);
            sh_new_arena((*session)->data);
            shdefault((*session)->data, NULL);

            // TODO let the user define a expire time and the other cookie settings
            (*session)->cookie->expires = 12 * 30 * 24 * 60 * 60;
            (*session)->cookie->domain = getenv("SERVER_NAME");
            add_cookie_to_header((*session)->cookie, headers);

            char session_file_name[256];
            // TODO use c11 to avoid insecure string functions
            sprintf(session_file_name, SESSION_NAME_TEMPLATE, session_files_path, sid);
            (*session)->db_filename = strdup(session_file_name);

            free(sid);

            // TODO We only need to create a new file for the session
            sqlite3 *session_file;
            int rc = sqlite3_open_v2(session_file_name, &session_file, SQLITE_OPEN_CREATE | SQLITE_OPEN_READWRITE, NULL);

            // TODO handle session errors
            if(rc != SQLITE_OK) {
                const char *err = sqlite3_errmsg(session_file);
                fprintf(stderr, "%s\n", err);
                sqlite3_close(session_file);
            }

            char *sql = "DROP TABLE IF EXISTS session_data;";
            char *error;

            rc = sqlite3_exec(session_file, sql, NULL, NULL, &error);

            // TODO handle session errors
            if(rc != SQLITE_OK) {
                sqlite3_close(session_file);
                sqlite3_free(error);
            }

            char *sql2 = "CREATE TABLE session_data (key TEXT PRIMARY KEY, value TEXT);";

            rc = sqlite3_exec(session_file, sql2, NULL, NULL, &error);

            // TODO handle session errors
            if(rc != SQLITE_OK) {
                sqlite3_close(session_file);
                sqlite3_free(error);
            }

            sqlite3_close(session_file);

        } else {
            char session_file_name[1024];
            // TODO use c11 to avoid insecure string functions
            sprintf(session_file_name, SESSION_NAME_TEMPLATE, session_files_path, (*session)->cookie->value);
            (*session)->db_filename = strdup(session_file_name);

            // We only need to create a new file for the session
            sqlite3 *session_file;
            int rc = sqlite3_open((*session)->db_filename, &session_file);

            // TODO handle session errors
            if(rc != SQLITE_OK) {
                sqlite3_close(session_file);
            }

            char *error;
            char *sql = "CREATE TABLE IF NOT EXISTS session_data (key TEXT PRIMARY KEY, value TEXT);";
            rc = sqlite3_exec(session_file, sql, NULL, NULL, &error);

            // TODO handle session errors
            if(rc != SQLITE_OK) {
                sqlite3_close(session_file);
                sqlite3_free(error);
            }

            char *sql2 = "SELECT * from session_data;";
            execute_query_for_session(sql2, session_file, &(*session)->data);
            sqlite3_close(session_file);
        }
    }
}

void cwf_session_destroy(cwf_session **session, http_header *headers, char *session_files_path) {
    if(*session == NULL) {
        return;
    } else {
        char session_file_name[1024];

        // TODO use c11 to avoid insecure string functions
        sprintf(session_file_name, SESSION_NAME_TEMPLATE, session_files_path, (*session)->cookie->value);

        (*session)->cookie->expires = -3600 * 24;
        add_cookie_to_header((*session)->cookie, headers);

        free_cookie((*session)->cookie);

        free((*session)->db_filename);

        free(*session);
        *session = NULL;
        remove(session_file_name);
    }
}

void cwf_save_session(cwf_session *session) {
    if(!session)
        return;

    sqlite3 *session_file;
    int rc = sqlite3_open(session->db_filename, &session_file);

    // TODO handle session errors
    if(rc != SQLITE_OK) {
        sqlite3_close(session_file);
    }

    int len = shlen(session->data);

    sds query = sdsempty();

    for(int i = 0; i < len; i++) {
        query = sdscatprintf(query, "REPLACE INTO session_data (key, value) VALUES('%s', '%s');", session->data[i].key, session->data[i].value);
    }

    char *error;
    rc = sqlite3_exec(session_file, query, NULL, NULL, &error);

    // TODO handle session errors
    if(rc != SQLITE_OK) {
        fprintf(stderr, "%s\n", error);
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

