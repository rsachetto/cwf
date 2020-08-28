#ifndef __CWF_H
#define __CWF_H

#include <stdbool.h>
#include <stdio.h>

#include "../3dparty/ccgi-1.2/ccgi.h"
#include "../3dparty/ctemplate-1.0/ctemplate.h"
#include "../3dparty/json/json.h"
#include "../3dparty/sds/sds.h"
#include "../3dparty/sqlite/sqlite3.h"

#define IS_REQ_GET(request) strcmp(request->method, "GET") == 0
#define IS_REQ_POST(request) strcmp(request->method, "POST") == 0

#define IS_GET() IS_REQ_GET(cwf_vars->request)
#define IS_POST() IS_REQ_POST(cwf_vars->request)

#define STRINGS_MATCH(a, b) strcmp((a), (b)) == 0
#define STRINGS_MATCH_NO_CASE_N(a, b, n) strncasecmp((a), (b), (n)) == 0

#define ENDSWITH(s, c) (s)[strlen((s)) - 1] == (c)

typedef enum { INT, STRING, FLOAT, INVALID } parameter_type;

typedef char *char_array;
typedef char **string_array;

typedef struct {
    char *name;
    char *value;
    parameter_type type;
} url_params;

typedef struct endpoint_config_t {
    char *function;
    url_params *params;
    char_array error;
} endpoint_config;

typedef struct endpoint_config_item_t {
    char *key;
    endpoint_config *value;
} endpoint_config_item;

typedef struct record_t {
    char *key;
    char *value;
} record;

typedef struct cfw_database_t {
    char *error;
    sqlite3 *db;
    record **records;
    unsigned int num_records;
} cfw_database;

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

typedef record *http_header;

typedef struct request_item_t {
    char *key;
    string_array value;
} request_item;

typedef struct server_data_t {
    char *key;
    char *value;
} server_data;

typedef struct cwf_request_t {
    char *method;
    char *data_type;
    int server_data_len;
    int data_len;
    struct server_data_t *server_data;
    union {
        json_value *json_data;
        request_item *urlencoded_data;
    };
} cwf_request;

typedef struct cwf_session_t {
    cwf_cookie *cookie;
    record *data;
    char *db_filename;
} cwf_session;

typedef struct cwf_vars_t {
    cwf_request *request;
    cwf_session *session;
    http_header headers;
    bool print_debug_info;
} cwf_vars;

#define ENDPOINT_LIB_PATH "/var/www/cwf/libendpoints.so"
#define ENDPOINT(name) sds name(cwf_vars *cwf_vars, endpoint_config *config)
typedef ENDPOINT(endpoint_fn);

typedef void modify_db_name_value_fn(char *name, char *value);

cwf_request *new_empty_request();
cwf_request *new_from_env_vars();

http_header new_empty_header();

#define header(key, value) add_custom_header((key), (value), &(cwf_vars->headers))
void add_custom_header(const char *name, const char *value, http_header *header);

void write_http_headers(http_header header);

#define SERVER(key) cwf_server_vars(cwf_vars->request, (key))
char *cwf_server_vars(cwf_request *req, char *key);

#define GET(key) cwf_get_vars(cwf_vars->request, (key)) ? cwf_get_vars(cwf_vars->request, (key))[0] : NULL
#define GET_ARRAY(key) cwf_get_vars(cwf_vars->request, (key))
string_array cwf_get_vars(cwf_request *req, char *key);

#define POST(key) cwf_post_vars(cwf_vars->request, (key)) ? cwf_post_vars(cwf_vars->request, (key))[0] : NULL
#define POST_ARRAY(key) cwf_post_vars(cwf_vars->request, (key))
string_array cwf_post_vars(cwf_request *req, char *key);

#define DUMP_REQUEST_VARS()        \
    generate_default_404_header(); \
    return cwf_dump_request_vars(cwf_vars->request)
sds cwf_dump_request_vars(cwf_request *req);

#define SESSION_GET(key) cwf_session_get(cwf_vars->session, (key))
char *cwf_session_get(cwf_session *session, const char *key);

#define SESSION_PUT(key, value) cwf_session_put(cwf_vars->session, (key), (value))
char *cwf_session_put(cwf_session *session, const char *key, const char *value);

#define render_template(varlist, path) cwf_render_template((varlist), (path), &(cwf_vars->headers))
sds cwf_render_template(TMPL_varlist *varlist, const char *template_path, http_header *headers);

#define request_to_varlist(varlist, modify_fn) cwf_request_to_varlist((varlist), (modify_fn), cwf_vars->request)
TMPL_varlist *cwf_request_to_varlist(TMPL_varlist *varlist, modify_db_name_value_fn *modify, cwf_request *req);

TMPL_varlist *db_record_to_varlist(TMPL_varlist *varlist, cfw_database *database, modify_db_name_value_fn *modify);
TMPL_varlist *db_records_to_loop(TMPL_varlist *varlist, cfw_database *database, char *loop_name,
                                 modify_db_name_value_fn *f);

cwf_cookie *get_cookie();
cwf_cookie *new_cookie(char *name, char *value);
void add_cookie_to_header(cwf_cookie *c, http_header *header);

endpoint_config *new_endpoint_config();
endpoint_config_item *new_endpoint_config_hash();
endpoint_config *get_endpoint_config(const char *REQUEST_URI, const char *QUERY_STRING, endpoint_config_item *configs);
void add_params_to_request(cwf_request *req, url_params *params);
cfw_database *open_database(const char *db_filename);
void execute_query(const char *query, cfw_database *db);
int get_num_columns(record *r);

char_array strip_html_tags(const char *buf);

#define generate_default_404_header() cwf_generate_default_404_header(&(cwf_vars->headers))
void cwf_generate_default_404_header(http_header *headers);

#define redirect(url)                          \
    cwf_redirect((url), &(cwf_vars->headers)); \
    return NULL;
void cwf_redirect(const char *url, http_header *headers);

#define session_start() cwf_session_start(&(cwf_vars->session), &(cwf_vars->headers))
void cwf_session_start(cwf_session **session, http_header *headers);

#define session_destroy() cwf_session_destroy(&(cwf_vars->session), &(cwf_vars->headers))
void cwf_session_destroy(cwf_session **session, http_header *headers);

void cwf_save_session(cwf_session *session);

#define generate_simple_404(format, ...) simple_404_page(cwf_vars, format, __VA_ARGS__)
sds simple_404_page(cwf_vars *cwf_vars, char *format, ...);

#endif /* __CWF_H */
