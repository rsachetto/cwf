#ifndef __CWF_H
#define __CWF_H

#include <stdbool.h>
#include <stdio.h>

#include "../3dparty/ccgi-1.2/ccgi.h"
#include "../3dparty/ctemplate-1.0/ctemplate.h"
#include "../3dparty/json/json.h"
#include "../3dparty/sds/sds.h"
#include "../3dparty/sqlite/sqlite3.h"

#include "common_data_structures.h"
#include "cookie.h"
#include "http.h"
#include "session.h"
#include "string_macros.h"

#define IS_REQ_GET(request) request->method ? (strcmp(request->method, "GET") == 0) : false
#define IS_REQ_POST(request) request->method ? (strcmp(request->method, "POST") == 0) : false

#define IS_GET() IS_REQ_GET(cwf_vars->request)
#define IS_POST() IS_REQ_POST(cwf_vars->request)

#define header(key, value) add_custom_header((key), (value), &(cwf_vars->headers))

#define session_start() cwf_session_start(&(cwf_vars->session), &(cwf_vars->headers), cwf_vars->session_files_path)
#define session_destroy() cwf_session_destroy(&(cwf_vars->session), &(cwf_vars->headers), cwf_vars->session_files_path)
#define SESSION_GET(key) cwf_session_get(cwf_vars->session, (key))
#define SESSION_PUT(key, value) cwf_session_put(cwf_vars->session, (key), (value))

#define generate_default_404_header() cwf_generate_default_404_header(&(cwf_vars->headers))

#define redirect(url)                                                                                                                                          \
    cwf_redirect((url), &(cwf_vars->headers));                                                                                                                 \
    return NULL;

#define generate_simple_404(format, ...) simple_404_page(cwf_vars, format, __VA_ARGS__)

#define ENDPOINT(name) sds name(cwf_vars *cwf_vars, endpoint_config *config)

#define SERVER(key) cwf_server_vars(cwf_vars->request, (key))

#define GET(key) cwf_get_vars(cwf_vars->request, (key)) ? cwf_get_vars(cwf_vars->request, (key))[0] : NULL
#define GET_ARRAY(key) cwf_get_vars(cwf_vars->request, (key))

#define POST(key) cwf_post_vars(cwf_vars->request, (key)) ? cwf_post_vars(cwf_vars->request, (key))[0] : NULL
#define POST_ARRAY(key) cwf_post_vars(cwf_vars->request, (key))

#define DUMP_REQUEST_VARS()                                                                                                                                    \
    generate_default_404_header();                                                                                                                             \
    return cwf_dump_request_vars(cwf_vars->request)

#define render_template(varlist, path) cwf_render_template((varlist), (path), &(cwf_vars->headers))

#define request_to_varlist(varlist, modify_fn) cwf_request_to_varlist((varlist), (modify_fn), cwf_vars->request)

#define db_record_to_varlist(varlist, modify) cwf_db_record_to_varlist((varlist), cwf_vars->database, (modify))

#define db_records_to_loop(varlist, loop_name, modify) cwf_db_records_to_loop((varlist), cwf_vars->database, (loop_name), (modify))

#define open_database() cwf_open_database(cwf_vars);
#define open_database_or_return_404()                                                                                                                          \
    open_database();                                                                                                                                           \
    if(cwf_vars->database->error) {                                                                                                                            \
        return generate_simple_404("Database error: %s", cwf_vars->database->error);                                                                           \
    }

#define close_database() cwf_close_database(cwf_vars);

#define execute_query(query) cwf_execute_query((query), cwf_vars->database)
#define execute_query_or_return_404(query)                                                                                                                     \
    execute_query((query));                                                                                                                                    \
    if(cwf_vars->database->error) {                                                                                                                            \
        return generate_simple_404("Database error: %s", cwf_vars->database->error);                                                                           \
    }

typedef enum { INT, STRING, FLOAT, INVALID } parameter_type;

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

typedef struct cwf_database_t {
    char *error;
    sqlite3 *db;
    string_hash *records;
    unsigned int num_records;
} cwf_database;

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

typedef struct cwf_vars_t {
    cwf_request *request;
    cwf_session *session;
    http_header headers;
    cwf_database *database;
    char *endpoints_lib_path;
    char *endpoints_config_path;
    char *database_path;
    char *session_files_path;
    char *templates_path;
    char *document_root;
    bool print_debug_info;
} cwf_vars;

typedef ENDPOINT(endpoint_fn);

typedef void modify_db_name_value_fn(char **name, char **value);

cwf_request *new_empty_request();
cwf_request *new_from_env_vars();

char *cwf_server_vars(cwf_request *req, char *key);

string_array cwf_get_vars(cwf_request *req, char *key);

string_array cwf_post_vars(cwf_request *req, char *key);

sds cwf_dump_request_vars(cwf_request *req);

sds cwf_render_template(TMPL_varlist *varlist, const char *template_path, http_header *headers);

TMPL_varlist *cwf_request_to_varlist(TMPL_varlist *varlist, modify_db_name_value_fn *modify, cwf_request *req);

TMPL_varlist *cwf_db_record_to_varlist(TMPL_varlist *varlist, cwf_database *database, modify_db_name_value_fn *modify);

TMPL_varlist *cwf_db_records_to_loop(TMPL_varlist *varlist, cwf_database *database, char *loop_name, modify_db_name_value_fn *f);

endpoint_config *new_endpoint_config();
endpoint_config_item *new_endpoint_config_hash();
void free_endpoint_config_hash(endpoint_config_item *hash);
endpoint_config *get_endpoint_config(const char *REQUEST_URI, const char *QUERY_STRING, endpoint_config_item *configs);
void add_params_to_request(cwf_request *req, url_params *params);

void cwf_open_database(cwf_vars *vars);

void cwf_close_database(cwf_vars *vars);

void cwf_execute_query(const char *query, cwf_database *db);

int get_num_columns(string_hash r);

char_array strip_html_tags(const char *buf);

sds simple_404_page(cwf_vars *cwf_vars, char *format, ...);

void free_cwf_vars(cwf_vars *vars);
#endif /* __CWF_H */
