#ifndef __CWF_H
#define __CWF_H

#include <stdbool.h>
#include <stdio.h>

#include "../../src/3dparty/stb/stb_ds.h"

#include "../../src/3dparty/unac/unac.h"
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
#include "debug_helper.h"
#include "logger.h"

#define IS_REQ_GET(request) request->method ? (strcmp(request->method, "GET") == 0) : false
#define IS_REQ_POST(request) request->method ? (strcmp(request->method, "POST") == 0) : false

#define IS_GET() IS_REQ_GET(cwf_vars->request)
#define IS_POST() IS_REQ_POST(cwf_vars->request)

#define header(key, value) add_custom_header((key), (value), &(cwf_vars->headers))
#define session_start() cwf_session_start(&(cwf_vars->session), &(cwf_vars->headers), cwf_vars->session_files_path, 31536000) // 1 year
#define session_start_with_expiration_date(expiration_date)                                                                                                    \
    cwf_session_start(&(cwf_vars->session), &(cwf_vars->headers), cwf_vars->session_files_path, (expiration_date))

#define session_destroy() cwf_session_destroy(&(cwf_vars->session), &(cwf_vars->headers), cwf_vars->session_files_path)
#define SESSION_GET(key) cwf_session_get(cwf_vars->session, (key))
#define SESSION_PUT(key, value) cwf_session_put(cwf_vars->session, (key), (value))

#define generate_default_404_header() cwf_generate_default_404_header(&(cwf_vars->headers))

#define redirect(url)                                                                                                                                          \
    do {                                                                                                                                                       \
        cwf_redirect((url), &(cwf_vars->headers));                                                                                                             \
        return NULL;                                                                                                                                           \
    } while(0)

#define generate_simple_404(format, ...) simple_404_page(cwf_vars, format, __VA_ARGS__)

#define ENDPOINT(name) sds name(cwf_vars *cwf_vars, endpoint_config *config)

#define SERVER(key) cwf_server_vars(cwf_vars->request, (key))

#define GET(key) cwf_get_vars(cwf_vars->request, (key)) ? cwf_get_vars(cwf_vars->request, (key))[0] : NULL
#define GET_ARRAY(key) cwf_get_vars(cwf_vars->request, (key))

#define POST(key) cwf_post_vars(cwf_vars->request, (key)) ? cwf_post_vars(cwf_vars->request, (key))[0] : NULL
#define POST_ARRAY(key) cwf_post_vars(cwf_vars->request, (key))

#define DUMP_REQUEST_VARS()                                                                                                                                    \
    do {                                                                                                                                                       \
        generate_default_404_header();                                                                                                                         \
        return cwf_dump_request_vars(cwf_vars->request);                                                                                                       \
    } while(0)

#define render_template(varlist, filename) cwf_render_template((varlist), (filename), cwf_vars)

#define request_to_varlist(varlist, modify_fn) varlist = cwf_request_to_varlist((varlist), (modify_fn), cwf_vars->request)

#define db_record_to_varlist(varlist, query_result, modify) varlist = cwf_db_record_to_varlist((varlist), query_result, (modify))

#define db_records_to_loop(varlist, query_result, loop_name, modify) (varlist) = cwf_db_records_to_loop((varlist), (query_result), (loop_name), (modify))

#define db_records_to_simple_json(query_result) cwf_db_records_to_simple_json((query_result))

#define get_column_value_from_line(query_result, index, name) shget(query_result->result_array[(index)], name)

#define new_query(format, ...) sdscatfmt(sdsempty(), format, __VA_ARGS__)

#define open_database() cwf_open_database(cwf_vars);
#define open_database_or_return_404()                                                                                                                          \
    do {                                                                                                                                                       \
        open_database();                                                                                                                                       \
        if(cwf_vars->database->error) {                                                                                                                        \
            return generate_simple_404("Database error: %s", cwf_vars->database->error);                                                                       \
        }                                                                                                                                                      \
    } while(0)

#define close_database() cwf_close_database(cwf_vars);

#define execute_query(result, query)                                                                                                                           \
    do {                                                                                                                                                       \
        (result) = cwf_execute_query((query), cwf_vars->database);                                                                                             \
        if(cwf_vars->database->error) {                                                                                                                        \
            LOG_ERROR("Database error in %s - %d: %s\n", __FILE__, __LINE__, cwf_vars->database->error);                                                       \
        }                                                                                                                                                      \
    } while(0)

#define execute_query_or_return_404(result, query)                                                                                                             \
    do {                                                                                                                                                       \
        execute_query((result), (query));                                                                                                                      \
        if(cwf_vars->database->error) {                                                                                                                        \
            return generate_simple_404("Database error: %s", cwf_vars->database->error);                                                                       \
        }                                                                                                                                                      \
    } while(0)

#define LOGOUT()                                                                                                                                               \
    do {                                                                                                                                                       \
        session_start();                                                                                                                                       \
        session_destroy();                                                                                                                                     \
    } while(0)

#define LOGOUT_AND_REDIRECT(redirect_url)                                                                                                                      \
    do {                                                                                                                                                       \
        LOGOUT();                                                                                                                                              \
        redirect((redirect_url));                                                                                                                              \
    } while(0)

#define add_to_template_varlist(varlist, name, value) varlist = TMPL_add_var(varlist, name, value, 0)
#define add_float_to_template_varlist(varlist, name, value) varlist = TMPL_add_float_var(varlist, name, value)
#define add_double_to_template_varlist(varlist, name, value) varlist = TMPL_add_double_var(varlist, name, value)
#define add_int_to_template_varlist(varlist, name, value) varlist = TMPL_add_int_var(varlist, name, value)

typedef enum { INT, STRING, FLOAT, INVALID } parameter_type;

typedef struct {
    char *name;
    char *value;
    parameter_type type;
	unsigned int num_received_params;
} url_params;

typedef struct endpoint_config_t {
    char *function;
    url_params *params;
    sds error;
} endpoint_config;

typedef struct endpoint_config_item_t {
    char *key;
    endpoint_config *value;
} endpoint_config_item;

typedef struct cwf_query_result_t {
    string_hash *result_array;
    unsigned int num_records;
} cwf_query_result;

typedef struct cwf_database_t {
    char *error;
    sqlite3 *db;
    bool opened;
} cwf_database;

typedef struct request_item_t {
    char *key;
    string_array value;
} request_item;

typedef struct cwf_request_t {
    char *method;
    char *data_type;
    int server_data_len;
    int data_len;
    string_hash server_data;
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
	char *static_path;
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

sds cwf_render_template(TMPL_varlist *varlist, const char *template_path, cwf_vars *vars);

TMPL_varlist *cwf_request_to_varlist(TMPL_varlist *varlist, modify_db_name_value_fn *modify, cwf_request *req);

sds cwf_escape_json(char *value);

TMPL_varlist *cwf_db_record_to_varlist(TMPL_varlist *varlist, cwf_query_result *data, modify_db_name_value_fn *modify);

TMPL_varlist *cwf_db_records_to_loop(TMPL_varlist *varlist, cwf_query_result *data, char *loop_name, modify_db_name_value_fn *f);

sds cwf_db_records_to_simple_json(cwf_query_result *data);

endpoint_config *new_endpoint_config();
endpoint_config_item *new_endpoint_config_hash();
void free_endpoint_config_hash(endpoint_config_item *hash);
endpoint_config *get_endpoint_config(const char *REQUEST_URI, endpoint_config_item *configs);
void add_params_to_request(cwf_request *req, url_params *params);

void cwf_open_database(cwf_vars *vars);

void cwf_close_database(cwf_vars *vars);

cwf_query_result *cwf_execute_query(const char *query, cwf_database *db);

int get_num_columns(string_hash r);

char_array strip_html_tags(const char *buf);

sds simple_404_page(cwf_vars *cwf_vars, char *format, ...);

void free_cwf_vars(cwf_vars *vars);
#endif /* __CWF_H */
