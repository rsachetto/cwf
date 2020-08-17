#ifndef __CWF_H
#define __CWF_H

#include <stdbool.h>
#include <stdio.h>

#include "3dparty/ccgi-1.2/ccgi.h"
#include "3dparty/ctemplate-1.0/ctemplate.h"
#include "3dparty/json/json.h"
#include "3dparty/sqlite/sqlite3.h"

#define IS_GET(req) strcmp(req->method, "GET") == 0
#define IS_POST(req) strcmp(req->method, "POST") == 0
#define STRINGS_MATCH(a, b) strcmp((a), (b)) == 0
#define STRINGS_MATCH_NO_CASE_N(a, b, n) strncasecmp((a), (b), (n)) == 0

static bool debug_server = true;

typedef enum { INT, STRING, FLOAT, INVALID } parameter_type;

typedef char *char_array;

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

typedef struct request_item_t {
    char *key;
    char *value;
} request_item;

typedef struct request_t {
    char *method;
    char *data_type;
    int server_data_len;
    int data_len;
    request_item *server_data;
    union {
        json_value *json_data;
        request_item *urlencoded_data;
    };
} request;

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

typedef struct  cookie_t {
	char *name;
	char *value;
	int  expires;
	int  max_age;
	char *domain;
	char *path;
	bool secure;
	bool http_only;
	char *same_site;
} cookie;

typedef record * http_header;

#define ENDPOINT_LIB_PATH "/var/www/cwf/libendpoints.so"
#define ENDPOINT(name) int name(request *request, endpoint_config *config)
typedef ENDPOINT(endpoint_fn);

typedef void modify_db_name_value_fn(char *name, char *value);

request *new_empty_request();
request *new_from_env_vars();

http_header new_empty_header();
void add_custom_header(const char *name, const char *value, http_header *header);
void write_http_headers(http_header header);

char *SERVER(request *req, char *key);
char *GET(request *req, char *key);

int render_template(TMPL_varlist *varlist, const char *template_path);
TMPL_varlist *request_to_varlist(TMPL_varlist *varlist, request *req,  modify_db_name_value_fn *modify);
TMPL_varlist *db_record_to_varlist(TMPL_varlist *varlist, cfw_database *database, modify_db_name_value_fn *modify);
TMPL_varlist *db_records_to_loop(TMPL_varlist *varlist, cfw_database *database, char *loop_name, modify_db_name_value_fn *f);

cookie *get_cookie();
cookie *new_cookie(char *name, char *value);
void add_cookie_to_header(cookie *c, http_header *header);

endpoint_config *new_endpoint_config();
endpoint_config_item *new_endpoint_config_hash();
endpoint_config *get_endpoint_config(const char *REQUEST_URI, const char *QUERY_STRING, endpoint_config_item *configs);
void add_params_to_request(request *req, url_params *params);
cfw_database *open_database(const char *db_filename);
void execute_query(const char *query, cfw_database *db);
int get_num_columns(record *r);

char_array strip_html_tags(const char *buf);

char *generate_b64_session_id(); 

void generate_default_404_header();
#endif /* __CWF_H */
