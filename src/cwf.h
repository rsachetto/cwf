#ifndef __CWF_H
#define __CWF_H

#include "3dparty/ccgi-1.2/ccgi.h"
#include "3dparty/json/json.h"

#define IS_GET(req) strcmp(req->method, "GET") == 0
#define IS_POST(req) strcmp(req->method, "POST") == 0

typedef enum {
	INT, 
	STRING,
	FLOAT
} parameter_type;

typedef struct {
	char *key;
	char *value;
	parameter_type type;
} url_template_params;

typedef struct endpoint_config_t{
	char *function;
	char *url_template;
	url_template_params *parsed_params;
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

char *SERVER(request *req, char *key);
char *GET(request *req, char *key);

int render_template(request *req, const char *template_path);
request *new_empty_request();
request *new_from_env_vars();

endpoint_config *new_endpoint_config();
endpoint_config_item *new_endpoint_config_hash();
char *get_endpoint(char *URL, endpoint_config_item *configs);

void generate_default_404_header();
#endif /* __CWF_H */
