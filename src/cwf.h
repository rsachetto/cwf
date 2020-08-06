#ifndef __CWF_H
#define __CWF_H 

#include "3dparty/ccgi-1.2/ccgi.h"
#include "3dparty/json/json.h"

#define IS_GET(req) strcmp(req->method, "GET") == 0
#define IS_POST(req) strcmp(req->method, "POST") == 0

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
		json_value* json_data;
		request_item *urlencoded_data;
	};
} request;

int render_template(request *req, const char *template_path);
request * new_empty_request();
request * new_from_env_vars(); 

#endif /* __CWF_H */
