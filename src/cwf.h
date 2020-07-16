#ifndef __CWF_H
#define __CWF_H 

#include "3dparty/ccgi-1.2/ccgi.h"

typedef struct request_item_t {
	char *key;
	char *value;
} request_item;

typedef struct request_t {
	char *type;
	request_item *env;
	request_item *get;
	request_item *post;
} request;

int render_template(request *req, const char *template_path);
request * new_empty_request();
request * new_from_env_vars(); 

#endif /* __CWF_H */
