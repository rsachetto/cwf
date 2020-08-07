#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>

#include "3dparty/ctemplate-1.0/ctemplate.h"

#define STB_DS_IMPLEMENTATION
#include "3dparty/stb/stb_ds.h"

#include "cwf.h"

/*These are from ccgi*/
static int hex(int digit) {
    switch(digit) {

    case '0': case '1': case '2': case '3': case '4':
    case '5': case '6': case '7': case '8': case '9':
        return digit - '0';

    case 'A': case 'B': case 'C': case 'D': case 'E': case 'F':
        return 10 + digit - 'A';

    case 'a': case 'b': case 'c': case 'd': case 'e': case 'f':
        return 10 + digit - 'a';

    default:
        return -1;
    }
}

static void decode_query(request_item **v, const char *query) {
    char *buf;
    const char *name, *value;
    int i, k, L, R, done;

    if (query == 0) {
        return;
    }
    buf = (char *) malloc(strlen(query) + 1);
    name = value = 0;
    for (i = k = done = 0; done == 0; i++) {
        switch (query[i]) {

        case '=':
            if (name != 0) {
                break;  /* treat extraneous '=' as data */
            }
            if (name == 0 && k > 0) {
                name = buf;
                buf[k++] = 0;
                value = buf + k;
            }
            continue;

        case 0:
            done = 1;  /* fall through */

        case '&':
            buf[k] = 0;
            if (name == 0 && k > 0) {
                name = buf;
                value = buf + k;
            }
            if (name != 0) {
               shput(*v, strdup(name), strdup(value));
            }
            k = 0;
            name = value = 0;
            continue;

        case '+':
            buf[k++] = ' ';
            continue;

        case '%':
            if ((L = hex(query[i + 1])) >= 0 &&
                (R = hex(query[i + 2])) >= 0)
            {
                buf[k++] = (L << 4) + R;
                i += 2;
                continue;
            }
            break;  /* treat extraneous '%' as data */
        }
        buf[k++] = query[i];
    }
    free(buf);
}

static void get_post(request_item **v, int len) {

	char *buf;

	buf = (char *) malloc(len + 1);
	if (fread(buf, 1, len, stdin) == len) {
		buf[len] = 0;
		decode_query(v, buf);
	}
	free(buf);
}

request * new_empty_request() {

	request *req         = (request*) malloc(sizeof(request));
	req->method          = NULL;
	req->urlencoded_data = NULL;
	req->data_type       = NULL;
	sh_new_arena(req->urlencoded_data);

	return req;

}

request * new_from_env_vars() {

	request *req = new_empty_request();

	shput(req->server_data, "HTTP_ACCEPT"          , getenv("HTTP_ACCEPT"));
	shput(req->server_data, "HTTP_COOKIE"          , getenv("HTTP_COOKIE"));
	shput(req->server_data, "HTTP_FORWARDED"       , getenv("HTTP_FORWARDED"));
	shput(req->server_data, "HTTP_HOST"            , getenv("HTTP_HOST"));
	shput(req->server_data, "HTTP_PROXY_CONNECTION", getenv("HTTP_PROXY_CONNECTION"));
	shput(req->server_data, "HTTP_REFERER"         , getenv("HTTP_REFERER"));
	shput(req->server_data, "HTTP_USER_AGENT"      , getenv("HTTP_USER_AGENT"));
	shput(req->server_data, "CONTENT_LENGTH"       , getenv("CONTENT_LENGTH"));
	shput(req->server_data, "REQUEST_METHOD"       , getenv("REQUEST_METHOD"));
	shput(req->server_data, "REQUEST_METHOD"       , getenv("REQUEST_METHOD"));
	shput(req->server_data, "REQUEST_SCHEME"       , getenv("REQUEST_SCHEME"));
	shput(req->server_data, "REQUEST_URI"          , getenv("REQUEST_URI"));
	shput(req->server_data, "DOCUMENT_URI"         , getenv("DOCUMENT_URI"));
	shput(req->server_data, "REQUEST_FILENAME"     , getenv("REQUEST_FILENAME"));
	shput(req->server_data, "SCRIPT_FILENAME"      , getenv("SCRIPT_FILENAME"));
	shput(req->server_data, "LAST_MODIFIED"        , getenv("LAST_MODIFIED"));
	shput(req->server_data, "SCRIPT_USER"          , getenv("SCRIPT_USER"));
	shput(req->server_data, "SCRIPT_GROUP"         , getenv("SCRIPT_GROUP"));
	shput(req->server_data, "PATH_INFO"            , getenv("PATH_INFO"));
	shput(req->server_data, "QUERY_STRING"         , getenv("QUERY_STRING"));
	shput(req->server_data, "IS_SUBREQ "           , getenv("IS_SUBREQ"));
	shput(req->server_data, "THE_REQUEST"          , getenv("THE_REQUEST"));
	shput(req->server_data, "REMOTE_ADDR"          , getenv("REMOTE_ADDR"));
	shput(req->server_data, "REMOTE_PORT"          , getenv("REMOTE_PORT"));
	shput(req->server_data, "REMOTE_HOST"          , getenv("REMOTE_HOST"));
	shput(req->server_data, "REMOTE_USER"          , getenv("REMOTE_USER"));
	shput(req->server_data, "REMOTE_IDENT"         , getenv("REMOTE_IDENT"));
	shput(req->server_data, "SERVER_NAME"          , getenv("SERVER_NAME"));
	shput(req->server_data, "SERVER_PORT"          , getenv("SERVER_PORT"));
	shput(req->server_data, "SERVER_ADMIN"         , getenv("SERVER_ADMIN"));
	shput(req->server_data, "SERVER_PROTOCOL"      , getenv("SERVER_PROTOCOL"));
	shput(req->server_data, "DOCUMENT_ROOT"        , getenv("DOCUMENT_ROOT"));
	shput(req->server_data, "AUTH_TYPE"            , getenv("AUTH_TYPE"));
	shput(req->server_data, "CONTENT_TYPE "        , getenv("CONTENT_TYPE"));
	shput(req->server_data, "HANDLER"              , getenv("HANDLER"));
	shput(req->server_data, "HTTP2"                , getenv("HTTP2"));
	shput(req->server_data, "HTTPS"                , getenv("HTTPS"));
	shput(req->server_data, "IPV6"                 , getenv("IPV6"));
	shput(req->server_data, "REQUEST_STATUS"       , getenv("REQUEST_STATUS"));
	shput(req->server_data, "REQUEST_LOG_ID"       , getenv("REQUEST_LOG_ID"));
	shput(req->server_data, "CONN_LOG_ID"          , getenv("CONN_LOG_ID"));
	shput(req->server_data, "CONN_REMOTE_ADDR"     , getenv("CONN_REMOTE_ADDR"));
	shput(req->server_data, "CONTEXT_PREFIX"       , getenv("CONTEXT_PREFIX"));
	shput(req->server_data, "CONTEXT_DOCUMENT_ROOT", getenv("CONTEXT_DOCUMENT_ROOT"));
	shput(req->server_data, "TIME_YEAR"            , getenv("TIME_YEAR"));
	shput(req->server_data, "TIME_MON"             , getenv("TIME_MON"));
	shput(req->server_data, "TIME_DAY"             , getenv("TIME_DAY"));
	shput(req->server_data, "TIME_HOUR"      	   , getenv("TIME_HOUR"));
	shput(req->server_data, "TIME_MIN"       	   , getenv("TIME_MIN"));
	shput(req->server_data, "TIME_SEC"       	   , getenv("TIME_SEC"));
	shput(req->server_data, "TIME_WDAY"      	   , getenv("TIME_WDAY"));
	shput(req->server_data, "TIME"           	   , getenv("TIME"));
	shput(req->server_data, "SERVER_SOFTWARE"	   , getenv("SERVER_SOFTWARE"));
	shput(req->server_data, "API_VERSION"    	   , getenv("API_VERSION"));

	req->server_data_len = shlen(req->server_data);

	req->method = getenv("REQUEST_METHOD");

	if(IS_GET(req)) {
		decode_query(&req->urlencoded_data, getenv("QUERY_STRING"));
		req->data_type = "urlencoded";
		req->data_len = shlen(req->urlencoded_data);
	}
	else if(IS_POST(req)) {

		const char *env;
		int len;

		if ((env = getenv("CONTENT_TYPE")) != 0 
				&& strncasecmp(env, "application/x-www-form-urlencoded", 33) == 0 
				&& (env = getenv("CONTENT_LENGTH")) != 0 && (len = atoi(env)) > 0) {
			get_post(&req->urlencoded_data, len);
			req->data_type = "urlencoded";
			req->data_len = shlen(req->urlencoded_data);
		}
		else if ((env = getenv("CONTENT_TYPE")) != 0 
				&& strncasecmp(env, "application/json", 16) == 0 
				&& (env = getenv("CONTENT_LENGTH")) != 0 && (len = atoi(env)) > 0) {
			
			req->data_type = "json";


		}
		else { //multipart
			//TODO: handle multpart input (get from liccgi)
			//
		}
	}

	return req;

}

char * SERVER(request *req, char *key) {
	return shget(req->server_data, key);
}

char * GET(request *req, char *key) {

	if(IS_GET(req)) {
		return shget(req->urlencoded_data, key);
	}

	return NULL;
}

int render_template(request *req, const char *template_path) {

	fputs("Content-type: text/html\r\n\r\n", stdout);

	int ret = 0;

	TMPL_varlist *varlist = 0;
	TMPL_fmtlist *fmtlist;

	const char *name;
	CGI_value  *value;

	for(int i = 0; i < shlen(req->urlencoded_data); i++) {
		varlist = TMPL_add_var(varlist, req->urlencoded_data[i].key, req->urlencoded_data[i].value, 0);
	}

	fmtlist = TMPL_add_fmt(0, "entity", TMPL_encode_entity);
	TMPL_add_fmt(fmtlist, "url", TMPL_encode_url);
	ret = TMPL_write(template_path, 0, fmtlist, varlist, stdout, stderr) != 0;

	TMPL_free_fmtlist(fmtlist);
	TMPL_free_varlist(varlist);


	return ret;
}
