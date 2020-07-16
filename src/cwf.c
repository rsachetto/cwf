#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>

#include "3dparty/ctemplate-1.0/ctemplate.h"
#include "cwf.h"

#define STB_DS_IMPLEMENTATION
#include "3dparty/stb/stb_ds.h"

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


request * new_empty_request() {

	request *req  = (request*) malloc(sizeof(request));
	req->type = NULL;
	req->env = NULL;
	req->get = NULL;
	req->post = NULL;
	sh_new_arena(req->env);
	sh_new_arena(req->get);
	sh_new_arena(req->post);

	return req;

}

request * new_from_env_vars() {

	request *req = new_empty_request();
	shput(req->env, "HTTP_ACCEPT"          , getenv("HTTP_ACCEPT"));
	shput(req->env, "HTTP_COOKIE"          , getenv("HTTP_COOKIE"));
	shput(req->env, "HTTP_FORWARDED"       , getenv("HTTP_FORWARDED"));
	shput(req->env, "HTTP_HOST"            , getenv("HTTP_HOST"));
	shput(req->env, "HTTP_PROXY_CONNECTION", getenv("HTTP_PROXY_CONNECTION"));
	shput(req->env, "HTTP_REFERER"         , getenv("HTTP_REFERER"));
	shput(req->env, "HTTP_USER_AGENT"      , getenv("HTTP_USER_AGENT"));
	shput(req->env, "REQUEST_METHOD"       , getenv("REQUEST_METHOD"));
	shput(req->env, "REQUEST_METHOD"       , getenv("REQUEST_METHOD"));
	shput(req->env, "REQUEST_SCHEME"       , getenv("REQUEST_SCHEME"));
	shput(req->env, "REQUEST_URI"          , getenv("REQUEST_URI"));
	shput(req->env, "DOCUMENT_URI"         , getenv("DOCUMENT_URI"));
	shput(req->env, "REQUEST_FILENAME"     , getenv("REQUEST_FILENAME"));
	shput(req->env, "SCRIPT_FILENAME"      , getenv("SCRIPT_FILENAME"));
	shput(req->env, "LAST_MODIFIED"        , getenv("LAST_MODIFIED"));
	shput(req->env, "SCRIPT_USER"          , getenv("SCRIPT_USER"));
	shput(req->env, "SCRIPT_GROUP"         , getenv("SCRIPT_GROUP"));
	shput(req->env, "PATH_INFO"            , getenv("PATH_INFO"));
	shput(req->env, "QUERY_STRING"         , getenv("QUERY_STRING"));
	shput(req->env, "IS_SUBREQ "           , getenv("IS_SUBREQ"));
	shput(req->env, "THE_REQUEST"          , getenv("THE_REQUEST"));
	shput(req->env, "REMOTE_ADDR"          , getenv("REMOTE_ADDR"));
	shput(req->env, "REMOTE_PORT"          , getenv("REMOTE_PORT"));
	shput(req->env, "REMOTE_HOST"          , getenv("REMOTE_HOST"));
	shput(req->env, "REMOTE_USER"          , getenv("REMOTE_USER"));
	shput(req->env, "REMOTE_IDENT"         , getenv("REMOTE_IDENT"));
	shput(req->env, "SERVER_NAME"          , getenv("SERVER_NAME"));
	shput(req->env, "SERVER_PORT"          , getenv("SERVER_PORT"));
	shput(req->env, "SERVER_ADMIN"         , getenv("SERVER_ADMIN"));
	shput(req->env, "SERVER_PROTOCOL"      , getenv("SERVER_PROTOCOL"));
	shput(req->env, "DOCUMENT_ROOT"        , getenv("DOCUMENT_ROOT"));
	shput(req->env, "AUTH_TYPE"            , getenv("AUTH_TYPE"));
	shput(req->env, "CONTENT_TYPE "        , getenv("CONTENT_TYPE"));
	shput(req->env, "HANDLER"              , getenv("HANDLER"));
	shput(req->env, "HTTP2"                , getenv("HTTP2"));
	shput(req->env, "HTTPS"                , getenv("HTTPS"));
	shput(req->env, "IPV6"                 , getenv("IPV6"));
	shput(req->env, "REQUEST_STATUS"       , getenv("REQUEST_STATUS"));
	shput(req->env, "REQUEST_LOG_ID"       , getenv("REQUEST_LOG_ID"));
	shput(req->env, "CONN_LOG_ID"          , getenv("CONN_LOG_ID"));
	shput(req->env, "CONN_REMOTE_ADDR"     , getenv("CONN_REMOTE_ADDR"));
	shput(req->env, "CONTEXT_PREFIX"       , getenv("CONTEXT_PREFIX"));
	shput(req->env, "CONTEXT_DOCUMENT_ROOT", getenv("CONTEXT_DOCUMENT_ROOT"));
	shput(req->env, "TIME_YEAR"            , getenv("TIME_YEAR"));
	shput(req->env, "TIME_MON"             , getenv("TIME_MON"));
	shput(req->env, "TIME_DAY"             , getenv("TIME_DAY"));
	shput(req->env, "TIME_HOUR"      	   , getenv("TIME_HOUR"));
	shput(req->env, "TIME_MIN"       	   , getenv("TIME_MIN"));
	shput(req->env, "TIME_SEC"       	   , getenv("TIME_SEC"));
	shput(req->env, "TIME_WDAY"      	   , getenv("TIME_WDAY"));
	shput(req->env, "TIME"           	   , getenv("TIME"));
	shput(req->env, "SERVER_SOFTWARE"	   , getenv("SERVER_SOFTWARE"));
	shput(req->env, "API_VERSION"    	   , getenv("API_VERSION"));


	//TODO: check for GET
	decode_query(&req->get, getenv("QUERY_STRING"));


	return req;

}

int render_template(request *req, const char *template_path) {

    //fputs("Content-type: text/html\r\n\r\n", stdout);
    fputs("CONTENT-TYPE: text/plain\r\n\r\n", stdout);

	for(int i = 0; i < shlen(req->env); i++) {
	    fprintf(stdout, "%s %s\n", req->env[i].key, req->env[i].value);
	}

	for(int i = 0; i < shlen(req->get); i++) {
	    fprintf(stdout, "%s %s\n", req->get[i].key, req->get[i].value);
	}

	int ret = 0;
	/*
	TMPL_varlist *varlist = 0;
	TMPL_fmtlist *fmtlist;

    CGI_varlist *cgi_varlist = 0;
    const char *name;
    CGI_value  *value;

    cgi_varlist = CGI_get_query(cgi_varlist);

	for (name = CGI_first_name(cgi_varlist); name != 0; name = CGI_next_name(cgi_varlist)) {
		value = CGI_lookup_all(cgi_varlist, name);
		varlist = TMPL_add_var(varlist, name, value[0], 0);
	}

    CGI_free_varlist(cgi_varlist); 

	fmtlist = TMPL_add_fmt(0, "entity", TMPL_encode_entity);
	TMPL_add_fmt(fmtlist, "url", TMPL_encode_url);
	ret = TMPL_write(template_path, 0, fmtlist, varlist, stdout, stderr) != 0;

	TMPL_free_fmtlist(fmtlist);
	TMPL_free_varlist(varlist);
	*/
	
	return ret;
}
