#include <ctype.h>
#include <openssl/sha.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define STB_DS_IMPLEMENTATION
#include "../3dparty/stb/stb_ds.h"
#include "cwf.h"

static void decode_query(request_item **v, const char *query) {
    char *buf;
    const char *name, *value;
    int i, k, L, R, done;

    if(query == 0) {
        return;
    }
    buf = (char *)malloc(strlen(query) + 1);
    name = value = 0;
    for(i = k = done = 0; done == 0; i++) {
        switch(query[i]) {
        case '=':
            if(name != 0) {
                break; /* treat extraneous '=' as data */
            }
            if(name == 0 && k > 0) {
                name = buf;
                buf[k++] = 0;
                value = buf + k;
            }
            continue;

        case 0:
            done = 1; /* fall through */

        case '&':
            buf[k] = 0;
            if(name == 0 && k > 0) {
                name = buf;
                value = buf + k;
            }
            if(name != 0) {
                string_array values = shget(*v, name);
                arrput(values, strdup(value));
                shput(*v, strdup(name), values);
            }
            k = 0;
            name = value = 0;
            continue;

        case '+':
            buf[k++] = ' ';
            continue;

        case '%':
            if((L = CGI_hex(query[i + 1])) >= 0 && (R = CGI_hex(query[i + 2])) >= 0) {
                buf[k++] = (L << 4) + R;
                i += 2;
                continue;
            }
            break; /* treat extraneous '%' as data */
        }
        buf[k++] = query[i];
    }
    free(buf);
}

static void get_post(cwf_request *r, int len, char *type) {
    char *buf;

    buf = (char *)malloc(len + 1);
    if(fread(buf, 1, len, stdin) == len) {
        buf[len] = 0;
        if(strncmp(type, "urlencoded", 10) == 0) {
            decode_query(&(r->urlencoded_data), buf);
        } else if(strncmp(type, "json", 4) == 0) {
            r->json_data = json_parse((json_char *)buf, len);
        }
    }
    free(buf);
}

static bool is_int(char *int_char) {
    size_t len = strlen(int_char);

    if(len == 0)
        return false;

    for(int i = 0; i < len; ++i) {
        if(!isdigit(int_char[i])) {
            return false;
        }
    }

    return true;
}

static bool is_float(char *float_char) {
    size_t len = strlen(float_char);

    if(len == 0)
        return false;

    bool dot_found = false;

    for(int i = 0; i < len; ++i) {
        if(float_char[i] == '.') {
            if(!dot_found) {
                dot_found = true;
            } else {
                return false;
            }
            continue;
        }

        if(!isdigit(float_char[i])) {
            return false;
        }
    }

    return true;
}

static void concat_error_msg(char_array *current_error, char *error_to_add) {
    for(int i = 0; i < strlen(error_to_add); ++i) {
        arrpush(*current_error, error_to_add[i]);
    }
}

cwf_cookie *new_cookie(char *name, char *value) {
    cwf_cookie *v = calloc(1, sizeof(cwf_cookie));
    v->name = strdup(name);
    v->value = strdup(value);
    return v;
}

void free_cookie(cwf_cookie *cookie) {
    if(!cookie)
        return;
    free(cookie->name);
    free(cookie->value);
    free(cookie->path);
    free(cookie->domain);
    free(cookie->same_site);
}

cwf_cookie *get_cookie() {
    const char *env;
    char *buf, *p, *cookie_data[2];

    cwf_cookie *v = calloc(1, sizeof(cwf_cookie));

    if((env = getenv("HTTP_COOKIE")) == 0) {
        free(v);
        return NULL;
    }
    buf = (char *)malloc(strlen(env) + 1);
    p = strcpy(buf, env);

    while((p = CGI_scanattr(p, cookie_data)) != 0) {
        if(v->name == NULL) {
            v->name = strdup(cookie_data[0]);
            v->value = strdup(cookie_data[1]);
        } else if(STRINGS_MATCH_NO_CASE_N(cookie_data[0], "Expires", 7)) {
            v->expires = (int)strtol(cookie_data[1], NULL, 10);
        } else if(STRINGS_MATCH_NO_CASE_N(cookie_data[0], "Max-Age", 7)) {
            v->max_age = (int)strtol(cookie_data[1], NULL, 10);
        } else if(STRINGS_MATCH_NO_CASE_N(cookie_data[0], "Domain", 6)) {
            v->domain = strdup(cookie_data[1]);

        } else if(STRINGS_MATCH_NO_CASE_N(cookie_data[0], "Path", 4)) {
            v->path = strdup(cookie_data[1]);
        } else if(STRINGS_MATCH_NO_CASE_N(cookie_data[0], "Secure", 6)) {
            v->secure = true;
        } else if(STRINGS_MATCH_NO_CASE_N(cookie_data[0], "HttpOnly", 8)) {
            v->http_only = true;
        } else if(STRINGS_MATCH_NO_CASE_N(cookie_data[0], "SameSite", 8)) {
            if(STRINGS_MATCH_NO_CASE_N(cookie_data[0], "Strict", 6)) {
                v->same_site = strdup("Strict");
            } else if(STRINGS_MATCH_NO_CASE_N(cookie_data[0], "Lax", 3)) {
                v->same_site = strdup("Lax");
            }
        }
    }
    free(buf);
    return v;
}

void write_http_headers(http_header header) {
    int h_len = shlen(header);
    for(int i = 0; i < h_len; i++) {
        if(i == h_len - 1) {
            fprintf(stdout, "%s: %s\r\n\r\n", header[i].key, header[i].value);
        } else {
            fprintf(stdout, "%s: %s\r\n", header[i].key, header[i].value);
        }
    }
    fflush(stdout);
}

http_header new_empty_header() {
    http_header header = NULL;
    sh_new_arena(header);
    shdefault(header, NULL);
    return header;
}

void add_custom_header(const char *name, const char *value, http_header *header) {
    if(value)
        shput(*header, name, strdup(value));
}

void add_cookie_to_header(cwf_cookie *c, http_header *header) {
    if(!c || !c->name || !c->value)
        return;

    size_t cookie_str_size = strlen(c->name);
    cookie_str_size += strlen(c->value);
    cookie_str_size += 2; // = and ;

    sds cookie_str = sdsnew(c->name);

    cookie_str = sdscatfmt(cookie_str, "=%s;", c->value);

    char buf[64];
    time_t cookie_date = c->expires + time(NULL);
    struct tm tm = *gmtime(&cookie_date);
    strftime(buf, sizeof buf, "%a, %d %b %Y %H:%M:%S %Z", &tm);

    cookie_str = sdscatfmt(cookie_str, "Expires=%s;", buf);

    if(c->max_age > 0) {
        cookie_str = sdscatfmt(cookie_str, "Max-Age=%i;", c->max_age);
    }

    if(c->domain) {
        cookie_str = sdscatfmt(cookie_str, "Domain=%s;", c->domain);
    }

    if(c->path) {
        cookie_str = sdscatfmt(cookie_str, "Path=%s;", c->path);
    }

    if(c->same_site) {
        cookie_str = sdscatfmt(cookie_str, "SameSite;");
    }

    if(c->secure) {
        cookie_str = sdscatfmt(cookie_str, "Secure;");
    }

    if(c->http_only) {
        cookie_str = sdscatfmt(cookie_str, "HttpOnly;");
    }

    add_custom_header("Set-Cookie", cookie_str, header);

    sdsfree(cookie_str);
}
endpoint_config *new_endpoint_config() {
    endpoint_config *config = calloc(1, sizeof(endpoint_config));
    return config;
}

endpoint_config_item *new_endpoint_config_hash() {
    endpoint_config_item *endpoint_config_hash = NULL;
    sh_new_arena(endpoint_config_hash);
    shdefault(endpoint_config_hash, NULL);
    return endpoint_config_hash;
}

void free_endpoint_config_hash(endpoint_config_item *hash) {
    // TODO: free all elements in the hash
    shfree(hash);
}

cwf_request *new_empty_request() {
    cwf_request *req = (cwf_request *)calloc(1, sizeof(struct cwf_request_t));

    sh_new_strdup(req->server_data);
    shdefault(req->server_data, NULL);

    sh_new_strdup(req->urlencoded_data);
    shdefault(req->urlencoded_data, NULL);

    return req;
}

void cwf_generate_default_404_header(http_header *headers) {
    add_custom_header("Status", "404 Not Found", headers);
    add_custom_header("Content-type", "text/html", headers);
}

endpoint_config *get_endpoint_config(const char *REQUEST_URI, const char *QUERY_STRING, endpoint_config_item *endpoints_cfg) {
    char *str = (char *)REQUEST_URI;

    endpoint_config *it;
    char *tmp = NULL;

    size_t uri_len = strlen(REQUEST_URI);

    if(uri_len > 1) {
        str = str + 1;
    }

    if(QUERY_STRING && !*QUERY_STRING) {
        char *first_slash = strchr(str, '/');
        if(first_slash) {
            if(uri_len > 1) {
                tmp = strndup(str, (int)(first_slash - str));
            } else {
                tmp = strdup(str);
            }
        } else {
            tmp = strdup(str);
        }

        it = shget(endpoints_cfg, tmp);

        if(it && it->params) {
            int expected_params = arrlen(it->params);
            char err[1024];

            if(first_slash) {
                char *aux = strdup(first_slash + 1);

                char *pch;
                pch = strtok(aux, "/");
                int num_params = 0;

                while(pch != NULL) {
                    url_params url_params;
                    if(num_params < expected_params) {
                        url_params = it->params[num_params];
                    } else {
                        sprintf(err, "Number of parameters exceed the configured number of parameters (%d).\n", expected_params);
                        concat_error_msg(&(it->error), err);
                        break;
                    }

                    switch(url_params.type) {
                    case STRING:
                        break;
                    case INT:
                        if(!is_int(pch)) {
                            sprintf(err, "%s is configured to be an integer but %s is not a valid integer.\n", url_params.name, pch);
                            concat_error_msg(&(it->error), err);
                        }
                        break;
                    case FLOAT:
                        if(!is_float(pch)) {
                            sprintf(err, "%s is configured to be a float but %s is not a valid float.\n", url_params.name, pch);
                            concat_error_msg(&(it->error), err);
                        }
                        break;
                    default:
                        sprintf(err, "%s is configured to an invalid type. Valid types are i, s or f.\n", url_params.name);
                        concat_error_msg(&(it->error), err);
                        break;
                    }

                    it->params[num_params].value = strdup(pch);

                    num_params++;

                    pch = strtok(NULL, "/");
                }

                free(aux);

                if(num_params != expected_params) {
                    sprintf(err,
                            "Number of parameters are different from the configured number of parameters (received %d, "
                            "expected %d).\n",
                            num_params, expected_params);
                    concat_error_msg(&(it->error), err);
                }
            } else {
                sprintf(err,
                        "Number of parameters are different from the configured number of parameters (received 0, "
                        "expected %d).\n",
                        expected_params);
                concat_error_msg(&(it->error), err);
            }
        }

    } else {
        char *question_mark = strchr(str, '?');
        int q_index = (int)(question_mark - str);
        tmp = strndup(str, q_index);

        if(!*tmp) {
            free(tmp);
            tmp = strdup("/");
        }

        it = shget(endpoints_cfg, tmp);
    }

    free(tmp);
    return it;
}

void add_params_to_request(cwf_request *req, url_params *params) {
    for(int i = 0; i < arrlen(params); i++) {
        string_array tmp = shget(req->urlencoded_data, params[i].name);
        arrput(tmp, strdup(params[i].value));
        shput(req->urlencoded_data, params[i].name, tmp);
    }
}

cwf_request *new_from_env_vars() {
    cwf_request *req = new_empty_request();

    shput(req->server_data, "HTTP_ACCEPT", getenv("HTTP_ACCEPT"));
    shput(req->server_data, "HTTP_COOKIE", getenv("HTTP_COOKIE"));
    shput(req->server_data, "HTTP_FORWARDED", getenv("HTTP_FORWARDED"));
    shput(req->server_data, "HTTP_HOST", getenv("HTTP_HOST"));
    shput(req->server_data, "HTTP_PROXY_CONNECTION", getenv("HTTP_PROXY_CONNECTION"));
    shput(req->server_data, "HTTP_REFERER", getenv("HTTP_REFERER"));
    shput(req->server_data, "HTTP_USER_AGENT", getenv("HTTP_USER_AGENT"));
    shput(req->server_data, "CONTENT_LENGTH", getenv("CONTENT_LENGTH"));
    shput(req->server_data, "REQUEST_METHOD", getenv("REQUEST_METHOD"));
    shput(req->server_data, "REQUEST_SCHEME", getenv("REQUEST_SCHEME"));
    shput(req->server_data, "REQUEST_URI", getenv("REQUEST_URI"));
    shput(req->server_data, "DOCUMENT_URI", getenv("DOCUMENT_URI"));
    shput(req->server_data, "REQUEST_FILENAME", getenv("REQUEST_FILENAME"));
    shput(req->server_data, "SCRIPT_FILENAME", getenv("SCRIPT_FILENAME"));
    shput(req->server_data, "LAST_MODIFIED", getenv("LAST_MODIFIED"));
    shput(req->server_data, "SCRIPT_USER", getenv("SCRIPT_USER"));
    shput(req->server_data, "SCRIPT_GROUP", getenv("SCRIPT_GROUP"));
    shput(req->server_data, "PATH_INFO", getenv("PATH_INFO"));
    shput(req->server_data, "QUERY_STRING", getenv("QUERY_STRING"));
    shput(req->server_data, "IS_SUBREQ ", getenv("IS_SUBREQ"));
    shput(req->server_data, "THE_REQUEST", getenv("THE_REQUEST"));
    shput(req->server_data, "REMOTE_ADDR", getenv("REMOTE_ADDR"));
    shput(req->server_data, "REMOTE_PORT", getenv("REMOTE_PORT"));
    shput(req->server_data, "REMOTE_HOST", getenv("REMOTE_HOST"));
    shput(req->server_data, "REMOTE_USER", getenv("REMOTE_USER"));
    shput(req->server_data, "REMOTE_IDENT", getenv("REMOTE_IDENT"));
    shput(req->server_data, "SERVER_NAME", getenv("SERVER_NAME"));
    shput(req->server_data, "SERVER_PORT", getenv("SERVER_PORT"));
    shput(req->server_data, "SERVER_ADMIN", getenv("SERVER_ADMIN"));
    shput(req->server_data, "SERVER_PROTOCOL", getenv("SERVER_PROTOCOL"));
    shput(req->server_data, "DOCUMENT_ROOT", getenv("DOCUMENT_ROOT"));
    shput(req->server_data, "AUTH_TYPE", getenv("AUTH_TYPE"));
    shput(req->server_data, "CONTENT_TYPE ", getenv("CONTENT_TYPE"));
    shput(req->server_data, "HANDLER", getenv("HANDLER"));
    shput(req->server_data, "HTTP2", getenv("HTTP2"));
    shput(req->server_data, "HTTPS", getenv("HTTPS"));
    shput(req->server_data, "IPV6", getenv("IPV6"));
    shput(req->server_data, "REQUEST_STATUS", getenv("REQUEST_STATUS"));
    shput(req->server_data, "REQUEST_LOG_ID", getenv("REQUEST_LOG_ID"));
    shput(req->server_data, "CONN_LOG_ID", getenv("CONN_LOG_ID"));
    shput(req->server_data, "CONN_REMOTE_ADDR", getenv("CONN_REMOTE_ADDR"));
    shput(req->server_data, "CONTEXT_PREFIX", getenv("CONTEXT_PREFIX"));
    shput(req->server_data, "CONTEXT_DOCUMENT_ROOT", getenv("CONTEXT_DOCUMENT_ROOT"));
    shput(req->server_data, "TIME_YEAR", getenv("TIME_YEAR"));
    shput(req->server_data, "TIME_MON", getenv("TIME_MON"));
    shput(req->server_data, "TIME_DAY", getenv("TIME_DAY"));
    shput(req->server_data, "TIME_HOUR", getenv("TIME_HOUR"));
    shput(req->server_data, "TIME_MIN", getenv("TIME_MIN"));
    shput(req->server_data, "TIME_SEC", getenv("TIME_SEC"));
    shput(req->server_data, "TIME_WDAY", getenv("TIME_WDAY"));
    shput(req->server_data, "TIME", getenv("TIME"));
    shput(req->server_data, "SERVER_SOFTWARE", getenv("SERVER_SOFTWARE"));
    shput(req->server_data, "API_VERSION", getenv("API_VERSION"));

    req->server_data_len = shlen(req->server_data);
    req->method = getenv("REQUEST_METHOD");

    if(IS_REQ_GET(req)) {
        decode_query(&req->urlencoded_data, getenv("QUERY_STRING"));
        req->data_type = "urlencoded";
        req->data_len = shlen(req->urlencoded_data);
    } else if(IS_REQ_POST(req)) {
        const char *env;
        int len = 0;

        if((env = getenv("CONTENT_TYPE")) != 0 && strncasecmp(env, "application/x-www-form-urlencoded", 33) == 0 && (env = getenv("CONTENT_LENGTH")) != 0 &&
           (len = (int)strtol(env, NULL, 10)) > 0) {
            req->data_type = "urlencoded";
        } else if((env = getenv("CONTENT_TYPE")) != 0 && strncasecmp(env, "application/json", 16) == 0 && (env = getenv("CONTENT_LENGTH")) != 0 &&
                  (len = (int)strtol(env, NULL, 10)) > 0) {
            req->data_type = "json";
        } else { // multipart
            // TODO handle multpart input (get from liccgi)
        }

        get_post(req, len, req->data_type);
        req->data_len = len;
    }

    return req;
}

char *cwf_server_vars(cwf_request *req, char *key) {
    return shget(req->server_data, key);
}

string_array cwf_get_vars(cwf_request *req, char *key) {
    if(IS_REQ_GET(req)) {
        return shget(req->urlencoded_data, key);
    }

    return NULL;
}

string_array cwf_post_vars(cwf_request *req, char *key) {
    if(IS_REQ_POST(req)) {
        return shget(req->urlencoded_data, key);
    }
    return NULL;
}

sds cwf_dump_request_vars(cwf_request *req) {
    sds response = sdsempty();
    for(int i = 0; i < shlen(req->urlencoded_data); i++) {
        string_array vars = req->urlencoded_data[i].value;
        for(int j = 0; j < arrlen(vars); j++) {
            response = sdscatfmt(response, "Key: %s, Value: %s<br/>", req->urlencoded_data[i].key, vars[j]);
        }
    }

    return response;
}

sds cwf_render_template(TMPL_varlist *varlist, const char *template_path, http_header *headers) {
    add_custom_header("Content-type", "text/html", headers);

    TMPL_fmtlist *fmtlist;
    fmtlist = TMPL_add_fmt(0, "entity", TMPL_encode_entity);
    TMPL_add_fmt(fmtlist, "url", TMPL_encode_url);

    sds template_str = sdsempty();

    int ret = TMPL_write(template_path, 0, fmtlist, varlist, &template_str, NULL, stderr) != 0;

    TMPL_free_fmtlist(fmtlist);
    TMPL_free_varlist(varlist);

    return template_str;
}

void cwf_open_database(cwf_vars *vars) {
    if(vars->database == NULL)
        vars->database = calloc(1, sizeof(struct cwf_database_t));

    int rc = sqlite3_open(vars->database_path, &(vars->database->db));

    if(rc != SQLITE_OK) {
        vars->database->error = strdup(sqlite3_errmsg(vars->database->db));
        sqlite3_close(vars->database->db);
    }
}

void cwf_close_database(cwf_vars *vars) {
    sqlite3_close(vars->database->db);
}

static int sqlite_callback(void *cwf_db, int num_results, char **column_values, char **column_names) {
    if(num_results) {
        cwf_database *database = (cwf_database *)cwf_db;

        record *line;
        sh_new_strdup(line);
        shdefault(line, NULL);
        sh_new_arena(line);

        int num_records = 0;

        for(int i = 0; i < num_results; i++) {
            if(column_names[i]) {
                if(column_values[i]) {
                    shput(line, column_names[i], strdup(column_values[i]));
                }
                num_records++;
            }
        }

        arrput(database->records, line);
        database->num_records += 1;
    }

    return 0;
}

void cwf_execute_query(const char *query, cwf_database *database) {
    char *errmsg;

    // TODO We will have to free all records
    if(database->records) {
        arrfree(database->records);
        database->records = NULL;
        database->num_records = 0;
    }

    int rc = sqlite3_exec(database->db, query, sqlite_callback, (void *)database, &errmsg);

    if(rc != SQLITE_OK) {
        database->error = strdup(errmsg);
        sqlite3_close(database->db);
        sqlite3_free(errmsg);
    }
}

int get_num_columns(record *r) {
    return shlen(r);
}

TMPL_varlist *cwf_request_to_varlist(TMPL_varlist *varlist, modify_db_name_value_fn *modify, cwf_request *req) {
    for(int i = 0; i < shlen(req->urlencoded_data); i++) {
        string_array tmp = req->urlencoded_data[i].value;

        char *name = strdup(req->urlencoded_data[i].key);
        char *value = NULL;

        if(tmp)
            value = tmp[0];

        if(modify) {
            modify(&name, &value);
        }

        varlist = TMPL_add_var(varlist, name, value, 0);
    }

    return varlist;
}

TMPL_varlist *cwf_db_record_to_varlist(TMPL_varlist *varlist, cwf_database *database, modify_db_name_value_fn *modify) {
    for(int i = 0; i < database->num_records; i++) {
        for(int j = 0; j < get_num_columns(database->records[i]); j++) {
            char *name = strdup(database->records[i][j].key);
            char *value = NULL;

            if(database->records[i][j].value) {
                value = strdup(database->records[i][j].value);
            }

            if(modify) {
                modify(&name, &value);
            }

            varlist = TMPL_add_var(varlist, name, value, 0);
        }
    }

    return varlist;
}

TMPL_varlist *cwf_db_records_to_loop(TMPL_varlist *varlist, cwf_database *database, char *loop_name, modify_db_name_value_fn *modify) {
    TMPL_loop *loop = 0;

    for(int i = 0; i < database->num_records; i++) {
        TMPL_varlist *loop_varlist = 0;

        for(int j = 0; j < get_num_columns(database->records[i]); j++) {
            char *name = strdup(database->records[i][j].key);
            char *value = NULL;

            if(database->records[i][j].value)
                value = strdup(database->records[i][j].value);

            if(modify) {
                modify(&name, &value);
            }

            loop_varlist = TMPL_add_var(loop_varlist, name, value, 0);
            free(name);
            free(value);
        }

        loop = TMPL_add_varlist(loop, loop_varlist);
    }

    varlist = TMPL_add_loop(varlist, loop_name, loop);

    sds num_records = sdsfromlonglong(database->num_records);
    varlist = TMPL_add_var(varlist, "num_records", num_records, 0);
    sdsfree(num_records);

    return varlist;
}

char_array strip_html_tags(const char *buf) {
    char_array result = NULL;
    bool opened = false;

    size_t len = strlen(buf);

    for(int i = 0; i < len; i++) {
        if(buf[i] == '<') {
            opened = true;
        } else if(buf[i] == '>') {
            opened = false;
        } else if(!opened) {
            arrput(result, buf[i]);
        }
    }

    arrput(result, '\0');

    return result;
}

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

void cwf_redirect(const char *url, http_header *headers) {
    char *tmp = (char *)url;

    sds value = NULL;

    if(strlen(url) > 1) {
        if(url[0] == '/') {
            tmp = tmp + 1;
        }

        value = sdsnew(tmp);

    } else if(strlen(url) == 1 && *url == '/') {
        value = sdscatfmt(sdsempty(), "%s://%s/", getenv("REQUEST_SCHEME"), getenv("HTTP_HOST"));
    }

    add_custom_header("Location", value, headers);
}

static int sqlite_callback_for_session(void *data, int num_results, char **column_values, char **column_names) {
    if(num_results) {
        record **line = (record **)data;

        int num_records = 0;

        for(int i = 0; i < num_results; i += 2) {
            shput(*line, strdup(column_values[i]), strdup(column_values[i + 1]));
        }
    }

    return 0;
}

static void execute_query_for_session(const char *query, sqlite3 *db, record **data) {
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

sds simple_404_page(cwf_vars *cwf_vars, char *format, ...) {
    generate_default_404_header();

    if(cwf_vars->print_debug_info) {
        va_list args;
        va_start(args, format);
        sds result = sdscatvprintf(sdsempty(), format, args);
        va_end(args);
        return result;
    }

    return NULL;
}

static void free_cwf_request(cwf_request *request) {
    shfree(request->server_data);

    // TODO: check for json
    int data_len = shlen(request->urlencoded_data);

    for(int i = 0; i < data_len; i++) {
        int value_len = arrlen(request->urlencoded_data[i].value);
        for(int j = 0; j < value_len; i++) {
            free(request->urlencoded_data[i].value[j]);
        }
        arrfree(request->urlencoded_data[i].value);
    }

    shfree(request->urlencoded_data);

    free(request);
}

static void free_cwf_headers(http_header header) {
    int len = shlen(header);

    for(int i = 0; i < len; i++) {
        free(header[i].value);
    }

    shfree(header);
}

void free_cwf_vars(cwf_vars *vars) {
    // cwf_request *request;
    // cwf_session *session;
    // http_header headers;
    free(vars->endpoints_lib_path);
    free(vars->endpoints_config_path);
    free(vars->database_path);
    free(vars->session_files_path);

    free_cwf_request(vars->request);
    free_cwf_headers(vars->headers);

    // TODO: free the rest
    free(vars);
}

#pragma clang diagnostic pop
