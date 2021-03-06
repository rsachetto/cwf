#include <ctype.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cwf.h"

#define STB_DS_IMPLEMENTATION
#include "../3dparty/stb/stb_ds.h"

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
            // fprintf(stderr, "%d %s\n", len, buf);
            decode_query(&(r->urlencoded_data), buf);
        } else if(strncmp(type, "json", 4) == 0) {
            r->json_data = json_parse((json_char *)buf, len);
        }
    }
    free(buf);
}

static bool is_int(char *int_char) {
    size_t len = strlen(int_char);

    if(len == 0) {
        return false;
    }

    int i = 0;

    if(int_char[0] == '-') {
        i++;
    }

    for(; i < len; ++i) {
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

static inline endpoint_config *probe_for_config(endpoint_config_item *endpoints_cfg, const char *uri, char **config_url) {

    if(strlen(uri) == 1) {
        return shget(endpoints_cfg, "/");
    } else {

        char *question_mark = strchr(uri, '?');
        char *endpoint_name = NULL;

        if(question_mark) {
            int q_index = (int)(question_mark - uri);
            endpoint_name = strndup(uri, q_index);

            if(!*endpoint_name || (strlen(endpoint_name) == 1 && *endpoint_name == '/') ) {
                free(endpoint_name);
                return shget(endpoints_cfg, "/");
            }
        } else {
            endpoint_name = strdup(uri);
        }

        endpoint_config *c = NULL;

        int num_slashes;
        sds *splitted_url = sdssplitlen(endpoint_name, strlen(endpoint_name), "/", 1, &num_slashes);

        sds endpoint_name_try = sdsempty();

        for(int i = 0; i < num_slashes; i++) {
            if(*splitted_url[i]) {
                endpoint_name_try = sdscatfmt(endpoint_name_try, "%S/", splitted_url[i]);
                char *tmp = strndup(endpoint_name_try, sdslen(endpoint_name_try) - 1);
                c = shget(endpoints_cfg, tmp);
                if(c) {
                    *config_url = tmp;
                    break;
                }

                free(tmp);
            }
        }

        free(endpoint_name);
        return c;
    }

    return NULL;
}

endpoint_config *get_endpoint_config(const char *REQUEST_URI, endpoint_config_item *endpoints_cfg) {

    char *config_url = NULL;

    endpoint_config *config = probe_for_config(endpoints_cfg, REQUEST_URI, &config_url);

    sds err = sdsempty();
    int num_params = 0;

    if(config && config->params) {

        int expected_params = arrlen(config->params);

        char *tmp = (char *)REQUEST_URI + 1;

        int count = 0;
        while(*tmp != config_url[count]) {
            tmp++;
            count++;
        }

        char *first_slash = strchr(tmp, '/');

        config->params->num_received_params = 0;

        if(first_slash) {
            char *aux = strdup(first_slash + 1);

            char *token;
            token = strtok(aux, "/");

            while(token != NULL) {
                url_params url_params;
                if(num_params < expected_params) {
                    url_params = config->params[num_params];
                } else {
                    err = sdscatfmt(err, "Number of parameters exceed the configured number of parameters (%i).\n", expected_params);
                    break;
                }

                switch(url_params.type) {
                case STRING:
                    break;
                case INT:
                    if(!is_int(token)) {
                        err = sdscatfmt(err, "%s is configured to be an integer but %s is not a valid integer.\n", url_params.name, token);
                    }
                    break;
                case FLOAT:
                    if(!is_float(token)) {
                        err = sdscatfmt(err, "%s is configured to be a float but %s is not a valid float.\n", url_params.name, token);
                    }
                    break;
                default:
                    err = sdscatfmt(err, "%s is configured to an invalid type. Valid types are i, s or f.\n", url_params.name);
                    break;
                }

                config->params[num_params].value = strdup(token);

                num_params++;

                token = strtok(NULL, "/");
            }

            config->params->num_received_params = num_params;
            free(aux);

            /*
            if(num_params != expected_params) {
                err = sdscatfmt(err,
                                "Number of parameters are different from the configured number of parameters (received %i, "
                                "expected %i).\n",
                                num_params, expected_params);
            }*/
        }
        /*
        else {
            err = sdscatfmt(err,
                            "Number of parameters are different from the configured number of parameters (received 0, "
                            "expected %i).\n",
                            expected_params);
        }
        */
    }

    if(sdslen(err) > 0) {
        config->error = err;
    }

    free(config_url);

    return config;
}

cwf_request *new_empty_request() {
    cwf_request *req = (cwf_request *)calloc(1, sizeof(struct cwf_request_t));

    sh_new_strdup(req->server_data);
    shdefault(req->server_data, NULL);

    sh_new_strdup(req->urlencoded_data);
    shdefault(req->urlencoded_data, NULL);

    return req;
}

void add_params_to_request(cwf_request *req, url_params *params) {
    for(int i = 0; i < params->num_received_params; i++) {
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
            // TODO handle multpart input (get from libcgi)
        }

        get_post(req, len, req->data_type);
        req->data_len = shlen(req->urlencoded_data);
    }

    return req;
}

char *cwf_server_vars(cwf_request *req, char *key) {
    return shget(req->server_data, key);
}

// TODO: think about this
string_array cwf_get_vars(cwf_request *req, char *key) {
    return shget(req->urlencoded_data, key);
    return NULL;
}

// TODO: think about this
string_array cwf_post_vars(cwf_request *req, char *key) {
    return shget(req->urlencoded_data, key);
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

sds cwf_render_template(TMPL_varlist *varlist, const char *template_file, cwf_vars *cwf_vars) {

    add_custom_header("Content-type", "text/html", &(cwf_vars->headers));

    TMPL_fmtlist *fmtlist;
    fmtlist = TMPL_add_fmt(0, "entity", TMPL_encode_entity);
    TMPL_add_fmt(fmtlist, "url", TMPL_encode_url);

    sds template_str = sdsempty();

    sds template_path = sdsnew(cwf_vars->templates_path);
    template_path = sdscat(template_path, template_file);

    int ret = TMPL_write(template_path, 0, fmtlist, varlist, &template_str, NULL, stderr) == 0;

    TMPL_free_fmtlist(fmtlist);
    TMPL_free_varlist(varlist);

    sdsfree(template_path);

    if(ret)
        return template_str;
    else
        return NULL;
}

void cwf_open_database(cwf_vars *vars) {

    // TODO: maybe we should allow multiples databases???
    if(vars->database->opened)
        return;

    int rc = sqlite3_open(vars->database_path, &(vars->database->db));

    if(rc != SQLITE_OK) {
        vars->database->error = strdup(sqlite3_errmsg(vars->database->db));
        goto error;
    }

    rc = sqlite3_exec(vars->database->db, "PRAGMA foreign_keys = ON;", NULL, NULL, &vars->database->error);

    if(rc != SQLITE_OK) {
        goto error;
    }

    vars->database->opened = true;
    return;

error:
    sqlite3_close(vars->database->db);
    vars->database->opened = false;
}

void cwf_begin_transaction(cwf_vars *vars) {

    if(!vars->database->opened) {
        vars->database->error = strdup("Database is closed. Call open_database first!\n");
        return;
    }

    int rc = sqlite3_exec(vars->database->db, "BEGIN TRANSACTION;", NULL, NULL, &vars->database->error);

    if(rc != SQLITE_OK) {
        vars->database->error = strdup(sqlite3_errmsg(vars->database->db));
    }
}

void cwf_commit_transaction(cwf_vars *vars) {

    if(!vars->database->opened) {
        vars->database->error = strdup("Database is closed. Call open_database first!\n");
        return;
    }

    int rc = sqlite3_exec(vars->database->db, "COMMIT TRANSACTION;", NULL, NULL, &vars->database->error);

    if(rc != SQLITE_OK) {
        vars->database->error = strdup(sqlite3_errmsg(vars->database->db));
    }
}

void cwf_rollback_transaction(cwf_vars *vars) {

    if(!vars->database->opened) {
        vars->database->error = strdup("Database is closed. Call open_database first!\n");
        return;
    }

    int rc = sqlite3_exec(vars->database->db, "ROLLBACK TRANSACTION;", NULL, NULL, &vars->database->error);

    if(rc != SQLITE_OK) {
        vars->database->error = strdup(sqlite3_errmsg(vars->database->db));
    }
}

void cwf_close_database(cwf_vars *vars) {
    sqlite3_close(vars->database->db);
}

static int default_sqlite_callback(void *void_result, int num_results, char **column_values, char **column_names) {

    if(num_results) {
        cwf_query_result *result = (cwf_query_result *)void_result;

        string_hash line = NULL;
        shdefault(line, NULL);
        sh_new_arena(line);

        int num_records = 0;

        for(int i = 0; i < num_results; i++) {
			//TODO: should we add NULL if the value returned from sqlite is empty???
            if(column_names[i] && column_values[i]) {
                shput(line, column_names[i], strdup(column_values[i]));
                num_records++;
            }
        }

        if(num_records) {
            arrput(result->result_array, line);
	        result->num_records += 1;
		}
    }

    return 0;
}

cwf_query_result *cwf_execute_query(const char *query, cwf_database *database, int (*callback)(void*,int,char**,char**)) {

    cwf_query_result *result = calloc(1, sizeof(struct cwf_query_result_t));

    if(!database->opened) {
        database->error = strdup("Database is closed. Call open_database first!\n");
        return NULL;
    }

    char *errmsg;


	int rc;

	if(!callback) {
	    rc = sqlite3_exec(database->db, query, default_sqlite_callback, (void *)result, &errmsg);
	}
	else {
	    rc = sqlite3_exec(database->db, query, callback, (void *)result, &errmsg);
	}

    if(rc != SQLITE_OK) {
        database->error = strdup(errmsg);
        sqlite3_close(database->db);
        sqlite3_free(errmsg);
        return NULL;
    }

    return result;
}

int get_num_columns(string_hash r) {
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

TMPL_varlist *cwf_db_record_to_varlist(TMPL_varlist *varlist, cwf_query_result *data, modify_db_name_value_fn *modify) {
    for(int i = 0; i < data->num_records; i++) {
        for(int j = 0; j < get_num_columns(data->result_array[i]); j++) {
            char *name = strdup(data->result_array[i][j].key);
            char *value = NULL;

            if(data->result_array[i][j].value) {
                value = strdup(data->result_array[i][j].value);
            }

            if(modify) {
                modify(&name, &value);
            }

            varlist = TMPL_add_var(varlist, name, value, 0);
        }
    }

    return varlist;
}

TMPL_varlist *cwf_db_records_to_loop(TMPL_varlist *varlist, cwf_query_result *data, char *loop_name, modify_db_name_value_fn *modify) {
    TMPL_loop *loop = 0;

    for(int i = 0; i < data->num_records; i++) {
        TMPL_varlist *loop_varlist = 0;

        for(int j = 0; j < get_num_columns(data->result_array[i]); j++) {
            char *name = strdup(data->result_array[i][j].key);
            char *value = NULL;

            if(data->result_array[i][j].value)
                value = strdup(data->result_array[i][j].value);

            if(modify) {
                modify(&name, &value);
            }

            char char_loop_value[11];

            sprintf(char_loop_value, "%d", i);
            
            loop_varlist = TMPL_add_var(loop_varlist, name, value, "loop_counter", char_loop_value, 0);

            if(i == data->num_records - 1) {
                loop_varlist = TMPL_add_var(loop_varlist, name, value, "last_record", char_loop_value, 0);
            }
            free(name);
            free(value);
        }

        loop = TMPL_add_varlist(loop, loop_varlist);
    }

    varlist = TMPL_add_loop(varlist, loop_name, loop);

    sds num_records = sdsfromlonglong(data->num_records);
    varlist = TMPL_add_var(varlist, "num_records", num_records, 0);
    sdsfree(num_records);

    return varlist;
}

sds cwf_escape_json(char *value) {

    sds return_value = sdsempty();
    char *tmp = value;

    while(*tmp) {
        if(*tmp == '\r') {
            return_value = sdscat(return_value, "\\r");
        } else if(*tmp == '\n') {
            return_value = sdscat(return_value, "\\n");
        } else if(*tmp == '\\') {
            return_value = sdscat(return_value, "\\\\");
        } else if(*tmp == '\"') {
            return_value = sdscat(return_value, "\\\"");
        } else {
            return_value = sdscatprintf(return_value, "%c", *tmp);
        }
        tmp++;
    }

    return return_value;
}

sds cwf_db_records_to_simple_json(cwf_query_result *data) {

    if(!data)
        return sdsnew("[]");

    sds json = sdsnew("[");

    unsigned int num_records = data->num_records;

    for(unsigned int i = 0; i < num_records; i++) {

        json = sdscatfmt(json, "%s", "{");

        int num_cols = get_num_columns(data->result_array[i]);

        for(int j = 0; j < num_cols; j++) {
            char *name = strdup(data->result_array[i][j].key);
            sds value = NULL;

            if(data->result_array[i][j].value) {
                value = cwf_escape_json(data->result_array[i][j].value);
            }

            if(j == num_cols - 1) {
                json = sdscatfmt(json, "\"%s\":\"%s\"", name, value);
            } else {
                json = sdscatfmt(json, "\"%s\":\"%s\",", name, value);
            }

            free(name);
            sdsfree(value);
        }

        if(i == num_records - 1) {
            json = sdscatfmt(json, "%s", "}");
        } else {
            json = sdscatfmt(json, "%s", "},");
        }
    }

    json = sdscatfmt(json, "%s", "]");
    return json;
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

        for(int j = 0; j < value_len; j++) {
            free(request->urlencoded_data[i].value[j]);
        }

        arrfree(request->urlencoded_data[i].value);
    }

    shfree(request->urlencoded_data);

    free(request);
}

void free_cwf_vars(cwf_vars *vars) {
    free(vars->endpoints_lib_path);
    free(vars->endpoints_config_path);
    free(vars->database_path);
    free(vars->session_files_path);

    free_cwf_request(vars->request);
    free_cwf_headers(vars->headers);

    // TODO: free the rest
    free(vars);
}
