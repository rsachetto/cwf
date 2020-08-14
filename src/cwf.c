#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#define STB_DS_IMPLEMENTATION
#include "3dparty/stb/stb_ds.h"
#include "cwf.h"

#define ENDSWITH(s, c) (s)[strlen((s)) - 1] == (c)

/*These are from ccgi*/
static int hex(int digit) {
    switch(digit) {
        case '0':
        case '1':
        case '2':
        case '3':
        case '4':
        case '5':
        case '6':
        case '7':
        case '8':
        case '9':
            return digit - '0';

        case 'A':
        case 'B':
        case 'C':
        case 'D':
        case 'E':
        case 'F':
            return 10 + digit - 'A';

        case 'a':
        case 'b':
        case 'c':
        case 'd':
        case 'e':
        case 'f':
            return 10 + digit - 'a';

        default:
            return -1;
    }
}

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
                    shput(*v, strdup(name), strdup(value));
                }
                k = 0;
                name = value = 0;
                continue;

            case '+':
                buf[k++] = ' ';
                continue;

            case '%':
                if((L = hex(query[i + 1])) >= 0 && (R = hex(query[i + 2])) >= 0) {
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

static void get_post(request_item **v, int len) {
    char *buf;

    buf = (char *)malloc(len + 1);
    if(fread(buf, 1, len, stdin) == len) {
        buf[len] = 0;
        decode_query(v, buf);
    }
    free(buf);
}

static bool is_int(char *int_char) {
	int len = strlen(int_char);

	if(len == 0) return false;

    for (int i = 0; i < len; ++i) {
        if (!isdigit(int_char[i]))  {
            return false;
        }
    }

	return true;
}

static bool is_float(char *float_char) {

	int len = strlen(float_char);

	if(len == 0) return false;

	bool dot_found = false;

    for (int i = 0; i < len; ++i) {

		if(float_char[i] == '.') {
			if(!dot_found) dot_found = true;
			else return false;

			continue;
		}

        if (!isdigit(float_char[i]))  {
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

endpoint_config *new_endpoint_config() {
	endpoint_config *config = calloc(1, sizeof(endpoint_config));
	return config;
}

endpoint_config_item *new_endpoint_config_hash() {
	endpoint_config_item *endpoint_config_hash = calloc(1, sizeof(endpoint_config_item));
	sh_new_arena(endpoint_config_hash);
	shdefault(endpoint_config_hash, NULL);
	return endpoint_config_hash;
}

request *new_empty_request() {
    request *req = (request *)malloc(sizeof(request));
    req->method = NULL;
    req->urlencoded_data = NULL;
    req->data_type = NULL;
    sh_new_arena(req->urlencoded_data);

    return req;
}

void generate_default_404_header() {
    fprintf(stdout, "Status: 404 Not Found\r\n");
    fprintf(stdout, "Content-type: text/html\r\n\r\n");
}

endpoint_config *get_endpoint_config(const char *REQUEST_URI, const char *QUERY_STRING, endpoint_config_item *endpoints_cfg) {

	char *str = (char*)REQUEST_URI;

	endpoint_config *it;
	char  *tmp = NULL;

	int uri_len = strlen(REQUEST_URI);

	if(uri_len > 1) {
		str = str + 1;
	}

	if(!*QUERY_STRING) {
		char *first_slash = strchr(str, '/');
		if(first_slash) {
			if(uri_len > 1) {
				tmp = strndup(str, (int)(first_slash - str));
			}
			else {
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

				char * pch;
				pch = strtok (aux, "/");
				int num_params = 0;

				while (pch != NULL) {
					url_params url_params;
					if(num_params < expected_params) {
						url_params = it->params[num_params];
					}
					else {
						sprintf(err, "Number of parameters exceed the configured number of parameters (%d).\n", expected_params);
						concat_error_msg(&(it->error), err);
						break;
					}	

					switch (url_params.type) {
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

					pch = strtok (NULL, "/");
				}

				free(aux);

				if(num_params != expected_params) {
					sprintf(err, "Number of parameters are different from the configured number of parameters (received %d, expected %d).\n", num_params, expected_params);
					concat_error_msg(&(it->error), err);
				}
			}
			else {
				sprintf(err, "Number of parameters are different from the configured number of parameters (received 0, expected %d).\n", expected_params);
				concat_error_msg(&(it->error), err);

			}

		} 

	}
	else {
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

void add_params_to_request(request *req, url_params *params) {
	for(int i = 0; i < arrlen(params); i++) {
		shput(req->urlencoded_data, params[i].name, strdup(params[i].value)); 
	}
}

request *new_from_env_vars() {
    request *req = new_empty_request();

    shput(req->server_data, "HTTP_ACCEPT", getenv("HTTP_ACCEPT"));
    shput(req->server_data, "HTTP_COOKIE", getenv("HTTP_COOKIE"));
    shput(req->server_data, "HTTP_FORWARDED", getenv("HTTP_FORWARDED"));
    shput(req->server_data, "HTTP_HOST", getenv("HTTP_HOST"));
    shput(req->server_data, "HTTP_PROXY_CONNECTION", getenv("HTTP_PROXY_CONNECTION"));
    shput(req->server_data, "HTTP_REFERER", getenv("HTTP_REFERER"));
    shput(req->server_data, "HTTP_USER_AGENT", getenv("HTTP_USER_AGENT"));
    shput(req->server_data, "CONTENT_LENGTH", getenv("CONTENT_LENGTH"));
    shput(req->server_data, "REQUEST_METHOD", getenv("REQUEST_METHOD"));
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

    if(IS_GET(req)) {
        decode_query(&req->urlencoded_data, getenv("QUERY_STRING"));
        req->data_type = "urlencoded";
        req->data_len = shlen(req->urlencoded_data);
    } else if(IS_POST(req)) {
        const char *env;
        int len;

        if((env = getenv("CONTENT_TYPE")) != 0 && strncasecmp(env, "application/x-www-form-urlencoded", 33) == 0 &&
           (env = getenv("CONTENT_LENGTH")) != 0 && (len = atoi(env)) > 0) {
            get_post(&req->urlencoded_data, len);
            req->data_type = "urlencoded";
            req->data_len = shlen(req->urlencoded_data);
        } else if((env = getenv("CONTENT_TYPE")) != 0 && strncasecmp(env, "application/json", 16) == 0 &&
                  (env = getenv("CONTENT_LENGTH")) != 0 && (len = atoi(env)) > 0) {
            req->data_type = "json";

        } else {  // multipart
            // TODO: handle multpart input (get from liccgi)
            //
        }
    }

    return req;
}

char *SERVER(request *req, char *key) {
    return shget(req->server_data, key);
}

char *GET(request *req, char *key) {
    if(IS_GET(req)) {
        return shget(req->urlencoded_data, key);
    }

    return NULL;
}

int render_template(TMPL_varlist *varlist, const char *template_path) {
    fputs("Content-type: text/html\r\n\r\n", stdout);

    int ret = 0;

    TMPL_fmtlist *fmtlist;

    fmtlist = TMPL_add_fmt(0, "entity", TMPL_encode_entity);
    TMPL_add_fmt(fmtlist, "url", TMPL_encode_url);
    ret = TMPL_write(template_path, 0, fmtlist, varlist, stdout, stderr) != 0;

    TMPL_free_fmtlist(fmtlist);
    TMPL_free_varlist(varlist);

    return ret;
}

cfw_database *open_database(const char *db_filename) {

	cfw_database *database = calloc(1, sizeof(cfw_database));

	int rc = sqlite3_open(db_filename, &(database->db));

	if (rc != SQLITE_OK) {
		database->error = strdup(sqlite3_errmsg(database->db));
		sqlite3_close(database->db);
	}

	return database;

}

static int sqlite_callback(void *cfw_db, int num_results, char **column_values, char **column_names) {

	if(num_results) {	

		cfw_database *database = (cfw_database *)cfw_db;

		record *line;
		sh_new_strdup(line);
		shdefault(line, NULL);

		int num_records = 0;

		for (int i = 0; i < num_results; i++) {
			if(column_names[i]) {
				shput(line, strdup(column_names[i]), strdup(column_values[i]));
				num_records++;
			}
		}

		arrput(database->records, line);
		database->num_records += 1;
	}

	return 0;

}

void execute_query(const char *query, cfw_database *database) {

	char *errmsg;

	//TODO: We will have to free all records
	if(database->records) { 
		arrfree(database->records);
		database->records = NULL;
		database->num_records = 0;
	}

	int rc = sqlite3_exec(database->db, query, sqlite_callback, (void *)database, &errmsg);

	if (rc != SQLITE_OK ) {
		database->error = strdup(errmsg);
		sqlite3_close(database->db);
		sqlite3_free(errmsg);            	
	}
}

int get_num_columns(record *r) {
	return shlen(r);
}

TMPL_varlist *request_to_varlist(request *req, TMPL_varlist *varlist, modify_db_name_value_fn *modify) {
	for(int i = 0; i < shlen(req->urlencoded_data); i++) {
		char *name = strdup(req->urlencoded_data[i].key);
			char *value = strdup(req->urlencoded_data[i].value);

			if(modify) {
				modify(name, value);
			}

			varlist = TMPL_add_var(varlist, name, value, 0);
	}

	return varlist;
}

TMPL_varlist *db_records_to_loop(TMPL_varlist *varlist, cfw_database *database, char *loop_name, modify_db_name_value_fn *modify) {
 
	TMPL_loop  *loop = 0;

	for(int i = 0; i < database->num_records; i++) {
		TMPL_varlist *loop_varlist = 0;

		for(int j = 0; j < get_num_columns(database->records[i]); j++) {
			char *name = strdup(database->records[i][j].key);
			char *value = strdup(database->records[i][j].value);

			if(modify) {
				modify(name, value);
			}

			loop_varlist = TMPL_add_var(loop_varlist, name, value, 0);
		}

		loop = TMPL_add_varlist(loop, loop_varlist);
	}

    varlist = TMPL_add_loop(varlist, loop_name, loop);

	return varlist;
}

