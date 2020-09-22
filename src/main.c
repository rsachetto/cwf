#ifdef ENABLE_BACKTRACE
#include "cwf/debug_helper.h"
#endif

#include <dlfcn.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "cwf/cwf.h"
#include "ini_parse/ini_parse.h"

int main(int argc, char **argv) {

#ifdef ENABLE_BACKTRACE
    setup_sigsegv();
#endif

    cwf_vars *cwf_vars = calloc(1, sizeof(struct cwf_vars_t));

    // check if the site or even the endpoint will use databases
    cwf_vars->database = calloc(1, sizeof(struct cwf_database_t));

    cwf_vars->request = new_from_env_vars();

    char *root = SERVER("DOCUMENT_ROOT");

    endpoint_config_item *endpoint_configs = NULL;

    if(root) {
        cwf_vars->document_root = root;
    } else {
        cwf_vars->document_root = getenv("PWD");
    }

    cwf_vars->templates_path = strdup(cwf_vars->document_root);
	cwf_vars->static_path = malloc(strlen(cwf_vars->document_root) + strlen("/static/") + 1);
	sprintf(cwf_vars->static_path, "%s%s", cwf_vars->document_root, "/static/");

    sds site_config_file = sdsnew(cwf_vars->document_root);

    site_config_file = sdscat(site_config_file, "site_config.ini");

    bool error_found = false;
    sds response = NULL;

    if(ini_parse(site_config_file, parse_site_configuration, (void *)cwf_vars) < 0) {
        response = simple_404_page(cwf_vars, "Error parsing ini file %s<br/>", site_config_file);
        error_found = true;
    }

    endpoint_fn *endpoint_function = NULL;

    if(!error_found) {
        void *handle = dlopen(cwf_vars->endpoints_lib_path, RTLD_LAZY);

        if(!handle) {
            response = simple_404_page(cwf_vars, "%s<br/>", dlerror());
            error_found = true;
        }

        endpoint_configs = new_endpoint_config_hash();

        if(ini_parse(cwf_vars->endpoints_config_path, parse_endpoint_configuration, (void *)&endpoint_configs) < 0) {
            if(!error_found) {
                response = simple_404_page(cwf_vars, "Error parsing ini file %s<br/>", cwf_vars->endpoints_config_path);
                error_found = true;
            }
        }

        char *uri = SERVER("REQUEST_URI");
        char *query_string = SERVER("QUERY_STRING");

        endpoint_config *endpoint_config = get_endpoint_config(uri, query_string, endpoint_configs);

        char *endpoint_name = NULL;

        if(endpoint_config)
            endpoint_name = endpoint_config->function;

        if(endpoint_name) {
            endpoint_function = dlsym(handle, endpoint_name);
            char *error = dlerror();

            if(error != NULL) {
                if(!error_found) {
                    response = simple_404_page(cwf_vars, "\n%s function not found in the provided in library %s. Error from dlsym %s\n", endpoint_name,
                                               cwf_vars->endpoints_lib_path, error);
                    error_found = true;
                }
            } else {
                if(endpoint_config->params) {
                    if(!endpoint_config->error) {
                        add_params_to_request(cwf_vars->request, endpoint_config->params);
                    } else {
                        if(!error_found) {
                            response = simple_404_page(cwf_vars,
                                                       "<h1>Error parsing parameters for endpoint [%s] with URL %s</h1><h2 "
                                                       "style=\"color:red;\">%s</h2> ",
                                                       endpoint_name, SERVER("REQUEST_URI"), endpoint_config->error);
                            error_found = true;
                        }
                    }
                }
            }
        } else {
            if(!error_found) {
                response = simple_404_page(cwf_vars, "No configured endpoint for the provided URL %s<br/> Check your endpoints config file (%s)",
                                           SERVER("REQUEST_URI"), cwf_vars->endpoints_config_path);
                error_found = true;
            }
        }
    }

    if(endpoint_function && !error_found)
        response = endpoint_function(cwf_vars, NULL);

    write_http_headers(cwf_vars->headers);

    if(response) {
        fprintf(stdout, "%s", response);
        fflush(stdout);
        sdsfree(response);
    }

    cwf_save_session(cwf_vars->session);
    sdsfree(site_config_file);
    free_cwf_vars(cwf_vars);

    if(endpoint_configs)
        free_endpoint_config_hash(endpoint_configs);

    // TODO: maybe we will also need to release the file locks if the section is not readonly
    return 0;
}

