#include <ctype.h>
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "cwf/cwf.h"
#include "ini_parse/ini_parse.h"

// TODO enable support for multiple applications in a single site.
// this can be achieved by creating a site.ini file that configure the endpoints
// and merging all endpoints in a single library

// TODO create a development server. We will need to fork a process and replace its stdin with the
// parent stdout and the parent stdin with the child stdout.

// TODO: create a ini file to configure the site options like the debug_server, the endpoints file, the endpoints
// library and the database file

// TODO add CSRF protection - https://owasp.org/www-community/attacks/csrf
// https://codefellows.github.io/sea-python-401d4/lectures/pyramid_day6_csrf.html

#ifdef GDB_DEBUG
static void wait_for_gdb_to_attach() {
    int is_waiting = 1;
    while(is_waiting) {
        sleep(1);  // sleep for 1 second
    }
}
#endif

int main(int argc, char **argv) {
#ifdef GDB_DEBUG
    wait_for_gdb_to_attach();
#endif

    cwf_vars *cwf_vars = calloc(1, sizeof(struct cwf_vars_t));
    cwf_vars->request = new_from_env_vars();

    cwf_vars->document_root = strdup(SERVER("DOCUMENT_ROOT"));

    sds site_config_file = sdsnew(cwf_vars->document_root);

    site_config_file = sdscat(site_config_file, "site_config.ini");

    bool error_found = false;
    sds response = NULL;

    if(ini_parse(site_config_file, parse_site_configuration, (void *)cwf_vars) < 0) {
        if(!error_found) {
            response = simple_404_page(cwf_vars, "Error parsing ini file %s<br/>", site_config_file);
            error_found = true;
        }
    }

    sdsfree(site_config_file);

    endpoint_fn *endpoint_function = NULL;

    if(!error_found) {
        void *handle = dlopen(cwf_vars->endpoints_lib_path, RTLD_LAZY);

        if(!handle) {
            response = simple_404_page(cwf_vars, "%s<br/>", dlerror());
            error_found = true;
        }

        endpoint_config_item *endpoint_configs = new_endpoint_config_hash();

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

        if(endpoint_config) endpoint_name = endpoint_config->function;

        if(endpoint_name) {
            endpoint_function = dlsym(handle, endpoint_name);
            char *error = dlerror();

            if(error != NULL) {
                if(!error_found) {
                    response = simple_404_page(
                        cwf_vars, "\n%s function not found in the provided in library %s. Error from dlsym %s\n",
                        endpoint_name, cwf_vars->endpoints_lib_path, error);
                    error_found = true;
                }
            } else {
                if(endpoint_config->params) {
                    if(!endpoint_config->error) {
                        add_params_to_request(cwf_vars->request, endpoint_config->params);
                    } else {
                        if(!error_found) {
                            response =
                                simple_404_page(cwf_vars,
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
                response = simple_404_page(
                    cwf_vars,
                    "No configured endpoint for the provided URL %s<br/> Check your endpoints config file (%s)",
                    SERVER("REQUEST_URI"), cwf_vars->endpoints_config_path);
                error_found = true;
            }
        }
    }

    if(endpoint_function && !error_found) response = endpoint_function(cwf_vars, NULL);

    write_http_headers(cwf_vars->headers);
    if(response) {
        fprintf(stdout, "%s", response);
        fflush(stdout);
    }
    cwf_save_session(cwf_vars->session);
    // TODO maybe we will also need to release the file locks if the section is not readonly
    return 0;
}

