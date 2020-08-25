#include <ctype.h>
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "src/cwf.h"
#include "src/ini_parse.h"

//@todo: create a ini file to configure the site options like the debug_seter and the endpoints file
//@todo add CSRF protection - https://owasp.org/www-community/attacks/csrf https://codefellows.github.io/sea-python-401d4/lectures/pyramid_day6_csrf.html
#define ENDPOINTS_FILE "/var/www/cwf/endpoints.ini"

#ifdef GDB_DEBUG
void wait_for_gdb_to_attach() {
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

    cwf_vars *cwf_vars = calloc(1, sizeof(cwf_vars));
    cwf_vars->request = new_from_env_vars();

    //@todo: create a config file to set this variables
    cwf_vars->print_debug_info = true;

    void *handle = dlopen(ENDPOINT_LIB_PATH, RTLD_LAZY);
    if(!handle) {
        generate_default_404_header();
        if(cwf_vars->print_debug_info) fprintf(stdout, "%s\n", dlerror());
        return 0;
    }

    endpoint_fn *endpoint_function;

    //@todo: here we have to parse the URL and configure the correct endpoint for the function
    char *config_file = ENDPOINTS_FILE;
    endpoint_config_item *endpoint_configs = new_endpoint_config_hash();

    if(ini_parse(config_file, parse_endpoint_configuration, (void *)&endpoint_configs) < 0) {
        generate_default_404_header();
        if(cwf_vars->print_debug_info) fprintf(stdout, "Error: Can't load the config file %s\n", config_file);
        return 0;
    }

    endpoint_config *endpoint_config = get_endpoint_config(SERVER("REQUEST_URI"),
                                                           SERVER("QUERY_STRING"), endpoint_configs);

    char *endpoint_name = NULL;

    if(endpoint_config) endpoint_name = endpoint_config->function;

    if(endpoint_name) {
        endpoint_function = dlsym(handle, endpoint_name);
        char *error = dlerror();

        if(error != NULL) {
            generate_default_404_header();
            if(cwf_vars->print_debug_info)
                fprintf(stdout, "\n%s function not found in the provided in library %s. Error from dlsym %s\n",
                        endpoint_name, ENDPOINT_LIB_PATH, error);
            return 0;
        }
    } else {
        generate_default_404_header();
        if(cwf_vars->print_debug_info)
            fprintf(stdout,
                    "\nNo configured endpoint for the provided URL %s<br/> Check your endpoints config file (%s)",
                    SERVER("REQUEST_URI"), ENDPOINTS_FILE);
        return 0;
    }

    if(endpoint_config->params) {
        if(!endpoint_config->error) {
            add_params_to_request(cwf_vars->request, endpoint_config->params);
        } else {
            //@todo: include an error message on the endpoint_config
            generate_default_404_header();

            if(cwf_vars->print_debug_info)
                fprintf(
                    stdout,
                    "<h1>Error parsing parameters for endpoint [%s] with URL %s</h1><h2 style=\"color:red;\">%s</h2> ",
                    endpoint_name, SERVER("REQUEST_URI"), endpoint_config->error);
            return 0;
        }
    }

	//Maybe we can put response inside the cwf_vars
    sds reponse = endpoint_function(cwf_vars, NULL);
	write_http_headers(cwf_vars->headers);
	if(reponse)
		fprintf(stdout, "%s", reponse);
    cwf_save_session(cwf_vars->session);
    //@todo maybe we will also need to release the file locks if the section is not readonly
    return 0;
}

