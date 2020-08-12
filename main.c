#include <ctype.h>
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "src/cwf.h"
#include "src/endpoints.h"
#include "src/ini_parse.h"

#define ENDPOINTS_FILE "/home/sachetto/cwf/endpoints.ini"

bool debug_server = true;

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

    request *req = new_from_env_vars();

    void *handle = dlopen(ENDPOINT_LIB_PATH, RTLD_LAZY);
    if(!handle) {
        generate_default_404_header();
        fprintf(stdout, "%s\n", dlerror());
        return 0;
    }

    endpoint_fn *endpoint_function;

    // TODO: here we have to parse the URL and configure the correct endpoint for the function
	char *config_file = ENDPOINTS_FILE;
	endpoint_config_item *endpoint_configs = new_endpoint_config_hash();

	if(ini_parse(config_file, parse_endpoint_configuration, (void*)&endpoint_configs) < 0) {
		fprintf(stderr, "Error: Can't load the config file %s\n", config_file);
		return EXIT_FAILURE;
	}

	endpoint_config *endpoint_config = get_endpoint_config(SERVER(req, "REQUEST_URI"), SERVER(req, "QUERY_STRING"), endpoint_configs);

	char *endpoint_name = NULL;

 	if(endpoint_config)	
		endpoint_name =	endpoint_config->function;

	if(endpoint_name) {
		endpoint_function = dlsym(handle, endpoint_name);
		char *error = dlerror();

		if(error != NULL) {
			generate_default_404_header();
			if(debug_server)
				fprintf(stdout, "\n%s function not found in the provided in library %s. Error from dlsym %s\n", endpoint_name,
					ENDPOINT_LIB_PATH, error);
			return 0;
		}
	}
	else {
		generate_default_404_header();
		if(debug_server)
			fprintf(stdout, "\nNo configured endpoint for the provided URL %s<br/> Check your endpoints config file (%s)", SERVER(req, "REQUEST_URI"), ENDPOINTS_FILE);
		return 0;
	}

	if(endpoint_config->params) {
		if(!endpoint_config->error) {
			add_params_to_request(req, endpoint_config->params);
		}
		else {
		//TODO: include an error message on the endpoint_config
		generate_default_404_header();

		if(debug_server)		
			fprintf(stdout, "<h1> Error parsing parameters for endpoint [%s] with URL %s</h1><h2>Errors:</h2> <h2 style=\"color:red;\">%s</h2> ", endpoint_name, SERVER(req, "REQUEST_URI"), endpoint_config->error);
		return 0;

		}
	}

    endpoint_function(req, NULL);

    return 0;
}

