#include <ctype.h>
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "src/cwf.h"
#include "src/endpoints.h"
#include "src/ini_parse.h"

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

	char *config_file = "endpoints.ini";
	endpoint_config_item *endpoint_configs = new_endpoint_config_hash();

	if(ini_parse(config_file, parse_endpoint_configuration, (void*)&endpoint_configs) < 0) {
		fprintf(stderr, "Error: Can't load the config file %s\n", config_file);
		return EXIT_FAILURE;
	}

	char *endpoint_name = get_endpoint(SERVER(req, "REQUEST_URI"), endpoint_configs);


    if(*endpoint_name == '/') {
        free(endpoint_name);
        endpoint_name = strdup("site_index");
    }

    endpoint_function = dlsym(handle, endpoint_name);
    char *error = dlerror();

    if(error != NULL) {
        generate_default_404_header();
        fprintf(stdout, "\n%s function not found in the provided in library %s. Error from dlsym %s\n", endpoint_name,
                ENDPOINT_LIB_PATH, error);
        return 0;
    }

    endpoint_function(req, NULL);

    return 0;
}

