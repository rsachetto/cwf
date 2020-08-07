#include <stdio.h>
#include <ctype.h>
#include <unistd.h>
#include <string.h>
#include <dlfcn.h>

#include "src/cwf.h"
#include "endpoints.h"

#ifdef GDB_DEBUG
void wait_for_gdb_to_attach() {
	int is_waiting = 1;
	while (is_waiting) {
		sleep(1); // sleep for 1 second
	}
}
#endif

int main(int argc, char **argv) {

#ifdef GDB_DEBUG
	wait_for_gdb_to_attach();
#endif

	request *req = new_from_env_vars();

	void *handle = dlopen (ENDPOINT_LIB_PATH, RTLD_LAZY);
	if (!handle) {
		fprintf(stdout, "Content-type: text/plain\r\n\r\n");
		fprintf(stdout, "%s\n", dlerror());
		return 0;
	}

	endpoint_fn *endpoint_function;


	//TODO: here we have to parse the URL and configure the correct endpoint for the function
	//
	char *endpoint_name = "site_index";
	endpoint_function = dlsym(handle, endpoint_name);
	char *error = dlerror();

	if (error != NULL)  {
		fprintf(stdout, "Content-type: text/plain\r\n\r\n");
		fprintf(stdout, "\n%s function not found in the provided in library %s. Error from dlsym %s\n", endpoint_name, ENDPOINT_LIB_PATH, error);
		return 0;
	}

	endpoint_function(req);

	//render_template(req, "/home/sachetto/cwf/template.tmpl");

	return 0;
}

