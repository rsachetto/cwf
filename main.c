#include <stdio.h>
#include <ctype.h>
#include <unistd.h>

#include "src/cwf.h"

void wait_for_gdb_to_attach() {
	int is_waiting = 1;
	while (is_waiting) {
		sleep(1); // sleep for 1 second
	}
}

int main(int argc, char **argv) {

//	wait_for_gdb_to_attach();
	//TODO: load the shared library with all the url endpoints
	//TODO: execute the function to handle the endpoint
	//TODO: try to work with regexp in URLs

	request *req = new_from_env_vars();

	fprintf(stdout, "Content-type: text/plain\r\n\r\n");
	
	for(int i = 0; i < req->server_data_len; i++) {
		fprintf(stdout, "%s %s\n", req->server_data[i].key, req->server_data[i].value);
	}

	//render_template(req, "/home/sachetto/cwf/template.tmpl");

    return 0;
}

