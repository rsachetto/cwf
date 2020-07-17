#include <stdio.h>
#include <ctype.h>
#include "src/cwf.h"

int main(int argc, char **argv) {

	//TODO: load the shared library with all the url endpoints
	//TODO: execute the function to handle the endpoint
	//TODO: try to work with regexp in URLs

	request *req = new_from_env_vars();

	for(int i = 0; i < shlen(req->server_data); i++) {

	}

	//render_template(req, "/home/sachetto/cwf/template.tmpl");

    return 0;
}

