#include "endpoints.h"
#include <string.h>

ENDPOINT(site_index) {
	fprintf(stdout, "Content-type: text/plain\r\n\r\n");

	for(int i = 0; i < request->server_data_len; i++) {
		fprintf(stdout, "%s %s\n", request->server_data[i].key, request->server_data[i].value);
	}

	if(strcmp(request->data_type, "urlencoded") == 0) {
		for(int i = 0; i < request->data_len; i++) {
			fprintf(stdout, "%s %s\n", request->urlencoded_data[i].key, request->urlencoded_data[i].value);
		}
	}

	return 1;
}

ENDPOINT(info) {
	
	render_template(request, "/home/sachetto/cwf/template.tmpl");

	return 1;
}

ENDPOINT(test) {
	fprintf(stdout, "Content-type: text/plain\r\n\r\n");

	for(int i = 0; i < request->server_data_len; i++) {
		fprintf(stdout, "%s %s\n", request->server_data[i].key, request->server_data[i].value);
	}

	if(strcmp(request->data_type, "urlencoded") == 0) {
		for(int i = 0; i < request->data_len; i++) {
			fprintf(stdout, "%s %s\n", request->urlencoded_data[i].key, request->urlencoded_data[i].value);
		}
	}

	return 1;
}

