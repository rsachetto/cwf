#include "endpoints.h"
#include <string.h>

ENDPOINT(cgi_info) {
	fprintf(stdout, "Content-type: text/plain\r\n\r\n");
	fprintf(stdout, "SQLITE VERSION: %s\r\n\r\n", sqlite3_libversion());

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

ENDPOINT(site_index) {
	
	render_template(request, "/var/www/cwf/index.tmpl");

	return 1;
}

