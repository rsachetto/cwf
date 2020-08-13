#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cwf.h"
#include "3dparty/ctemplate-1.0/ctemplate.h"

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
    cfw_database *database = open_database("/var/www/cwf/blog.sqlite");

    if(database->error) {
        generate_default_404_header();

        if(debug_server) {
            fprintf(stdout, "Database error: %s", database->error);
        }

        return 1;
    }

    execute_query("select * from Cars", database);

    if(database->error) {
        generate_default_404_header();

        if(debug_server) {
            fprintf(stdout, "Database error: %s", database->error);
        }

        return 1;
    }
	
	TMPL_varlist *varlist = 0;
    varlist = db_records_to_loop(varlist, database, "loop");

    /*fprintf(stdout, "Content-type: text/plain\r\n\r\n");

    fprintf(stdout, "Num records %d\n", database->num_records);

    for(int i = 0; i < database->num_records; i++) {
        for(int j = 0; j < get_num_columns(database->records[i]); j++) {
            fprintf(stdout, "%s: %s\n", database->records[i].key, database->records[i].value);
        }
    }
    
*/
	render_template(varlist, "/var/www/cwf/index.tmpl");
    return 1;
}

