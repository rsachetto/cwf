#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cwf.h"
#include "3dparty/ctemplate-1.0/ctemplate.h"
#include <time.h> 


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

void modify_value(char *name, char *value) {

	time_t now;

	now = time(NULL);  
	double seconds;
	int days;
	char tmp[10];

	if(strcmp(name, "date") == 0) {
		time_t post_date = strtol(value, NULL, 10); 
		seconds = difftime(now, post_date);
		days = seconds/3600/24;
		sprintf(tmp, "%d", days);
		free(value);
		value = strdup(tmp);
	}

}

//TODO: remove html tags https://stackoverflow.com/questions/9444200/c-strip-html-between
ENDPOINT(site_index) {
    cfw_database *database = open_database("/var/www/cwf/blog.sqlite");

    if(database->error) {
        generate_default_404_header();

        if(debug_server) {
            fprintf(stdout, "Database error: %s", database->error);
        }

        return 1;
    }

    execute_query("select * from posts", database);

    if(database->error) {
        generate_default_404_header();

        if(debug_server) {
            fprintf(stdout, "Database error: %s", database->error);
        }

        return 1;
    }
	
	TMPL_varlist *varlist = 0;
    varlist = db_records_to_loop(varlist, database, "loop", modify_value);

	TMPL_varlist *loop_varlist = TMPL_get_loop_varlist(TMPL_get_loop(varlist));
	
	for(int i = 0; i < database->num_records; i++) {

		for(int j = 0; j < get_num_columns(database->records[i]); j++) {
			char *name = strdup(database->records[i][j].key);
			char *value = database->records[i][j].value;
		
			if(strcmp(name, "content") == 0) {
				char *less_content;
				int len = strlen(value);
				int max = 570;
				if(len > max) {
					less_content = malloc(max + 4);
					less_content = strncpy(less_content, value, max);
					less_content[max] = '\0';
					less_content[max-1] = '.';
					less_content[max-2] = '.';
					less_content[max-3] = '.';
				}
				else {
					less_content = strdup(value);
				}
				loop_varlist = TMPL_add_var(loop_varlist, "content_main_page", less_content, 0);
			}

		}

	}

	render_template(varlist, "/var/www/cwf/index.tmpl");
    return 1;
}

ENDPOINT(post_detail) {
	render_template(NULL, "/var/www/cwf/blog-post.tmpl");
}
