#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cwf.h"
#include "3dparty/ctemplate-1.0/ctemplate.h"
#include <time.h> 


//TODO: we neeed to figure out the headers situation
ENDPOINT(login) {

	TMPL_varlist *varlist = 0;
	varlist = request_to_varlist(varlist, request, NULL);

	if(IS_GET(request)) {
		render_template(varlist, "/var/www/cwf/login.tmpl");
	}
	else if(IS_POST(request)) {
	
		http_header headers = NULL;	

		session_start(&headers);

		bool auth = (SESSION("auth") != NULL);

		if(!auth) {

			char *username = POST(request, "username");
			char *password = POST(request, "password");

			if(username && strcmp(username, "sachetto") == 0) {
				if(password && strcmp(password, "abc") == 0) {
					redirect("/admin_index");
				}

			}

			else {
				render_template(varlist, "/var/www/cwf/login.tmpl");
			}
		}
	}

	return 1;
}

ENDPOINT(admin_index) {
	fprintf(stdout, "Content-Type: text/html\r\n\r\n");
	fprintf(stdout, "LOGGED IN");

	return 1;
}

ENDPOINT(test_cookie) {

	http_header headers = new_empty_header();

	//TODO: make helper functions for this	
	add_custom_header("Content-Type", "text/html", &headers);

	cookie *c = get_cookie();
	bool cookie = true;

	if(!c) {

		//TODO: create a function to start a section
		char *sid = generate_b64_session_id();
		c = new_cookie("sid", sid);
		free(sid);


		c->expires = 12 * 30 * 24 * 60 * 60;
		c->domain = "cwf_test";
		c->path = "/test_cookie";
		add_cookie_to_header(c, &headers);
		cookie = false;
	}

	write_http_headers(headers);

	if(cookie) {
		fprintf(stdout, "COOKIES!!!!!");
	}
	else {
		fprintf(stdout, "NO COOKIES!!!!!");
	}

	return 1;

}


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

    execute_query("SELECT * FROM posts ORDER BY id DESC; ", database);

    if(database->error) {
        generate_default_404_header();

        if(debug_server) {
            fprintf(stdout, "Database error: %s", database->error);
        }

        return 1;
    }
	
	TMPL_varlist *varlist = 0;
    varlist = db_records_to_loop(varlist, database, "loop", modify_value);
	
	//TODO: add a function to do this
	TMPL_varlist *loop_varlist = TMPL_get_loop_varlist(TMPL_get_loop(varlist));
	
	for(int i = 0; i < database->num_records; i++) {

		for(int j = 0; j < get_num_columns(database->records[i]); j++) {
			char *name = strdup(database->records[i][j].key);
			char *value = database->records[i][j].value;

			if(strcmp(name, "content") == 0) {
				char *less_content = strip_html_tags(value);
				int len = strlen(less_content);
				int max = 570;
				if(len > max) {
					less_content[max] = '\0';
					less_content[max-1] = '.';
					less_content[max-2] = '.';
					less_content[max-3] = '.';
				}
				loop_varlist = TMPL_add_var(loop_varlist, "content_main_page", less_content, 0);
			}

		}

		loop_varlist = TMPL_get_next_varlist(loop_varlist);
	}
	render_template(varlist, "/var/www/cwf/index.tmpl");
    return 1;
}

ENDPOINT(post_detail) {

	cfw_database *database = open_database("/var/www/cwf/blog.sqlite");

	if(database->error) {
		generate_default_404_header();

		if(debug_server) {
			fprintf(stdout, "Database error: %s", database->error);
		}

		return 1;
	}

	//TODO: prepared statement here
	char query[1024];

	int id = strtol(GET(request, "id"), NULL, 10);

	sprintf(query, "SELECT content FROM posts WHERE id=%d", id); 

	execute_query(query, database);

	if(database->error) {
		generate_default_404_header();

		if(debug_server) {
			fprintf(stdout, "Database error: %s", database->error);
		}

		return 1;
	}

	TMPL_varlist *varlist = 0;
	varlist = db_record_to_varlist(varlist, database, NULL);

	render_template(varlist, "/var/www/cwf/blog-post.tmpl");

	return 1;
}
