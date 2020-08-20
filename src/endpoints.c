#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cwf.h"
#include "3dparty/ctemplate-1.0/ctemplate.h"
#include <time.h> 


//TODO: we neeed to figure out the headers situation
ENDPOINT(login) {

	TMPL_varlist *varlist = 0;
	varlist = request_to_varlist(varlist, NULL);

	session_start();

	if(IS_GET()) {
		bool auth = (SESSION_GET("auth") != NULL);

		if(!auth) {
			return render_template(varlist, "/var/www/cwf/login.tmpl");
		}
		else {
			redirect("/admin_index");
		}
	}
	else if(IS_POST()) {

		char *username = POST("username");
		char *password = POST("password");

		if((username && strcmp(username, "sachetto") == 0) && (password && strcmp(password, "abc") == 0)) {
			SESSION_PUT("auth", "true");
			redirect("/admin_index");
		}
		else {
			return render_template(varlist, "/var/www/cwf/login.tmpl");
		}
	}

	return NULL;
}

ENDPOINT(admin_index) {

	session_start();

	bool auth = (SESSION_GET("auth") != NULL);

	if(auth) {
		header("Content-Type", "text/html");
		sds response = sdsnew("<a href=\"/logout\">Logout</a>");
		return response;
	}
	else {
		redirect("/login");
	}
}

ENDPOINT(logout) {
	session_start();
	session_destroy();
	redirect("/login");
}

ENDPOINT(cgi_info) {


	header("Content-Type", "text/plain");
	sds response = sdsempty();

	response = sdscatprintf(response, "SQLITE VERSION: %s\r\n\r\n", sqlite3_libversion());

	cwf_request *request = cwf_vars->request;

	

    for(int i = 0; i < request->server_data_len; i++) {
		response = sdscatprintf(response, "%s %s\n", request->server_data[i].key, request->server_data[i].value);
    }

    if(strcmp(request->data_type, "urlencoded") == 0) {
        for(int i = 0; i < request->data_len; i++) {
			response = sdscatprintf(response, "%s %s\n", request->urlencoded_data[i].key, request->urlencoded_data[i].value);
        }
    }

	return response;
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

	sds response = sdsempty();

    if(database->error) {
        
		generate_default_404_header();

        if(cwf_vars->print_debug_info) {
            response = sdscatprintf(response, "Database error: %s", database->error);
        }

        return response;
    }

    execute_query("SELECT * FROM posts ORDER BY id DESC; ", database);

    if(database->error) {
        generate_default_404_header();

        if(cwf_vars->print_debug_info) {
            response = sdscatprintf(response, "Database error: %s", database->error);
        }

        return response;
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

	return render_template(varlist, "/var/www/cwf/index.tmpl");
}

ENDPOINT(post_detail) {

	cfw_database *database = open_database("/var/www/cwf/blog.sqlite");

	sds response = sdsempty();

	if(database->error) {
		generate_default_404_header();

		if(cwf_vars->print_debug_info) {
			response = sdscatprintf(response, "Database error: %s", database->error);
		}
		return response;
	}

	//TODO: prepared statement here
	char query[1024];

	int id = strtol(GET("id"), NULL, 10);

	sprintf(query, "SELECT content FROM posts WHERE id=%d", id); 

	execute_query(query, database);

	if(database->error) {
		generate_default_404_header();

		if(cwf_vars->print_debug_info) {
			response = sdscatprintf(response, "Database error: %s", database->error);
		}

		return response;
	}

	TMPL_varlist *varlist = 0;
	varlist = db_record_to_varlist(varlist, database, NULL);

	return render_template(varlist, "/var/www/cwf/blog-post.tmpl");

}
