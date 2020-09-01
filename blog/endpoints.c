#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "../src/3dparty/ctemplate-1.0/ctemplate.h"
#include "../src/3dparty/stb/stb_ds.h"
#include "../src/cwf/cwf.h"

ENDPOINT(login) {
    TMPL_varlist *varlist = 0;
    varlist = request_to_varlist(varlist, NULL);

    session_start();

    sds template_path = sdsnew(cwf_vars->document_root);
    template_path = sdscat(template_path, "login.tmpl");

    if(IS_GET()) {
        bool auth = (SESSION_GET("auth") != NULL);

        if(!auth) {
            return render_template(varlist, template_path);
        } else {
            redirect("/admin_index");
        }
    } else if(IS_POST()) {
        char *username = POST("username");
        char *password = POST("password");

        if((username && strcmp(username, "sachetto") == 0) && (password && strcmp(password, "abc") == 0)) {
            SESSION_PUT("auth", "true");
            redirect("/admin_index");
        } else {
            return render_template(varlist, template_path);
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
    } else {
        redirect("/login");
    }
}

ENDPOINT(logout) {
    session_start();
    session_destroy();
    redirect("/login");
}

void modify_value(char **name, char **value) {
    time_t now;

    now = time(NULL);
    double seconds;
    int days;

    if(strcmp(*name, "date") == 0) {
        char tmp[64];
        time_t post_date = strtol(*value, NULL, 10);
        seconds = difftime(now, post_date);
        days = seconds / 3600 / 24;
        sprintf(tmp, "%d", days);
        free(*value);
        *value = strdup(tmp);
    }
}

ENDPOINT(site_index) {

	open_database_or_return_404();

    execute_query_or_return_404("SELECT * FROM posts ORDER BY id DESC;");

    TMPL_varlist *varlist = 0;

    varlist = db_records_to_loop(varlist, "loop", modify_value);

    //@todo add a function to do this
    TMPL_varlist *loop_varlist = TMPL_get_loop_varlist(TMPL_get_loop(varlist));

    for(int i = 0; i < cwf_vars->database->num_records; i++) {
        for(int j = 0; j < get_num_columns(cwf_vars->database->records[i]); j++) {
            char *name = strdup(cwf_vars->database->records[i][j].key);
            char *value = cwf_vars->database->records[i][j].value;

            if(strcmp(name, "content") == 0) {
                char *less_content = strip_html_tags(value);
                int len = strlen(less_content);
                int max = 570;
                if(len > max) {
                    less_content[max] = '\0';
                    less_content[max - 1] = '.';
                    less_content[max - 2] = '.';
                    less_content[max - 3] = '.';
                }
                loop_varlist = TMPL_add_var(loop_varlist, "content_main_page", less_content, 0);
            }
        }

        loop_varlist = TMPL_get_next_varlist(loop_varlist);
    }

    sds template_path = sdsnew(cwf_vars->document_root);
    template_path = sdscat(template_path, "index.tmpl");

    sds response = render_template(varlist, template_path);
    sdsfree(template_path);

    return response;
}

ENDPOINT(post_detail) {

	open_database_or_return_404();

    //@todo use a prepared statement here
    char query[1024];

    int id = strtol(GET("id"), NULL, 10);

    sprintf(query, "SELECT content FROM posts WHERE id=%d", id);

    execute_query_or_return_404(query);

    TMPL_varlist *varlist = 0;
    varlist = db_record_to_varlist(varlist, NULL);

    // TODO: provide a macro or function
    sds template_path = sdsnew(cwf_vars->document_root);
    template_path = sdscat(template_path, "blog-post.tmpl");

    sds response = render_template(varlist, template_path);
    sdsfree(template_path);

    return response;
}

ENDPOINT(cgi_info) {
    header("Content-Type", "text/plain");
    sds response = sdsempty();

    // response = sdscatfmt(response, "SQLITE VERSION: %s\r\n\r\n", sqlite3_libversion());

    cwf_request *request = cwf_vars->request;

    for(int i = 0; i < request->server_data_len; i++) {
        char *tmp = request->server_data[i].value;
        if(tmp) response = sdscatfmt(response, "%s %s\n", request->server_data[i].key, tmp);
    }

    if(strcmp(request->data_type, "urlencoded") == 0) {
        for(int i = 0; i < request->data_len; i++) {
            string_array values = request->urlencoded_data[i].value;
            for(int j = 0; j < arrlen(values); j++)
                response = sdscatfmt(response, "%s %s\n", request->urlencoded_data[i].key, values[j]);
        }
    }

    return response;
}
