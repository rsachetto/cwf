#include <string.h>
#include <time.h>

#include "../../src/3dparty/ctemplate-1.0/ctemplate.h"
#include "../../src/3dparty/stb/stb_ds.h"
#include "../../src/cwf/cwf.h"

#include <sys/time.h>

ENDPOINT(todo) {

    open_database_or_return_404();

    if(IS_POST()) {
        if(POST("taskAdd")) {
            char *title = POST("description");
            char *date = POST("date");
            char *category = POST("category_select");

            char created[11];
            time_t now = time(NULL);
            struct tm tm = *gmtime(&now);
            strftime(created, sizeof(created), "%d/%m/%Y", &tm);

            sds query = sdscatfmt(sdsempty(),
                                  "INSERT INTO todolist_todolist (title, due_date, created, category_id, content) "
                                  "VALUES('%s', '%s', '%s', '%s', 'Not used')",
                                  title, date, created, category);

            execute_query_or_return_404(query);

            redirect("/");
        }

        else if(POST("taskDelete")) {
            string_array checkedlist = POST_ARRAY("checkedbox");
            int num_ids = arrlen(checkedlist);
            sds query = sdsempty();

            if(num_ids > 0) {
                sds ids_list = sdsjoin(checkedlist, num_ids, ", ");
                query = sdscatfmt(query, "DELETE FROM todolist_todolist where id in (%s);", ids_list);
                execute_query_or_return_404(query);
                sdsfree(query);
            }

            redirect("/");
        }
    }

    execute_query_or_return_404("SELECT * FROM todolist_category ORDER BY name ASC;");


    TMPL_varlist *varlist = 0;
    varlist = db_records_to_loop(varlist, "categories", NULL);

    execute_query_or_return_404(
        "SELECT todolist_todolist.id, todolist_todolist.title, todolist_todolist.created, "
        "todolist_todolist.due_date, "
        "todolist_category.name FROM todolist_todolist LEFT JOIN todolist_category ON "
        "todolist_todolist.category_id = "
        "todolist_category.id;");

    varlist = db_records_to_loop(varlist, "todos", NULL);

    sds template_path = sdsnew(cwf_vars->templates_path);
    template_path = sdscat(template_path, "index.tmpl");

    // The varlist is freed in the render_template function
    sds response = render_template(varlist, template_path);

    sdsfree(template_path);

    close_database();

    return response;
}

ENDPOINT(cgi_info) {

    header("Content-Type", "text/plain");
    sds response = sdsempty();

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
