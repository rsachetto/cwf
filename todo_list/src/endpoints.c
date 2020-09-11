#include <string.h>
#include <time.h>

#include "../../src/3dparty/ctemplate-1.0/ctemplate.h"
#include "../../src/3dparty/stb/stb_ds.h"
#include "../../src/cwf/cwf.h"

#include <sys/time.h>

#define IF_TRUE_REDIRECT_TO(condition, url)                                                                                                                    \
    if(condition) {                                                                                                                                            \
        redirect((url));                                                                                                                                       \
    }

#define IS_LOGGED_IN() (SESSION_GET("auth") != NULL) ? true : false

#define IF_LOGGED_IN_REDIRECT_TO(url)                                                                                                                          \
    do {                                                                                                                                                       \
        bool logged_in = IS_LOGGED_IN();                                                                                                                       \
        IF_TRUE_REDIRECT_TO(logged_in, (url));                                                                                                                 \
    } while(0)

#define IF_NOT_LOGGED_IN_REDIRECT_TO(url)                                                                                                                      \
    do {                                                                                                                                                       \
        bool logged_in = IS_LOGGED_IN();                                                                                                                       \
        IF_TRUE_REDIRECT_TO(!logged_in, (url));                                                                                                                \
    } while(0)

ENDPOINT(todo) {
    open_database_or_return_404();

    session_start_with_expiration_date(2 * 24 * 60 * 60);

    IF_NOT_LOGGED_IN_REDIRECT_TO("/");

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

            redirect("/todo");

        } else if(POST("taskDelete")) {
            string_array checkedlist = POST_ARRAY("checkedbox");
            int num_ids = arrlen(checkedlist);
            sds query = sdsempty();

            if(num_ids > 0) {
                sds ids_list = sdsjoin(checkedlist, num_ids, ", ");
                query = sdscatfmt(query, "DELETE FROM todolist_todolist where id in (%s);", ids_list);
                execute_query_or_return_404(query);
                sdsfree(query);
            }

            redirect("/todo");
        }
    }

    execute_query_or_return_404("SELECT * FROM todolist_category ORDER BY name ASC;");

    TMPL_varlist *varlist = 0;
    varlist = db_records_to_loop(varlist, "categories", NULL);

    execute_query_or_return_404("SELECT todolist_todolist.id, todolist_todolist.title, todolist_todolist.created, "
                                "todolist_todolist.due_date, "
                                "todolist_category.name FROM todolist_todolist LEFT JOIN todolist_category ON "
                                "todolist_todolist.category_id = "
                                "todolist_category.id;");

    varlist = db_records_to_loop(varlist, "todos", NULL);

    varlist = TMPL_add_var(varlist, "username", SESSION_GET("username"));

    sds template_path = sdsnew(cwf_vars->templates_path);
    template_path = sdscat(template_path, "todo.tmpl");

    // The varlist is freed in the render_template function
    sds response = render_template(varlist, template_path);

    sdsfree(template_path);

    close_database();

    return response;
}

ENDPOINT(login) {

    sds response;

    session_start();

    if(IS_POST()) {
        char *username = POST("username");
        char *password = POST("password");

        if(STRINGS_MATCH(username, "cwf") && STRINGS_MATCH(password, "cwf")) {
            SESSION_PUT("auth", "y");
            SESSION_PUT("username", username);
            redirect("/todo");
        } else {
            redirect("/?login_error=y");
        }

    } else {

        IF_LOGGED_IN_REDIRECT_TO("/todo");

        TMPL_varlist *varlist = 0;
        varlist = request_to_varlist(varlist, NULL);

        sds template_path = sdsnew(cwf_vars->templates_path);
        template_path = sdscat(template_path, "index.tmpl");
        response = render_template(varlist, template_path);
        sdsfree(template_path);
        return response;
    }
}

ENDPOINT(logout) {
    LOGOUT_AND_REDIRECT("/");
}
