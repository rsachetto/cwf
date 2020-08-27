#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "../src/3dparty/ctemplate-1.0/ctemplate.h"
#include "../src/3dparty/stb/stb_ds.h"
#include "../src/cwf.h"

ENDPOINT(todo) {

    //@todo provide a helper function to handle all this crap
    cfw_database *database = open_database("/var/www/cwf/database.sqlite");

    if(database->error) {
        return generate_simple_404("Database error: %s", database->error);
    }
    
	sds response = sdsempty();

    if(IS_POST()) {
        if(POST("taskAdd")) {
            char *title = POST("description");
            char *date = POST("date");
            char *category = POST("category_select");

            char created[64];
            time_t now = time(NULL);
            struct tm tm = *gmtime(&now);
            strftime(created, sizeof(created), "%Y-%m-%d", &tm);

            sds query = sdscatfmt(sdsempty(),
                                  "INSERT INTO todolist_todolist (title, due_date, created, category_id, content) "
                                  "VALUES('%s', '%s', '%s', '%s', 'Not used')",
                                  title, date, created, category);

            execute_query(query, database);

            if(database->error) {
                return generate_simple_404("Database error: %s", database->error);
            }

            sdsfree(query);
            redirect("/");
        }

        else if(POST("taskDelete")) {
            string_array checkedlist = POST_ARRAY("checkedbox");

            for(int i = 0; i < arrlen(checkedlist); i++) {
                sds query = sdscatfmt(sdsempty(), "DELETE FROM todolist_todolist where id=%s;", checkedlist[i]);

                execute_query(query, database);

                if(database->error) {
                    return generate_simple_404("Database error: %s", database->error);
                }

                sdsfree(query);
            }
            redirect("/");
        }
    }
    execute_query("SELECT * FROM todolist_category ORDER BY name ASC; ", database);

    if(database->error) {
        return generate_simple_404("Database error: %s", database->error);
    }

    TMPL_varlist *varlist = 0;
    varlist = db_records_to_loop(varlist, database, "categories", NULL);

    execute_query(
        "SELECT todolist_todolist.id, todolist_todolist.title, todolist_todolist.created, "
        "todolist_todolist.due_date, "
        "todolist_category.name FROM todolist_todolist LEFT JOIN todolist_category ON "
        "todolist_todolist.category_id = "
        "todolist_category.id;",
        database);

    if(database->error) {
        return generate_simple_404("Database error: %s", database->error);
    }

    varlist = db_records_to_loop(varlist, database, "todos", NULL);

    return render_template(varlist, "/var/www/cwf/todo_index.tmpl");
}

