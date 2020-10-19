//
// Created by sachetto on 19/10/2020.
//

#ifndef CWF_CWF_MACROS_H
#define CWF_CWF_MACROS_H

#define IS_REQ_GET(request) request->method ? (strcmp(request->method, "GET") == 0) : false
#define IS_REQ_POST(request) request->method ? (strcmp(request->method, "POST") == 0) : false

#define IS_GET() IS_REQ_GET(cwf_vars->request)
#define IS_POST() IS_REQ_POST(cwf_vars->request)

#define header(key, value) add_custom_header((key), (value), &(cwf_vars->headers))
#define session_start() cwf_session_start(&(cwf_vars->session), &(cwf_vars->headers), cwf_vars->session_files_path, 31536000) // 1 year
#define session_start_with_expiration_date(expiration_date)                                                                                                    \
    cwf_session_start(&(cwf_vars->session), &(cwf_vars->headers), cwf_vars->session_files_path, (expiration_date))

#define session_destroy() cwf_session_destroy(&(cwf_vars->session), &(cwf_vars->headers))
#define SESSION_GET(key) cwf_session_get(cwf_vars->session, (key))
#define SESSION_PUT(key, value) cwf_session_put(cwf_vars->session, (key), (value))

#define generate_default_404_header() cwf_generate_default_404_header(&(cwf_vars->headers))

#define redirect(url)                                                                                                                                          \
    do {                                                                                                                                                       \
        cwf_redirect((url), &(cwf_vars->headers));                                                                                                             \
        return NULL;                                                                                                                                           \
    } while(0)

#define generate_simple_404(format, ...) simple_404_page(cwf_vars, format, __VA_ARGS__)

#define SERVER(key) cwf_server_vars(cwf_vars->request, (key))

#define GET(key) cwf_get_vars(cwf_vars->request, (key)) ? cwf_get_vars(cwf_vars->request, (key))[0] : NULL
#define GET_ARRAY(key) cwf_get_vars(cwf_vars->request, (key))

#define POST(key) cwf_post_vars(cwf_vars->request, (key)) ? cwf_post_vars(cwf_vars->request, (key))[0] : NULL
#define POST_ARRAY(key) cwf_post_vars(cwf_vars->request, (key))

#define DUMP_REQUEST_VARS()                                                                                                                                    \
    do {                                                                                                                                                       \
        generate_default_404_header();                                                                                                                         \
        return cwf_dump_request_vars(cwf_vars->request);                                                                                                       \
    } while(0)

#define render_template(varlist, filename) cwf_render_template((varlist), (filename), cwf_vars)

#define request_to_varlist(varlist, modify_fn) varlist = cwf_request_to_varlist((varlist), (modify_fn), cwf_vars->request)

#define db_record_to_varlist(varlist, query_result, modify) varlist = cwf_db_record_to_varlist((varlist), query_result, (modify))

#define db_records_to_loop(varlist, query_result, loop_name, modify) (varlist) = cwf_db_records_to_loop((varlist), (query_result), (loop_name), (modify))

#define db_records_to_simple_json(query_result) cwf_db_records_to_simple_json((query_result))

#define get_column_value_from_line(query_result, index, name) shget(query_result->result_array[(index)], name)

#define last_insert_rowid() sqlite3_last_insert_rowid(cwf_vars->database->db)

#define new_query(format, ...) sdscatprintf(sdsempty(), format, __VA_ARGS__)

#define begin_transaction() cwf_begin_transaction(cwf_vars)
#define commit_transaction() cwf_commit_transaction(cwf_vars)
#define rollback_transaction() cwf_rollback_transaction(cwf_vars)

#define open_database() cwf_open_database(cwf_vars)
#define open_database_or_return_404()                                                                                                                          \
    do {                                                                                                                                                       \
        open_database();                                                                                                                                       \
        if(cwf_vars->database->error) {                                                                                                                        \
            return generate_simple_404("Database error: %s", cwf_vars->database->error);                                                                       \
        }                                                                                                                                                      \
    } while(0)

#define close_database() cwf_close_database(cwf_vars);

#define execute_query(result, query)                                                                                                                           \
    do {                                                                                                                                                       \
        (result) = cwf_execute_query((query), cwf_vars->database);                                                                                             \
        if(cwf_vars->database->error) {                                                                                                                        \
            LOG_ERROR("Error while executing query %s in %s - %d: %s\n", query, __FILE__, __LINE__, cwf_vars->database->error);                                \
        }                                                                                                                                                      \
    } while(0)

#define execute_query_or_return_404(result, query)                                                                                                             \
    do {                                                                                                                                                       \
        execute_query((result), (query));                                                                                                                      \
        if(cwf_vars->database->error) {                                                                                                                        \
            return generate_simple_404("Database error: %s", cwf_vars->database->error);                                                                       \
        }                                                                                                                                                      \
    } while(0)

#define LOGOUT()                                                                                                                                               \
    do {                                                                                                                                                       \
        session_start();                                                                                                                                       \
        session_destroy();                                                                                                                                     \
    } while(0)

#define LOGOUT_AND_REDIRECT(redirect_url)                                                                                                                      \
    do {                                                                                                                                                       \
        LOGOUT();                                                                                                                                              \
        redirect((redirect_url));                                                                                                                              \
    } while(0)

#define add_to_template_varlist(varlist, name, value) varlist = TMPL_add_var(varlist, name, value, 0)
#define add_float_to_template_varlist(varlist, name, value) varlist = TMPL_add_float_var(varlist, name, value)
#define add_double_to_template_varlist(varlist, name, value) varlist = TMPL_add_double_var(varlist, name, value)
#define add_int_to_template_varlist(varlist, name, value) varlist = TMPL_add_int_var(varlist, name, value)

#endif // CWF_CWF_MACROS_H
