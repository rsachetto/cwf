#ifdef ENABLE_BACKTRACE
#define _GNU_SOURCE
#endif

#include <dlfcn.h>
#include <stdio.h>
#include <string.h>

#include "cwf/cwf.h"
#include "ini_parse/ini_parse.h"

// TODO enable support for multiple applications in a single site.
// this can be achieved by creating a site.ini file that configure the endpoints
// and merging all endpoints in a single library

// TODO add CSRF protection - https://owasp.org/www-community/attacks/csrf
// https://codefellows.github.io/sea-python-401d4/lectures/pyramid_day6_csrf.html

// TODO: add a stack trace on segfaults... https://stackoverflow.com/questions/2663456/how-to-write-a-signal-handler-to-catch-sigsegv
// TODO: https://www.gnu.org/software/libc/manual/html_node/Backtraces.html

// TODO: add a sql function with prepared statments. https://stackoverflow.com/questions/9804371/syntax-and-sample-usage-of-generic-in-c11 and
// https://www.tutorialspoint.com/cprogramming/c_variable_arguments.htm

// TODO: test internacionalization features
// https://kirste.userpage.fu-berlin.de/chemnet/use/info/libc/libc_19.html
// Maybe use gettext - https://man7.org/linux/man-pages/man3/gettext.3.html

/* Obtain a backtrace and print it to stdout. */

#ifdef ENABLE_BACKTRACE
#define HAVE_ADDR2LINE

/* Bug in gcc prevents from using CPP_DEMANGLE in pure "C" */
#if !defined(__cplusplus) && !defined(NO_CPP_DEMANGLE)
#define NO_CPP_DEMANGLE
#endif

#include <memory.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>

#ifndef NO_CPP_DEMANGLE
#include <cxxabi.h>
#ifdef __cplusplus
using __cxxabiv1::__cxa_demangle;
#endif
#endif

#include <ucontext.h>
#include <execinfo.h>

void dump_backtrace() {
  Dl_info mdlinfo;
  char syscom[256];
  int f = 0;
  char funcname[1024];
  char fileline[1024];
  int status;

  void *_bt[100];
  void **bt = (void **)_bt;
  int sz = backtrace(bt, 100);
  // skip i = 0 since it is this dump_backtrace function
  for(int i = 1; i < sz; ++i) {
    if(!dladdr(bt[i], &mdlinfo)) break;
    if (mdlinfo.dli_saddr == NULL) continue;

    const char *symname = mdlinfo.dli_sname;

#ifndef NO_CPP_DEMANGLE
    char * tmp = __cxa_demangle(symname, NULL, 0, &status);

    if (status == 0 && tmp) symname = tmp;
#endif

#ifdef HAVE_ADDR2LINE
    sprintf(syscom, "addr2line --demangle --basenames --functions -e %s %p", mdlinfo.dli_fname, mdlinfo.dli_saddr - mdlinfo.dli_fbase + bt[i]-mdlinfo.dli_saddr);
    FILE *cmd = popen(syscom, "r");
    int num = fscanf(cmd, "%s\n%s\n", funcname, fileline);
    status = pclose(cmd);
    if (num == EOF || WIFEXITED(status)) {
      status = WEXITSTATUS(status);
    }
    if (status == 0 && strcmp(funcname, "??") != 0) {
      symname = funcname;
    }
    else {
      sprintf(fileline, "in %s", mdlinfo.dli_fname);
    }
#else
    sprintf(fileline, "in %s", mdlinfo.dli_fname);
#endif

    if (++f == 1) {
      fprintf(stderr, "   at");
    }
    else {
      fprintf(stderr, "   by");
    }

    fprintf(stderr, " %p: %s (%s)\n", mdlinfo.dli_saddr, symname, fileline);


#ifndef NO_CPP_DEMANGLE
    if (tmp) free(tmp);
#endif

    if(mdlinfo.dli_sname && !strcmp(mdlinfo.dli_sname, "main")) break;

  }
}

static void signal_segv(int signum, siginfo_t* info, void* ptr) {
  signal(SIGSEGV, SIG_DFL);

  fprintf(stderr, "\033[1;31m");


  static const char *si_codes[3] = {"", "SEGV_MAPERR", "SEGV_ACCERR"};
  static const char *si_message[3] = {"", "Address not mapped", "Invalid permissions"};
  fprintf(stderr, "Segmentation Fault!\n\n");

  fprintf(stderr, "%s\n", si_message[info->si_code]);

  dump_backtrace();

  char msg[256];
  sprintf(msg, " Address %p cannot be accessed", info->si_addr);
  if (info->si_errno != 0) perror(msg);
  else fprintf(stderr, "%s\n\n\n", msg);
  //_exit (-1);
//   avoid unused warning
  signum = 0; ptr = NULL;

  fprintf(stderr, "\033[0m;");

}

void setup_sigsegv() {
  struct sigaction action;
  memset(&action, 0, sizeof(action));
  action.sa_sigaction = signal_segv;
  action.sa_flags = SA_SIGINFO;
  if(sigaction(SIGSEGV, &action, NULL) < 0)
    perror("sigaction");
}
#endif

#ifdef DEBUG_CGI
static void wait_for_gdb_to_attach() {
    int is_waiting = 1;
    while(is_waiting) {
        sleep(1); // sleep for 1 second
    }
}
#endif

int main(int argc, char **argv) {
#ifdef DEBUG_CGI
    wait_for_gdb_to_attach();
#endif

#ifdef ENABLE_BACKTRACE
    struct sigaction action;
    memset(&action, 0, sizeof(action));
    action.sa_sigaction = signal_segv;
    action.sa_flags = SA_SIGINFO;
    if(sigaction(SIGSEGV, &action, NULL) < 0)
        perror("sigaction");
#endif
    cwf_vars *cwf_vars = calloc(1, sizeof(struct cwf_vars_t));

    cwf_vars->request = new_from_env_vars();

    char *root = SERVER("DOCUMENT_ROOT");

    endpoint_config_item *endpoint_configs = NULL;

    if(root) {
        cwf_vars->document_root = root;
    } else {
        cwf_vars->document_root = getenv("PWD");
    }

    cwf_vars->templates_path = strdup(cwf_vars->document_root);

    sds site_config_file = sdsnew(cwf_vars->document_root);

    site_config_file = sdscat(site_config_file, "site_config.ini");

    bool error_found = false;
    sds response = NULL;

    if(ini_parse(site_config_file, parse_site_configuration, (void *)cwf_vars) < 0) {
        response = simple_404_page(cwf_vars, "Error parsing ini file %s<br/>", site_config_file);
        error_found = true;
    }

    endpoint_fn *endpoint_function = NULL;

    if(!error_found) {
        void *handle = dlopen(cwf_vars->endpoints_lib_path, RTLD_LAZY);

        if(!handle) {
            response = simple_404_page(cwf_vars, "%s<br/>", dlerror());
            error_found = true;
        }

        endpoint_configs = new_endpoint_config_hash();

        if(ini_parse(cwf_vars->endpoints_config_path, parse_endpoint_configuration, (void *)&endpoint_configs) < 0) {
            if(!error_found) {
                response = simple_404_page(cwf_vars, "Error parsing ini file %s<br/>", cwf_vars->endpoints_config_path);
                error_found = true;
            }
        }

        char *uri = SERVER("REQUEST_URI");
        char *query_string = SERVER("QUERY_STRING");

        endpoint_config *endpoint_config = get_endpoint_config(uri, query_string, endpoint_configs);

        char *endpoint_name = NULL;

        if(endpoint_config)
            endpoint_name = endpoint_config->function;

        if(endpoint_name) {
            endpoint_function = dlsym(handle, endpoint_name);
            char *error = dlerror();

            if(error != NULL) {
                if(!error_found) {
                    response = simple_404_page(cwf_vars, "\n%s function not found in the provided in library %s. Error from dlsym %s\n", endpoint_name,
                                               cwf_vars->endpoints_lib_path, error);
                    error_found = true;
                }
            } else {
                if(endpoint_config->params) {
                    if(!endpoint_config->error) {
                        add_params_to_request(cwf_vars->request, endpoint_config->params);
                    } else {
                        if(!error_found) {
                            response = simple_404_page(cwf_vars,
                                                       "<h1>Error parsing parameters for endpoint [%s] with URL %s</h1><h2 "
                                                       "style=\"color:red;\">%s</h2> ",
                                                       endpoint_name, SERVER("REQUEST_URI"), endpoint_config->error);
                            error_found = true;
                        }
                    }
                }
            }
        } else {
            if(!error_found) {
                response = simple_404_page(cwf_vars, "No configured endpoint for the provided URL %s<br/> Check your endpoints config file (%s)",
                                           SERVER("REQUEST_URI"), cwf_vars->endpoints_config_path);
                error_found = true;
            }
        }
    }

    if(endpoint_function && !error_found)
        response = endpoint_function(cwf_vars, NULL);

    write_http_headers(cwf_vars->headers);

    if(response) {
        fprintf(stdout, "%s", response);
        fflush(stdout);
        sdsfree(response);
    }

    cwf_save_session(cwf_vars->session);
    sdsfree(site_config_file);
    free_cwf_vars(cwf_vars);

    if(endpoint_configs)
        free_endpoint_config_hash(endpoint_configs);

    // TODO maybe we will also need to release the file locks if the section is not readonly
    return 0;
}

