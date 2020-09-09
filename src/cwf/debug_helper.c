//
// Created by sachetto on 08/09/2020.
//

#include "debug_helper.h"

#include <stddef.h>       
#include <unistd.h>

#ifdef DEBUG_CGI
static void wait_for_gdb_to_attach() {
    int is_waiting = 1;
    while(is_waiting) {
        sleep(1); 
    }
}
#endif

static void dump_backtrace() {

#ifdef DEBUG_CGI
    wait_for_gdb_to_attach();
#endif

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
        if(!dladdr(bt[i], &mdlinfo))
            break;
        if(mdlinfo.dli_saddr == NULL)
            continue;

        const char *symname = mdlinfo.dli_sname;

#ifndef NO_CPP_DEMANGLE
        char *tmp = __cxa_demangle(symname, NULL, 0, &status);
        if(status == 0 && tmp)
            symname = tmp;
#endif

#ifdef HAVE_ADDR2LINE
		ptrdiff_t real_addr = bt[i] - mdlinfo.dli_fbase;
        sprintf(syscom, "addr2line --demangle --basenames --functions -e %s %lx", mdlinfo.dli_fname, real_addr);
        FILE *cmd = popen(syscom, "r");
        int num = fscanf(cmd, "%s\n%s\n", funcname, fileline);
        status = pclose(cmd);
        if(num == EOF || WIFEXITED(status)) {
            status = WEXITSTATUS(status);
        }

        if(status == 0 && strcmp(funcname, "??") != 0 && strcmp(fileline, "??:?")) {
            symname = funcname;
        } else {
            sprintf(fileline, "in %s", mdlinfo.dli_fname);
        }
#else
        sprintf(fileline, "in %s", mdlinfo.dli_fname);
#endif

        if(++f == 1) {
            fprintf(stderr, "   at");
        } else {
            fprintf(stderr, "   by");
        }

        fprintf(stderr, " %p: %s (%s)\n", mdlinfo.dli_saddr, symname, fileline);

#ifndef NO_CPP_DEMANGLE
        if(tmp)
            free(tmp);
#endif

        if(mdlinfo.dli_sname && !strcmp(mdlinfo.dli_sname, "main"))
            break;
    }
}

static void signal_segv(int signum, siginfo_t *info, void *ptr) {
    signal(SIGSEGV, SIG_DFL);

    fprintf(stderr, "\033[1;31m");

    static const char *si_codes[3] = {"", "SEGV_MAPERR", "SEGV_ACCERR"};
    static const char *si_message[3] = {"", "Address not mapped", "Invalid permissions"};
    fprintf(stderr, "Segmentation Fault!\n\n");

    fprintf(stderr, "%s\n", si_message[info->si_code]);

    dump_backtrace();

    char msg[256];
    sprintf(msg, " Address %p cannot be accessed", info->si_addr);
    if(info->si_errno != 0)
        perror(msg);
    else
        fprintf(stderr, "%s\n\n\n", msg);
    //_exit (-1);
    //   avoid unused warning
    signum = 0;
    ptr = NULL;

    fprintf(stderr, "\033[0m");
}

void setup_sigsegv() {
    struct sigaction action;
    memset(&action, 0, sizeof(action));
    action.sa_sigaction = signal_segv;
    action.sa_flags = SA_SIGINFO;
    if(sigaction(SIGSEGV, &action, NULL) < 0)
        perror("sigaction");
}
