#include <stdio.h>
#include "3dparty/ccgi-1.2/ccgi.h"

int main(int argc, char **argv) {
    CGI_varlist *varlist;
    const char *name;
    CGI_value  *value;
    int i;

    fputs("Content-type: text/plain\r\n\r\n", stdout);
    if ((varlist = CGI_get_all(0)) == 0) {
        printf("No CGI data received\r\n");
        return 0;
    }

    /* output all values of all variables and cookies */

    for (name = CGI_first_name(varlist); name != 0;
        name = CGI_next_name(varlist))
    {
        value = CGI_lookup_all(varlist, 0);

        /* CGI_lookup_all(varlist, name) could also be used */

        for (i = 0; value[i] != 0; i++) {
            printf("%s [%d] = %s\r\n", name, i, value[i]);
        }
    }
    CGI_free_varlist(varlist);  /* free variable list */
    return 0;
}


