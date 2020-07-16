#include <stdio.h>
#include <ctype.h>
#include "src/cwf.h"

int main(int argc, char **argv) {

	request *req = new_from_env_vars();
	render_template(req, "/home/sachetto/cwf/template.tmpl");

    return 0;
}

