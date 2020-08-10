#include "cwf.h"
#include "ini_parse.h"
#include "3dparty/stb/stb_ds.h"
#include <string.h>
#include <stdlib.h>


int parse_endpoint_configuration(void* user, const char* section, const char* name, const char* value) {

	endpoint_config_item **config_hash = (endpoint_config_item**)user;

	static char *current_section = NULL;

	if(current_section == NULL) {
		current_section = strdup(section);
	}
	else if(strcmp(section, current_section) != 0) {
		free(current_section);
		current_section = strdup(section);
	}

	endpoint_config *endpoint_cfg = shget(*config_hash, current_section);

	if(!endpoint_cfg) {
		endpoint_cfg = new_endpoint_config();
		shput(*config_hash, current_section, endpoint_cfg);
	}
	
	if(strcmp(name, "function") == 0) {
		endpoint_cfg->function = strdup(value);
	}
	if(strcmp(name, "url_template") == 0) {
		endpoint_cfg->url_template = strdup(value);
	}

	return 1;
}
