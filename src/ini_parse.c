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
		endpoint_cfg->error_parsing = false;
		shput(*config_hash, current_section, endpoint_cfg);
	}
	
	if(strcmp(name, "function") == 0) {
		endpoint_cfg->function = strdup(value);
	}
	else {
		
		url_params url_params;
		url_params.name = strdup(name);
		
		switch(*value) {
			case 's':
				url_params.type = STRING;
				break;
			case 'i':
				url_params.type = INT;
				break;
			case 'f':
				url_params.type = FLOAT;
				break;
			default: 
				endpoint_cfg->error_parsing = true;
				fprintf(stderr, "Invalid parameter type %s\n", value);
				break;
		}				

		arrput(endpoint_cfg->params, url_params);
	}

	return 1;
}
