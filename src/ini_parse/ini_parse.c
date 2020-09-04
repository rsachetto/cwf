#include "ini_parse.h"

#include <stdlib.h>
#include <string.h>

#include "../3dparty/stb/stb_ds.h"
#include "../cwf/cwf.h"

int parse_site_configuration(void* user, const char* section, const char* name, const char* value) {
    cwf_vars* config = (cwf_vars*)user;

    if(strncmp(section, "site_config", 11) == 0) {
        if(strncmp(name, "database_path", 13) == 0) {
            config->database_path = strdup(value);
        } else if(strncmp(name, "endpoints_config_path", 21) == 0) {
            config->endpoints_config_path = strdup(value);
        } else if(strncmp(name, "endpoints_lib_path", 18) == 0) {
            config->endpoints_lib_path = strdup(value);
        } else if(strncmp(name, "session_files_path", 18) == 0) {
            config->session_files_path = strdup(value);
		} else if(strncmp(name, "templates_path", 14) == 0) {
			free(config->templates_path);
            config->templates_path = strdup(value);
        } else if(strncmp(name, "print_debug_info", 16) == 0) {
            if(strncasecmp(value, "yes", 3) == 0 || strncasecmp(value, "true", 4) == 0 || strncmp(value, "1", 1) == 0) {
                config->print_debug_info = true;
            } else {
                config->print_debug_info = false;
            }
        } else {
            // TODO: handle errors
        }
    }

    return 1;
}

int parse_endpoint_configuration(void* user, const char* section, const char* name, const char* value) {
    endpoint_config_item** config_hash = (endpoint_config_item**)user;

    static char* current_section = NULL;

    if(current_section == NULL) {
        current_section = strdup(section);
    } else if(strcmp(section, current_section) != 0) {
        free(current_section);
        current_section = strdup(section);
    }

    endpoint_config* endpoint_cfg = shget(*config_hash, current_section);

    if(!endpoint_cfg) {
        endpoint_cfg = new_endpoint_config();
        shput(*config_hash, current_section, endpoint_cfg);
    }

    if(strcmp(name, "function") == 0) {
        endpoint_cfg->function = strdup(value);
    } else {
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
                url_params.type = INVALID;
                break;
        }

        arrput(endpoint_cfg->params, url_params);
    }

    return 1;
}
