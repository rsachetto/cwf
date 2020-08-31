#ifndef __INI_PARSE_H
#define __INI_PARSE_H 

#include "../3dparty/ini/ini.h"

int parse_endpoint_configuration(void* user, const char* section, const char* name, const char* value);
int parse_site_configuration(void* user, const char* section, const char* name, const char* value);

#endif /* __INI_PARSE_H */
