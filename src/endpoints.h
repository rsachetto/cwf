#ifndef __ENDPOINTS_H
#define __ENDPOINTS_H 

#include "cwf.h"
#include <stdlib.h>
#include <stdio.h>


#define ENDPOINT_LIB_PATH "/home/sachetto/cwf/libendpoints.so"
#define ENDPOINT(name) int name(request *request, endpoint_config *config)
typedef ENDPOINT(endpoint_fn);

#endif /* __ENDPOINTS_H */
