#ifndef __SERVER_H
#define __SERVER_H

#include <stdbool.h>
#include <unistd.h>
#include <sys/socket.h>

#include "mimetypes.h"
#include "ssl_helper.h"
#include "../3dparty/sds/sds.h"

#define STB_DS_IMPLEMENTATION
#include "../3dparty/stb/stb_ds.h"

#define VERSION "0.1"
#define SERVER_SOFTWARE "CWF Development server (" VERSION ")"

#define SERVER_PROTOCOL "HTTP/1.0"
#define HEADER_OK SERVER_PROTOCOL " 200 OK"
#define HEADER_NOT_FOUND SERVER_PROTOCOL " 404 Not Found"
#define HEADER_BAD_REQUEST SERVER_PROTOCOL " 400 Bad Request"
#define HEADER_INTERNAL_SERVER_ERROR SERVER_PROTOCOL " 500 Internal Server Error"
#define HEADER_REDIRECT SERVER_PROTOCOL " 302 Found"

#define MAX_BUFFER_SIZE 1024

struct mime_type {
    char *key;   // file extension
    char *value; // mime-type
};

#endif /* __SERVER_H */
