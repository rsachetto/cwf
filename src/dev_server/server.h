#ifndef __SERVER_H
#define __SERVER_H

#include <stdbool.h>

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

#define BYTES 1024

struct mime_type {
    char *key;   // file extension
    char *value; // mime-type
};

static const char *get_filename_ext(const char *filename) {
    const char *dot = strrchr(filename, '.');
    if(!dot || dot == filename)
        return "";
    return dot + 1;
}

static void load_mime_types(struct mime_type **mime_types) {
    int ext_number;
    shdefault(*mime_types, NULL);
    sh_new_arena(*mime_types);

    for(int i = 0; i < NUM_MIME_TYPES; i++) {
        sds *extensions = sdssplitlen(mime_types_raw[i][1], sizeof(mime_types_raw[i][1]), " ", 1, &ext_number);
        for(int j = 0; j < ext_number; j++) {
            shput(*mime_types, extensions[j], mime_types_raw[i][0]);
        }
        sdsfreesplitres(extensions, ext_number);
    }
}

static int server_read(void *sock, void *buf, int bytes, bool ssl_enabled) {
    if(ssl_enabled) {
        SSL *ssl_sock = (SSL *)sock;
        return SSL_read(ssl_sock, buf, bytes);
    } else {
        int socket = *((int *)sock);
        return read(socket, buf, bytes);
    }
}

static int server_write(void *sock, void *buf, int bytes, bool ssl_enabled) {
    if(ssl_enabled) {
        SSL *ssl_sock = (SSL *)sock;
        return SSL_write(ssl_sock, buf, bytes);
    } else {
        int socket = *((int *)sock);
        return send(socket, buf, bytes, MSG_NOSIGNAL);
    }
}

void start_server(int port);
void respond(int, bool, bool);

#endif /* __SERVER_H */
