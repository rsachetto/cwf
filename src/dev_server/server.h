#ifndef __SERVER_H
#define __SERVER_H

#include <stdbool.h>
#include <sys/socket.h>
#include <unistd.h>
#include <sys/stat.h>

#include "../3dparty/sds/sds.h"
#include "mimetypes.h"
#include "ssl_helper.h"

#define STB_DS_IMPLEMENTATION
#include "../3dparty/stb/stb_ds.h"

#define VERSION "0.1"
#define SERVER_SOFTWARE "CWF Development server (" VERSION ")"

#define SERVER_PROTOCOL "HTTP/1.0"
#define HEADER_OK SERVER_PROTOCOL " 200 OK"
#define HEADER_UNAUTHORIZED SERVER_PROTOCOL " 401 Unauthorized"
#define HEADER_NOT_FOUND SERVER_PROTOCOL " 404 Not Found"
#define HEADER_BAD_REQUEST SERVER_PROTOCOL " 400 Bad Request"
#define HEADER_INTERNAL_SERVER_ERROR SERVER_PROTOCOL " 500 Internal Server Error"
#define HEADER_REDIRECT SERVER_PROTOCOL " 302 Found"

#define MAX_BUFFER_SIZE 1024

#define MAX_EVENTS 1024  /* Maximum number of events to process*/
#define LEN_NAME 1024  /* Assuming that the length of the filename won't exceed 1024 bytes*/
#define EVENT_SIZE  ( sizeof (struct inotify_event) ) /*size of one event*/
#define BUF_LEN     ( MAX_EVENTS * ( EVENT_SIZE + LEN_NAME )) /*buffer to store the data of events*/

struct static_file {
    size_t real_size;
    struct stat st;
    char *data;
};

struct watch_entry {
    int key;
    char *value;
};

struct cache_entry {
	char *key;
	struct static_file value;
};

typedef struct cache_entry * file_cache;
typedef struct watch_entry * notify_entries_t;

struct mime_type {
    char *key;   // file extension
    char *value; // mime-type
};

#endif /* __SERVER_H */
