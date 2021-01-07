#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/mman.h>
#include<sys/inotify.h>
#include <dirent.h>

#include "server.h"

// TODO: change this to parameters??
char *ROOT;
sds cert_file, key_file;
int listener;
struct mime_type *mime_types;
static char *response_header_returned = NULL;
struct static_file file_not_in_cache = (struct static_file){-1, {0}, 0};

file_cache cache = NULL;
notify_entries_t notify_entries = NULL;

pthread_mutex_t lock;

static const char *get_filename_ext(const char *filename) {
    const char *dot = strrchr(filename, '.'); // Return the last ocurrency of the .
    if(!dot || dot == filename) {
        return "";
    }
    return dot + 1;
}

static void load_mime_types(struct mime_type **mime_types_hash) {
    int ext_number;
    shdefault(*mime_types_hash, NULL);
    sh_new_arena(*mime_types_hash);

    for(int i = 0; i < NUM_MIME_TYPES; i++) {
        sds *extensions = sdssplitlen(mime_types_raw[i][1], sizeof(mime_types_raw[i][1]), " ", 1, &ext_number);
        for(int j = 0; j < ext_number; j++) {
            shput(*mime_types_hash, extensions[j], mime_types_raw[i][0]);
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

static void send_header(void *socket, const char *header, bool last, bool ssl_enabled) {

    if(ssl_enabled) {
        SSL *sc = (SSL *)socket;
        SSL_write(sc, header, strlen(header));
        SSL_write(sc, "\r\n", 2);

        if(last) {
            SSL_write(sc, "\r\n", 2);
        }
    } else {
        int sc = *((int *)socket);
        send(sc, header, strlen(header), MSG_NOSIGNAL);
        send(sc, "\r\n", 2, MSG_NOSIGNAL);

        if(last) {
            send(sc, "\r\n", 2, MSG_NOSIGNAL);
        }
    }
}

static void start_server(int port) {
    int yes = 1;
    struct sockaddr_in serveraddr;

    if((listener = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        perror("socket() error!");
        exit(1);
    }

    if(setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1) {
        perror("setsockopt() error!");
        exit(1);
    }

    /* bind */
    serveraddr.sin_family = AF_INET;
    serveraddr.sin_addr.s_addr = INADDR_ANY;
    serveraddr.sin_port = htons(port);
    memset(&(serveraddr.sin_zero), '\0', 8);

    if(bind(listener, (struct sockaddr *)&serveraddr, sizeof(serveraddr)) == -1) {
        perror("bind() error!");
        exit(1);
    }

    /* listen */
    if(listen(listener, 4096) == -1) {
        perror("listen() error!");
        exit(1);
    }
}

static void execute_cgi(void *socket, sds *request_headers, sds request_content, int num_headers, bool https, bool verbose) {

// Macros for reading and writing in the child pipe
#define PARENT_READ readpipe[0]
#define CHILD_WRITE readpipe[1]

#define CHILD_READ writepipe[0]
#define PARENT_WRITE writepipe[1]

    int writepipe[2] = {-1, -1}, /* parent -> child */
        readpipe[2] = {-1, -1};  /* child -> parent */

    pid_t childpid;

    if(pipe(readpipe) < 0 || pipe(writepipe) < 0) {
        perror("pipe");
        exit(1);
    }

    int method_uri_version_count;
    sds *method_uri_version = sdssplitlen(request_headers[0], sdslen(request_headers[0]), " ", 1, &method_uri_version_count);

    char *method = method_uri_version[0];
    char *uri = method_uri_version[1];

    setenv("REQUEST_METHOD", method, 1);
    setenv("REQUEST_URI", uri, 1);
    setenv("SERVER_PROTOCOL", SERVER_PROTOCOL, 1);
    if(https) {
        setenv("REQUEST_SCHEME", "https", 1);
    } else {
        setenv("REQUEST_SCHEME", "http", 1);
    }
    setenv("DOCUMENT_ROOT", ROOT, 1);

    setenv("SERVER_SOFTWARE", SERVER_SOFTWARE, 1);

    char *question_mark = strchr(uri, '?');

    if(question_mark) {
        char *query_string = strndup(question_mark + 1, strlen(uri) - (size_t)question_mark);
        setenv("QUERY_STRING", query_string, 1);
        free(query_string);
    } else {
        setenv("QUERY_STRING", "", 1);
    }

    for(int i = 0; i < num_headers; i++) {
        if(*request_headers[i]) {
            int pair_count;
            sds *key_value = sdssplitlen(request_headers[i], sdslen(request_headers[i]), ": ", 2, &pair_count);
            char *header_name = key_value[0];
            char *header_value = key_value[1];

            if(strncasecmp(header_name, "Content-Length", 15) == 0) {
                setenv("CONTENT_LENGTH", header_value, 1);
            } else if(strncasecmp(header_name, "Content-Type", 12) == 0) {
                setenv("CONTENT_TYPE", header_value, 1);
            } else if(strncasecmp(header_name, "Cookie", 6) == 0) {
                setenv("HTTP_COOKIE", header_value, 1);
            } else if(strncasecmp(header_name, "Accept", 6) == 0) {
                setenv("HTTP_ACCEPT", header_value, 1);
            } else if(strncasecmp(header_name, "User-Agent", 10) == 0) {
                setenv("HTTP_USER_AGENT", header_value, 1);
            } else if(strncasecmp(header_name, "Host", 12) == 0) {
                setenv("HTTP_HOST", header_value, 1);
                int count;
                sds *host_port = sdssplitlen(header_value, strlen(header_value), ":", 1, &count);
                if(count == 1) {
                    setenv("SERVER_NAME", header_value, 1);
                } else if(count == 2) {
                    setenv("SERVER_NAME", host_port[0], 1);
                    setenv("SERVER_PORT", host_port[1], 1);
                }
            }

            sdsfreesplitres(key_value, pair_count);
        }
    }

    if((childpid = fork()) == -1) {
        perror("fork");
    }

    if(childpid == 0) {
        close(PARENT_WRITE);
        close(PARENT_READ);

        dup2(CHILD_READ, STDIN_FILENO);
        close(CHILD_READ);

        dup2(CHILD_WRITE, STDOUT_FILENO);
        close(CHILD_WRITE);

        sds path = sdsnew(ROOT);

        path = sdscat(path, "/cgi-bin/cwf.cgi");

        execlp(path, path, NULL);

    } else {
        close(CHILD_READ);
        close(CHILD_WRITE);

        if(request_content) {
            // Writing to the child pipe

			size_t request_content_len = sdslen(request_content);
            ssize_t bytes  = write(PARENT_WRITE, request_content, request_content_len);

			if(bytes != request_content_len) {
				fprintf(stderr, "Error writing data to cliente. Written %zu, expected %zu\n", bytes, request_content_len);
			}
        }

        char buffer[2] = {0};

        sds response_from_child = sdsempty();

        bool headers_end_found = false;

        // here we read the headers
		int len = 0;
        while(1) {
            ssize_t count = read(PARENT_READ, buffer, 1);
            if(count == -1) {
                if(errno == EINTR) {
                    continue;
                } else {
                    perror("reading from child");
                    exit(EXIT_FAILURE);
                }
            } else if(count == 0) {
                break;
            } else {
                response_from_child = sdscatlen(response_from_child, buffer, count);

				len++;
                if(len >= 4) {
                    headers_end_found = (response_from_child[len - 4] == '\r' && response_from_child[len - 3] == '\n' && response_from_child[len - 2] == '\r' &&
                                         response_from_child[len - 1] == '\n');
                    if(headers_end_found)
                        break;
                }
            }
        }

        sds status_msg = sdsnew(HEADER_OK);
        response_header_returned = HEADER_OK;

        sds response_headers = NULL;

        if(!headers_end_found) {
            response_header_returned = HEADER_INTERNAL_SERVER_ERROR;
            send_header(socket, HEADER_INTERNAL_SERVER_ERROR, true, https);
        } else {

        	bool header_error = false;
        	int status_index = -1;

            int lines_count;
            sds *response_lines = sdssplitlen(response_from_child, sdslen(response_from_child), "\r\n", strlen("\r\n"), &lines_count);
            // The last 2 lines are empty strings
            lines_count -= 2;

            for(int i = 0; i < lines_count; i++) {
                int pair_count;
                sds *key_value = sdssplitlen(response_lines[i], sdslen(response_lines[i]), ": ", 2, &pair_count);

                if(pair_count != 2) {
                    fprintf(stderr, "Invalid header %s\n", response_lines[i]);
                    sdsfreesplitres(key_value, pair_count);
                    header_error = true;
                    sdsfreesplitres(key_value, pair_count);
                    break;
                }

                if(strncasecmp(key_value[0], "Status", 6) == 0) {
                    status_index = i;
                    sdsfree(status_msg);
                    status_msg = sdscatfmt(sdsempty(), "HTTP/1.0 %s", key_value[1]);

                    if(strncmp(key_value[1], "200", 3) == 0) {
                        response_header_returned = HEADER_OK;
                    } 
					else if(strncmp(key_value[1], "401", 3) == 0) {
                        response_header_returned = HEADER_UNAUTHORIZED;
                    }
					else if(strncmp(key_value[1], "404", 3) == 0) {
                        response_header_returned = HEADER_NOT_FOUND;
                    } else if(strncmp(key_value[1], "400", 3) == 0) {
                        response_header_returned = HEADER_BAD_REQUEST;
                    } else if(strncmp(key_value[1], "500", 3) == 0) {
                        response_header_returned = HEADER_INTERNAL_SERVER_ERROR;
                    }
                } else if(strncasecmp(key_value[0], "Location", 8) == 0) {
                    sdsfree(status_msg);
                    status_msg = sdsnew(HEADER_REDIRECT);
                    response_header_returned = HEADER_REDIRECT;
                }

                sdsfreesplitres(key_value, pair_count);
            }

            if(header_error) {
                send_header(socket, HEADER_INTERNAL_SERVER_ERROR, true, https);
                response_header_returned = HEADER_INTERNAL_SERVER_ERROR;
            } else {
                response_headers = sdsempty();

                // We only have the status to send
                if(lines_count == 1 && status_index == 0) {
                    response_headers = sdscatfmt(response_headers, "%s\r\n", status_msg);
                }
                // We have only one header and is not the status. Send it;
                else if(lines_count == 1 && status_index == -1) {
                    response_headers = sdscatfmt(response_headers, "%s\r\n", status_msg);
                    response_headers = sdscatfmt(response_headers, "%s\r\n", response_lines[0]);
                } else {
                    response_headers = sdscatfmt(response_headers, "%s\r\n", status_msg);
                    for(int i = 0; i < lines_count; i++) {
                        if(i != status_index) {
                            response_headers = sdscatfmt(response_headers, "%s\r\n", response_lines[i]);
                        }
                    }
                }
            }
            sdsfreesplitres(response_lines, lines_count);

            char response_buffer[2];
            sds response_content = sdsempty();
            // here we read the headers
            while(1) {
                ssize_t count = read(PARENT_READ, response_buffer, sizeof(response_buffer) - 1);
                if(count == -1) {
                    if(errno == EINTR) {
                        continue;
                    } else {
                        perror("read");
                        exit(1);
                    }
                } else if(count == 0) {
                    break;
                } else {
                    response_content = sdscatlen(response_content, response_buffer, count);
                }
            }

            if(verbose)
                printf("%s\n", response_headers);

            // TODO: maybe we can send the headers without having to make a string buffer
            size_t content_length = sdslen(response_content);
            sds content_length_header = NULL;

            if(content_length > 0) {
                content_length_header = sdscatfmt(sdsempty(), "Content-Length:%i\r\n\r\n", sdslen(response_content));
            } else {
                content_length_header = sdsnew("\r\n\r\n");
            }

            server_write(socket, response_headers, sdslen(response_headers), https);
            server_write(socket, content_length_header, sdslen(content_length_header), https);
            server_write(socket, response_content, sdslen(response_content), https);

            sdsfree(response_from_child);
            sdsfree(response_headers);
            sdsfree(response_content);
            sdsfree(content_length_header);
        }
        close(PARENT_READ);
        close(PARENT_WRITE);
        wait(0);
    }
}

// client connection
void respond(int client_socket, bool https, bool verbose) {

    struct timeval start, end;
    long secs_used, micros_used;

    gettimeofday(&start, NULL);

    // TODO: change all this
    char mesg[2] = {0};

    sds request = sdsempty();

    int rcvd, fd;

    sds *request_lines;
    sds *method_uri_version;

    int lines_count;
    int method_uri_version_count;
    sds path = sdsnew(ROOT);

    SSL_CTX *sslctx = NULL;
    SSL *cSSL = NULL;

    if(https) {

        sslctx = new_SSL_CTX(cert_file, key_file);

        cSSL = SSL_new(sslctx);
        SSL_set_fd(cSSL, client_socket);

        int ssl_err = SSL_accept(cSSL);

        if(ssl_err < 1) {
            ssl_err = SSL_get_error(cSSL, ssl_err);
            printf("SSL error #%d in SSL_accept,program terminated\n", ssl_err);

            if(ssl_err == SSL_ERROR_SSL) {
                ERR_load_crypto_strings();
                SSL_load_error_strings(); // just once
                char msg[1024];
                ERR_error_string_n(ERR_get_error(), msg, sizeof(msg));
                printf("%s %s %s %s\n", msg, ERR_lib_error_string(0), ERR_func_error_string(0), ERR_reason_error_string(0));

                // error:14094416:SSL routines:ssl3_read_bytes:sslv3 alert certificate unknown
            }

            // close(client_socket);
            // shutdown_SSL(cSSL);

            // exit(EXIT_FAILURE);
        }
    }

    void *socket_pointer = NULL;

    if(https) {
        socket_pointer = cSSL;
    } else {
        socket_pointer = &client_socket;
    }

    // TODO: this is only the header. We need to read more after we get the content-length. This will be necessary when reading POST data;
	int len = 0;
    while((rcvd = server_read(socket_pointer, mesg, 1, https)) > 0) {
        request = sdscatlen(request, mesg, rcvd);
		len += rcvd;
        if(len >= 4) {
            bool header_end = (request[len - 4] == '\r' && request[len - 3] == '\n' && request[len - 2] == '\r' && request[len - 1] == '\n');
            if(header_end)
                break;
        }
    }

    bool error = false;
    struct stat st;

    if(rcvd < 0) { // receive error
        fprintf(stderr, ("recv() error\n"));
        error = true;
    } else if(rcvd == 0) { // receive socket closed
        fprintf(stderr, "Client disconnected upexpectedly.\n");
        error = true;
    } else {
        request_lines = sdssplitlen(request, sdslen(request), "\r\n", strlen("\r\n"), &lines_count);

        method_uri_version = sdssplitlen(request_lines[0], sdslen(request_lines[0]), " ", 1, &method_uri_version_count);

        if(method_uri_version_count != 3) {
            send_header(socket_pointer, HEADER_BAD_REQUEST, true, https);
            response_header_returned = HEADER_BAD_REQUEST;
        } else {
            char *method = method_uri_version[0];
            char *uri = method_uri_version[1];
            char *http_version = method_uri_version[2];

            if(strncmp(http_version, "HTTP/1.0", 8) != 0 && strncmp(http_version, "HTTP/1.1", 8) != 0) {
                // TODO: check for an ssl option
                send_header(socket_pointer, HEADER_BAD_REQUEST, true, https);
                response_header_returned = HEADER_BAD_REQUEST;
            } else {
                if(strncmp(method, "GET", 3) == 0) {
                    if((strncmp(uri, "/static/", 8) == 0) || (strncmp(uri, "/media/", 7) == 0) || (strncmp(uri, "/favicon.ico", 11) == 0)) {
                        path = sdscat(path, uri);

                        pthread_mutex_lock(&lock);
                        struct static_file cached_file = shget(cache, path);

                        //TODO: implement a cache substituion policy. We dont need this now, as we are only using the server for development
                        if(cached_file.data == NULL) {
                            if((fd = open(path, O_RDONLY)) != -1) {
                                stat(path, &st);

                                size_t to_page_size = st.st_size;

                                int pagesize = getpagesize();
                                to_page_size += pagesize - (to_page_size % pagesize);

                                cached_file.data = (char *)mmap(0, to_page_size, PROT_READ, MAP_PRIVATE, fd, 0);
                                cached_file.st = st;
                                cached_file.real_size = to_page_size;
                                shput(cache, path, cached_file);
                                close(fd);
                            }
                        }

                        if(cached_file.data) {
                            send_header(socket_pointer, HEADER_OK, false, https);
                            response_header_returned = HEADER_OK;

                            sds content_length_header = sdscatprintf(sdsempty(), "Content-Length: %ld", cached_file.st.st_size);
                            char *mime_type = shget(mime_types, get_filename_ext(path));

                            sds content_type_header;
                            if(mime_type) {
                                content_type_header = sdscatfmt(sdsempty(), "Content-Type: %s", mime_type);
                            } else {
                                content_type_header = sdsnew("Content-Type: application/octet-stream");
                            }

                            send_header(socket_pointer, content_length_header, false, https);
                            send_header(socket_pointer, content_type_header, true, https);

                            sdsfree(content_length_header);
                            sdsfree(content_type_header);

                            server_write(socket_pointer, cached_file.data, cached_file.st.st_size, https);

                        } else {
                            send_header(socket_pointer, HEADER_NOT_FOUND, true, https);
                            response_header_returned = HEADER_NOT_FOUND;
                        }
                        pthread_mutex_unlock(&lock);

                    } else {
                        execute_cgi(socket_pointer, request_lines, NULL, lines_count, https, verbose);
                    }
                } else if(strncmp(method, "POST", 4) == 0) {
                    long content_length = 0;
                    for(int i = 0; i < lines_count; i++) {
                        if(strncmp(request_lines[i], "Content-Length:", 15) == 0) {
                            char *ptr = strchr(request_lines[i], ':');
                            content_length = strtol(ptr + 1, NULL, 10);
                        }
                    }

                    long received_data = 0;
                    char buff[MAX_BUFFER_SIZE] = {0};
                    sds request_content = sdsempty();

                    int bytes_to_read = (content_length > MAX_BUFFER_SIZE) ? MAX_BUFFER_SIZE : content_length;

                    while(received_data < content_length) {
                        rcvd = server_read(socket_pointer, buff, bytes_to_read, https);
                        request_content = sdscatlen(request_content, buff, rcvd);
                        received_data += rcvd;
                    }

                    if(rcvd < 0) { // receive error
                        fprintf(stderr, ("recv() error\n"));
                    } else if(rcvd == 0) { // receive socket closed
                        fprintf(stderr, "Client disconnected upexpectedly.\n");
                    } else {
                        if(verbose)
                            printf("%s\n", request_content);
                        execute_cgi(socket_pointer, request_lines, request_content, lines_count, https, verbose);
                    }

                } else {
                    send_header(socket_pointer, HEADER_BAD_REQUEST, true, https);
                    response_header_returned = HEADER_BAD_REQUEST;
                }
            }
        }
    }
    // Closing SOCKET
    shutdown(client_socket, SHUT_RDWR); // All further send and recieve operations are DISABLED...
    close(client_socket);

    if(https)
        destroy_SSL();

    gettimeofday(&end, NULL);

    secs_used = (end.tv_sec - start.tv_sec); // avoid overflow by subtracting first
    micros_used = ((secs_used * 1000000) + end.tv_usec) - (start.tv_usec);
    if(!error) {
        //We want to compare the pointers here, not the strings
        if(response_header_returned == HEADER_BAD_REQUEST || response_header_returned == HEADER_NOT_FOUND) {
            fprintf(stderr, "\033[1;31m%s %s - %s - took %ld ms\033[0m\n", method_uri_version[0], method_uri_version[1], response_header_returned + 9,
                    micros_used / 1000);
        } else if(response_header_returned == HEADER_REDIRECT) {
            fprintf(stderr, "\033[1;33m%s %s - %s - took %ld ms\033[0m\n", method_uri_version[0], method_uri_version[1], response_header_returned + 9,
                    micros_used / 1000);
        } else {
            fprintf(stderr, "\033[1;34m%s %s - %s - took %ld ms\033[0m\n", method_uri_version[0], method_uri_version[1], response_header_returned + 9,
                    micros_used / 1000);
        }
    }
}

int add_dir_watch(int fd, char *path) {
    return inotify_add_watch(fd, path, IN_MODIFY | IN_DELETE | IN_CREATE | IN_DELETE_SELF);
}


static void add_all_watches(const char *name, int indent, int fd, bool verbose) {

    DIR *dir;
    struct dirent *entry;

    if (!(dir = opendir(name)))
        return;

    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type == DT_DIR) {
            char path[1024];

            if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0 || strcmp(entry->d_name, ".git") == 0 || strcmp(entry->d_name, ".idea") == 0)
                continue;

            snprintf(path, sizeof(path), "%s/%s", name, entry->d_name);

            int wd = add_dir_watch(fd, path);

            if(wd != -1) {
                hmput(notify_entries, wd, strdup(path));
            }

            if(verbose) {
                if(wd == -1) {
                    printf("Could not watch : %s\n", path);
                } else {
                    printf("Watching : %s\n", path);
                }
            }

            add_all_watches(path, indent + 2, fd, verbose);
        }
    }
    closedir(dir);
}

static void *check_for_cached_file_changes(void *args) {

    pthread_detach(pthread_self());

    int fd_notify = *(int*)(args);

    while(1) {

        int i=0, length;
        char buffer[BUF_LEN];

        length = read(fd_notify, buffer, BUF_LEN);

        while(i < length) {

            struct inotify_event *event = (struct inotify_event *) &buffer[i];

            if(event->len) {

             if ( event->mask & IN_DELETE ) {
                    if ( event->mask & IN_ISDIR ) {
                    }
                    else {
                        pthread_mutex_lock(&lock);
                        sds path = sdscatfmt(sdsempty(),"%s/%s", hmget(notify_entries, event->wd), event->name);
                        struct static_file cached_file = shget(cache, path);

                        //file was cached and deleted. We need to remove it from cache
                        if(cached_file.data != NULL) {
                            printf("%s was cached and deleted, removing it from cache\n", path);
                            munmap(cached_file.data, cached_file.real_size);
                            cached_file.data = NULL;
                            cached_file.st = (struct stat){0};
                            cached_file.real_size = -1;
                            shput(cache, path, cached_file);
                        }

                        pthread_mutex_unlock(&lock);

                        sdsfree(path);

                    }
                }
                else if ( event->mask & IN_CREATE ) {

                    if(event->mask & IN_ISDIR) {
                        sds path = sdscatfmt(sdsempty(), "%s/%s", hmget(notify_entries, event->wd), event->name);
                        pthread_mutex_lock(&lock);

                        int wd = add_dir_watch(fd_notify, path);

                        if(wd != -1) {
                            printf("The directory %s was created.\n", path);
                            hmput(notify_entries, wd, strdup(path));
                        }
                        pthread_mutex_unlock(&lock);
                    }
                }
                else if ( event->mask & IN_MODIFY ) {

                    if ( event->mask & IN_ISDIR ) {
                    }
                    else {
                        sds path = sdscatfmt(sdsempty(),"%s/%s", hmget(notify_entries, event->wd), event->name);

                        pthread_mutex_lock(&lock);

                        struct static_file cached_file = shget(cache, path);

                        //file was cached and changed. We need to reload it
                        if(cached_file.data != NULL) {

                            printf("%s was cached and modified, reloading it\n", path);
                            struct stat st;

                            munmap(cached_file.data, cached_file.real_size);

                            int fd_file = open(path, O_RDONLY);

                            stat(path, &st);

                            size_t to_page_size = st.st_size;

                            int pagesize = getpagesize();
                            to_page_size += pagesize - (to_page_size % pagesize);

                            cached_file.data = (char *)mmap(0, to_page_size, PROT_READ, MAP_PRIVATE, fd_file, 0);
                            cached_file.st = st;
                            cached_file.real_size = to_page_size;

                            shput(cache, path, cached_file);
                            close(fd_file);
                        }
                        pthread_mutex_unlock(&lock);

                        sdsfree(path);
                    }

                }
            }
            i += EVENT_SIZE + event->len;
        }
    }
}

int main(int argc, char *argv[]) {

    struct sockaddr_in clientaddr;
    socklen_t addrlen;
    int client_socket;
    char c;

    fd_set master;
    fd_set read_fds;
    int fdmax;
    FD_ZERO(&master);
    FD_ZERO(&read_fds);

    bool verbose = false;
    bool https = false;

    ROOT = getenv("PWD");

    shdefault(cache, file_not_in_cache);
    sh_new_strdup(cache);

    hmdefault(notify_entries, NULL);

    int port = 8080;

    uid_t uid = getuid(), euid = geteuid();

    // Parsing the command line arguments
    while((c = getopt(argc, argv, "p:r:vs")) != -1) {
        switch(c) {
        case 'r': {
            int arglen = strlen(optarg);
            if(optarg[arglen - 1] != '/') {
                ROOT = malloc(arglen + 2);
                strcpy(ROOT, optarg);
                ROOT[arglen] = '/';
                ROOT[arglen + 1] = '\0';
            } else {
                ROOT = strdup(optarg);
            }
        } break;
        case 'p':
            port = strtol(optarg, NULL, 10);
            if(port < 1 || port > 65535) {
                fprintf(stderr, "Invalid port number %d. Valid values are from 1 to 65535\n", port);
                exit(1);
            } else if(port < 1024) {
                if(uid > 0 && uid == euid) {
                    fprintf(stderr, "Invalid port number %d. You need to be root to open a port < 1024", port);
                    exit(1);
                }
            }
            break;
        case 'v':
            verbose = true;
            break;
        case 's':
            https = true;
            break;
        case '?':
            fprintf(stderr, "Usage: %s -p PORT -r ROOT\n", argv[0]);
            exit(1);
        default:
            exit(1);
        }
    }

    if(https) {
        cert_file = sdscatfmt(sdsempty(), "%scert.pem", ROOT);
        key_file = sdscatfmt(sdsempty(), "%skey.pem", ROOT);
    }

    load_mime_types(&mime_types);
	
    int fd = inotify_init();

    add_all_watches(ROOT, 0, fd, verbose);

    pthread_t inotify_thread;

    if (pthread_mutex_init(&lock, NULL) != 0) {
        printf("\n mutex init has failed\n");
        return EXIT_FAILURE;
    }

    pthread_create(&inotify_thread, NULL, check_for_cached_file_changes, (void*)&fd);

    start_server(port);

    if(https) {
        printf("HTTPS server started at port no. %shttp://localhost:%d%s with root directory as %s%s%s\n", "\033[92m", port, "\033[0m", "\033[92m", ROOT,
               "\033[0m");
    } else {
        printf("HTTP server started at %shttp://localhost:%d%s with root directory as %s%s%s\n", "\033[92m", port, "\033[0m", "\033[92m", ROOT, "\033[0m");
    }

    FD_SET(listener, &master);
    fdmax = listener;

    addrlen = sizeof(clientaddr);

	while(1) {
		if((client_socket = accept(listener, (struct sockaddr *)&clientaddr, &addrlen)) != -1) {
			respond(client_socket, https, verbose);
		} 
	}

    return 0;
}

