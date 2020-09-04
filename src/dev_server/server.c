#include "../3dparty/sds/sds.h"
#include "mimetypes.h"
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define STB_DS_IMPLEMENTATION
#include "../3dparty/stb/stb_ds.h"

#define SERVER_PROTOCOL "HTTP/1.0"
#define HEADER_OK SERVER_PROTOCOL " 200 OK"
#define HEADER_NOT_FOUND SERVER_PROTOCOL " 404 Not Found"
#define HEADER_BAD_REQUEST SERVER_PROTOCOL " 400 Bad Request"
#define HEADER_INTERNAL_SERVER_ERROR SERVER_PROTOCOL " 500 Internal Server Error"
#define HEADER_REDIRECT SERVER_PROTOCOL " 302 Found"

#define BYTES 1024

char *ROOT;
int listener;
void error(char *);
void start_server(int port);
void respond(int);
bool verbose = false;

struct mime_type {
    char *key;   // file extension
    char *value; // mime-type
};

struct mime_type *mime_types;

const char *get_filename_ext(const char *filename) {
    const char *dot = strrchr(filename, '.');
    if(!dot || dot == filename)
        return "";
    return dot + 1;
}

static void load_mime_types() {
    int ext_number;
    shdefault(mime_types, NULL);
    sh_new_arena(mime_types);

    for(int i = 0; i < NUM_MIME_TYPES; i++) {
        sds *extensions = sdssplitlen(mime_types_raw[i][1], sizeof(mime_types_raw[i][1]), " ", 1, &ext_number);
        for(int j = 0; j < ext_number; j++) {
            shput(mime_types, extensions[j], mime_types_raw[i][0]);
        }
        sdsfreesplitres(extensions, ext_number);
    }
}

int main(int argc, char *argv[]) {
    struct sockaddr_in clientaddr;
    socklen_t addrlen;
    int client_socket;
    char c;

    ROOT = getenv("PWD");

    int port = 8080;

    uid_t uid = getuid(), euid = geteuid();

    // Parsing the command line arguments
    while((c = getopt(argc, argv, "p:r:v")) != -1) {
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
        case '?':
            fprintf(stderr, "Usage: %s -p PORT -r ROOT\n", argv[0]);
            exit(1);
        default:
            exit(1);
        }
    }

    load_mime_types();
    start_server(port);

    printf("Server started at port no. %s%d%s with root directory as %s%s%s\n", "\033[92m", port, "\033[0m", "\033[92m", ROOT, "\033[0m");

    while(1) {
        addrlen = sizeof(clientaddr);
        client_socket = accept(listener, (struct sockaddr *)&clientaddr, &addrlen);

        if(client_socket < 0) {
            perror("accept() error");
        } else {
            respond(client_socket);
        }
    }

    return 0;
}

// start server
void start_server(int port) {
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
    if(listen(listener, 10) == -1) {
        perror("listen() error!");
        exit(1);
    }
}

void send_header(int socket, const char *header, bool last) {
    send(socket, header, strlen(header), MSG_NOSIGNAL);
    send(socket, "\r\n", 2, MSG_NOSIGNAL);

    if(last) {
        send(socket, "\r\n", 2, MSG_NOSIGNAL);
    }
}

#define PARENT_READ readpipe[0]
#define CHILD_WRITE readpipe[1]
#define CHILD_READ writepipe[0]
#define PARENT_WRITE writepipe[1]

void execute_cgi(int socket, sds *request_headers, sds request_content, int num_headers) {

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
    setenv("REQUEST_SCHEME", "http", 1);
    setenv("DOCUMENT_ROOT", ROOT, 1);

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

        if(request_content)
            write(PARENT_WRITE, request_content, sdslen(request_content));

        char buffer[2] = {0};

        sds response_from_child = sdsempty();

        bool headers_end_found = false;

        // here we read the headers
        while(1) {
            ssize_t count = read(PARENT_READ, buffer, 1);
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
                response_from_child = sdscat(response_from_child, buffer);
                int len = sdslen(response_from_child);

                if(len >= 4) {
                    headers_end_found = (response_from_child[len - 4] == '\r' && response_from_child[len - 3] == '\n' && response_from_child[len - 2] == '\r' &&
                                         response_from_child[len - 1] == '\n');
                    if(headers_end_found)
                        break;
                }
            }
        }

        bool header_error = false;
        sds status_msg = sdsnew(HEADER_OK);
        int status_index = -1;

        sds response_headers = NULL;

        if(!headers_end_found) {
            fprintf(stderr, "No headers found - sending %s\n", HEADER_INTERNAL_SERVER_ERROR);
            send_header(socket, HEADER_INTERNAL_SERVER_ERROR, true);
        } else {
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
                } else if(strncasecmp(key_value[0], "Location", 8) == 0) {
                    sdsfree(status_msg);
                    status_msg = sdsnew(HEADER_REDIRECT);
                }

                sdsfreesplitres(key_value, pair_count);
            }

            if(header_error) {
                send_header(socket, HEADER_INTERNAL_SERVER_ERROR, true);
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
                    response_buffer[count] = '\0';
                    response_content = sdscat(response_content, response_buffer);
                }
            }

            if(verbose)
                printf("%s\n", response_headers);

            // TODO: maybe we can send the headers withou having to make a string buffer
            size_t content_length = sdslen(response_content);
            sds content_length_header = NULL;

            if(content_length > 0) {
                content_length_header = sdscatfmt(sdsempty(), "Content-Length:%i\r\n\r\n", sdslen(response_content));
            } else {
                content_length_header = sdsnew("\r\n\r\n");
            }

            send(socket, response_headers, sdslen(response_headers), MSG_NOSIGNAL);
            send(socket, content_length_header, sdslen(content_length_header), MSG_NOSIGNAL);
            send(socket, response_content, sdslen(response_content), MSG_NOSIGNAL);

            sdsfree(response_from_child);
            sdsfree(response_headers);
            sdsfree(response_content);
            sdsfree(content_length_header);
        }
        close(PARENT_READ);
        wait(0);
    }
}

// client connection
void respond(int client_socket) {

    struct timeval start, end;
    long secs_used, micros_used;

    gettimeofday(&start, NULL);

    // TODO: change all this
    char mesg[2] = {0};

    sds request = sdsempty();

    char data_to_send[BYTES];
    int rcvd, fd, bytes_read;

    sds *request_lines;
    sds *method_uri_version;

    int lines_count;
    int method_uri_version_count;
    sds path = sdsnew(ROOT);

    // TODO: this is only the header. We need to read more after we get the content-length. This will be necessary when
    // reading POST data;
    while((rcvd = read(client_socket, mesg, 1)) > 0) {
        request = sdscat(request, mesg);
        int len = sdslen(request);
        if(len >= 4) {
            bool end = (request[len - 4] == '\r' && request[len - 3] == '\n' && request[len - 2] == '\r' && request[len - 1] == '\n');
            if(end)
                break;
        }
    }

    bool error = false;

    if(rcvd < 0) { // receive error
        fprintf(stderr, ("recv() error\n"));
        error = true;
    } else if(rcvd == 0) { // receive socket closed
        fprintf(stderr, "Client disconnected upexpectedly.\n");
        error = true;
    } else {
        if(verbose)
            printf("%s\n", request);

        request_lines = sdssplitlen(request, sdslen(request), "\r\n", strlen("\r\n"), &lines_count);

        method_uri_version = sdssplitlen(request_lines[0], sdslen(request_lines[0]), " ", 1, &method_uri_version_count);

        if(method_uri_version_count != 3) {
            send_header(client_socket, HEADER_BAD_REQUEST, true);
        } else {
            char *method = method_uri_version[0];
            char *uri = method_uri_version[1];
            char *http_version = method_uri_version[2];

            if(strncmp(http_version, "HTTP/1.0", 8) != 0 && strncmp(http_version, "HTTP/1.1", 8) != 0) {
                send_header(client_socket, HEADER_BAD_REQUEST, true);
            } else {
                if(strncmp(method, "GET", 3) == 0) {
                    if((strncmp(uri, "/static/", 8) == 0) || (strncmp(uri, "/media/", 7) == 0) || (strncmp(uri, "/favicon.ico", 11) == 0)) {
                        path = sdscat(path, uri);

                        if((fd = open(path, O_RDONLY)) != -1) {
                            struct stat st;
                            stat(path, &st);
                            size_t size = st.st_size;

                            send_header(client_socket, HEADER_OK, false);

                            sds content_length_header = sdscatprintf(sdsempty(), "Content-Length: %ld", size);
                            sds content_type_header = sdsempty();
                            char *mime_type = shget(mime_types, get_filename_ext(path));

                            if(mime_type) {
                                content_type_header = sdscatfmt(sdsempty(), "Content-Type: %s", mime_type);
                            } else {
                                content_type_header = sdsnew("Content-Type: application/octet-stream");
                            }

                            send_header(client_socket, content_length_header, false);
                            send_header(client_socket, content_type_header, true);

                            sdsfree(content_length_header);
                            sdsfree(content_type_header);

                            while((bytes_read = read(fd, data_to_send, BYTES)) > 0)
                                send(client_socket, data_to_send, bytes_read, MSG_NOSIGNAL);
                        } else {
                            send_header(client_socket, HEADER_NOT_FOUND, true);
                        }
                    } else {
                        execute_cgi(client_socket, request_lines, NULL, lines_count);
                    }
                }

                else if(strncmp(method, "POST", 4) == 0) {
                    long content_length = 0;
                    for(int i = 0; i < lines_count; i++) {
                        if(strncmp(request_lines[i], "Content-Length:", 15) == 0) {
                            char *ptr = strchr(request_lines[i], ':');

                            content_length = strtol(ptr + 1, NULL, 10);
                        }
                    }

                    long received_data = 0;
                    char buff[2] = {0};
                    sds request_content = sdsempty();

                    // TODO: we can read by a content_length/max_buffer
                    while(received_data < content_length) {
                        rcvd = read(client_socket, buff, 1);
                        request_content = sdscat(request_content, buff);
                        received_data += rcvd;
                    }

                    if(rcvd < 0) { // receive error
                        fprintf(stderr, ("recv() error\n"));
                    } else if(rcvd == 0) { // receive socket closed
                        fprintf(stderr, "Client disconnected upexpectedly.\n");
                    } else {
                        if(verbose)
                            printf("%s\n", request_content);
                        execute_cgi(client_socket, request_lines, request_content, lines_count);
                    }

                } else {
                    send_header(client_socket, HEADER_BAD_REQUEST, true);
                }
            }
        }
    }
    // Closing SOCKET
    shutdown(client_socket, SHUT_RDWR); // All further send and recieve operations are DISABLED...
    close(client_socket);

    gettimeofday(&end, NULL);

    secs_used = (end.tv_sec - start.tv_sec); // avoid overflow by subtracting first
    micros_used = ((secs_used * 1000000) + end.tv_usec) - (start.tv_usec);
    if(!error)
        fprintf(stderr, "Respond to request %s %s took %ld ms\n", method_uri_version[0], method_uri_version[1], micros_used / 1000);
}
