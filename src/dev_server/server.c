#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "../3dparty/sds/sds.h"

#define HEADER_OK "HTTP/1.0 200 OK"
#define HEADER_NOT_FOUND "HTTP/1.0 404 Not Found"
#define HEADER_BAD_REQUEST "HTTP/1.0 400 Bad Request"

#define BYTES 1024

char *ROOT;
int listener;
void error(char *);
void start_server(int port);
void respond(int);

int main(int argc, char *argv[]) {
    struct sockaddr_in clientaddr;
    socklen_t addrlen;
    int client_socket;
    char c;

    ROOT = getenv("PWD");

    int port = 8080;

    uid_t uid = getuid(), euid = geteuid();

    // Parsing the command line arguments
    while((c = getopt(argc, argv, "p:r:")) != -1) {
        switch(c) {
            case 'r':
                ROOT = strdup(optarg);
                break;
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
            case '?':
                fprintf(stderr, "Usage: %s -p PORT -r ROOT\n", argv[0]);
                exit(1);
            default:
                exit(1);
        }
    }

    start_server(port);

    printf("Server started at port no. %s%d%s with root directory as %s%s%s\n", "\033[92m", port, "\033[0m", "\033[92m",
           ROOT, "\033[0m");

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
    write(socket, header, strlen(header));
    write(socket, "\r\n", 2);

    if(last) {
        write(socket, "\r\n", 2);
    }
}

#define PARENT_READ readpipe[0]
#define CHILD_WRITE readpipe[1]
#define CHILD_READ writepipe[0]
#define PARENT_WRITE writepipe[1]

void execute_cgi(int socket, sds *request_lines) {
    int writepipe[2] = {-1, -1}, /* parent -> child */
        readpipe[2] = {-1, -1};  /* child -> parent */
    pid_t childpid;

    if(pipe(readpipe) < 0 || pipe(writepipe) < 0) {
        perror("pipe");
        exit(1);
    }

    int method_uri_version_count;
    sds *method_uri_version =
        sdssplitlen(request_lines[0], sdslen(request_lines[0]), " ", 1, &method_uri_version_count);

    char *method = method_uri_version[0];
    char *uri = method_uri_version[1];

    setenv("REQUEST_METHOD", method, 1);
    setenv("REQUEST_URI", uri, 1);
    setenv("QUERY_STRING", "", 1);

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

        path = sdscatfmt(path, "/cgi-bin/cwf.cgi");

        execlp(path, path, NULL);

    } else {
        close(CHILD_READ);
        close(CHILD_WRITE);
        // TODO: read child stdout to send through the socket
        char buffer[4096];

        // TODO: we need to decide how to handle status messages comming from the cgi script.
        // The cgi sends us a Header Status: 404....
        send_header(socket, HEADER_NOT_FOUND, false);

        while(1) {
            ssize_t count = read(PARENT_READ, buffer, sizeof(buffer));
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
                printf("%s\n", buffer);
                write(socket, buffer, count);
            }
        }
        close(PARENT_READ);
        wait(0);
    }
}

// client connection
void respond(int client_socket) {
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
    while((rcvd = recv(client_socket, mesg, 1, 0)) > 0) {
        request = sdscat(request, mesg);
        int len = sdslen(request);
        if(len >= 4) {
            bool end = (request[len - 4] == '\r' && request[len - 3] == '\n' && request[len - 2] == '\r' &&
                        request[len - 1] == '\n');
            if(end) break;
        }
    }

    if(rcvd < 0) {  // receive error
        fprintf(stderr, ("recv() error\n"));
    } else if(rcvd == 0) {  // receive socket closed
        fprintf(stderr, "Client disconnected upexpectedly.\n");
    } else {
        printf("%s", request);

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
                    if((strncmp(uri, "/static/", 8) == 0) || (strncmp(uri, "/media/", 7) == 0)) {
                        path = sdscat(path, uri);

                        printf("file: %s\n", path);
                        if((fd = open(path, O_RDONLY)) != -1) {
                            send_header(client_socket, HEADER_OK, true);
                            while((bytes_read = read(fd, data_to_send, BYTES)) > 0)
                                write(client_socket, data_to_send, bytes_read);
                        } else {
                            send_header(client_socket, HEADER_NOT_FOUND, true);
                        }
                    } else {
                        execute_cgi(client_socket, request_lines);
                    }
                }

                else if(strncmp(method, "POST", 4) == 0) {
                    // TODO: handle post here
                } else {
                    send_header(client_socket, HEADER_BAD_REQUEST, true);
                }
            }
        }
    }
    // Closing SOCKET
    shutdown(client_socket, SHUT_RDWR);  // All further send and recieve operations are DISABLED...
    close(client_socket);
}
