#!/usr/bin/bash

export REQUEST_METHOD=GET 
export REQUEST_URI=/ 
export SERVER_PROTOCOL=HTTP/1.1 
export REQUEST_SCHEME=http 
export DOCUMENT_ROOT=./ 
export HTTP_HOST=localhost:8080 
export SERVER_NAME=localhost 
export SERVER_PORT=8080 

valgrind --xml=yes --xml-file=valgrind.xml --leak-check=full --leak-check=yes ./cgi-bin/cwf.cgi
