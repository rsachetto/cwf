# C web framework
A proof of concept C web framework using CGI and C99. This was never intended to be used in production. The code is not safe and contain a lot of bugs.

# Installation and configuration

##Using the development server

### Todo List example app

````console
$ git clone https://github.com/rsachetto/cwf.git
$ cd cwf
$ make
$ cd todo_list
$ make 
$ ../bin/server -p 8080 -r . 
````
Open your browser and point to http://localhost:8080

### Creating an empty app
````console
$ git clone https://github.com/rsachetto/cwf.git
$ cd cwf
$ make
$ ./bin/cwf app new_app
$ cd new_app
$ make
$ ../bin/server -p 8080 -r .  
````

Open your browser and point to http://localhost:8080

You should see something like this in your browser:

````
HTTP_ACCEPT en-US,en;q=0.9,pt-BR;q=0.8,pt;q=0.7
HTTP_HOST localhost:8080
HTTP_USER_AGENT Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/85.0.4183.83 Safari/537.36
REQUEST_METHOD GET
REQUEST_SCHEME http
REQUEST_URI /
QUERY_STRING 
SERVER_NAME localhost
SERVER_PORT 8080
SERVER_PROTOCOL HTTP/1.0
DOCUMENT_ROOT ./
SERVER_SOFTWARE CWF Development server (0.1)
````

##Installing on apache
TDB