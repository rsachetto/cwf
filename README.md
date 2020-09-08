# C web framework
A proof of concept C web framework using CGI and C99. This was never intended to be used in production. The code is not safe and contain a lot of bugs.

# Installation and configuration

### TODO example app

````console
$ git clone https://github.com/rsachetto/cwf.git
$ cd cwf
$ make
$ cd todo_list
$ make 
$ ../bin/server -p 8080 -s . 
```

Open your brownser and point to http://localhost:8080