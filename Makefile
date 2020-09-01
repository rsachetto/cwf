OPT_FLAGS=-g3

all: server todo blog

server:
	gcc ${OPT_FLAGS} src/dev_server/server.c src/3dparty/sds/sds.c -o bin/server -lpthread

todo: cwf
	gcc ${OPT_FLAGS} todo_list/endpoints.c -fPIC -shared -o todo_list/libendpoints.so -Lsrc -lcwf -lssl -lcrypto
	cp cwf.cgi todo_list/cgi-bin/

blog: cwf
	gcc ${OPT_FLAGS} blog/endpoints.c -fPIC -shared -o blog/libendpoints.so -Lsrc -lcwf -lssl -lcrypto
	cp cwf.cgi blog/cgi-bin/

cwf:
	cd src/ &&  $(MAKE) EXTRA_C_FLAGS=${OPT_FLAGS}  && cd ..
	gcc ${OPT_FLAGS} src/main.c src/libcwf.a -o cwf.cgi -ldl -lpthread -lssl -lcrypto

clean:
	cd src/ &&  $(MAKE) clean  && cd ..
