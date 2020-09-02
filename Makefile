PHONY = release debug debug_cgi

all: release server todo blog
	rm cwf.cgi

all_debug: debug server todo blog
	rm cwf.cgi

all_debug_cig: debug_cgi debug server todo blog
	rm cwf.cgi

release:
	$(eval OPT_FLAGS=-O3)

debug:
	$(eval OPT_FLAGS=-g3)

debug_cgi:
	$(eval DEBUG_CGI=-DDEBUG_CGI)

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
	gcc ${OPT_FLAGS} ${DEBUG_CGI} src/main.c src/libcwf.a -o cwf.cgi -ldl -lpthread -lssl -lcrypto

clean:
	cd src/ &&  $(MAKE) clean  && cd ..
