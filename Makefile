.PHONY = all debug release server cwf clean debug_set release_set

all: release

debug: debug_set server cwf todo_list
release: release_set server cwf  todo_list

OPT_RELEASE=-O3

release_set:
	$(eval OPT_FLAGS=${OPT_RELEASE})
	$(eval OPT_FLAGS2=${OPT_RELEASE})

debug_set:
	$(eval OPT_FLAGS="-g3 -DDEBUG_CGI -Wall" )
	$(eval OPT_FLAGS2=-g3)
	$(eval ENABLE_BACKTRACE=-DENABLE_BACKTRACE)

server: src/dev_server/ssl_helper.c src/dev_server/server.c src/3dparty/sds/sds.c src/dev_server/ssl_helper.h  src/3dparty/sds/sds.h
	gcc ${OPT_FLAGS2} src/dev_server/ssl_helper.c src/dev_server/server.c src/3dparty/sds/sds.c -o bin/server -lssl -lcrypto

todo_list: cwf server todo_list/src/endpoints.c
	gcc ${OPT_FLAGS2} todo_list/src/endpoints.c -fPIC -shared -o todo_list/lib/libendpoints.so -L./src  -lcwf -lssl -lcrypto -lm
	gcc ${OPT_FLAGS2} ${ENABLE_BACKTRACE} src/main.c src/libcwf.a -o todo_list.cgi -ldl -lpthread -lssl -lcrypto -lm
	mv todo_list.cgi todo_list/cgi-bin/cwf.cgi

cwf:
	cd src/ && $(MAKE) EXTRA_C_FLAGS=${OPT_FLAGS} && cd -

clean:
	rm bin/server
	cd src/ && $(MAKE) clean & cd -
