.PHONY = all debug release server cwf clean debug_set release_set

all: release

debug: debug_set server cwf provas precos
release: release_set server cwf provas precos

OPT_RELEASE=-O3

release_set:
	$(eval OPT_FLAGS=${OPT_RELEASE})
	$(eval OPT_FLAGS2=${OPT_RELEASE})

debug_set:
	$(eval OPT_FLAGS="-g3 -DDEBUG_CGI -Wall")
	$(eval OPT_FLAGS2=-g3)
	$(eval ENABLE_BACKTRACE=-DENABLE_BACKTRACE)

server: src/dev_server/ssl_helper.c src/dev_server/server.c src/3dparty/sds/sds.c src/dev_server/ssl_helper.h  src/3dparty/sds/sds.h
	gcc ${OPT_FLAGS2} src/dev_server/ssl_helper.c src/dev_server/server.c src/3dparty/sds/sds.c -o bin/server -lssl -lcrypto

provas: cwf server provas/src/endpoints.c provas/src/exam_helpers.c provas/src/exam_helpers.h provas/src/helpers.h
	gcc ${OPT_FLAGS2} provas/src/endpoints.c provas/src/exam_helpers.c -fPIC -shared -o provas/lib/libendpoints.so -L./src  -lcwf -lssl -lcrypto -lm
	gcc ${OPT_FLAGS2} ${ENABLE_BACKTRACE} src/main.c src/libcwf.a -o provas.cgi -ldl -lpthread -lssl -lcrypto -lm
	mv provas.cgi provas/cgi-bin/cwf.cgi

precos: cwf server precos/src/endpoints.c precos/src/database_utils.h
	gcc ${OPT_FLAGS2} precos/src/endpoints.c precos/src/database_utils.c -fPIC -shared -o precos/lib/libendpoints.so -L./src  -lcwf -lssl -lcrypto -lm
	gcc ${OPT_FLAGS2} ${ENABLE_BACKTRACE} src/main.c src/libcwf.a -o precos.cgi -ldl -lpthread -lssl -lcrypto -lm
	mv precos.cgi precos/cgi-bin/cwf.cgi

cwf:
	cd src/ && $(MAKE) EXTRA_C_FLAGS=${OPT_FLAGS} && cd -

clean:
	rm bin/server
	cd src/ && $(MAKE) clean & cd -
