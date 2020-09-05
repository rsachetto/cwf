PHONY = release debug debug_cgi

all: release 

debug: debug_set server cwf
release: release_set server cwf

release_set:
	$(eval OPT_FLAGS=-O3)

debug_set:
	$(eval OPT_FLAGS=-g3)
	$(eval ENABLE_BACKTRACE=-DENABLE_BACKTRACE)


server:
	gcc ${OPT_FLAGS} src/dev_server/server.c src/3dparty/sds/sds.c -o bin/server

cwf:
	cd src/ && $(MAKE) EXTRA_C_FLAGS=${OPT_FLAGS} && cd -
	gcc ${OPT_FLAGS} ${DEBUG_CGI} ${ENABLE_BACKTRACE} src/main.c src/libcwf.a -o src/cwf.cgi -ldl -lpthread -lssl -lcrypto -lm

clean:
	rm bin/server
	cd src/ && $(MAKE) clean & cd -
