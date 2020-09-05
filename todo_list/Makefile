PHONY = release_set debug_set debug_cgi_set

all: release

debug: debug_set todo
release: release_set todo
debug_cgi: debug_cgi_set todo

release_set:
	$(eval OPT_FLAGS=-O3)
 
debug_set:
	$(eval OPT_FLAGS=-g3)
	$(eval ENABLE_BACKTRACE=-DENABLE_BACKTRACE)

debug_cgi_set: 
	$(eval DEBUG_CGI=-DDEBUG_CGI)

todo: cwf
	gcc ${OPT_FLAGS} src/endpoints.c -fPIC -shared -o lib/libendpoints.so -L../src  -lcwf -lssl -lcrypto -lm
	mv cwf.cgi cgi-bin/

cwf:
	cd ../src/ &&  $(MAKE) EXTRA_C_FLAGS=${OPT_FLAGS}  && cd -
	gcc ${OPT_FLAGS} ${DEBUG_CGI} ${ENABLE_BACKTRACE} ../src/main.c ../src/libcwf.a -o cwf.cgi -ldl -lpthread -lssl -lcrypto -lm

clean:
	cd ../src/ &&  $(MAKE) clean  && cd -
