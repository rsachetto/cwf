.PHONY = all debug release server cwf clean debug_set release_set

all: release

debug: debug_set server cwf
release: release_set server cwf

release_set:
	$(eval OPT_FLAGS=-O3)

debug_set:
	$(eval OPT_FLAGS=-g3)
	$(eval ENABLE_BACKTRACE=-DENABLE_BACKTRACE)

server: src/dev_server/ssl_helper.c src/dev_server/server.c src/3dparty/sds/sds.c src/dev_server/ssl_helper.h  src/3dparty/sds/sds.h
	gcc ${OPT_FLAGS} src/dev_server/ssl_helper.c src/dev_server/server.c src/3dparty/sds/sds.c -o bin/server -lssl -lcrypto

cwf:
	cd src/ && $(MAKE) EXTRA_C_FLAGS=${OPT_FLAGS} && cd -

clean:
	rm bin/server
	cd src/ && $(MAKE) clean & cd -
