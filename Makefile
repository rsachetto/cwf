PHONY = release debug debug_cgi

all: release 

debug: debug_set server
release: release_set server

release_set:
	$(eval OPT_FLAGS=-O3)

debug_set:
	$(eval OPT_FLAGS=-g3)

server:
	gcc ${OPT_FLAGS} src/dev_server/server.c src/3dparty/sds/sds.c -o bin/server

clean:
	rm bin/server
