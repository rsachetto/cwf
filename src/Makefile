# Set OPENSSL_INCLUDE to the directory that contains the
# "openssl" include directory.

OPENSSL_INCLUDE = /usr/include

# To build without openssl comment out the "CRYPT =" line
CRYPT = crypt.o

CFLAGS = -fPIC $(EXTRA_C_FLAGS) -D_DEFAULT_SOURCE -std=c99 -I . -I $(OPENSSL_INCLUDE)

OBJS = debug_helper.o cwf.o session.o http.o cookie.o ctemplate.o ccgi.o prefork.o json.o ini.o ini_parse.o sqlite3.o sds.o
libcwf.a: $(OBJS) $(CRYPT)
	ar r libcwf.a $(OBJS) $(CRYPT)
	ranlib libcwf.a

debug_helper.o: cwf/debug_helper.c cwf/debug_helper.h
	gcc $(CFLAGS) -c cwf/debug_helper.c

cwf.o: cwf/cwf.c cwf/cwf.h 
	gcc $(CFLAGS) -c cwf/cwf.c

cookie.o: cwf/cookie.c cwf/cookie.h
	gcc $(CFLAGS) -c cwf/cookie.c

session.o: cwf/session.o cwf/session.h
	gcc $(CFLAGS) -c cwf/session.c

http.o: cwf/http.o cwf/http.h
	gcc $(CFLAGS) -c cwf/http.c

ini_parse.o: ini_parse/ini_parse.c ini_parse/ini_parse.h
	gcc $(CFLAGS) -c ini_parse/ini_parse.c

ctemplate.o: 3dparty/ctemplate-1.0/ctemplate.c 3dparty/ctemplate-1.0/ctemplate.h
	gcc $(CFLAGS) -c 3dparty/ctemplate-1.0/ctemplate.c

ccgi.o: 3dparty/ccgi-1.2/ccgi.c 3dparty/ccgi-1.2/ccgi.h
	gcc $(CFLAGS) -c 3dparty/ccgi-1.2/ccgi.c

prefork.o: 3dparty/ccgi-1.2/prefork.c
	gcc $(CFLAGS) -c 3dparty/ccgi-1.2/prefork.c

crypt.o: 3dparty/ccgi-1.2/crypt.c 3dparty/ccgi-1.2/ccgi.h
	gcc $(CFLAGS) -c  3dparty/ccgi-1.2/crypt.c

json.o: 3dparty/json/json.c 3dparty/json/json.h
	gcc $(CFLAGS) -c 3dparty/json/json.c

ini.o: 3dparty/ini/ini.c 3dparty/ini/ini.h
	gcc $(CFLAGS) -c 3dparty/ini/ini.c

sqlite3.o: 3dparty/sqlite/sqlite3.c 3dparty/sqlite/sqlite3.h
	gcc $(CFLAGS) -c 3dparty/sqlite/sqlite3.c

sds.o: 3dparty/sds/sds.c 3dparty/sds/sds.h
	gcc $(CFLAGS) -c 3dparty/sds/sds.c

clean:
	rm -f *.o *.a */*.o
