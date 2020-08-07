# Set OPENSSL_INCLUDE to the directory that contains the
# "openssl" include directory.

OPENSSL_INCLUDE = /usr/include

# To build without openssl comment out the "CRYPT =" line


CRYPT = crypt.o

CFLAGS = $(EXTRA_C_FLAGS) -D_DEFAULT_SOURCE -std=c99 -I . -I $(OPENSSL_INCLUDE)

libcwf.a: cwf.o ctemplate.o ccgi.o prefork.o json.o $(CRYPT)
	ar r libcwf.a cwf.o ctemplate.o ccgi.o prefork.o json.o $(CRYPT)
	ranlib libcwf.a

cwf.o: cwf.c cwf.h

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

clean:
	rm -f *.o *.a */*.o