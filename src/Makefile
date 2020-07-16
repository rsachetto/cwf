# Set OPENSSL_INCLUDE to the directory that contains the
# "openssl" include directory.

OPENSSL_INCLUDE = /usr/include

# To build without openssl comment out the "CRYPT =" line


CRYPT = crypt.o

CFLAGS = -std=c99 -I . -I $(OPENSSL_INCLUDE)

libcwf.a: cwf.o ctemplate.o ccgi.o prefork.o $(CRYPT)
	ar r libcwf.a cwf.o ctemplate.o ccgi.o prefork.o $(CRYPT)
	ranlib libcwf.a

cwf.o: cwf.c cwf.h

ccgi.o: 3dparty/ccgi-1.2/ccgi.c 3dparty/ccgi-1.2/ccgi.h

prefork.o: 3dparty/ccgi-1.2/prefork.c

crypt.o: 3dparty/ccgi-1.2/crypt.c 3dparty/ccgi-1.2/ccgi.h

ctemplate.o: 3dparty/ctemplate-1.0/ctemplate.c 3dparty/ctemplate-1.0/ctemplate.h

clean:
	rm -f *.o *.a */*.o
