
all:
	cd src/3dparty/ccgi-1.2/ &&  $(MAKE) && cd ..
	gcc src/cwf.c src/3dparty/ccgi-1.2/libccgi.a -o cwf.cgi
	cp cwf.cgi /usr/pkg/libexec/cgi-bin/

