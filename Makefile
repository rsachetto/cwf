
all:
	cd src/ &&  $(MAKE) && cd ..
	gcc main.c src/libcwf.a -o cwf.cgi
	cp cwf.cgi /usr/pkg/libexec/cgi-bin/

