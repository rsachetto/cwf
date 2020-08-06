
all:
	cd src/ &&  $(MAKE) && cd ..
	gcc -g main.c src/libcwf.a -o cwf.cgi
	cp cwf.cgi /usr/lib/cgi-bin/

