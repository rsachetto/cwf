
all:
	cd src/ &&  $(MAKE) && cd ..
	gcc main.c src/libcwf.a -o cwf.cgi -ldl
	cp cwf.cgi /usr/lib/cgi-bin/
	gcc endpoints.c -fPIC -shared -o libendpoints.so

debug:
	cd src/ &&  $(MAKE) EXTRA_C_FLAGS=-g  && cd ..
	gcc -g main.c src/libcwf.a -o cwf.cgi -ldl
	cp cwf.cgi /usr/lib/cgi-bin/
	gcc -g endpoints.c -fPIC -shared -o libendpoints.so

clean:
	rm *.so
	rm cwf.cgi
	cd src/ &&  $(MAKE) clean  && cd ..
	


