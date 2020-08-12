
all:
	cd src/ &&  $(MAKE) && cd ..
	gcc main.c src/libcwf.a -o cwf.cgi -ldl
	#cp cwf.cgi /usr/lib/cgi-bin/
	gcc src/endpoints.c -fPIC -shared -o libendpoints.so -Lsrc -lcwf

debug:
	cd src/ &&  $(MAKE) EXTRA_C_FLAGS=-g  && cd ..
	gcc -g -DGDB_DEBUG main.c src/libcwf.a -o cwf.cgi -ldl
	#cp cwf.cgi /usr/lib/cgi-bin/
	gcc -g src/endpoints.c -fPIC -shared -o libendpoints.so

clean:
	rm *.so
	rm cwf.cgi
	cd src/ &&  $(MAKE) clean  && cd ..
	


