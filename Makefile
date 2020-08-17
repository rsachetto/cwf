all:
	cd src/ &&  $(MAKE) && cd ..
	gcc main.c src/libcwf.a -o cwf.cgi -ldl -lpthread -lssl -lcrypto
	gcc src/endpoints.c -fPIC -shared -o libendpoints.so -Lsrc -lcwf -lssl -lcrypto

debug:
	cd src/ &&  $(MAKE) EXTRA_C_FLAGS=-g  && cd ..
	gcc -g -DGDB_DEBUG main.c src/libcwf.a -o cwf.cgi -ldl -lpthread -lssl -lcrypto
	gcc -g src/endpoints.c -fPIC -shared -o libendpoints.so -Lsrc -lcwf -lssl -lcrypto

clean:
	rm *.so
	rm cwf.cgi
	cd src/ &&  $(MAKE) clean  && cd ..
	


