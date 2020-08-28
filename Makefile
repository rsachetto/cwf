server:
	gcc -g src/dev_server/server.c src/3dparty/sds/sds.c -o bin/server

todo: cwf
	gcc -g todo_list/endpoints.c -fPIC -shared -o todo_list/lbendpoints.so -Lsrc -lcwf -lssl -lcrypto
	mv cwf.cgi todo_list/cgi-bin/

blog: cwf
	gcc -g blog/endpoints.c -fPIC -shared -o blog/libendpoints.so -Lsrc -lcwf -lssl -lcrypto
	mv cwf.cgi blog/cgi-bin/

cwf:
	cd src/ &&  $(MAKE) EXTRA_C_FLAGS=-g && cd ..
	#gcc -DGDB_DEBUG -g main.c src/libcwf.a -o cwf.cgi -ldl -lpthread -lssl -lcrypto
	gcc -g main.c src/libcwf.a -o cwf.cgi -ldl -lpthread -lssl -lcrypto

clean:
	cd src/ &&  $(MAKE) clean  && cd ..
	


