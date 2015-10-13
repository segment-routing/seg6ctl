all:
	cd libnlmem && gcc -c nlmem.c -g -Wall -W -I/usr/include/libnl3 && cd ..
	cd libseg6 && gcc -c seg6.c -g -Wall -W -I/usr/include/libnl3 -I../libnlmem && cd ..
	gcc -o seg6ctl seg6ctl.c libnlmem/nlmem.o libseg6/seg6.o -g -Wall -W -Ilibnlmem -Ilibseg6 -I/usr/include/libnl3 -lnl-3 -lnl-genl-3
	cd examples && gcc -o count count.c ../libnlmem/nlmem.o ../libseg6/seg6.o -g -Wall -W -I/usr/include/libnl3 -I../libnlmem -I../libseg6 -lnl-3 -lnl-genl-3 && cd ..
	cd examples && gcc -o count_sync count_sync.c ../libnlmem/nlmem.o ../libseg6/seg6.o -g -Wall -W -I/usr/include/libnl3 -I../libnlmem -I../libseg6 -lnl-3 -lnl-genl-3 && cd ..
	cd examples && gcc -o bindoverride bindoverride.c ../libnlmem/nlmem.o ../libseg6/seg6.o -g -Wall -W -I/usr/include/libnl3 -I../libnlmem -I../libseg6 -lnl-3 -lnl-genl-3 && cd ..

clean:
	rm -f seg6ctl *.o libseg6/*.o libnlmem/*.o examples/*.o examples/count examples/count_sync examples/bindoverride
