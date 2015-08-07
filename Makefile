all:
	cd libseg6 && gcc -c seg6.c -g -Wall -W -I/usr/include/libnl3 && cd ..
	gcc -o seg6ctl seg6ctl.c libseg6/seg6.o -g -Wall -W -Ilibseg6 -I/usr/include/libnl3 -lnl-3 -lnl-genl-3
