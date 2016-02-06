CC=gcc
CFLAGS=-I. -g -Wall -W -I/usr/include/libnl3 -I../libnlmem/
DEPS = seg6.c seg6.h
OBJ = seg6.o

$(OBJ): $(DEPS) libnlmem
	$(CC) -c $< $(CFLAGS)

libnlmem:
	make -C ../libnlmem/

all: libseg6.o

clean:
	rm $(OBJ)