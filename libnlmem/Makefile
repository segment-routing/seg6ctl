CC=gcc
CFLAGS=-I. -g -Wall -W -I/usr/include/libnl3
DEPS = nlmem.c nlmem.h
OBJ = nlmem.o

$(OBJ): $(DEPS)
	$(CC) -c $< $(CFLAGS)

all: nlmem.o

clean:
	rm $(OBJ)