CC=clang
CFLAGS=-Wall -pedantic --std=c89 -O3 
LIBS=-lrt

all:	     com

com:	     ../ipc.c ipc_com.c
	     $(CC) ../ipc.c ipc_com.c -o com $(CFLAGS) $(LIBS)

clean:
	rm com
