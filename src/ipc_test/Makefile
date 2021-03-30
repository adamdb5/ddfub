CC=clang
CFLAGS=-Wall -pedantic --std=c89 -O3 -c

all:	     com

com:	     ../ipc.c ipc_com.c
	     $(CC) ../ipc.c ipc_com.c -o com -lrt

clean:
	del *.o
	del dfw
