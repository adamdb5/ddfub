CC=clang
CFLAGS=-Wall
LIBS=-lrt

all:	send recv

send:	ipc_send.c
	$(CC) $(CFLAGS) ipc_send.c $(LIBS) -o send

recv:	ipc_recv.c
	$(CC) $(CFLAGS) ipc_recv.c $(LIBS) -o recv

clean:
	rm send
	rm recv
