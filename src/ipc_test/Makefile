CC=clang
CFLAGS=-Wall
LIBS=
LLIBS=-lrt

all:	send recv

send:	ipc_send.c
	$(CC) $(CFLAGS) ipc_send.c $(LIBS) -o send.exe

recv:	ipc_recv.c
	$(CC) $(CFLAGS) ipc_recv.c $(LIBS) -o recv.exe

clean:
	del send.exe
	del recv.exe
