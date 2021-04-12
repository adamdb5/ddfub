CC=clang
CFLAGS=-Wall -pedantic --std=c89 -O3 
LIBS=-lrt

client:	../ipc.c client.c
	$(CC) ../ipc.c client.c -o client $(CFLAGS) $(LIBS)

clean:
	rm client
