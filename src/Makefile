CC=clang
SOURCES=main.c socket.c net.c ipc.c blockchain.c
OBJECTS=main.o socket.o net.o ipc.o blockchain.o
CFLAGS=-Wall -pedantic --std=c89 -O3 -c
INCLUDE=
LIBS=-lrt -lcrypto

dfw:	$(OBJECTS)
	$(CC) $(INCLUDE) -o dfw $(OBJECTS) $(LIBS)
	strip dfw

%.o:	%.c
	$(CC) $(CFLAGS) $(INCLUDE) $< $(LIBS) -o $@
	
clean:
	rm *.o
	rm dfw
