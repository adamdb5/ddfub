CC=clang
OBJECTS=main.o socket.o net.o ipc.o blockchain.o
CFLAGS=-Wall -pedantic --std=c89 -O3 -c
INCLUDE=
LIBS=-lrt -lcrypto

dfw:	$(OBJECTS)
	$(CC) -o dfw $(OBJECTS) $(LIBS)
	strip dfw

%.o:	%.c
	$(CC) $(CFLAGS) $(INCLUDE) $< -o $@
	
clean:
	rm *.o
	rm dfw
