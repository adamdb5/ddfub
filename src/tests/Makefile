CC=clang
CFLAGS=-Wall -pedantic -g
INCLUDE=
LIBS=-lcmocka -lcrypto

all:	blockchain_test \
	socket_test \
	network_test

blockchain_test:	blockchain_test.c ../blockchain.c
	$(CC) $(CFLAGS) $(INCLUDE) $(LIBS) blockchain_test.c ../blockchain.c -o blockchain_test

socket_test:		socket_test.c ../socket.c
	$(CC) $(CFLAGS) $(INCLUDE) $(LIBS) socket_test.c ../socket.c -o socket_test

network_test:		network_test.c ../socket.c ../net.c
	$(CC) $(CFLAGS) $(INCLUDE) $(LIBS) network_test.c ../socket.c ../net.c -o network_test

clean:
	rm blockchain_test
	rm socket_test
	rm network_test
