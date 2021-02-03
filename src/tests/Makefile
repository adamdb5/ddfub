CC=clang
CFLAGS=-Wall -pedantic -Os -g
LIBS=-lcmocka -lcrypto

all:
	$(CC) $(CFLAGS) $(LIBS) blockchain_test.c ../blockchain.c -o blockchain_test
