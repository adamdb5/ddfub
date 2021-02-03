CC=clang
CFLAGS=-Wall -pedantic -Os -g `pkg-config libcrypto --cflags` `pkg-config cmocka --cflags`
LIBS=`pkg-config libcrypto --libs` `pkg-config cmocka --libs`

all:
	$(CC) $(CFLAGS) $(LIBS) blockchain_test.c ../blockchain.c -o blockchain_test
