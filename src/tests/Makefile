CC=clang
CFLAGS=-Wall -pedantic
INCLUDE=-I/usr/local/include
LIBS=-L/usr/local/lib -lcrypto -lcmocka

all:
	$(CC) $(CFLAGS) $(INCLUDE) $(LIBS) blockchain_test.c ../blockchain.c -o blockchain_test


win:
	x86_64-w64-mingw32-gcc $(SRCS) $(CFLAGS) $(INCLUDE) $(LIBS) -lcmocka -lcrypto -lws2_32 -o blockchain_test
