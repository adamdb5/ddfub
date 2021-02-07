SRCS=main.c socket.c blockchain.c
CFLAGS=-Wall -pedantic --std=c89
INCLUDE=-I/usr/local/include -I/pkg/include
LIBS=-L/usr/local/lib -L/pkg/lib -lcrypto

EXE=main

unix:
	clang $(SRCS) $(CFLAGS) $(INCLUDE) $(LIBS) -o $(EXE)

win:
	x86_64-w64-mingw32-gcc $(SRCS) $(CFLAGS) -lws2_32 -o $(EXE)

clean:
	rm main
	rm main.exe
