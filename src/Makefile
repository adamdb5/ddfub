SRCS=main.c socket.c blockchain.c
CFLAGS=-Wall -pedantic --std=c89 -Os `pkg-config libcrypto --cflags`
LIBS=`pkg-config libcrypto --libs`
EXE=main

unix:
	clang $(SRCS) $(CFLAGS) $(LIBS) -o $(EXE)

win:
	x86_64-w64-mingw32-gcc $(SRCS) $(CFLAGS) -lws2_32 -o $(EXE)

clean:
	rm main
	rm main.exe
