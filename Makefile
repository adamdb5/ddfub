SRCS=main.c socket.c
CFLAGS=-Wall --std=c89
EXE=main

unix:
	clang $(SRCS) $(CFLAGS) -o $(EXE)

win:
	x86_64-w64-mingw32-gcc $(SRCS) $(CFLAGS) -lws2_32 -o $(EXE)

clean:
	rm main
	rm main.exe
