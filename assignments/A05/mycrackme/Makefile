CFLAGS=-g -O0
CC=g++

all: shellcode.o mycrackme.o
	$(CC) mycrackme.o shellcode.o -o mycrackme

shellcode.o: shellcode.s
	as -o shellcode.o shellcode.s

mycrackme.o: mycrackme.c
	$(CC) -c mycrackme.c -o mycrackme.o $(CFLAGS)

clean:
	rm -f mycrackme.o shellcode.o mycrackme
