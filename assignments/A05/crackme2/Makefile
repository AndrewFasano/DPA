CFLAGS=-O2
CC=g++

all: shellcode.o crackme2.o
	$(CC) crackme2.o shellcode.o -o crackme2

shellcode.o: shellcode.s
	as -o shellcode.o shellcode.s

crackme2.o: crackme2.c
	$(CC) -c crackme2.c -o crackme2.o $(CFLAGS)

clean:
	rm -f crackme2.o shellcode.o crackme2
