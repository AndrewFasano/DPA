all: hello.asm
	nasm -f elf32 -o hello.o hello.asm
	ld -melf_i386 -o hello hello.o
	cp hello hello.stripped && strip hello.stripped
