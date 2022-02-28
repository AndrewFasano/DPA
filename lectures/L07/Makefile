PDFS := $(wildcard *.pdf)
MDS := $(wildcard *.md)
FINAL := $(shell basename "$(CURDIR)").pdf

all : $(MDS) bug stack heapbug
	pandoc \
	$(MDS) \
	-o $(FINAL) \
	-t beamer \
	-V colorlinks=true \
	-V urlcolor=Maroon \
	-V colortheme=seahorse \
	-V theme=Berlin \
	-V monofont=Consolas \
	-V classoption=dvipsnames \
	--toc

bug: bug.c
	gcc bug.c -g -o bug

stack: stack.c
	gcc stack.c -g -o stack

heapbug: heapbug.c
	gcc heapbug.c -g -o heapbug

clean:
	rm -rf $(PDFS)
