PDFS := $(wildcard *.pdf)
MDS := $(wildcard *.md)
FINAL := $(shell basename "$(CURDIR)").pdf

all : $(MDS)
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

bad: bad.c
	gcc bad.c -o bad

badasan: bad.c
	clang -O1 -g -fsanitize=address -fno-omit-frame-pointer bad.c -o badasan

clean:
	rm -rf $(PDFS)
