PDFS := $(wildcard *.pdf)
MDS := $(wildcard *.md)
FINAL := $(shell basename "$(CURDIR)").pdf

all : $(MDS)
	pandoc \
	$(MDS) \
	-o $(FINAL) \
	-t beamer \
	-V colortheme:seahorse \
	-V theme:Berlin \
	-V monofont=Consolas \
	--toc

clean:
	rm -rf $(PDFS)
