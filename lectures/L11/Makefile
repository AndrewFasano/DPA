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
	--listings \
	--toc

clean:
	rm -rf $(PDFS)
