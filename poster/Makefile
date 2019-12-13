#
# Makefile for compiling paper notes
#

PDFS = $(patsubst %.tex,%.pdf,$(wildcard *.tex))
STYS = $(wildcard *.sty)

all: $(PDFS)

%.pdf: %.tex %.bib $(STYS)
	pdflatex $<
	@make clean

clean:
	-@rm -f *.aux *.log *.toc *.out *.bbl *.blg *.snm *.nav *.vrb

.PHONY: all clean
