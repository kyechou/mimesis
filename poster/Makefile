#
# Makefile for compiling paper notes
#

PDFS = $(patsubst %.tex,%.pdf,$(wildcard *.tex))
STYS = $(wildcard *.sty)

all: $(PDFS)

%.pdf: %.tex %.bib $(STYS)
	pdflatex $<
	bibtex $(basename $<)
	pdflatex $<
	pdflatex $<
	@make clean

clean:
	-@rm -f *.aux *.log *.toc *.out *.bbl *.blg *.snm *.nav

.PHONY: all clean
