#
# Makefile for compiling paper notes
#

PDFS = $(patsubst %.tex,%.pdf,$(wildcard *.tex))

all: $(PDFS)

%.pdf: %.tex %.bib
	pdflatex $<
	bibtex $(basename $<)
	pdflatex $<
	pdflatex $<
	@make clean

clean:
	-@rm -f *.aux *.log *.toc *.out *.bbl *.blg

.PHONY: all clean
