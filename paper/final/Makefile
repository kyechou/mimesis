#
# Makefile for compiling paper notes
#

TARGET = report.pdf
SOURCE = $(shell find . -type f -name '*.tex')
STYLE  = $(wildcard *.sty)

all: $(TARGET)

%.pdf: %.tex %.bib $(SOURCE) $(STYLE)
	pdflatex $<
	bibtex $(basename $<)
	pdflatex $<
	pdflatex $<
	@make clean

clean:
	-@rm -f *.aux *.log *.toc *.out *.bbl *.blg

.PHONY: all clean
