#
# To use this on Debian:
#   apt-get install texlive-fonts-recommended texlive-base \
#     biblatex texlive-bibtex-extra texlive-extra-utils
#
# Then type `make` to produce the $PAPER
#

PAPER=panda
LATEX=pdflatex
BIBTEX=bibtex

SRCS=$(wildcard *.tex) $(wildcard *.sty)  $(wildcard *.bst)  $(wildcard *.pl)
REFS=$(wildcard *.bib)
FIGS=$(wildcard figures/*)

all: $(PAPER).pdf

$(PAPER).pdf: $(SRCS) $(REFS) $(FIGS)
	$(LATEX) $(PAPER)
	$(BIBTEX) $(PAPER)
	$(LATEX) $(PAPER)
	$(LATEX) $(PAPER)

evince: $(PAPER).pdf
	evince $(PAPER).pdf

clean:
	rm -f *.dvi *.aux *.log *.blg *.bbl $(PAPER).ps $(PAPER).pdf $(PAPER).out
