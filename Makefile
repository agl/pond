TARGET = pond
PSPICFILES = 

INPUT_SOURCES = $(shell cat $(TARGET).tex | grep -v ^[\t\ ]*% | grep input\{ | cut -d{ -f2 | cut -d} -f1)
INCLUDE_SOURCES = $(shell cat $(TARGET).tex | grep -v ^[\t\ ]*% | grep include\{ | cut -d{ -f2 | cut -d} -f1)

SOURCES = \
	$(TARGET).tex \
	$(INPUT_SOURCES:%=%.tex) \
	$(INCLUDE_SOURCES:%=%.tex)

$(TARGET).pdf: $(TARGET).tex $(SOURCES)
	pdflatex $(TARGET).tex

pspics: $(PSPICFILES)
	-latex $(TARGET).tex
	-dvips -o $(TARGET)-pics.ps $(TARGET).dvi
	-ps2pdf $(TARGET)-pics.ps

clean:
	rm -f $(TARGET).ps $(TARGET).dvi
	rm -f $(TARGET).ind $(TARGET).toc $(TARGET).bbl $(TARGET).blg $(TARGET).ilg $(TARGET).idx $(TARGET).log $(TARGET).out $(TARGET).snm $(TARGET).nav
	rm -f $(SOURCES:%.tex=%.aux)
	rm -f $(TARGET)-pics*
	rm -f $(TARGET).pdf
