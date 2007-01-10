all: man

XMLTO_FLAGS_man = -x custom.xsl
man pdf txt xhtml xhtml-nochunks:
	xmlto $@ $(XMLTO_FLAGS_$@) pax-utils.docbook

clean distclean:
	rm -f *.1 *.html

.PHONY: all distclean xhtml man
