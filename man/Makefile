all: man

XMLTO_FLAGS_man = -x custom.xsl
man pdf txt xhtml xhtml-nochunks:
	@echo "If this fails, you probably need to emerge ~app-text/docbook-xml-dtd-4.4"
	xmlto $@ $(XMLTO_FLAGS_$@) pax-utils.docbook

clean distclean:
	rm -f *.1 *.html

.PHONY: all clean distclean \
        man pdf txt xhtml xhtml-nochunks
