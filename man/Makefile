all: man

XMLTO_FLAGS_man = -x custom.xsl
man pdf txt xhtml xhtml-nochunks:
	@xmlto $@ $(XMLTO_FLAGS_$@) pax-utils.docbook || echo "If this failed, you probably need to emerge ~app-text/docbook-xml-dtd-4.4 app-text/xmlto dev-tex/xmltex"
clean distclean:
	rm -f *.1 *.html

.PHONY: all clean distclean \
        man pdf txt xhtml xhtml-nochunks
