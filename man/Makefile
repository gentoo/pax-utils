all: man

XMLTO_FLAGS_man = -x custom.xsl --skip-validation
man pdf txt xhtml xhtml-nochunks:
	@xmlto $@ $(XMLTO_FLAGS_$@) pax-utils.docbook || echo "If this failed, you probably need to emerge ~app-text/docbook-xml-dtd-4.4 app-text/xmlto dev-tex/xmltex"
	@# scanelf.1 has funky indented lists ... hack it back
	@sed -i.tmp 's:^[.]TP 4:.TP 2:' scanelf.1
	@rm scanelf.1.tmp
clean distclean:
	rm -f *.1 *.html

.PHONY: all clean distclean \
        man pdf txt xhtml xhtml-nochunks
