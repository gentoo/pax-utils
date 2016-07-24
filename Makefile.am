ACLOCAL_AMFLAGS = -I autotools/m4

SUBDIRS = autotools/gnulib

AM_CPPFLAGS = \
	-I$(top_builddir)/autotools/gnulib \
	-I$(top_srcdir)/autotools/gnulib

noinst_LTLIBRARIES = libpaxutils.la
libpaxutils_la_LDFLAGS = -no-undefined
libpaxutils_la_SOURCES = \
	paxelf.c \
	paxinc.c \
	paxldso.c \
	paxmacho.c \
	security.c \
	xfuncs.c
LDADD = libpaxutils.la $(top_builddir)/autotools/gnulib/libgnu.a

bin_SCRIPTS = lddtree symtree
bin_PROGRAMS = scanelf dumpelf pspax scanmacho
CLEANFILES = $(bin_SCRIPTS)

if USE_PYTHON
lddtree: lddtree.py
else
lddtree: lddtree.sh
endif
	cp $< $@

symtree: symtree.sh
	cp $< $@

TMAKE = \
	$(MAKE) -C $(abs_top_srcdir)/tests \
		AUTOTOOLS=true \
		abs_top_builddir="$(abs_top_builddir)" \
		abs_top_srcdir="$(abs_top_srcdir)"
check-hook:
	$(TMAKE) check
check: check-hook

# Start off with base values which we append below
dist_man_MANS =
EXTRA_DIST = autotools/m4/gnulib-cache.m4

# @@@ GEN START @@@ #
dist_man_MANS += \
	man/dumpelf.1 \
	man/pspax.1 \
	man/scanelf.1 \
	man/scanmacho.1
EXTRA_DIST += \
	.depend \
	.gitignore \
	.travis.yml \
	BUGS \
	COPYING \
	Makefile \
	Makefile.am \
	README.md \
	TODO \
	autogen.sh \
	configure.ac \
	dumpelf.c \
	elf.h \
	lddtree.py \
	lddtree.sh \
	macho.h \
	make-tarball.sh \
	man/Makefile \
	man/custom.xsl \
	man/dumpelf.docbook \
	man/fragment/date \
	man/fragment/reftail \
	man/fragment/version \
	man/pax-utils.docbook \
	man/pspax.docbook \
	man/scanelf.docbook \
	man/scanmacho.docbook \
	paxelf.c \
	paxelf.h \
	paxinc.c \
	paxinc.h \
	paxldso.c \
	paxldso.h \
	paxmacho.c \
	paxmacho.h \
	porting.h \
	pspax.c \
	scanelf.c \
	scanmacho.c \
	security.c \
	security.h \
	symtree.sh \
	tests/Makefile \
	tests/lddtree/Makefile \
	tests/lddtree/dotest.cmp \
	tests/lddtree/dotest.py \
	tests/lddtree/dotest.sfx \
	tests/lddtree/dotest.sh \
	tests/lib.sh \
	tests/scanelf/Makefile \
	tests/scanelf/dotest \
	tests/scanelf/scanelf.simple.good \
	tests/source/Makefile \
	tests/source/dotest \
	tests/source/space \
	xfuncs.c \
	xfuncs.h
# @@@ GEN END @@@ #
