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
	paxmacho.c \
	xfuncs.c
LDADD = libpaxutils.la $(top_builddir)/autotools/gnulib/libgnu.a

bin_SCRIPTS = lddtree symtree
bin_PROGRAMS = scanelf dumpelf pspax scanmacho

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
dist_man_MANS += 
EXTRA_DIST += \
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
	tests/source/space
# @@@ GEN START @@@ #
