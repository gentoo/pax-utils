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
LDADD = libpaxutils.la

bin_PROGRAMS = scanelf dumpelf pspax scanmacho

install-exec-hook:
	cd $(DESTDIR)$(bindir); \
	for applet in $(APPLETS) ; do \
		[ ! -e "$$applet" ] && ln -s q $${applet} ; \
	done

TMAKE = \
	$(MAKE) -C $(abs_top_srcdir)/tests \
		AUTOTOOLS=true \
		abs_top_builddir="$(abs_top_builddir)" \
		abs_top_srcdir="$(abs_top_srcdir)"
check-hook:
	$(TMAKE) check
clean-local:
	$(TMAKE) clean
	-rmdir tests/*/ tests/
	rm -f $(APPLETS)
check: check-hook

# Start off with base values which we append below
dist_man_MANS =
APPLETS =
EXTRA_DIST = autotools/m4/gnulib-cache.m4

# @@@ GEN START @@@ #
dist_man_MANS += 
EXTRA_DIST += \
	tests/CVS/Entries \
	tests/CVS/Repository \
	tests/CVS/Root \
	tests/Makefile \
	tests/lddtree/CVS/Entries \
	tests/lddtree/CVS/Repository \
	tests/lddtree/CVS/Root \
	tests/lddtree/Makefile \
	tests/lddtree/dotest.cmp \
	tests/lddtree/dotest.py \
	tests/lddtree/dotest.sfx \
	tests/lddtree/dotest.sh \
	tests/lib.sh \
	tests/scanelf/CVS/Entries \
	tests/scanelf/CVS/Repository \
	tests/scanelf/CVS/Root \
	tests/scanelf/Makefile \
	tests/scanelf/dotest \
	tests/scanelf/scanelf.simple.good \
	tests/source/CVS/Entries \
	tests/source/CVS/Repository \
	tests/source/CVS/Root \
	tests/source/Makefile \
	tests/source/dotest \
	tests/source/space
# @@@ GEN START @@@ #
