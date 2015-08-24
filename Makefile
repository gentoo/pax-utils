# Copyright 2003-2006 Ned Ludd <solar@linbsd.net>
# Distributed under the terms of the GNU General Public License v2
####################################################################

check_gcc = $(shell if $(CC) $(1) -S -o /dev/null -xc /dev/null > /dev/null 2>&1; \
	then echo "$(1)"; else echo "$(2)"; fi)
check_gcc_many = $(foreach flag,$(1),$(call check_gcc,$(flag)))

####################################################################
# Avoid CC overhead when installing
ifneq ($(MAKECMDGOALS),install)
_WFLAGS   := \
	-Wdeclaration-after-statement \
	-Wextra \
	-Wsequence-point \
	-Wstrict-overflow
WFLAGS    := -Wall -Wunused -Wimplicit -Wshadow -Wformat=2 \
             -Wmissing-declarations -Wmissing-prototypes -Wwrite-strings \
             -Wbad-function-cast -Wnested-externs -Wcomment -Winline \
             -Wchar-subscripts -Wcast-align -Wno-format-nonliteral \
             $(call check_gcc_many,$(_WFLAGS))
endif

CFLAGS    ?= -O2 -pipe
override CPPFLAGS  += -D_GNU_SOURCE -D_FILE_OFFSET_BITS=64
LDFLAGS   +=
LIBS      :=
DESTDIR    =
PREFIX     = $(DESTDIR)/usr
DATADIR    = $(PREFIX)/share
MANDIR     = $(DATADIR)/man
DOCDIR     = $(DATADIR)/doc
PKGDOCDIR  = $(DOCDIR)/pax-utils
STRIP     := strip
MKDIR     := mkdir -p
INS_EXE   := install -m755
INS_DATA  := install -m644

PKG_CONFIG ?= pkg-config

ifeq ($(USE_CAP),yes)
LIBCAPS_CFLAGS := $(shell $(PKG_CONFIG) --cflags libcap)
LIBCAPS_LIBS   := $(shell $(PKG_CONFIG) --libs libcap)
CPPFLAGS-pspax.c += $(LIBCAPS_CFLAGS) -DWANT_SYSCAP
LIBS-pspax       += $(LIBCAPS_LIBS)
endif

ifeq ($(USE_DEBUG),yes)
override CPPFLAGS += -DEBUG
endif

ifeq ($(USE_SECCOMP),yes)
LIBSECCOMP_CFLAGS := $(shell $(PKG_CONFIG) --cflags libseccomp)
LIBSECCOMP_LIBS   := $(shell $(PKG_CONFIG) --libs libseccomp)
override CPPFLAGS += $(LIBSECCOMP_CFLAGS) -DWANT_SECCOMP
LIBS              += $(LIBSECCOMP_LIBS)
endif

ifdef PV
override CPPFLAGS  += -DVERSION=\"$(PV)\"
else
VCSID     := $(shell git describe --tags HEAD)
endif
override CPPFLAGS  += -DVCSID='"$(VCSID)"'

####################################################################
ELF_TARGETS  = scanelf dumpelf $(shell echo | $(CC) -dM -E - | grep -q __svr4__ || echo pspax)
ELF_OBJS     = paxelf.o
MACH_TARGETS = scanmacho
MACH_OBJS    = paxmacho.o
COMMON_OBJS  = paxinc.o security.o xfuncs.o
TARGETS      = $(ELF_TARGETS) $(MACH_TARGETS)
SCRIPTS_SH   = lddtree symtree
SCRIPTS_PY   = lddtree
OBJS         = $(ELF_OBJS) $(MACH_OBJS) $(COMMON_OBJS) $(TARGETS:%=%.o)
MPAGES       = $(TARGETS:%=man/%.1)
SOURCES      = $(OBJS:%.o=%.c)

all: $(OBJS) $(TARGETS)
	@:

DEBUG_FLAGS = \
	-nopie \
	-fsanitize=address \
	-fsanitize=leak \
	-fsanitize=undefined
debug: clean
	$(MAKE) CFLAGS="$(CFLAGS) -g3 -ggdb $(call check_gcc_many,$(DEBUG_FLAGS))" all
	@-chpax  -permsx $(ELF_TARGETS)
	@-paxctl -permsx $(ELF_TARGETS)

fuzz: clean
	$(MAKE) AFL_HARDEN=1 CC=afl-gcc all
	@rm -rf findings
	@printf '\nNow run:\n%s\n' \
		"afl-fuzz -t 100 -i tests/fuzz/small/ -o findings/ ./scanelf -s '*' -axetrnibSDIYZB @@"

compile.c = $(CC) $(CFLAGS) $(CPPFLAGS) $(CPPFLAGS-$<) -o $@ -c $<

ifeq ($(V),)
Q := @
else
Q :=
endif
%.o: %.c
ifeq ($(V),)
	@echo $(compile.c)
endif
	$(Q)$(compile.c) $(WFLAGS)

$(ELF_TARGETS): %: $(ELF_OBJS) $(COMMON_OBJS) %.o
	$(CC) $(CFLAGS) $(LDFLAGS) $^ -o $@ $(LIBS) $(LIBS-$@)

$(MACH_TARGETS): %: $(MACH_OBJS) $(COMMON_OBJS) %.o
	$(CC) $(CFLAGS) $(LDFLAGS) $^ -o $@ $(LIBS) $(LIBS-$@)

%.so: %.c
	$(CC) -shared -fPIC -o $@ $<

depend:
	$(CC) $(CFLAGS) -MM $(SOURCES) > .depend

clean:
	-rm -f $(OBJS) $(TARGETS)

distclean: clean
	-rm -f *~ core *.o
	-cd man && $(MAKE) clean
strip: all
	$(STRIP) $(TARGETS)
strip-more:
	$(STRIP) --strip-unneeded $(TARGETS)

install: all
	$(MKDIR) $(PREFIX)/bin/ $(MANDIR)/man1/ $(PKGDOCDIR)/
	for sh in $(SCRIPTS_SH) ; do $(INS_EXE) $$sh.sh $(PREFIX)/bin/$$sh || exit $$? ; done
ifneq ($(USE_PYTHON),no)
	for py in $(SCRIPTS_PY) ; do $(INS_EXE) $$py.py $(PREFIX)/bin/$$py || exit $$? ; done
endif
	$(INS_EXE) $(TARGETS) $(PREFIX)/bin/
	$(INS_DATA) README BUGS TODO $(PKGDOCDIR)/
	$(INS_DATA) $(MPAGES) $(MANDIR)/man1/

PN = pax-utils
P = $(PN)-$(PV)
dist:
	./make-tarball.sh $(DISTCHECK) $(PV)
distcheck:
	$(MAKE) dist DISTCHECK=--check

-include .depend

check test:
	$(MAKE) -C tests

.PHONY: all check clean dist install test

#
# All logic related to autotools is below here
#
GEN_MARK_START = \# @@@ GEN START @@@ \#
GEN_MARK_END   = \# @@@ GEN END @@@ \#
EXTRA_DIST     = $(shell git ls-files)
autotools-update:
	$(MAKE) -C man -j
	sed -i '/^$(GEN_MARK_START)$$/,/^$(GEN_MARK_END)$$/d' Makefile.am
	( \
		echo "$(GEN_MARK_START)"; \
		printf 'dist_man_MANS +='; \
		printf ' \\\n\t%s' $(wildcard man/*.1); \
		echo; \
		printf 'EXTRA_DIST +='; \
		printf ' \\\n\t%s' $(EXTRA_DIST); \
		echo; \
		echo "$(GEN_MARK_END)"; \
	) >> Makefile.am
autotools:
ifeq ($(SKIP_AUTOTOOLS_UPDATE),)
	$(MAKE) autotools-update
endif
	./autogen.sh --from=make

.PHONY: autotools autotools-update _autotools-update
