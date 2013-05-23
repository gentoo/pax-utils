# Copyright 2003-2006 Ned Ludd <solar@linbsd.net>
# Distributed under the terms of the GNU General Public License v2
# $Header: /var/cvsroot/gentoo-projects/pax-utils/Makefile,v 1.83 2013/05/23 00:09:01 vapier Exp $
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

# Some fun settings
#CFLAGS   += -DEBUG -g
#LDFLAGS  += -pie

ifeq ($(USE_CAP),yes)
CPPFLAGS-pspax.c += -DWANT_SYSCAP
LIBS-pspax       += -lcap
endif

ifdef PV
override CPPFLAGS  += -DVERSION=\"$(PV)\"
endif

####################################################################
ELF_TARGETS  = scanelf dumpelf $(shell echo | $(CC) -dM -E - | grep -q __svr4__ || echo pspax)
ELF_OBJS     = paxelf.o
MACH_TARGETS = scanmacho
MACH_OBJS    = paxmacho.o
COMMON_OBJS  = paxinc.o xfuncs.o
TARGETS      = $(ELF_TARGETS) $(MACH_TARGETS)
OBJS         = $(ELF_OBJS) $(MACH_OBJS) $(COMMON_OBJS) $(TARGETS:%=%.o)
MPAGES       = $(TARGETS:%=man/%.1)
SOURCES      = $(OBJS:%.o=%.c)

all: $(OBJS) $(TARGETS)
	@:

DEBUG_FLAGS = \
	-nopie \
	-fsanitize=address
debug: clean
	$(MAKE) CFLAGS="$(CFLAGS) -g3 -ggdb $(call check_gcc_many,$(DEBUG_FLAGS))" all
	@-chpax  -permsx $(ELF_TARGETS)
	@-paxctl -permsx $(ELF_TARGETS)

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
	for sh in *.sh ; do $(INS_EXE) $$sh $(PREFIX)/bin/$${sh%.sh} || exit $$? ; done
ifeq ($(USE_PYTHON),yes)
	for py in *.py ; do $(INS_EXE) $$py $(PREFIX)/bin/$${py%.py} || exit $$? ; done
endif
	$(INS_EXE) $(TARGETS) $(PREFIX)/bin/
	$(INS_DATA) README BUGS TODO $(PKGDOCDIR)/
	$(INS_DATA) $(MPAGES) $(MANDIR)/man1/

PN = pax-utils
P = $(PN)-$(PV)
dist:
	@if [ "$(PV)" = "" ] ; then \
		echo "Please run 'make dist PV=<ver>'" ; \
		exit 1 ; \
	fi
	rm -rf $(P)
	mkdir $(P)
	cp -a CVS $(P)/
	cd $(P) && cvs up
	echo "<releaseinfo>$(PV)</releaseinfo>" > $(P)/man/fragment/version
	$(MAKE) -C $(P)/man
	tar cf - $(P) --exclude=CVS --exclude=.cvsignore | xz > $(P).tar.xz
	@printf "\n ..... Making sure clean cvs build works ..... \n\n"
	unset CFLAGS; \
	for t in all check clean debug check ; do \
		$(MAKE) -C $(P) $$t || exit $$? ; \
	done
	rm -rf $(P)
	du -b $(P).tar.xz

-include .depend

check test:
	$(MAKE) -C tests

.PHONY: all check clean dist install test
