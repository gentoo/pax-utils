# Copyright 2003-2006 Ned Ludd <solar@linbsd.net>
# Distributed under the terms of the GNU General Public License v2
# $Header: /var/cvsroot/gentoo-projects/pax-utils/Makefile,v 1.75 2010/06/08 05:51:31 vapier Exp $
####################################################################

check_gcc=$(shell if $(CC) $(1) -S -o /dev/null -xc /dev/null > /dev/null 2>&1; \
	then echo "$(1)"; else echo "$(2)"; fi)

####################################################################
# Avoid CC overhead when installing
ifneq ($(MAKECMDGOALS),install)
WFLAGS    := -Wall -Wunused -Wimplicit -Wshadow -Wformat=2 \
             -Wmissing-declarations -Wmissing-prototypes -Wwrite-strings \
             -Wbad-function-cast -Wnested-externs -Wcomment -Winline \
             -Wchar-subscripts -Wcast-align -Wno-format-nonliteral \
             $(call check_gcc, -Wdeclaration-after-statement) \
             $(call check-gcc, -Wsequence-point) \
             $(call check-gcc, -Wstrict-overflow) \
             $(call check-gcc, -Wextra)
endif

CFLAGS    ?= -O2 -pipe
override CPPFLAGS  += -D_GNU_SOURCE
LDFLAGS   +=
LIBS      :=
DESTDIR    =
PREFIX    := $(DESTDIR)/usr
STRIP     := strip
MKDIR     := mkdir -p
CP        := cp
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

debug:
	$(MAKE) CFLAGS="$(CFLAGS) -g3 -ggdb $(call check-gcc,-nopie)" clean all
	@-/sbin/chpax  -permsx $(ELF_TARGETS)
	@-/sbin/paxctl -permsx $(ELF_TARGETS)

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
	$(MKDIR) $(PREFIX)/bin/ $(PREFIX)/share/man/man1/
	for sh in *.sh ; do $(INS_EXE) $$sh $(PREFIX)/bin/$${sh%.sh} || exit $$? ; done
	$(INS_EXE) $(TARGETS) $(PREFIX)/bin/
ifeq ($(S),)
	$(MKDIR) $(PREFIX)/share/doc/pax-utils/
	$(CP) README BUGS TODO $(PREFIX)/share/doc/pax-utils/
	-$(INS_DATA) $(MPAGES) $(PREFIX)/share/man/man1/
else
	$(INS_DATA) $(MPAGES) $(PREFIX)/share/man/man1/
endif

dist:
	@if [ "$(PV)" = "" ] ; then \
		echo "Please run 'make dist PV=<ver>'" ; \
		exit 1 ; \
	fi
	rm -rf pax-utils-$(PV)
	mkdir pax-utils-$(PV)
	cp -a CVS pax-utils-$(PV)/
	cd pax-utils-$(PV) && cvs up
	echo "<releaseinfo>$(PV)</releaseinfo>" > pax-utils-$(PV)/man/fragment/version
	$(MAKE) -C pax-utils-$(PV)/man
	tar jcf pax-utils-$(PV).tar.bz2 pax-utils-$(PV) --exclude=CVS --exclude=.cvsignore
	@printf "\n ..... Making sure clean cvs build works ..... \n\n"
	unset CFLAGS; \
	for t in all check clean debug check ; do \
		$(MAKE) -C pax-utils-$(PV) $$t || exit $$? ; \
	done
	rm -rf pax-utils-$(PV)
	du -b pax-utils-$(PV).tar.bz2

-include .depend

check test:
	$(MAKE) -C tests

.PHONY: all check clean dist install test
