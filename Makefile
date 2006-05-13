# Copyright 2003 Ned Ludd <solar@linbsd.net>
# Distributed under the terms of the GNU General Public License v2
# $Header: /var/cvsroot/gentoo-projects/pax-utils/Makefile,v 1.54 2006/05/13 23:42:08 vapier Exp $
####################################################################

check_gcc=$(shell if $(CC) $(1) -S -o /dev/null -xc /dev/null > /dev/null 2>&1; \
	then echo "$(1)"; else echo "$(2)"; fi)

####################################################################
WFLAGS    := -Wall -Wunused -Wimplicit -Wshadow -Wformat=2 \
             -Wmissing-declarations -Wmissing-prototypes -Wwrite-strings \
             -Wbad-function-cast -Wnested-externs -Wcomment -Winline \
             -Wchar-subscripts -Wcast-align -Wno-format-nonliteral \
             $(call check_gcc, -Wdeclaration-after-statement) \
             $(call check-gcc, -Wsequence-point) \
             $(call check-gcc, -Wextra)

CFLAGS    ?= -O2 -pipe
CPPFLAGS  += -D_GNU_SOURCE
LDFLAGS   +=
LIBS      :=
DESTDIR    =
PREFIX    := $(DESTDIR)/usr
STRIP     := strip
MKDIR     := mkdir -p
CP        := cp

# Some fun settings
#CFLAGS   += -DEBUG -g
#LDFLAGS  += -pie

ifeq ($(USE_CAP),yes)
CPPFLAGS  += -DWANT_SYSCAP
LIBS      += -lcap
endif

ifdef PV
CPPFLAGS  += -DVERSION=\"$(PV)\"
endif

####################################################################
ELF_TARGETS  = scanelf pspax dumpelf
ELF_OBJS     = $(ELF_TARGETS:%=%.o) paxelf.o
MACH_TARGETS = scanmacho
MACH_OBJS    = $(MACH_TARGETS:%=%.o) paxmacho.o
OBJS         = $(ELF_OBJS) $(MACH_OBJS) paxinc.o
TARGETS      = $(ELF_TARGETS) $(MACH_TARGETS)
MPAGES       = $(TARGETS:%=man/%.1)
SOURCES      = $(OBJS:%.o=%.c)

ifneq ($(MACH),1)
MACH_TARGETS = 
MACH_OBJS    = 
endif

all: $(OBJS) $(TARGETS)
	@:

debug:
	$(MAKE) CFLAGS="$(CFLAGS) -g3 -ggdb -nopie" clean all
	@-/sbin/chpax  -permsx $(ELF_TARGETS)
	@-/sbin/paxctl -permsx $(ELF_TARGETS)

%.o: %.c
ifeq ($(findstring s,$(MAKEFLAGS)),)
	@echo $(CC) $(CFLAGS) $(CPPFLAGS) -c $<
endif
	@$(CC) $(CFLAGS) $(CPPFLAGS) $(WFLAGS) -c $<

$(ELF_TARGETS): $(ELF_OBJS) paxinc.o
	$(CC) $(CFLAGS) $(LDFLAGS) paxinc.o paxelf.o -o $@ $@.o $(LIBS)

$(MACH_TARGETS): $(MACH_OBJS) paxinc.o
	$(CC) $(CFLAGS) $(LDFLAGS) paxinc.o paxmacho.o -o $@ $@.o $(LIBS)

%.so: %.c
	$(CC) -shared -fPIC -o $@ $<

depend:
	$(CC) $(CFLAGS) -MM $(SOURCES) > .depend

clean:
	-rm -f $(OBJS) $(TARGETS)

distclean: clean
	-rm -f *~ core *.o

strip: all
	$(STRIP) $(TARGETS)
strip-more:
	$(STRIP) --strip-unneeded $(TARGETS)

install: all
	-$(MKDIR) $(PREFIX)/bin/ $(PREFIX)/share/man/man1/
	$(CP) $(TARGETS) $(PREFIX)/bin/
ifeq ($(S),)
	-$(MKDIR) $(PREFIX)/share/doc/pax-utils/
	$(CP) README BUGS TODO $(PREFIX)/share/doc/pax-utils/
endif
	for mpage in $(MPAGES) ; do \
		[ -e $$mpage ] \
			&& cp $$mpage $(PREFIX)/share/man/man1/ || : ;\
	done

dist: distclean
	@tempfiles=`ls .#* *.o 2>/dev/null` ; \
	if [ -n "$$tempfiles" ] ; then \
		echo "Please remove these files first:" ; \
		echo "$$tempfiles" ; \
		exit 1 ; \
	fi
	@if [ "$(PV)" = "" ] ; then \
		echo "Please run 'make dist PV=<ver>'" ; \
		exit 1 ; \
	fi
	$(MAKE) -s distclean
	rm -rf ../pax-utils-$(PV)*
	mkdir ../pax-utils-$(PV)
	cp -R * .depend ../pax-utils-$(PV)/
	rm -rf ../pax-utils-$(PV)/CVS ../pax-utils-$(PV)/*/CVS ../pax-utils-$(PV)/make-tarball.sh
	tar jcf ../pax-utils-$(PV).tar.bz2 -C .. pax-utils-$(PV)
	rm -rf ../pax-utils-$(PV)
	du -b ../pax-utils-$(PV).tar.bz2

-include .depend
