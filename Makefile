# Copyright 2003 Ned Ludd <solar@linbsd.net>
# Distributed under the terms of the GNU General Public License v2
# $Header: /var/cvsroot/gentoo-projects/pax-utils/Makefile,v 1.39 2005/10/13 01:53:55 vapier Exp $
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
#CFLAGS   += -DEBUG -g
#LDFLAGS  := -pie
DESTDIR    =
PREFIX    := $(DESTDIR)/usr
STRIP     := strip
MKDIR     := mkdir -p
CP        := cp

ifdef PV
HFLAGS    += -DVERSION=\"$(PV)\"
endif

####################################################################
ELF_TARGETS  = scanelf pspax dumpelf
ELF_OBJS     = $(ELF_TARGETS:%=%.o) paxelf.o
#MACH_TARGETS = scanmacho
#MACH_OBJS    = $(MACH_TARGETS:%=%.o) paxmacho.o
OBJS         = $(ELF_OBJS) $(MACH_OBJS) paxinc.o
TARGETS      = $(ELF_TARGETS) $(MACH_TARGETS)
MPAGES       = $(TARGETS:%=man/%.1)
SOURCES      = $(OBJS:%.o=%.c)

all: $(OBJS) $(TARGETS)
	@:

debug: all
	@-/sbin/chpax  -permsx $(TARGETS)
	@-/sbin/paxctl -permsx $(TARGETS)

%.o: %.c
ifeq ($(subst s,,$(MAKEFLAGS)),$(MAKEFLAGS))
	@echo $(CC) $(CFLAGS) -c $<
endif
	@$(CC) $(CFLAGS) $(WFLAGS) $(HFLAGS) -c $<

$(ELF_TARGETS): $(ELF_OBJS) paxinc.o
	$(CC) $(CFLAGS) $(LDFLAGS) paxinc.o paxelf.o -o $@ $<

$(MACH_TARGETS): $(MACH_OBJS) paxinc.o
	$(CC) $(CFLAGS) $(LDFLAGS) paxinc.o paxmacho.o -o $@ $<

%.so: %.c
	$(CC) -shared -fPIC -o $@ $<

depend:
	$(CC) $(CFLAGS) -MM $(SOURCES) > .depend

clean:
	-rm -f $(OBJS) $(TARGETS)

distclean: clean
	-rm -f *~ core

install: all
	-$(STRIP) $(TARGETS)
	-$(MKDIR) $(PREFIX)/bin/ $(PREFIX)/share/man/man1/
	$(CP) $(TARGETS) $(PREFIX)/bin/
ifeq ($(S),)
	$(PREFIX)/share/doc/pax-utils/
	$(CP) README BUGS TODO $(PREFIX)/share/doc/pax-utils/
endif
	for mpage in $(MPAGES) ; do \
		[ -e $$mpage ] \
			&& cp $$mpage $(PREFIX)/share/man/man1/ || : ;\
	done

-include .depend
