# Copyright 2003 Ned Ludd <solar@linbsd.net>
# Distributed under the terms of the GNU General Public License v2
# $Header: /var/cvsroot/gentoo-projects/pax-utils/Makefile,v 1.38 2005/08/21 02:08:59 vapier Exp $
####################################################################
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License as
# published by the Free Software Foundation; either version 2 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston,
# MA 02111-1307, USA.
####################################################################

check_gcc=$(shell if $(CC) $(1) -S -o /dev/null -xc /dev/null > /dev/null 2>&1; \
	then echo "$(1)"; else echo "$(2)"; fi)

####################################################
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

#####################################################
TARGETS    = scanelf pspax dumpelf
OBJS       = ${TARGETS:%=%.o} paxelf.o
MPAGES     = ${TARGETS:%=man/%.1}
SOURCES    = ${OBJS:%.o=%.c}

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

%: %.o paxelf.o
	$(CC) $(CFLAGS) $(LDFLAGS) paxelf.o -o $@ $<

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
