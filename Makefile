# Copyright 2003 Ned Ludd <solar@linbsd.net>
# Distributed under the terms of the GNU General Public License v2
# $Header: /var/cvsroot/gentoo-projects/pax-utils/Makefile,v 1.11 2004/08/15 06:10:04 solar Exp $
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

VERSION	= 0.0.3

####################################################
CFLAGS	:= -Wall -O2
#CFLAGS += -DEBUG -g
#LDFLAGS :=-pie
DESTDIR	=
PREFIX	:= $(DESTDIR)/usr
STRIP	:= strip
MKDIR	:= mkdir -p
CP	:= cp
#####################################################
TARGETS	= scanexec scanelf scan4sym pttool pspax
OBJS	= ${TARGETS:%=%.o} paxelf.o
MPAGES	= ${TARGETS:%=man/%.1}
SOURCES	= ${OBJS:%.o=%.c}

all: $(OBJS) $(TARGETS)
	@#chpax -zperms $(TARGETS)

%.o: %.c
	$(CC) $(CFLAGS) -c $<

%: %.o
	$(CC) -o $@ $(CFLAGS) -o $@ paxelf.o $< $(LDFLAGS)

%.so: %.c
	$(CC) -shared -fPIC -o $@ $<

scan4sym:
	$(CC) -o $@ $(CFLAGS) paxelf.o $@.o -ldl $(LDFLAGS)

depend:
	$(CC) $(CFLAGS) -MM $(SOURCES) > .depend

pttool:
	$(CC) -o $@ $(CFLAGS) $@.o $(LDFLAGS)

pspax:
	$(CC) -o $@ $(CFLAGS) $@.o $(LDFLAGS)

clean:
	-rm -f $(OBJS) $(TARGETS)

distclean: clean
	-rm -f *~ core
	
install : all
	-$(STRIP) $(TARGETS)
	-$(MKDIR) $(PREFIX)/bin/ $(PREFIX)/share/man/man1/
	-$(CP) $(TARGETS) $(PREFIX)/bin/
	for mpage in $(MPAGES) ; do \
		[ -e $$mpage ] \
			&& cp $$mpage $(PREFIX)/share/man/man1/ || : ;\
	done

include .depend
