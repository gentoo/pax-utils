# Copyright 2003 Ned Ludd <solar@linbsd.net>
# Distributed under the terms of the GNU General Public License v2
# $Header: /var/cvsroot/gentoo-projects/pax-utils/Makefile,v 1.5 2003/10/25 03:13:24 solar Exp $
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

## User Defined
####################################################
CFLAGS	= -Wall -O2
DESTDIR	=
PREFIX	= $(DESTDIR)/usr

STRIP	= strip
MKDIR	= mkdir -p
CP	= cp
#####################################################

VERSION	= 0.0.2

TARGETS	= isetdyn scanexec scanelf
OBJS	= ${TARGETS:%=%.o} paxelf.o
MPAGES	= ${TARGETS:%=man/%.1}
SOURCES	= ${OBJS:%.o=%.c}

all: $(OBJS) $(TARGETS)

%.o: %.c
	$(CC) $(CFLAGS) -c $<

%: %.o
	$(CC) $(CFLAGS) -o $@ paxelf.o $<

isetdyn:
	$(CC) $(CFLAGS) -o isetdyn paxelf.o isetdyn.o -ldl

depend:
	$(CC) $(CFLAGS) -MM $(SOURCES) > .depend

clean:
	rm -f $(OBJS)
	rm -f $(TARGETS)

distclean: clean
	rm -f *~ core

include .depend
	
install : all
	$(STRIP) $(TARGETS)
	$(MKDIR) $(PREFIX)/bin/ $(PREFIX)/share/man/man1/
	$(CP) $(TARGETS) $(PREFIX)/bin/
	for mpage in $(MPAGES) ; do \
		cp $$mpage $(PREFIX)/share/man/man1/ ;\
	done
