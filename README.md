# ELF/PaX Utilities

| What     | How                                                   |
| -------- | ----------------------------------------------------- |
| HOMEPAGE | https://wiki.gentoo.org/wiki/Hardened/PaX_Utilities   |
| GIT      | git clone git://anongit.gentoo.org/proj/pax-utils.git |
| VIEWVCS  | https://gitweb.gentoo.org/proj/pax-utils.git/         |
| STATUS   | [![Build Status](https://travis-ci.org/gentoo/pax-utils.svg?branch=master)](https://travis-ci.org/gentoo/pax-utils) [![Coverity Status](https://scan.coverity.com/projects/9213/badge.svg)](https://scan.coverity.com/projects/gentoo-pax-utils) |

pax-utils is a small set of utilities for peforming Q/A (mostly security)
checks on systems (most notably, `scanelf`).  It is focused on the ELF
format, but does include a Mach-O helper too for OS X systems.

While heavily integrated into Gentoo's build system, it can be used on any
distro as it is a generic toolset.

Originally focused only on [PaX](https://pax.grsecurity.net/), it has been
expanded to be generally security focused.  It still has a good number of
PaX helpers for people interested in that.

## Building

Just run `make`.  This should work on any recent POSIX compliant system.

Note: To rebuild the man-pages, you will need xmlto and the docbook-xml-dtd
      packages installed on your system.

## Installation

`make install`

You don't need PaX to use the pax-utils. Infact the only thing they
really have in common is that pax-utils was initially written to aid in
deploying PaX systems so it includes support for PT_PAX_FLAGS and the
deprecated but still in use EI_PAX flags. For more information about PaX
see the homepage at http://pax.grsecurity.net/

## Links

If you include pax-utils in your distro, feel free to send an update for this.

##### Gentoo
 * https://wiki.gentoo.org/wiki/Hardened/PaX_Utilities
 * https://gitweb.gentoo.org/proj/pax-utils.git/
 * Maintainer: Mike Frysinger <vapier@gentoo.org>, Ned Ludd <solar@gentoo.org>

##### openSUSE
 * https://build.opensuse.org/package/show?package=pax-utils&project=openSUSE%3AFactory
 * Maintainer: ludwig.nussel@suse.de

##### Ubuntu
 * http://packages.ubuntu.com/edgy/devel/pax-utils
 * Maintainer: john.r.moser@gmail.com

##### Debian
 * http://packages.debian.org/unstable/misc/pax-utils
 * http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=388200
 * Maintainer: rdenis@simphalempin.com

##### FreeBSD
 * http://portsmon.freebsd.org/portoverview.py?category=sysutils&portname=pax-utils
 * http://www.freshports.org/sysutils/pax-utils/
 * http://archive.netbsd.se/?ml=freebsd-cvs-all&a=2006-08&m=2311441
 * Maintainer: sbz@FreeBSD.org

##### OpenEmedded
 * http://www.openembedded.org/filebrowser/org.openembedded.dev/packages/pax-utils

##### Crux
 * http://magog.se/crux/pax-utils/Pkgfile
 * Maintainer: mattias@hedenskog.se

##### Fedora
 * https://apps.fedoraproject.org/packages/pax-utils
 * Maintainer: Dominik 'Rathann' Mierzejewski <rpm@greysector.net>

##### ArchLinux
 * https://www.archlinux.org/packages/community/x86_64/pax-utils/
