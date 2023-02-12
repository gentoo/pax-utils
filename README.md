# ELF/PaX Utilities

| What     | How                                                   |
| -------- | ----------------------------------------------------- |
| HOMEPAGE | https://wiki.gentoo.org/wiki/Hardened/PaX_Utilities   |
| GIT      | git clone git://anongit.gentoo.org/proj/pax-utils.git |
| VIEWVCS  | https://gitweb.gentoo.org/proj/pax-utils.git/         |
| STATUS   | [![Build Status](https://github.com/gentoo/pax-utils/actions/workflows/build-test-ci.yml/badge.svg)](https://github.com/gentoo/pax-utils/actions/workflows/build-test-ci.yml) [![Coverity Status](https://scan.coverity.com/projects/9213/badge.svg)](https://scan.coverity.com/projects/gentoo-pax-utils) |

pax-utils is a small set of utilities for performing Q/A (mostly security)
checks on systems (most notably, `scanelf`).  It is focused on the ELF
format, but does include a Mach-O helper too for OS X systems.

While heavily integrated into Gentoo's build system, it can be used on any
distro as it is a generic toolset.

Originally focused only on [PaX](https://pax.grsecurity.net/), it has been
expanded to be generally security focused.  It still has a good number of
PaX helpers for people interested in that.

## Building and installing
pax-utils uses a bog-standard meson-based build system. See `meson_options.txt`
for configuration options.

You don't need PaX to use the pax-utils. Infact the only thing they
really have in common is that pax-utils was initially written to aid in
deploying PaX systems so it includes support for PT_PAX_FLAGS and the
deprecated but still in use EI_PAX flags. For more information about PaX
see the homepage at https://pax.grsecurity.net/

## Links

If you include pax-utils in your distro, feel free to send an update for this.

##### Gentoo
 * https://wiki.gentoo.org/wiki/Hardened/PaX_Utilities
 * https://gitweb.gentoo.org/proj/pax-utils.git/
 * Maintainer: Mike Frysinger <vapier@gentoo.org>, Toolchain Project <toolchain@gentoo.org>
 * Original author: Ned Ludd <solar@gentoo.org>

##### openSUSE
 * https://build.opensuse.org/package/show?package=pax-utils&project=openSUSE%3AFactory
 * Maintainer: ludwig.nussel@suse.de

##### Ubuntu
 * https://packages.ubuntu.com/hirsute/pax-utils
 * Maintainer: john.r.moser@gmail.com

##### Debian
 * https://packages.debian.org/unstable/misc/pax-utils
 * https://bugs.debian.org/388200
 * Maintainer: rdenis@simphalempin.com

##### FreeBSD
 * https://portsmon.freebsd.org/portoverview.py?category=sysutils&portname=pax-utils
 * https://www.freshports.org/sysutils/pax-utils/
 * http://archive.netbsd.se/?ml=freebsd-cvs-all&a=2006-08&m=2311441
 * Maintainer: sbz@FreeBSD.org

##### OpenEmedded
 * https://www.openembedded.org/filebrowser/org.openembedded.dev/packages/pax-utils

##### Crux
 * https://magog.se/crux/pax-utils/Pkgfile
 * Maintainer: mattias@hedenskog.se

##### Fedora
 * https://apps.fedoraproject.org/packages/pax-utils
 * Maintainer: Dominik 'Rathann' Mierzejewski <rpm@greysector.net>

##### ArchLinux
 * https://www.archlinux.org/packages/community/x86_64/pax-utils/
