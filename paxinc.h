/*
 * Copyright 2005-2006 Gentoo Foundation
 * Distributed under the terms of the GNU General Public License v2
 * $Header: /var/cvsroot/gentoo-projects/pax-utils/paxinc.h,v 1.3 2006/01/05 03:12:07 vapier Exp $
 *
 * Copyright 2005-2006 Ned Ludd        - <solar@gentoo.org>
 * Copyright 2005-2006 Mike Frysinger  - <vapier@gentoo.org>
 *
 * Make sure all of the common stuff is setup as we expect
 */

#ifndef _PAX_INC_H
#define _PAX_INC_H

#include "porting.h"

#ifndef VERSION
# define VERSION "cvs"
#endif

/* ELF love */
#include "elf.h"
#include "paxelf.h"

/* MACH-O sucks */
#include "macho.h"
#include "paxmacho.h"

extern char do_reverse_endian;

/* Get a value 'X', compensating for endianness. */
#define EGET(X) \
	(__extension__ ({ \
		uint64_t __res; \
		if (!do_reverse_endian) {    __res = (X); \
		} else if (sizeof(X) == 1) { __res = (X); \
		} else if (sizeof(X) == 2) { __res = bswap_16((X)); \
		} else if (sizeof(X) == 4) { __res = bswap_32((X)); \
		} else if (sizeof(X) == 8) { __res = bswap_64((X)); \
		} else { \
			fprintf(stderr, "EGET failed ;(\n"); \
			exit(EXIT_FAILURE); \
		} \
		__res; \
	}))

/* helper functions for showing errors */
#define color 1
#define COLOR(c,b) (color ? "\e[" c ";" b "m" : "")
#define NORM      COLOR("00", "00")
#define RED       COLOR("31", "01")
#define YELLOW    COLOR("33", "01")

/* we need the space before the last comma or we trigger a bug in gcc-2 :( */
#define warn(fmt, args...) \
	fprintf(stderr, "%s%s%s: " fmt "\n", RED, argv0, NORM , ## args) 
#define warnf(fmt, args...) warn("%s%s%s(): " fmt, YELLOW, __FUNCTION__, NORM , ## args)
#define _err(wfunc, fmt, args...) \
	do { \
	wfunc(fmt, ## args); \
	exit(EXIT_FAILURE); \
	} while (0)
#define err(fmt, args...) _err(warn, fmt, ## args)
#define errf(fmt, args...) _err(warnf, fmt, ## args)

#endif /* _PAX_INC_H */
