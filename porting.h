/*
 * Copyright 2005-2006 Gentoo Foundation
 * Distributed under the terms of the GNU General Public License v2
 * $Header: /var/cvsroot/gentoo-projects/pax-utils/porting.h,v 1.20 2006/05/14 21:21:35 vapier Exp $
 *
 * Copyright 2005-2006 Ned Ludd        - <solar@gentoo.org>
 * Copyright 2005-2006 Mike Frysinger  - <vapier@gentoo.org>
 *
 * Make sure all of the common elf stuff is setup as we expect
 */

#ifndef _PORTING_H
#define _PORTING_H

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof(*arr))

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <limits.h>
#include <fcntl.h>
#include <assert.h>
#include <getopt.h>
#include <libgen.h>
#include <ctype.h>
#include <pwd.h>
#include <fnmatch.h>

#include <sys/mman.h>
#include "elf.h"
#if defined(__linux__)
# include <endian.h>
# include <byteswap.h>
#elif defined(__FreeBSD__)
# include <sys/endian.h>
#endif

#if defined(__GLIBC__) || defined(__UCLIBC__)
# include <glob.h>
#endif

#if defined(__GLIBC__) || defined(__UCLIBC__)
# define __PAX_UTILS_DEFAULT_LD_CACHE_CONFIG "/etc/ld.so.conf"
#elif defined(__FreeBSD__) || defined(__DragonFly__)
# include <elf-hints.h>
# define __PAX_UTILS_DEFAULT_LD_CACHE_CONFIG _PATH_ELF_HINTS
#else
# undef __PAX_UTILS_DEFAULT_LD_CACHE_CONFIG
#endif

#if !defined(bswap_16)
# if defined(bswap16)
#  define bswap_16 bswap16
#  define bswap_32 bswap32
#  define bswap_64 bswap64
# else
#  define bswap_16(x) \
			((((x) & 0xff00) >> 8) | \
			 (((x) & 0x00ff) << 8))
#  define bswap_32(x) \
			((((x) & 0xff000000) >> 24) | \
			 (((x) & 0x00ff0000) >>  8) | \
			 (((x) & 0x0000ff00) <<  8) | \
			 (((x) & 0x000000ff) << 24))
#  if defined(__GNUC__)
#   define bswap_64(x) \
			((((x) & 0xff00000000000000ull) >> 56) | \
			 (((x) & 0x00ff000000000000ull) >> 40) | \
			 (((x) & 0x0000ff0000000000ull) >> 24) | \
			 (((x) & 0x000000ff00000000ull) >>  8) | \
			 (((x) & 0x00000000ff000000ull) <<  8) | \
			 (((x) & 0x0000000000ff0000ull) << 24) | \
			 (((x) & 0x000000000000ff00ull) << 40) | \
			 (((x) & 0x00000000000000ffull) << 56))
#  else
#   define bswap_64(x) \
			((((x) & 0xff00000000000000) >> 56) | \
			 (((x) & 0x00ff000000000000) >> 40) | \
			 (((x) & 0x0000ff0000000000) >> 24) | \
			 (((x) & 0x000000ff00000000) >>  8) | \
			 (((x) & 0x00000000ff000000) <<  8) | \
			 (((x) & 0x0000000000ff0000) << 24) | \
			 (((x) & 0x000000000000ff00) << 40) | \
			 (((x) & 0x00000000000000ff) << 56))
#  endif
# endif
#endif

#if !defined(_POSIX_PATH_MAX) && !defined(PATH_MAX)
# define __PAX_UTILS_PATH_MAX 8192
#elif _POSIX_PATH_MAX > PATH_MAX
# define __PAX_UTILS_PATH_MAX _POSIX_PATH_MAX
#else
# define __PAX_UTILS_PATH_MAX PATH_MAX
#endif

#if !defined(ELF_DATA)
# undef __PAX_UTILS_BO
# if defined(BYTE_ORDER)
#  define __PAX_UTILS_BO BYTE_ORDER
# elif defined(__BYTE_ORDER)
#  define __PAX_UTILS_BO __BYTE_ORDER
# elif defined(WORDS_LITTLENDIAN)
#  define __PAX_UTILS_BO LITTLE_ENDIAN
# elif defined(WORDS_BIGENDIAN)
#  define __PAX_UTILS_BO BIG_ENDIAN
# else
#  error "no idea what the native byte order is"
# endif
# if __PAX_UTILS_BO == LITTLE_ENDIAN
#  define ELF_DATA ELFDATA2LSB
# else
#  define ELF_DATA ELFDATA2MSB
# endif
#endif

/*
 * in case we are not defined by proper/up-to-date system headers, 
 * we check for a whole lot of things and copy them from elf.h.
 */

#ifndef PT_GNU_STACK
# define PT_GNU_STACK	0x6474e551
#endif

/* not in <=binutils-2.14.90.0.8 (should come in by way of .9) */
#ifndef PT_GNU_RELRO
# define PT_GNU_RELRO	0x6474e552
#endif

/* 
 * propably will never be official added to the toolchain.
 * But none the less we should try to get 0x65041580 reserved 
 */
#ifndef PT_PAX_FLAGS
# define PT_PAX_FLAGS	0x65041580

# define PF_PAGEEXEC     (1 << 4)	/* Enable  PAGEEXEC */
# define PF_NOPAGEEXEC   (1 << 5)	/* Disable PAGEEXEC */
# define PF_SEGMEXEC     (1 << 6)	/* Enable  SEGMEXEC */
# define PF_NOSEGMEXEC   (1 << 7)	/* Disable SEGMEXEC */
# define PF_MPROTECT     (1 << 8)	/* Enable  MPROTECT */
# define PF_NOMPROTECT   (1 << 9)	/* Disable MPROTECT */
# define PF_RANDEXEC     (1 << 10)	/* Enable  RANDEXEC */
# define PF_NORANDEXEC   (1 << 11)	/* Disable RANDEXEC */
# define PF_EMUTRAMP     (1 << 12)	/* Enable  EMUTRAMP */
# define PF_NOEMUTRAMP   (1 << 13)	/* Disable EMUTRAMP */
# define PF_RANDMMAP     (1 << 14)	/* Enable  RANDMMAP */
# define PF_NORANDMMAP   (1 << 15)	/* Disable RANDMMAP */
#endif				/* PT_PAX_ */

/* older glibc/uclibc will need this since they typo-ed the define */
#ifndef EM_ST19
# ifdef EM_AT19
#  define EM_ST19	EM_AT19
# else
#  define EM_ST19	74
# endif
#endif

#endif /* _PORTING_H */
