/*
 * Copyright 2005-2012 Gentoo Foundation
 * Distributed under the terms of the GNU General Public License v2
 *
 * Copyright 2005-2012 Ned Ludd        - <solar@gentoo.org>
 * Copyright 2005-2012 Mike Frysinger  - <vapier@gentoo.org>
 *
 * Make sure all of the common elf stuff is setup as we expect
 */

#ifndef _PORTING_H
#define _PORTING_H

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof(*arr))

#include <assert.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <fnmatch.h>
#include <getopt.h>
#include <inttypes.h>
#include <libgen.h>
#include <limits.h>
#include <pwd.h>
#include <regex.h>
#include <sched.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include "elf.h"
#if !defined(__FreeBSD__) && !defined(__OpenBSD__)
# include <alloca.h>
#endif
#if defined(__linux__)
# include <sys/prctl.h>
# include <linux/securebits.h>
#endif
#if defined(__GLIBC__) || defined(__UCLIBC__) || defined(__ANDROID__)
# include <byteswap.h>
# include <endian.h>
#elif defined(__FreeBSD__)
# include <sys/endian.h>
#elif defined(__sun__)
# include <sys/isa_defs.h>
#elif defined(__MACH__)
# include <machine/endian.h>
#endif

#if defined(__GLIBC__) || defined(__UCLIBC__)
# include <glob.h>
#endif

#if defined(__GLIBC__) || defined(__UCLIBC__) || defined(__NetBSD__)
# define __PAX_UTILS_DEFAULT_LD_CACHE_CONFIG "/etc/ld.so.conf"
#elif defined(__FreeBSD__) || defined(__DragonFly__)
# include <elf-hints.h>
# define __PAX_UTILS_DEFAULT_LD_CACHE_CONFIG _PATH_ELF_HINTS
#else
# define __PAX_UTILS_DEFAULT_LD_CACHE_CONFIG ""
#endif

#undef PAX_UTILS_CLEANUP
/* bounds checking code will fart on free(NULL) even though that
 * is valid usage.  So let's wrap it if need be.
 */
#ifdef __BOUNDS_CHECKING_ON
# define free(ptr) do { if (ptr) free(ptr); } while (0)
# define PAX_UTILS_CLEANUP 1
#endif
/* LSAN (Leak Sanitizer) will complain about things we leak. */
#ifdef __SANITIZE_ADDRESS__
# define PAX_UTILS_CLEANUP 1
#endif
/* Coverity catches some things we leak on purpose. */
#ifdef __COVERITY__
# define PAX_UTILS_CLEANUP 1
#endif
#ifndef PAX_UTILS_CLEANUP
# define PAX_UTILS_CLEANUP 0
#endif

/* Few arches can safely do unaligned accesses */
#if defined(__cris__) || \
    defined(__i386__) || \
    defined(__powerpc__) || \
    defined(__s390__) || \
    defined(__x86_64__)
# define __PAX_UNALIGNED_OK 1
#else
# define __PAX_UNALIGNED_OK 0
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

#define _minmax(x, y, op) \
	({ __typeof__(x) __x = (x); __typeof__(y) __y = (y); (__x op __y ? __x : __y); })
#if !defined(min)
# define min(x, y) _minmax(x, y, <)
#endif
#if !defined(max)
# define max(x, y) _minmax(x, y, >)
#endif

#if !defined(_POSIX_PATH_MAX) && !defined(PATH_MAX) /* __PAX_UTILS_PATH_MAX */
# define __PAX_UTILS_PATH_MAX 8192
#elif _POSIX_PATH_MAX > PATH_MAX /* __PAX_UTILS_PATH_MAX */
# define __PAX_UTILS_PATH_MAX _POSIX_PATH_MAX
#else
# define __PAX_UTILS_PATH_MAX PATH_MAX
#endif

/* fall back case for non-Linux hosts ... so lame */
#if !defined(ELF_DATA)
# if defined(BYTE_ORDER)
#  if BYTE_ORDER == LITTLE_ENDIAN
#   define ELF_DATA ELFDATA2LSB
#  elif BYTE_ORDER == BIG_ENDIAN
#   define ELF_DATA ELFDATA2MSB
#  else
#   error "BYTE_ORDER: you fail"
#  endif
# elif defined(__BYTE_ORDER)
#  if __BYTE_ORDER == __LITTLE_ENDIAN
#   define ELF_DATA ELFDATA2LSB
#  elif __BYTE_ORDER == __BIG_ENDIAN
#   define ELF_DATA ELFDATA2BSB
#  else
#   error "__BYTE_ORDER: you fail"
#  endif
# elif defined(WORDS_LITTLENDIAN)
#  define ELF_DATA ELFDATA2LSB
# elif defined(WORDS_BIGENDIAN)
#  define ELF_DATA ELFDATA2MSB
# elif defined(_LITTLE_ENDIAN)
#  define ELF_DATA ELFDATA2LSB
# elif defined(_BIG_ENDIAN) || defined(__BIG_ENDIAN__)
#  define ELF_DATA ELFDATA2MSB
# else
#  error "no idea what the native byte order is"
# endif
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

#ifndef O_CLOEXEC
# define O_CLOEXEC 0
#endif
#ifndef O_PATH
# define O_PATH 0
#endif

#define __unused__ __attribute__((__unused__))

#endif /* _PORTING_H */
