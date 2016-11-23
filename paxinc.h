/*
 * Copyright 2005-2012 Gentoo Foundation
 * Distributed under the terms of the GNU General Public License v2
 *
 * Copyright 2005-2012 Ned Ludd        - <solar@gentoo.org>
 * Copyright 2005-2012 Mike Frysinger  - <vapier@gentoo.org>
 *
 * Make sure all of the common stuff is setup as we expect
 */

#ifndef _PAX_INC_H
#define _PAX_INC_H

#include "porting.h"
#include "xfuncs.h"
#include "security.h"

#ifndef VERSION
# define VERSION "git"
#endif
#ifndef VCSID
# define VCSID "<unknown>"
#endif

#ifdef EBUG
# define USE_DEBUG 1
#else
# define USE_DEBUG 0
#endif

/* ELF love */
#include "elf.h"
#include "paxelf.h"
#include "paxldso.h"

/* Mach-O love */
#include "macho.h"
#include "paxmacho.h"

extern char do_reverse_endian;

#ifdef IN_paxinc
typedef struct {
	int fd;
	const char *filename;
	size_t skip;
	char *extfn;
	bool verbose;
} archive_handle;
#else
typedef void archive_handle;
#endif
typedef struct {
	char name[__PAX_UTILS_PATH_MAX];
	time_t date;
	uid_t uid;
	gid_t gid;
	mode_t mode;
	off_t size;
#ifdef IN_paxinc
	union {
		char raw[60];
		struct {
			char name[16];
			char date[12];
			char uid[6];
			char gid[6];
			char mode[8];
			char size[10];
			char magic[2];
		} formatted;
	} buf;
#endif
} archive_member;
archive_handle *ar_open_fd(const char *filename, int fd, bool verbose);
archive_handle *ar_open(const char *filename, bool verbose);
archive_member *ar_next(archive_handle *);

const char *strfileperms(const char *fname);

/* Get a value 'X', compensating for endianness. */
#define EGET(X) \
	(__extension__ ({ \
		uint64_t __res; \
		if (!do_reverse_endian) {    __res = (X); \
		} else if (sizeof(X) == 1) { __res = (X); \
		} else if (sizeof(X) == 2) { __res = bswap_16((X)); \
		} else if (sizeof(X) == 4) { __res = bswap_32((X)); \
		} else if (sizeof(X) == 8) { __res = bswap_64((X)); \
		} else { errf("EGET failed :( (sizeof(X) == %i)", (int)sizeof(X)); } \
		__res; \
	}))

/* Set a value 'Y' to 'X', compensating for endianness. */
#define ESET(Y,X) \
	do { \
		if (!do_reverse_endian) { Y = (X); \
		} else if (sizeof(Y) == 1) { Y = (X); \
		} else if (sizeof(Y) == 2) { Y = bswap_16((uint16_t)(X)); \
		} else if (sizeof(Y) == 4) { Y = bswap_32((uint32_t)(X)); \
		} else if (sizeof(Y) == 8) { Y = bswap_64((uint64_t)(X)); \
		} else { errf("ESET failed :( (size(Y) == %i)", (int)sizeof(Y)); } \
	} while (0)

/* alignment helpers */
#define ALIGN_DOWN(base, size) ((base) & -((__typeof__(base)) (size)))
#define ALIGN_UP(base, size)   ALIGN_DOWN((base) + (size) - 1, (size))
#define PTR_ALIGN_DOWN(base, size) ((__typeof__(base))ALIGN_DOWN((uintptr_t)(base), (size)))
#define PTR_ALIGN_UP(base, size)   ((__typeof__(base))ALIGN_UP  ((uintptr_t)(base), (size)))

/* helper functions for showing errors */
extern const char *NORM, *RED, *YELLOW;
void color_init(bool disable);

/* constant pointer to a constant buffer ... each program needs to set this */
extern const char argv0[];

/* we need the space before the last comma or we trigger a bug in gcc-2 :( */
#define warn(fmt, args...) \
	fprintf(stderr, "%s%s%s: " fmt "\n", RED, argv0, NORM , ## args)
#define warnf(fmt, args...) warn("%s%s%s(): " fmt, YELLOW, __FUNCTION__, NORM , ## args)
#define warnp(fmt, args...) warn(fmt ": %s" , ## args , strerror(errno))
#define warnfp(fmt, args...) warnf(fmt ": %s" , ## args , strerror(errno))
#define _err(wfunc, fmt, args...) \
	do { \
	wfunc(fmt, ## args); \
	exit(EXIT_FAILURE); \
	} while (0)
#define err(fmt, args...) _err(warn, fmt, ## args)
#define errf(fmt, args...) _err(warnf, fmt, ## args)
#define errp(fmt, args...) _err(warnp, fmt , ## args)

/* File system helper functions. */
extern int root_fd;
FILE *fopenat_r(int dir_fd, const char *path);
const char *root_rel_path(const char *path);

#endif /* _PAX_INC_H */
