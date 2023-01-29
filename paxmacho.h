/*
 * Copyright 2005-2012 Gentoo Foundation
 * Distributed under the terms of the GNU General Public License v2
 *
 * Copyright 2005-2012 Ned Ludd        - <solar@gentoo.org>
 * Copyright 2005-2012 Mike Frysinger  - <vapier@gentoo.org>
 *           2008-2012 Fabian Groffen  - <grobian@gentoo.org>
 *
 * Make sure all of the common mach-o stuff is setup as we expect
 */

#ifndef _PAX_MACHO_H
#define _PAX_MACHO_H

#include "macho.h"

#define MGET(swapped, value) (swapped ? (__typeof__(value))bswap_32(value) : value)
#define MOBJGET(obj, member) MGET((obj)->swapped, (obj)->member)

typedef struct _fatobj {
	void *data;                 /* mmapped image of the whole file */
	size_t len;                 /* length of data (file length) */
	int fd;                     /* open filedescriptor to the file */
	const char *filename;       /* full filename */
	const char *base_filename;  /* basename of filename (don't free) */
	char swapped;               /* whether values need to be swapped */
	char ismach64;              /* whether mach_header_64 is in use */
	char isbigendian;			/* whether the byte order is big-endian */
	union {
		struct mach_header *hdr32;    /* pointer to arch Mach-O header */
		struct mach_header_64 *hdr64; /* 64-bits variant */
	} mhdr;
	char *mhdata;               /* pointer to the image of the mach_header */
	struct _fatobj *next;       /* pointer to the next arch */
} fatobj;

typedef struct {
	void *data;                 /* pointer to the current command header */
	struct load_command* lcmd;  /* the load command */
	uint32_t cleft;             /* load commands left */
	uint32_t align;             /* alignment size in bytes */
	char swapped;               /* whether values need to be swapped */
} loadcmd;

const char *get_machomhtype(fatobj *fobj);
void get_machomhflags(fatobj *fobj, char **ret, size_t *ret_len);
const char *get_machocputype(fatobj *fobj);
const char *get_machosubcputype(fatobj *fobj);
fatobj *readmacho(const char *filename);
fatobj *readmacho_fd(const char *filename, int fd, size_t len);
fatobj *readmacho_buffer(const char *filename, char *buffer, size_t buffer_len);
void unreadmacho(fatobj *macho);
loadcmd *firstloadcmd(fatobj *fobj);
int nextloadcmd(loadcmd* lcmd);
const char *get_machoendian(fatobj *fobj);
const char *get_machomtype(fatobj *fobj);

#endif /* _PAX_MACHO_H */
