/*
 * Copyright 2003-2007 Gentoo Foundation
 * Distributed under the terms of the GNU General Public License v2
 * $Header: /var/cvsroot/gentoo-projects/pax-utils/paxmacho.c,v 1.6 2008/01/17 04:37:19 solar Exp $
 *
 * Copyright 2005-2007 Ned Ludd        - <solar@gentoo.org>
 * Copyright 2005-2007 Mike Frysinger  - <vapier@gentoo.org>
 */

#include "paxinc.h"

const char * const argv0 = "paxmacho";

/*
 * Setup a bunch of helper functions to translate
 * binary defines into readable strings.
 */
#define QUERY(n) { #n, n }
typedef struct {
	const char *str;
	int value;
} pairtype;
static inline const char *find_pairtype(pairtype *pt, int type)
{
	int i;
	for (i = 0; pt[i].str; ++i)
		if (type == pt[i].value)
			return pt[i].str;
	return "UNKNOWN TYPE";
}

/* translate misc mach-o MH_ defines */
static pairtype macho_mh_type[] = {
	QUERY(MH_OBJECT),
	QUERY(MH_EXECUTE),
	QUERY(MH_BUNDLE),
	QUERY(MH_DYLIB),
	QUERY(MH_PRELOAD),
	QUERY(MH_CORE),
	QUERY(MH_DYLINKER),
	{ 0, 0 }
};
const char *get_machomhtype(int mh_type)
{
	return find_pairtype(macho_mh_type, mh_type);
}

/* Read a macho into memory */
#define IS_MACHO_MAGIC(m) \
	(m == MH_MAGIC    || m == MH_CIGAM || \
	 m == MH_MAGIC_64 || m == MH_CIGAM_64)
#define DO_WE_LIKE_MACHO(buff) 1
machoobj *readmacho(const char *filename)
{
	struct stat st;
	int fd;
	machoobj *macho;
	struct mach_header *mhdr;

	if (stat(filename, &st) == -1)
		return NULL;

	if ((fd = open(filename, O_RDONLY)) == -1)
		return NULL;

	/* make sure we have enough bytes to scan e_ident */
	if (st.st_size <= sizeof(struct mach_header))
		goto close_fd_and_return;

	macho = (machoobj*)malloc(sizeof(*macho));
	if (macho == NULL)
		goto close_fd_and_return;
	memset(macho, 0x00, sizeof(*macho));

	macho->fd = fd;
	macho->len = st.st_size;
	macho->data = (char*)mmap(0, macho->len, PROT_READ, MAP_PRIVATE, fd, 0);
	if (macho->data == (char*)MAP_FAILED) {
		warn("mmap on '%s' of %li bytes failed :(", filename, (unsigned long)macho->len);
		goto free_macho_and_return;
	}

	mhdr = (struct mach_header*)macho->data;
	do_reverse_endian = (mhdr->magic == MH_CIGAM || mhdr->magic == MH_CIGAM_64);
	macho->macho_class = (EGET(mhdr->magic) == MH_MAGIC ? MH_MAGIC : MH_MAGIC_64);

	if (!IS_MACHO_MAGIC(mhdr->magic)) /* make sure we have an macho */
		goto unmap_data_and_return;
	if (1 || !DO_WE_LIKE_MACHO(mhdr)) { /* check class and stuff */
		warn("we no likey %s: {%i:%s}",
		     filename,
		     (int)EGET(mhdr->filetype), get_machomhtype(EGET(mhdr->filetype)));
		goto unmap_data_and_return;
	}

	macho->filename = filename;
	macho->base_filename = strrchr(filename, '/');
	if (macho->base_filename == NULL)
		macho->base_filename = macho->filename;
	else
		macho->base_filename = macho->base_filename + 1;
	macho->mhdr = (void*)macho->data;

	return macho;

unmap_data_and_return:
	munmap(macho->data, macho->len);
free_macho_and_return:
	free(macho);
close_fd_and_return:
	close(fd);
	return NULL;
}

/* undo the readmacho() stuff */
void unreadmacho(machoobj *macho)
{
	munmap(macho->data, macho->len);
	close(macho->fd);
	free(macho);
}
