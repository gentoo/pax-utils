/*
 * Copyright 2003-2012 Gentoo Foundation
 * Distributed under the terms of the GNU General Public License v2
 *
 * Copyright 2005-2012 Ned Ludd        - <solar@gentoo.org>
 * Copyright 2005-2012 Mike Frysinger  - <vapier@gentoo.org>
 *           2008-2012 Fabian Groffen  - <grobian@gentoo.org>
 */

#include "paxinc.h"

/* lil' static string pool */
static const char STR_BE[]      = "BE";
static const char STR_LE[]      = "LE";
static const char STR_PPC[]     = "ppc";
static const char STR_PPC64[]   = "ppc64";
static const char STR_I386[]    = "i386";
static const char STR_X86_64[]  = "x86_64";
static const char STR_ARM[]     = "arm"; /* iPhone */
static const char STR_UNKNOWN[] = "unknown";

#define QUERY(n) { #n, n }
typedef const struct {
	const char *str;
	unsigned int value;
} pairtype;

static inline const char *find_pairtype(pairtype *pt, unsigned int type)
{
	size_t i;
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
	QUERY(MH_DYLIB_STUB),
	QUERY(MH_DSYM),
	{ 0, 0 }
};
const char *get_machomhtype(fatobj *fobj)
{
	/* can use 32-bits header, since 64 and 32 are aligned here */
	return find_pairtype(macho_mh_type, MOBJGET(fobj, mhdr.hdr32->filetype));
}

/* translate misc mach-o MH_ flags */
static pairtype macho_mh_flag[] = {
	QUERY(MH_NOUNDEFS),
	QUERY(MH_INCRLINK),
	QUERY(MH_DYLDLINK),
	QUERY(MH_TWOLEVEL),
	QUERY(MH_BINDATLOAD),
	QUERY(MH_PREBOUND),
	QUERY(MH_PREBINDABLE),
	QUERY(MH_NOFIXPREBINDING),
	QUERY(MH_ALLMODSBOUND),
	QUERY(MH_CANONICAL),
	QUERY(MH_SPLIT_SEGS),
	QUERY(MH_FORCE_FLAT),
	QUERY(MH_SUBSECTIONS_VIA_SYMBOLS),
	QUERY(MH_NOMULTIDEFS),
	{ 0, 0 }
};
void get_machomhflags(fatobj *fobj, char **ret, size_t *ret_len)
{
	uint32_t flags;
	int i;
	char first = 1;

	/* can use 32-bits header, since 64 and 32 are aligned here */
	flags = MOBJGET(fobj, mhdr.hdr32->flags);

	for (i = 0; macho_mh_flag[i].str; ++i)
		if ((flags & macho_mh_flag[i].value) == macho_mh_flag[i].value) {
			if (!first)
				xchrcat(ret, ',', ret_len);
			xstrcat(ret, macho_mh_flag[i].str, ret_len);
			first = 0;
		}
}

static pairtype macho_cputype[] = {
	QUERY(CPU_TYPE_POWERPC),
	QUERY(CPU_TYPE_I386),
	QUERY(CPU_TYPE_ARM),
	QUERY(CPU_TYPE_POWERPC64),
	QUERY(CPU_TYPE_X86_64),
	{ 0, 0 }
};
const char *get_machocputype(fatobj *fobj)
{
	/* can use 32-bits header, since 64 and 32 are aligned here */
	const char *ret = find_pairtype(macho_cputype, MOBJGET(fobj, mhdr.hdr32->cputype));
	return ret + sizeof("CPU_TYPE_") - 1;
}

/* translate cpusubtypes */
static pairtype macho_cpusubtypeppc[] = {
	QUERY(CPU_SUBTYPE_POWERPC_ALL),
	QUERY(CPU_SUBTYPE_POWERPC_601),
	QUERY(CPU_SUBTYPE_POWERPC_602),
	QUERY(CPU_SUBTYPE_POWERPC_603),
	QUERY(CPU_SUBTYPE_POWERPC_603e),
	QUERY(CPU_SUBTYPE_POWERPC_603ev),
	QUERY(CPU_SUBTYPE_POWERPC_604),
	QUERY(CPU_SUBTYPE_POWERPC_604e),
	QUERY(CPU_SUBTYPE_POWERPC_620),
	QUERY(CPU_SUBTYPE_POWERPC_750),
	QUERY(CPU_SUBTYPE_POWERPC_7400),
	QUERY(CPU_SUBTYPE_POWERPC_7450),
	QUERY(CPU_SUBTYPE_POWERPC_970),
	{ 0, 0 }
};
static pairtype macho_cpusubtypex86[] = {
	QUERY(CPU_SUBTYPE_I386_ALL),
	QUERY(CPU_SUBTYPE_486),
	QUERY(CPU_SUBTYPE_586),
	QUERY(CPU_SUBTYPE_PENTIUM_3),
	QUERY(CPU_SUBTYPE_PENTIUM_M),
	QUERY(CPU_SUBTYPE_PENTIUM_4),
	QUERY(CPU_SUBTYPE_ITANIUM),
	QUERY(CPU_SUBTYPE_XEON),
	{ 0, 0 }
};
const char *get_machosubcputype(fatobj *fobj)
{
	const char *ret;
	/* can use 32-bits header, since 64 and 32 are aligned here */
	uint32_t type = MOBJGET(fobj, mhdr.hdr32->cputype);
	pairtype *pt = NULL;

	if (type == CPU_TYPE_I386 || type == CPU_TYPE_X86_64)
		pt = macho_cpusubtypex86;
	else if (type == CPU_TYPE_POWERPC || type == CPU_TYPE_POWERPC64)
		pt = macho_cpusubtypeppc;

	if (pt) {
		type = MOBJGET(fobj, mhdr.hdr32->cpusubtype);
		ret = find_pairtype(pt, type);
		return ret + sizeof("CPU_SUBTYPE_") - 1;
	} else
		return STR_UNKNOWN;
}

/* Determines the type of this object, and sets the right 32-bit or
 * 64-bits pointer.  The ismach64 flag is filled in appropriately.  The
 * return of this function is the read magic value, or 0 when the file
 * is not recognised.
 * Note: the input addr must be enough to map on struct mach_header! */
inline static uint32_t read_mach_header(fatobj *fobj, void *addr)
{
	struct mach_header *mhdr = addr;
	fobj->mhdata = addr;
	switch (mhdr->magic) {
		case MH_CIGAM:
			fobj->swapped = 1;
			/* fall through */
		case MH_MAGIC:
			/* 32-bits */
			fobj->ismach64 = 0;
			fobj->mhdr.hdr32 = mhdr;
			fobj->isbigendian = (*fobj->mhdata == (char)(MH_MAGIC >> 24) ? 1 : 0);
			return mhdr->magic;
		case MH_CIGAM_64:
			fobj->swapped = 1;
			/* fall through */
		case MH_MAGIC_64:
			/* 64-bits */
			fobj->ismach64 = 1;
			fobj->mhdr.hdr64 = addr;
			fobj->isbigendian = (*fobj->mhdata == (char)(MH_MAGIC_64 >> 24) ? 1 : 0);
			return mhdr->magic;
		default:
			return 0; /* unrecognised file */
	}
}

/* Read a macho into memory, returning a fatobj struct with at least one
 * arch. */
fatobj *readmacho(const char *filename)
{
	int fd;
	fatobj *ret;

	if ((fd = open(filename, O_RDONLY)) == -1)
		return NULL;

	ret = readmacho_fd(filename, fd, 0);
	if (ret == NULL)
		close(fd);
	return ret;
}

fatobj *readmacho_fd(const char *filename, int fd, size_t len)
{
	char *data;
	fatobj *ret;

	if (len == 0) {
		struct stat st;
		if (fstat(fd, &st) == -1)
			return NULL;
		len = st.st_size;
		if (len == 0)
			return NULL;
	}

	data = mmap(0, len, PROT_READ, MAP_PRIVATE, fd, 0);
	if (data == MAP_FAILED) {
		warn("mmap on '%s' of %zu bytes failed :(", filename, len);
		return NULL;
	}

	ret = readmacho_buffer(filename, data, len);
	if (ret != NULL) {
		ret->fd = fd;
		return ret;
	}

	munmap(data, len);
	return NULL;
}

fatobj *readmacho_buffer(const char *filename, char *buffer, size_t buffer_len)
{
	struct fat_header *fhdr;
	fatobj *ret = xmalloc(sizeof(*ret));

	ret->fd = -1;
	ret->filename = filename;
	ret->base_filename = strrchr(ret->filename, '/');
	ret->base_filename =
		(ret->base_filename == NULL ? ret->filename : ret->base_filename + 1);
	ret->len = buffer_len;
	ret->data = buffer;
	ret->swapped = 0;

	/* make sure we have enough bytes to scan */
	if (ret->len <= sizeof(struct fat_header))
		goto fail;

	fhdr = ret->data;
	/* Check what kind of file this is.  Unfortunately we don't have
	 * configure, so we don't know if we're on big or little endian, so
	 * we cannot check if the fat_header is in bigendian like it should.
	 */
	if (fhdr->magic == FAT_MAGIC || fhdr->magic == FAT_CIGAM) {
		/* we're indeed in a FAT file */
		uint32_t i;
		fatobj *fobj = ret;
		struct fat_arch *farch;
		void *dptr = ret->data + sizeof(struct fat_header);
		uint32_t bufleft = ret->len - sizeof(struct fat_header);
		char swapped = 0;
		uint32_t narchs = fhdr->nfat_arch;
		uint32_t offset;

		/* FAT headers are always big-endian, so swap if on little
		 * machines... */
		if (fhdr->magic == FAT_CIGAM) {
			swapped = 1;
			narchs = bswap_32(narchs);
		}

		/* can we read the headers at all?
		 * beware of corrupt files and Java bytecode which shares
		 * the same magic with us :( */
		if (sizeof(struct fat_arch) * narchs > bufleft)
			goto fail;

		for (i = 1; i <= narchs; i++) {
			farch = (struct fat_arch *)dptr;
			offset = MGET(swapped, farch->offset);
			if (offset + sizeof(struct mach_header) >= bufleft ||
					read_mach_header(fobj, ret->data + offset) == 0)
				goto fail;
			if (i < narchs) {
				fobj = fobj->next = xzalloc(sizeof(*fobj));
				/* filename and size are necessary for printing */
				fobj->filename = ret->filename;
				fobj->base_filename = ret->base_filename;
				fobj->len = ret->len;
			} else {
				fobj->next = NULL;
			}
			dptr += sizeof(struct fat_arch);
			bufleft -= sizeof(struct fat_arch);
		}
	} else {
		/* simple Mach-O file, treat as single arch FAT file */
		if (ret->len < sizeof(struct mach_header) ||
				read_mach_header(ret, ret->data) == 0)
			goto fail;
		ret->next = NULL;
	}

	return ret;

 fail:
	free(ret);
	return NULL;
}

/* undo the readmacho() stuff */
void unreadmacho(fatobj *macho)
{
	if (macho->data != NULL) {
		munmap(macho->data, macho->len);
		close(macho->fd);
	}
	/* free all arches recursively */
	if (macho->next != NULL)
		unreadmacho(macho->next);
	free(macho);
}

/* Returns the first load_command in the file (after the mach_header)
 * and allocates a loadcmd struct to store it together with some
 * convenience data.  The struct can be manually freed, if not traversed
 * until the end of the load section. */
loadcmd *firstloadcmd(fatobj *fobj)
{
	loadcmd *ret = xmalloc(sizeof(*ret));
	ret->data = fobj->mhdata +
		(fobj->ismach64 ? sizeof(struct mach_header_64) : sizeof(struct mach_header));
	ret->lcmd = ret->data;
	ret->cleft = MOBJGET(fobj, mhdr.hdr32->ncmds); /* 32 and 64 bits are aligned here */
	ret->align = (fobj->ismach64 ? 8 : 4);
	ret->swapped = fobj->swapped;
	/* a bit useless, but a nice consistency check for ourselves now */
	if (ret->lcmd->cmdsize % ret->align != 0)
		warn("cmdsize isn't properly aligned on %d bytes boundary (%d)",
				ret->align, ret->lcmd->cmdsize);
	return ret;
}

/* Sets up the given loadcmd struct with the next load command, or frees
 * it if there are no more load commands.  If a new load command was
 * loaded, 1 is returned, 0 otherwise.  This behaviour is useful when
 * looping over all load commands, since firstloadcmd will allocate the
 * loadcmd struct, and nextloadcmd will free it once all load commands
 * have been seen. */
int nextloadcmd(loadcmd *lcmd)
{
	uint32_t size = MOBJGET(lcmd, lcmd->cmdsize);

	if (--(lcmd->cleft) == 0) {
		free(lcmd);
		return 0;
	}

	if (size % lcmd->align != 0) {
		/* fix alignment, this should actually never happen, but the doc
		 * says we have to pad if the alignment sucks */
		size += lcmd->align - (size % lcmd->align);
	}
	lcmd->data += size;
	lcmd->lcmd = lcmd->data;

	return 1;
}

const char *get_machoendian(fatobj *fobj)
{
	return fobj->isbigendian ? STR_BE : STR_LE;
}

const char *get_machomtype(fatobj *fobj)
{
	switch (MOBJGET(fobj, mhdr.hdr32->cputype)) {
		case CPU_TYPE_POWERPC:   return STR_PPC;
		case CPU_TYPE_I386:      return STR_I386;
		case CPU_TYPE_ARM:       return STR_ARM;
		case CPU_TYPE_POWERPC64: return STR_PPC64;
		case CPU_TYPE_X86_64:    return STR_X86_64;
		default:                 return STR_UNKNOWN;
	}
}
