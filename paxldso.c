/*
 * Copyright 2003-2016 Gentoo Foundation
 * Distributed under the terms of the GNU General Public License v2
 *
 * Copyright 2003-2012 Ned Ludd        - <solar@gentoo.org>
 * Copyright 2004-2016 Mike Frysinger  - <vapier@gentoo.org>
 */

#include <ctype.h>
#include <fcntl.h>
#include <features.h>
#include <glob.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include "paxinc.h"
#include "elf.h"
#include "paxelf.h"
#include "paxldso.h"
#include "xfuncs.h"

/*
 * ld.so.cache logic
 */

#if PAX_LDSO_CACHE

/* Memory region containing a specific cache. Will be a subset of the mmap. */
static const void *ldcache = NULL;
static size_t ldcache_size = 0;

/* Entire memory mapped cache file. */
static void *ldcache_mmap_base = NULL;
static size_t ldcache_mmap_size = 0;

static char *ldso_cache_buf = NULL;
static size_t ldso_cache_buf_size = 0;

#if defined(__GLIBC__) || defined(__UCLIBC__)

/* Defines can be seen in glibc's sysdeps/generic/ldconfig.h */
#define LDSO_CACHE_MAGIC_OLD         "ld.so-"
#define LDSO_CACHE_MAGIC_OLD_LEN     (sizeof LDSO_CACHE_MAGIC_OLD - 1)
#define LDSO_CACHE_VER_OLD           "1.7.0"
#define LDSO_CACHE_VER_OLD_LEN       (sizeof LDSO_CACHE_VER_OLD - 1)
#define LDSO_CACHE_MAGIC_NEW         "glibc-ld.so.cache"
#define LDSO_CACHE_MAGIC_NEW_LEN     (sizeof LDSO_CACHE_MAGIC_NEW - 1)
#define LDSO_CACHE_VER_NEW           "1.1"
#define LDSO_CACHE_VER_NEW_LEN       (sizeof LDSO_CACHE_VER_NEW - 1)
#define FLAG_ANY                     -1
#define FLAG_TYPE_MASK               0x00ff
#define FLAG_LIBC4                   0x0000
#define FLAG_ELF                     0x0001
#define FLAG_ELF_LIBC5               0x0002
#define FLAG_ELF_LIBC6               0x0003
#define FLAG_REQUIRED_MASK           0xff00
#define FLAG_SPARC_LIB64             0x0100
#define FLAG_IA64_LIB64              0x0200
#define FLAG_X8664_LIB64             0x0300
#define FLAG_S390_LIB64              0x0400
#define FLAG_POWERPC_LIB64           0x0500
#define FLAG_MIPS64_LIBN32           0x0600
#define FLAG_MIPS64_LIBN64           0x0700
#define FLAG_X8664_LIBX32            0x0800
#define FLAG_ARM_LIBHF               0x0900
#define FLAG_AARCH64_LIB64           0x0a00
#define FLAG_ARM_LIBSF               0x0b00
#define FLAG_MIPS_LIB32_NAN2008      0x0c00
#define FLAG_MIPS64_LIBN32_NAN2008   0x0d00
#define FLAG_MIPS64_LIBN64_NAN2008   0x0e00
#define FLAG_RISCV_FLOAT_ABI_SOFT    0x0f00
#define FLAG_RISCV_FLOAT_ABI_DOUBLE  0x1000

typedef struct {
	int flags;
	unsigned int sooffset;
	unsigned int liboffset;
} libentry_old_t;

typedef struct {
	const char magic[LDSO_CACHE_MAGIC_OLD_LEN];
	const char version[LDSO_CACHE_VER_OLD_LEN];
	unsigned int nlibs;
	libentry_old_t libs[0];
} header_old_t;

typedef struct {
	int32_t flags;
	uint32_t sooffset;
	uint32_t liboffset;
	uint32_t osversion;
	uint64_t hwcap;
} libentry_new_t;

typedef struct {
	const char magic[LDSO_CACHE_MAGIC_NEW_LEN];
	const char version[LDSO_CACHE_VER_NEW_LEN];
	uint32_t nlibs;
	uint32_t len_strings;
	uint8_t flags;
	uint8_t _pad_flags[3];
	uint32_t extension_offset;
	uint32_t _pad_ext[3];
	libentry_new_t libs[0];
} header_new_t;

static bool ldcache_is_new;

static bool is_compatible(elfobj *elf, const libentry_old_t *libent)
{
	int flags = libent->flags & FLAG_REQUIRED_MASK;

	/* We assume that ((flags & FLAG_TYPE_MASK) == FLAG_ELF_LIBC6)
	 * since anything older is very very old and no one cares.
	 *
	 * Otherwise we really only need to check here for cases where
	 * an arch has more than one ABI per bitsize (e.g. x86, x32, and
	 * x86_64).  The default case should be fine otherwise.
	 */

	if (elf->elf_class == ELFCLASS32) {
		const Elf32_Ehdr *ehdr = EHDR32(elf->ehdr);

		switch (EGET(ehdr->e_machine)) {
		case EM_AARCH64:
			break;
		case EM_ARM:
			if ((flags == FLAG_ARM_LIBHF && (ehdr->e_flags & EF_ARM_ABI_FLOAT_HARD)) ||
			    (flags == FLAG_ARM_LIBSF && (ehdr->e_flags & EF_ARM_ABI_FLOAT_SOFT)) ||
			    (flags == 0 && !(ehdr->e_flags & (EF_ARM_ABI_FLOAT_HARD | EF_ARM_ABI_FLOAT_SOFT))))
				return true;
			break;
		case EM_IA_64:
			break;
		case EM_MIPS: {
			int ef_flags = (ehdr->e_flags & (EF_MIPS_ABI2 | EF_MIPS_NAN2008));
			if ((flags == 0 && ef_flags == 0) ||
			    (flags == FLAG_MIPS64_LIBN32 && ef_flags == EF_MIPS_ABI2) ||
			    (flags == FLAG_MIPS_LIB32_NAN2008 && ef_flags == EF_MIPS_NAN2008) ||
			    (flags == FLAG_MIPS64_LIBN32_NAN2008 && ef_flags == (EF_MIPS_ABI2 | EF_MIPS_NAN2008)))
				return true;
			break;
		}
		case EM_X86_64:
			if (flags == FLAG_X8664_LIBX32)
				return true;
			break;
		default:
			/* A sane enough default. */
			if (flags == 0)
				return true;
			break;
		}
	} else {
		const Elf64_Ehdr *ehdr = EHDR64(elf->ehdr);

		switch (EGET(ehdr->e_machine)) {
		case EM_AARCH64:
			if (flags == FLAG_AARCH64_LIB64)
				return true;
			break;
		case EM_ARM:
			break;
		case EM_IA_64:
			if (flags == FLAG_IA64_LIB64)
				return true;
			break;
		case EM_MIPS: {
			int ef_flags = (ehdr->e_flags & EF_MIPS_NAN2008);
			if ((flags == FLAG_MIPS64_LIBN64 && ef_flags == 0) ||
			    (flags == FLAG_MIPS64_LIBN64_NAN2008 && ef_flags == EF_MIPS_NAN2008))
				return true;
			break;
		}
		case EM_X86_64:
			if (flags == FLAG_X8664_LIB64)
				return true;
			break;
		default:
			/* A sane enough default. */
			if (flags != 0)
				return true;
			break;
		}
	}

	return false;
}

static void ldso_cache_load(void)
{
	int fd;
	const char *cachefile;
	struct stat st;
	const header_old_t *header_old;
	const header_new_t *header_new;

	if (ldcache_mmap_base != NULL)
		return;

	cachefile = root_rel_path(ldcache_path);

	if (fstatat(root_fd, cachefile, &st, 0))
		return;

	fd = openat(root_fd, cachefile, O_RDONLY);
	if (fd == -1)
		return;

	/* cache these values so we only map/unmap the cache file once */
	ldcache_mmap_size = st.st_size;
	ldcache_mmap_base = mmap(0, ldcache_mmap_size, PROT_READ, MAP_SHARED, fd, 0);
	close(fd);

	if (ldcache_mmap_base == MAP_FAILED) {
		ldcache_mmap_base = NULL;
		return;
	}

	ldcache_size = ldcache_mmap_size;
	ldcache = ldcache_mmap_base;
	header_old = ldcache;
	header_new = ldcache;
#define memeq(mem1, mem2) (memcmp(mem1, mem2, sizeof(mem2) - 1) == 0)
	if (memeq(header_new->magic, LDSO_CACHE_MAGIC_NEW) &&
	    memeq(header_new->version, LDSO_CACHE_VER_NEW)) {
		ldcache_is_new = true;
	} else if (memeq(header_old->magic, LDSO_CACHE_MAGIC_OLD) &&
	           memeq(header_old->version, LDSO_CACHE_VER_OLD)) {
		/* See if the new cache format is appended after the old cache. */
		uintptr_t end =
			(uintptr_t)ldcache + sizeof(header_old_t) +
			(header_old->nlibs * sizeof(libentry_old_t));
		header_new = (const void *)ALIGN_UP(end, __alignof__(header_new_t));
		if (memeq(header_new->magic, LDSO_CACHE_MAGIC_NEW) &&
		    memeq(header_new->version, LDSO_CACHE_VER_NEW)) {
			ldcache_is_new = true;
			ldcache_size -= ((uintptr_t)header_new - (uintptr_t)ldcache);
			ldcache = header_new;
		} else {
			ldcache_is_new = false;
		}
	} else {
		munmap(ldcache_mmap_base, ldcache_mmap_size);
		ldcache_mmap_base = NULL;
		return;
	}
#undef memq

	ldso_cache_buf_size = 4096;
	ldso_cache_buf = xrealloc(ldso_cache_buf, ldso_cache_buf_size);
}

char *ldso_cache_lookup_lib(elfobj *elf, const char *fname)
{
	unsigned int nlib, nlibs;
	char *ret = NULL;
	const char *strs;
	const libentry_old_t *libent_old;
	const libentry_new_t *libent_new;

	if (fname == NULL)
		return NULL;

	ldso_cache_load();
	if (ldcache == NULL)
		return NULL;

	if (ldcache_is_new) {
		const header_new_t *header = ldcache;
		libent_old = NULL;
		libent_new = &header->libs[0];
		strs = (const char *)header;
		nlibs = header->nlibs;
	} else {
		const header_old_t *header = ldcache;
		libent_old = &header->libs[0];
		libent_new = NULL;
		strs = (const char *)&libent_old[header->nlibs];
		nlibs = header->nlibs;
	}

	/*
	 * TODO: Should add memory range checking in case cache file is corrupt.
	 * TODO: We search the cache from start to finish, but since we know the cache
	 * is sorted, we really should be doing a binary search to speed it up.
	 */
	for (nlib = 0; nlib < nlibs; ++nlib) {
		const char *lib;
		size_t lib_len;

		/* The first few fields are the same between new/old formats. */
		const libentry_old_t *libent;
		if (ldcache_is_new) {
			libent = (void *)&libent_new[nlib];
		} else {
			libent = &libent_old[nlib];
		}

		if (!is_compatible(elf, libent))
			continue;

		if (strcmp(fname, strs + libent->sooffset) != 0)
			continue;

		/* Return first hit because that is how the ldso rolls */
		lib = strs + libent->liboffset;
		lib_len = strlen(lib) + 1;
		if (lib_len > ldso_cache_buf_size) {
			ldso_cache_buf = xrealloc(ldso_cache_buf, ldso_cache_buf_size + 4096);
			ldso_cache_buf_size += 4096;
		}
		memcpy(ldso_cache_buf, lib, lib_len);
		ret = ldso_cache_buf;
		break;
	}

	return ret;
}

#endif

static void ldso_cache_cleanup(void)
{
	free(ldso_cache_buf);

	if (ldcache_mmap_base != NULL)
		munmap(ldcache_mmap_base, ldcache_mmap_size);
}

#else
# define ldso_cache_cleanup()
#endif /* PAX_LDSO_CACHE */

/*
 * ld.so.conf logic
 */

static array_t _ldpaths = array_init_decl;
array_t *ldpaths = &_ldpaths;

#if PAX_LDSO_CONFIG

#if defined(__GLIBC__) || defined(__UCLIBC__) || defined(__NetBSD__)

int ldso_config_load(const char *fname)
{
	FILE *fp = NULL;
	char *p, *path;
	size_t len;
	int curr_fd = -1;

	fp = fopenat_r(root_fd, root_rel_path(fname));
	if (fp == NULL)
		return -1;

	path = NULL;
	len = 0;
	while (getline(&path, &len, fp) != -1) {
		if ((p = strrchr(path, '\r')) != NULL)
			*p = 0;
		if ((p = strchr(path, '\n')) != NULL)
			*p = 0;

		/* recursive includes of the same file will make this segfault. */
		if ((memcmp(path, "include", 7) == 0) && isblank(path[7])) {
			glob_t gl;
			size_t x;
			const char *gpath;

			/* re-use existing path buffer ... need to be creative */
			if (path[8] != '/')
				gpath = memcpy(path + 3, "/etc/", 5);
			else
				gpath = path + 8;
			if (root_fd != AT_FDCWD) {
				if (curr_fd == -1) {
					curr_fd = open(".", O_RDONLY|O_CLOEXEC);
					if (fchdir(root_fd))
						errp("unable to change to root dir");
				}
				gpath = root_rel_path(gpath);
			}

			if (glob(gpath, 0, NULL, &gl) == 0) {
				for (x = 0; x < gl.gl_pathc; ++x) {
					/* try to avoid direct loops */
					if (strcmp(gl.gl_pathv[x], fname) == 0)
						continue;
					ldso_config_load(gl.gl_pathv[x]);
				}
				globfree(&gl);
			}

			/* failed globs are ignored by glibc */
			continue;
		}

		if (*path != '/')
			continue;

		xarraypush_str(ldpaths, path);
	}
	free(path);

	fclose(fp);

	if (curr_fd != -1) {
		if (fchdir(curr_fd))
			{/* don't care */}
		close(curr_fd);
	}

	return 0;
}

#elif defined(__FreeBSD__) || defined(__DragonFly__)

int ldso_config_load(const char *fname)
{
	FILE *fp = NULL;
	char *b = NULL, *p;
	struct elfhints_hdr hdr;

	fp = fopenat_r(root_fd, root_rel_path(fname));
	if (fp == NULL)
		return -1;

	if (fread(&hdr, 1, sizeof(hdr), fp) != sizeof(hdr) ||
	    hdr.magic != ELFHINTS_MAGIC || hdr.version != 1 ||
	    fseek(fp, hdr.strtab + hdr.dirlist, SEEK_SET) == -1)
	{
		fclose(fp);
		return -1;
	}

	b = xmalloc(hdr.dirlistlen + 1);
	if (fread(b, 1, hdr.dirlistlen+1, fp) != hdr.dirlistlen+1) {
		fclose(fp);
		free(b);
		return -1;
	}

	while ((p = strsep(&b, ":"))) {
		if (*p == '\0')
			continue;
		xarraypush_str(ldpaths, p);
	}

	free(b);
	fclose(fp);
	return 0;
}

#endif

static void ldso_config_cleanup(void)
{
	xarrayfree(ldpaths);
}

#else
# define ldso_config_cleanup()
#endif /* PAX_LDSO_CONFIG */

#ifndef paxldso_cleanup
void paxldso_cleanup(void)
{
	ldso_cache_cleanup();
	ldso_config_cleanup();
}
#endif

const char *ldcache_path = "/etc/ld.so.cache";

#ifdef MAIN

const char argv0[] = "paxldso";

int main(int argc, char *argv[])
{
	elfobj *elf = readelf(argv[0]);
	ldso_cache_load();
	printf("cache file memory base is %p\n", ldcache_mmap_base);
	printf("cache memory base is %p\n", ldcache);
	for (int i = 1; i < argc; ++i) {
		const char *search = argv[i];
		const char *lib = ldso_cache_lookup_lib(elf, search);
		printf("%s -> %s\n", search, lib);
	}
	unreadelf(elf);

	if (ldcache) {
		unsigned int nlib;
		const char *strs, *s;

		if (ldcache_is_new) {
			const header_new_t *header = ldcache;
			const libentry_new_t *libents = &header->libs[0];
			strs = (const char *)header;
			printf("dumping new cache format\n");

			for (nlib = 0; nlib < header->nlibs; ++nlib) {
				const libentry_new_t *libent = &libents[nlib];
				s = strs + libent->sooffset;
				printf("%p: %s\n", libent, s);
			}
		} else {
			const header_old_t *header = ldcache;
			const libentry_old_t *libents = &header->libs[0];
			strs = (const char *)&libents[header->nlibs];
			printf("dumping old cache format\n");

			for (nlib = 0; nlib < header->nlibs; ++nlib) {
				const libentry_old_t *libent = &libents[nlib];
				s = strs + libent->sooffset;
				printf("%p: %s\n", libent, s);
			}
		}
	}

	paxldso_cleanup();
}

#endif
