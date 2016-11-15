/*
 * Copyright 2003-2016 Gentoo Foundation
 * Distributed under the terms of the GNU General Public License v2
 *
 * Copyright 2003-2012 Ned Ludd        - <solar@gentoo.org>
 * Copyright 2004-2016 Mike Frysinger  - <vapier@gentoo.org>
 */

#include "paxinc.h"

/*
 * ld.so.cache logic
 */

#if PAX_LDSO_CACHE

static void *ldcache = NULL;
static size_t ldcache_size = 0;

static char *ldso_cache_buf = NULL;
static size_t ldso_cache_buf_size = 0;

#if defined(__GLIBC__) || defined(__UCLIBC__)

/* Defines can be seen in glibc's sysdeps/generic/ldconfig.h */
#define LDSO_CACHE_MAGIC             "ld.so-"
#define LDSO_CACHE_MAGIC_LEN         (sizeof LDSO_CACHE_MAGIC -1)
#define LDSO_CACHE_VER               "1.7.0"
#define LDSO_CACHE_VER_LEN           (sizeof LDSO_CACHE_VER -1)
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

typedef struct {
	int flags;
	unsigned int sooffset;
	unsigned int liboffset;
} libentry_t;

static bool is_compatible(elfobj *elf, libentry_t *libent)
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
		Elf32_Ehdr *ehdr = EHDR32(elf->ehdr);

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
		Elf64_Ehdr *ehdr = EHDR64(elf->ehdr);

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

char *ldso_cache_lookup_lib(elfobj *elf, const char *fname)
{
	unsigned int nlib;
	char *ret = NULL;
	char *strs;

	typedef struct {
		char magic[LDSO_CACHE_MAGIC_LEN];
		char version[LDSO_CACHE_VER_LEN];
		unsigned int nlibs;
	} header_t;
	header_t *header;

	libentry_t *libent;

	if (fname == NULL)
		return NULL;

	if (ldcache == NULL) {
		int fd;
		const char *cachefile = root_rel_path("/etc/ld.so.cache");
		struct stat st;

		if (fstatat(root_fd, cachefile, &st, 0))
			return NULL;

		fd = openat(root_fd, cachefile, O_RDONLY);
		if (fd == -1)
			return NULL;

		/* cache these values so we only map/unmap the cache file once */
		ldcache_size = st.st_size;
		header = ldcache = mmap(0, ldcache_size, PROT_READ, MAP_SHARED, fd, 0);
		close(fd);

		if (ldcache == MAP_FAILED) {
			ldcache = NULL;
			return NULL;
		}

		if (memcmp(header->magic, LDSO_CACHE_MAGIC, LDSO_CACHE_MAGIC_LEN) ||
		    memcmp(header->version, LDSO_CACHE_VER, LDSO_CACHE_VER_LEN))
		{
			munmap(ldcache, ldcache_size);
			ldcache = NULL;
			return NULL;
		}

		ldso_cache_buf_size = 4096;
		ldso_cache_buf = xrealloc(ldso_cache_buf, ldso_cache_buf_size);
	} else
		header = ldcache;

	libent = ldcache + sizeof(header_t);
	strs = (char *) &libent[header->nlibs];

	for (nlib = 0; nlib < header->nlibs; ++nlib) {
		const char *lib;
		size_t lib_len;

		if (!is_compatible(elf, &libent[nlib]))
			continue;

		if (strcmp(fname, strs + libent[nlib].sooffset) != 0)
			continue;

		/* Return first hit because that is how the ldso rolls */
		lib = strs + libent[nlib].liboffset;
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

	if (ldcache != NULL)
		munmap(ldcache, ldcache_size);
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
