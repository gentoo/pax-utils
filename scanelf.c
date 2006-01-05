/*
 * Copyright 2003-2006 Gentoo Foundation
 * Distributed under the terms of the GNU General Public License v2
 * $Header: /var/cvsroot/gentoo-projects/pax-utils/scanelf.c,v 1.98 2006/01/05 03:12:07 vapier Exp $
 *
 * Copyright 2003-2006 Ned Ludd        - <solar@gentoo.org>
 * Copyright 2004-2006 Mike Frysinger  - <vapier@gentoo.org>
 */

#include "paxinc.h"

static const char *rcsid = "$Id: scanelf.c,v 1.98 2006/01/05 03:12:07 vapier Exp $";
#define argv0 "scanelf"

#define IS_MODIFIER(c) (c == '%' || c == '#')



/* prototypes */
static void scanelf_file(const char *filename);
static void scanelf_dir(const char *path);
static void scanelf_ldpath();
static void scanelf_envpath();
static void usage(int status);
static void parseargs(int argc, char *argv[]);
static char *xstrdup(const char *s);
static void *xmalloc(size_t size);
static void xstrncat(char **dst, const char *src, size_t *curr_len, size_t n);
#define xstrcat(dst,src,curr_len) xstrncat(dst,src,curr_len,0)
static inline void xchrcat(char **dst, const char append, size_t *curr_len);

/* variables to control behavior */
static char *ldpaths[256];
static char scan_ldpath = 0;
static char scan_envpath = 0;
static char scan_symlink = 1;
static char dir_recurse = 0;
static char dir_crossmount = 1;
static char show_pax = 0;
static char show_phdr = 0;
static char show_textrel = 0;
static char show_rpath = 0;
static char show_needed = 0;
static char show_interp = 0;
static char show_bind = 0;
static char show_soname = 0;
static char show_textrels = 0;
static char show_banner = 1;
static char be_quiet = 0;
static char be_verbose = 0;
static char be_wewy_wewy_quiet = 0;
static char *find_sym = NULL, *versioned_symname = NULL;
static char *find_lib = NULL;
static char *out_format = NULL;
static char *search_path = NULL;
static char gmatch = 0;
static char printcache = 0;


caddr_t ldcache = 0;
size_t ldcache_size = 0;

/* sub-funcs for scanelf_file() */
static void scanelf_file_get_symtabs(elfobj *elf, void **sym, void **tab)
{
	/* find the best SHT_DYNSYM and SHT_STRTAB sections */
#define GET_SYMTABS(B) \
	if (elf->elf_class == ELFCLASS ## B) { \
		Elf ## B ## _Shdr *symtab, *strtab, *dynsym, *dynstr; \
		/* debug sections */ \
		symtab = SHDR ## B (elf_findsecbyname(elf, ".symtab")); \
		strtab = SHDR ## B (elf_findsecbyname(elf, ".strtab")); \
		/* runtime sections */ \
		dynsym = SHDR ## B (elf_findsecbyname(elf, ".dynsym")); \
		dynstr = SHDR ## B (elf_findsecbyname(elf, ".dynstr")); \
		if (symtab && dynsym) { \
			*sym = (void*)((EGET(symtab->sh_size) > EGET(dynsym->sh_size)) ? symtab : dynsym); \
		} else { \
			*sym = (void*)(symtab ? symtab : dynsym); \
		} \
		if (strtab && dynstr) { \
			*tab = (void*)((EGET(strtab->sh_size) > EGET(dynstr->sh_size)) ? strtab : dynstr); \
		} else { \
			*tab = (void*)(strtab ? strtab : dynstr); \
		} \
	}
	GET_SYMTABS(32)
	GET_SYMTABS(64)
}
static char *scanelf_file_pax(elfobj *elf, char *found_pax)
{
	static char ret[7];
	unsigned long i, shown;

	if (!show_pax) return NULL;

	shown = 0;
	memset(&ret, 0, sizeof(ret));

	if (elf->phdr) {
#define SHOW_PAX(B) \
	if (elf->elf_class == ELFCLASS ## B) { \
	Elf ## B ## _Ehdr *ehdr = EHDR ## B (elf->ehdr); \
	Elf ## B ## _Phdr *phdr = PHDR ## B (elf->phdr); \
	for (i = 0; i < EGET(ehdr->e_phnum); i++) { \
		if (EGET(phdr[i].p_type) != PT_PAX_FLAGS) \
			continue; \
		if (be_quiet && (EGET(phdr[i].p_flags) == 10240)) \
			continue; \
		memcpy(ret, pax_short_pf_flags(EGET(phdr[i].p_flags)), 6); \
		*found_pax = 1; \
		++shown; \
		break; \
	} \
	}
	SHOW_PAX(32)
	SHOW_PAX(64)
	}

	/* fall back to EI_PAX if no PT_PAX was found */
	if (!*ret) {
		static char *paxflags;
		paxflags = pax_short_hf_flags(EI_PAX_FLAGS(elf));
		if (!be_quiet || (be_quiet && EI_PAX_FLAGS(elf))) {
			*found_pax = 1;
			return (be_wewy_wewy_quiet ? NULL : paxflags);
		}
		strncpy(ret, paxflags, sizeof(ret));
	}

	if (be_wewy_wewy_quiet || (be_quiet && !shown))
		return NULL;
	else
		return ret;
}

static char *scanelf_file_phdr(elfobj *elf, char *found_phdr, char *found_relro, char *found_load)
{
	static char ret[12];
	char *found;
	unsigned long i, shown;
	unsigned char multi_stack, multi_relro, multi_load;

	if (!show_phdr) return NULL;

	memcpy(ret, "--- --- ---\0", 12);

	shown = 0;
	multi_stack = multi_relro = multi_load = 0;

#define SHOW_PHDR(B) \
	if (elf->elf_class == ELFCLASS ## B) { \
	Elf ## B ## _Ehdr *ehdr = EHDR ## B (elf->ehdr); \
	Elf ## B ## _Off offset; \
	uint32_t flags, check_flags; \
	if (elf->phdr != NULL) { \
		Elf ## B ## _Phdr *phdr = PHDR ## B (elf->phdr); \
		for (i = 0; i < EGET(ehdr->e_phnum); ++i) { \
			if (EGET(phdr[i].p_type) == PT_GNU_STACK) { \
				if (multi_stack++) warnf("%s: multiple PT_GNU_STACK's !?", elf->filename); \
				found = found_phdr; \
				offset = 0; \
				check_flags = PF_X; \
			} else if (EGET(phdr[i].p_type) == PT_GNU_RELRO) { \
				if (multi_relro++) warnf("%s: multiple PT_GNU_RELRO's !?", elf->filename); \
				found = found_relro; \
				offset = 4; \
				check_flags = PF_X; \
			} else if (EGET(phdr[i].p_type) == PT_LOAD) { \
				if (multi_load++ > 2) warnf("%s: more than 2 PT_LOAD's !?", elf->filename); \
				found = found_load; \
				offset = 8; \
				check_flags = PF_W|PF_X; \
			} else \
				continue; \
			flags = EGET(phdr[i].p_flags); \
			if (be_quiet && ((flags & check_flags) != check_flags)) \
				continue; \
			memcpy(ret+offset, gnu_short_stack_flags(flags), 3); \
			*found = 1; \
			++shown; \
		} \
	} else if (elf->shdr != NULL) { \
		/* no program headers which means this is prob an object file */ \
		Elf ## B ## _Shdr *shdr = SHDR ## B (elf->shdr); \
		Elf ## B ## _Shdr *strtbl = shdr + EGET(ehdr->e_shstrndx); \
		check_flags = SHF_WRITE|SHF_EXECINSTR; \
		for (i = 0; i < EGET(ehdr->e_shnum); ++i) { \
			if (EGET(shdr[i].sh_type) != SHT_PROGBITS) continue; \
			offset = EGET(strtbl->sh_offset) + EGET(shdr[i].sh_name); \
			if (!strcmp((char*)(elf->data + offset), ".note.GNU-stack")) { \
				if (multi_stack++) warnf("%s: multiple .note.GNU-stack's !?", elf->filename); \
				flags = EGET(shdr[i].sh_flags); \
				if (be_quiet && ((flags & check_flags) != check_flags)) \
					continue; \
				++*found_phdr; \
				shown = 1; \
				if (flags & SHF_WRITE)     ret[0] = 'W'; \
				if (flags & SHF_ALLOC)     ret[1] = 'A'; \
				if (flags & SHF_EXECINSTR) ret[2] = 'X'; \
				if (flags & 0xFFFFFFF8)    warn("Invalid section flags for GNU-stack"); \
				break; \
			} \
		} \
		if (!multi_stack) { \
			*found_phdr = 1; \
			shown = 1; \
			memcpy(ret, "!WX", 3); \
		} \
	} \
	}
	SHOW_PHDR(32)
	SHOW_PHDR(64)

	if (be_wewy_wewy_quiet || (be_quiet && !shown))
		return NULL;
	else
		return ret;
}
static const char *scanelf_file_textrel(elfobj *elf, char *found_textrel)
{
	static const char *ret = "TEXTREL";
	unsigned long i;

	if (!show_textrel && !show_textrels) return NULL;

	if (elf->phdr) {
#define SHOW_TEXTREL(B) \
	if (elf->elf_class == ELFCLASS ## B) { \
	Elf ## B ## _Dyn *dyn; \
	Elf ## B ## _Ehdr *ehdr = EHDR ## B (elf->ehdr); \
	Elf ## B ## _Phdr *phdr = PHDR ## B (elf->phdr); \
	Elf ## B ## _Off offset; \
	for (i = 0; i < EGET(ehdr->e_phnum); i++) { \
		if (EGET(phdr[i].p_type) != PT_DYNAMIC) continue; \
		offset = EGET(phdr[i].p_offset); \
		if (offset >= elf->len - sizeof(Elf ## B ## _Dyn)) continue; \
		dyn = DYN ## B (elf->data + offset); \
		while (EGET(dyn->d_tag) != DT_NULL) { \
			if (EGET(dyn->d_tag) == DT_TEXTREL) { /*dyn->d_tag != DT_FLAGS)*/ \
				*found_textrel = 1; \
				/*if (dyn->d_un.d_val & DF_TEXTREL)*/ \
				return (be_wewy_wewy_quiet ? NULL : ret); \
			} \
			++dyn; \
		} \
	} }
	SHOW_TEXTREL(32)
	SHOW_TEXTREL(64)
	}

	if (be_quiet || be_wewy_wewy_quiet)
		return NULL;
	else
		return "   -   ";
}
static char *scanelf_file_textrels(elfobj *elf, char *found_textrels, char *found_textrel)
{
	unsigned long s, r, rmax;
	void *symtab_void, *strtab_void, *text_void;

	if (!show_textrels) return NULL;

	/* don't search for TEXTREL's if the ELF doesn't have any */
	if (!*found_textrel) scanelf_file_textrel(elf, found_textrel);
	if (!*found_textrel) return NULL;

	scanelf_file_get_symtabs(elf, &symtab_void, &strtab_void);
	text_void = elf_findsecbyname(elf, ".text");

	if (symtab_void && strtab_void && text_void && elf->shdr) {
#define SHOW_TEXTRELS(B) \
	if (elf->elf_class == ELFCLASS ## B) { \
	Elf ## B ## _Ehdr *ehdr = EHDR ## B (elf->ehdr); \
	Elf ## B ## _Shdr *shdr = SHDR ## B (elf->shdr); \
	Elf ## B ## _Shdr *symtab = SHDR ## B (symtab_void); \
	Elf ## B ## _Shdr *strtab = SHDR ## B (strtab_void); \
	Elf ## B ## _Shdr *text = SHDR ## B (text_void); \
	Elf ## B ## _Addr vaddr = EGET(text->sh_addr); \
	uint ## B ## _t memsz = EGET(text->sh_size); \
	Elf ## B ## _Rel *rel; \
	Elf ## B ## _Rela *rela; \
	/* search the section headers for relocations */ \
	for (s = 0; s < EGET(ehdr->e_shnum); ++s) { \
		uint32_t sh_type = EGET(shdr[s].sh_type); \
		if (sh_type == SHT_REL) { \
			rel = REL ## B (elf->data + EGET(shdr[s].sh_offset)); \
			rela = NULL; \
			rmax = EGET(shdr[s].sh_size) / sizeof(*rel); \
		} else if (sh_type == SHT_RELA) { \
			rel = NULL; \
			rela = RELA ## B (elf->data + EGET(shdr[s].sh_offset)); \
			rmax = EGET(shdr[s].sh_size) / sizeof(*rela); \
		} else \
			continue; \
		/* now see if any of the relocs are in the .text */ \
		for (r = 0; r < rmax; ++r) { \
			unsigned long sym_max; \
			Elf ## B ## _Addr offset_tmp; \
			Elf ## B ## _Sym *func; \
			Elf ## B ## _Sym *sym; \
			Elf ## B ## _Addr r_offset; \
			uint ## B ## _t r_info; \
			if (sh_type == SHT_REL) { \
				r_offset = EGET(rel[r].r_offset); \
				r_info = EGET(rel[r].r_info); \
			} else { \
				r_offset = EGET(rela[r].r_offset); \
				r_info = EGET(rela[r].r_info); \
			} \
			/* make sure this relocation is inside of the .text */ \
			if (r_offset < vaddr || r_offset >= vaddr + memsz) { \
				if (be_verbose <= 2) continue; \
			} else \
				*found_textrels = 1; \
			/* locate this relocation symbol name */ \
			sym = SYM ## B (elf->data + EGET(symtab->sh_offset)); \
			sym_max = ELF ## B ## _R_SYM(r_info); \
			if (sym_max * EGET(symtab->sh_entsize) < symtab->sh_size) \
				sym += sym_max; \
			else \
				sym = NULL; \
			sym_max = EGET(symtab->sh_size) / EGET(symtab->sh_entsize); \
			/* show the raw details about this reloc */ \
			printf("  %s: ", elf->base_filename); \
			if (sym && sym->st_name) \
				printf("%s", (char*)(elf->data + EGET(strtab->sh_offset) + EGET(sym->st_name))); \
			else \
				printf("(memory/fake?)"); \
			printf(" [0x%lX]", (unsigned long)r_offset); \
			/* now try to find the closest symbol that this rel is probably in */ \
			sym = SYM ## B (elf->data + EGET(symtab->sh_offset)); \
			func = NULL; \
			offset_tmp = 0; \
			while (sym_max--) { \
				if (EGET(sym->st_value) < r_offset && EGET(sym->st_value) > offset_tmp) { \
					func = sym; \
					offset_tmp = EGET(sym->st_value); \
				} \
				++sym; \
			} \
			printf(" in "); \
			if (func && func->st_name) \
				printf("%s", (char*)(elf->data + EGET(strtab->sh_offset) + EGET(func->st_name))); \
			else \
				printf("(NULL: fake?)"); \
			printf(" [0x%lX]\n", (unsigned long)offset_tmp); \
		} \
	} }
	SHOW_TEXTRELS(32)
	SHOW_TEXTRELS(64)
	}
	if (!*found_textrels)
		warnf("ELF %s has TEXTREL markings but doesnt appear to have any real TEXTREL's !?", elf->filename);

	return NULL;
}

static void rpath_security_checks(elfobj *, char *);
static void rpath_security_checks(elfobj *elf, char *item) {
	struct stat st;
	switch (*item) {
		case '/': break;
		case '.':
			warnf("Security problem with relative RPATH '%s' in %s", item, elf->filename);
			break;
		case '\0':
			warnf("Security problem NULL RPATH in %s", elf->filename);
			break;
		case '$':
			if (fstat(elf->fd, &st) != -1)
				if ((st.st_mode & S_ISUID) || (st.st_mode & S_ISGID))
					warnf("Security problem with RPATH='%s' in %s with mode set of %o", 
						item, elf->filename, st.st_mode & 07777);
			break;
		default:
			warnf("Maybe? sec problem with RPATH='%s' in %s", item, elf->filename);
			break;
	}
}
static void scanelf_file_rpath(elfobj *elf, char *found_rpath, char **ret, size_t *ret_len)
{
	unsigned long i, s;
	char *rpath, *runpath, **r;
	void *strtbl_void;

	if (!show_rpath) return;

	strtbl_void = elf_findsecbyname(elf, ".dynstr");
	rpath = runpath = NULL;

	if (elf->phdr && strtbl_void) {
#define SHOW_RPATH(B) \
		if (elf->elf_class == ELFCLASS ## B) { \
		Elf ## B ## _Dyn *dyn; \
		Elf ## B ## _Ehdr *ehdr = EHDR ## B (elf->ehdr); \
		Elf ## B ## _Phdr *phdr = PHDR ## B (elf->phdr); \
		Elf ## B ## _Shdr *strtbl = SHDR ## B (strtbl_void); \
		Elf ## B ## _Off offset; \
		Elf ## B ## _Xword word; \
		/* Scan all the program headers */ \
		for (i = 0; i < EGET(ehdr->e_phnum); i++) { \
			/* Just scan dynamic headers */ \
			if (EGET(phdr[i].p_type) != PT_DYNAMIC) continue; \
			offset = EGET(phdr[i].p_offset); \
			if (offset >= elf->len - sizeof(Elf ## B ## _Dyn)) continue; \
			/* Just scan dynamic RPATH/RUNPATH headers */ \
			dyn = DYN ## B (elf->data + offset); \
			while ((word=EGET(dyn->d_tag)) != DT_NULL) { \
				if (word == DT_RPATH) { \
					r = &rpath; \
				} else if (word == DT_RUNPATH) { \
					r = &runpath; \
				} else { \
					++dyn; \
					continue; \
				} \
				/* Verify the memory is somewhat sane */ \
				offset = EGET(strtbl->sh_offset) + EGET(dyn->d_un.d_ptr); \
				if (offset < (Elf ## B ## _Off)elf->len) { \
					if (*r) warn("ELF has multiple %s's !?", get_elfdtype(word)); \
					*r = (char*)(elf->data + offset); \
					/* If quiet, don't output paths in ld.so.conf */ \
					if (be_quiet) { \
						size_t len; \
						char *start, *end; \
						/* note that we only 'chop' off leading known paths. */ \
						/* since *r is read-only memory, we can only move the ptr forward. */ \
						start = *r; \
						/* scan each path in : delimited list */ \
						while (start) { \
							rpath_security_checks(elf, start); \
							end = strchr(start, ':'); \
							len = (end ? abs(end - start) : strlen(start)); \
							for (s = 0; ldpaths[s]; ++s) { \
								if (!strncmp(ldpaths[s], start, len) && !ldpaths[s][len]) { \
									*r = (end ? end + 1 : NULL); \
									break; \
								} \
							} \
							if (!*r || !ldpaths[s] || !end) \
								start = NULL; \
							else \
								start = start + len + 1; \
						} \
					} \
					if (*r) *found_rpath = 1; \
				} \
				++dyn; \
			} \
		} }
		SHOW_RPATH(32)
		SHOW_RPATH(64)
	}

	if (be_wewy_wewy_quiet) return;

	if (rpath && runpath) {
		if (!strcmp(rpath, runpath)) {
			xstrcat(ret, runpath, ret_len);
		} else {
			fprintf(stderr, "RPATH [%s] != RUNPATH [%s]\n", rpath, runpath);
			xchrcat(ret, '{', ret_len);
			xstrcat(ret, rpath, ret_len);
			xchrcat(ret, ',', ret_len);
			xstrcat(ret, runpath, ret_len);
			xchrcat(ret, '}', ret_len);
		}
	} else if (rpath || runpath)
		xstrcat(ret, (runpath ? runpath : rpath), ret_len);
	else if (!be_quiet)
		xstrcat(ret, "  -  ", ret_len);
}

#define LDSO_CACHE_MAGIC "ld.so-"
#define LDSO_CACHE_MAGIC_LEN (sizeof LDSO_CACHE_MAGIC -1)
#define LDSO_CACHE_VER "1.7.0"
#define LDSO_CACHE_VER_LEN (sizeof LDSO_CACHE_VER -1)
#define FLAG_ANY            -1
#define FLAG_TYPE_MASK      0x00ff
#define FLAG_LIBC4          0x0000
#define FLAG_ELF            0x0001
#define FLAG_ELF_LIBC5      0x0002
#define FLAG_ELF_LIBC6      0x0003
#define FLAG_REQUIRED_MASK  0xff00
#define FLAG_SPARC_LIB64    0x0100
#define FLAG_IA64_LIB64     0x0200
#define FLAG_X8664_LIB64    0x0300
#define FLAG_S390_LIB64     0x0400
#define FLAG_POWERPC_LIB64  0x0500
#define FLAG_MIPS64_LIBN32  0x0600
#define FLAG_MIPS64_LIBN64  0x0700

static char *lookup_cache_lib(elfobj *, char *);
static char *lookup_cache_lib(elfobj *elf, char *fname)
{
	int fd = 0;
	char *strs;
	static char buf[_POSIX_PATH_MAX] = "";
	const char *cachefile = "/etc/ld.so.cache";
	struct stat st;

	typedef struct {
		char magic[LDSO_CACHE_MAGIC_LEN];
		char version[LDSO_CACHE_VER_LEN];
		int nlibs;
	} header_t;
	header_t *header;

	typedef struct {
		int flags;
		int sooffset;
		int liboffset;
	} libentry_t;
	libentry_t *libent;

	if (fname == NULL)
		return NULL;

	if (ldcache == 0) {
		if (stat(cachefile, &st) || (fd = open(cachefile, O_RDONLY)) == -1)
			return NULL;

		/* cache these values so we only map/unmap the cache file once */
		ldcache_size = st.st_size;
		ldcache = mmap(0, ldcache_size, PROT_READ, MAP_SHARED, fd, 0);

		close(fd);

		if (ldcache == (caddr_t)-1)
			return NULL;

		if (memcmp(((header_t *) ldcache)->magic, LDSO_CACHE_MAGIC, LDSO_CACHE_MAGIC_LEN))
			return NULL;
		if (memcmp (((header_t *) ldcache)->version, LDSO_CACHE_VER, LDSO_CACHE_VER_LEN))
			return NULL;
	}

	header = (header_t *) ldcache;
	libent = (libentry_t *) (ldcache + sizeof(header_t));
	strs = (char *) &libent[header->nlibs];

	for (fd = 0; fd < header->nlibs; fd++) {
		/* this should be more fine grained, but for now we assume that
		 * diff arches will not be cached together.  and we ignore the
		 * the different multilib mips cases. */
		if (elf->elf_class == ELFCLASS64 && !(libent[fd].flags & FLAG_REQUIRED_MASK))
			continue;
		if (elf->elf_class == ELFCLASS32 && (libent[fd].flags & FLAG_REQUIRED_MASK))
			continue;

		if (strcmp(fname, strs + libent[fd].sooffset) != 0)
			continue;
		strncpy(buf, strs + libent[fd].liboffset, sizeof(buf));
	}
	return buf;
}


static const char *scanelf_file_needed_lib(elfobj *elf, char *found_needed, char *found_lib, int op, char **ret, size_t *ret_len)
{
	unsigned long i;
	char *needed;
	void *strtbl_void;
	char *p;

	if ((op==0 && !show_needed) || (op==1 && !find_lib)) return NULL;

	strtbl_void = elf_findsecbyname(elf, ".dynstr");

	if (elf->phdr && strtbl_void) {
#define SHOW_NEEDED(B) \
		if (elf->elf_class == ELFCLASS ## B) { \
		Elf ## B ## _Dyn *dyn; \
		Elf ## B ## _Ehdr *ehdr = EHDR ## B (elf->ehdr); \
		Elf ## B ## _Phdr *phdr = PHDR ## B (elf->phdr); \
		Elf ## B ## _Shdr *strtbl = SHDR ## B (strtbl_void); \
		Elf ## B ## _Off offset; \
		for (i = 0; i < EGET(ehdr->e_phnum); i++) { \
			if (EGET(phdr[i].p_type) != PT_DYNAMIC) continue; \
			offset = EGET(phdr[i].p_offset); \
			if (offset >= elf->len - sizeof(Elf ## B ## _Dyn)) continue; \
			dyn = DYN ## B (elf->data + offset); \
			while (EGET(dyn->d_tag) != DT_NULL) { \
				if (EGET(dyn->d_tag) == DT_NEEDED) { \
					offset = EGET(strtbl->sh_offset) + EGET(dyn->d_un.d_ptr); \
					if (offset >= (Elf ## B ## _Off)elf->len) { \
						++dyn; \
						continue; \
					} \
					needed = (char*)(elf->data + offset); \
					if (op == 0) { \
						if (!be_wewy_wewy_quiet) { \
							if (*found_needed) xchrcat(ret, ',', ret_len); \
							if (printcache) \
								if ((p = lookup_cache_lib(elf, needed)) != NULL) \
									needed = p; \
							xstrcat(ret, needed, ret_len); \
						} \
						*found_needed = 1; \
					} else { \
						if (!strncmp(find_lib, needed, strlen( !gmatch ? needed : find_lib))) { \
							*found_lib = 1; \
							return (be_wewy_wewy_quiet ? NULL : needed); \
						} \
					} \
				} \
				++dyn; \
			} \
		} }
		SHOW_NEEDED(32)
		SHOW_NEEDED(64)
		if (op == 0 && !*found_needed && be_verbose)
			warn("ELF lacks DT_NEEDED sections: %s", elf->filename);
	}

	return NULL;
}
static char *scanelf_file_interp(elfobj *elf, char *found_interp)
{
	void *strtbl_void;

	if (!show_interp) return NULL;

	strtbl_void = elf_findsecbyname(elf, ".interp");

	if (strtbl_void) {
#define SHOW_INTERP(B) \
		if (elf->elf_class == ELFCLASS ## B) { \
			Elf ## B ## _Shdr *strtbl = SHDR ## B (strtbl_void); \
			*found_interp = 1; \
			return (be_wewy_wewy_quiet ? NULL : elf->data + EGET(strtbl->sh_offset)); \
		}
		SHOW_INTERP(32)
		SHOW_INTERP(64)
	}
	return NULL;
}
static char *scanelf_file_bind(elfobj *elf, char *found_bind)
{
	unsigned long i;
	struct stat s;

	if (!show_bind) return NULL;
	if (!elf->phdr) return NULL;

#define SHOW_BIND(B) \
	if (elf->elf_class == ELFCLASS ## B) { \
		Elf ## B ## _Dyn *dyn; \
		Elf ## B ## _Ehdr *ehdr = EHDR ## B (elf->ehdr); \
		Elf ## B ## _Phdr *phdr = PHDR ## B (elf->phdr); \
		Elf ## B ## _Off offset; \
		for (i = 0; i < EGET(ehdr->e_phnum); i++) { \
			if (EGET(phdr[i].p_type) != PT_DYNAMIC) continue; \
			offset = EGET(phdr[i].p_offset); \
			if (offset >= elf->len - sizeof(Elf ## B ## _Dyn)) continue; \
			dyn = DYN ## B (elf->data + offset); \
			while (EGET(dyn->d_tag) != DT_NULL) { \
				if (EGET(dyn->d_tag) == DT_BIND_NOW || \
				   (EGET(dyn->d_tag) == DT_FLAGS && EGET(dyn->d_un.d_val) & DF_BIND_NOW)) \
				{ \
					if (be_quiet) return NULL; \
					*found_bind = 1; \
					return (char *)(be_wewy_wewy_quiet ? NULL : "NOW"); \
				} \
				++dyn; \
			} \
		} \
	}
	SHOW_BIND(32)
	SHOW_BIND(64)

	if (be_wewy_wewy_quiet) return NULL;

	if (be_quiet && !fstat(elf->fd, &s) && !(s.st_mode & S_ISUID || s.st_mode & S_ISGID)) {
		return NULL;
	} else {
		*found_bind = 1;
		return (char *) "LAZY";
	}
}
static char *scanelf_file_soname(elfobj *elf, char *found_soname)
{
	unsigned long i;
	char *soname;
	void *strtbl_void;

	if (!show_soname) return NULL;

	strtbl_void = elf_findsecbyname(elf, ".dynstr");

	if (elf->phdr && strtbl_void) {
#define SHOW_SONAME(B) \
		if (elf->elf_class == ELFCLASS ## B) { \
		Elf ## B ## _Dyn *dyn; \
		Elf ## B ## _Ehdr *ehdr = EHDR ## B (elf->ehdr); \
		Elf ## B ## _Phdr *phdr = PHDR ## B (elf->phdr); \
		Elf ## B ## _Shdr *strtbl = SHDR ## B (strtbl_void); \
		Elf ## B ## _Off offset; \
		/* only look for soname in shared objects */ \
		if (ehdr->e_type != ET_DYN) \
			return NULL; \
		for (i = 0; i < EGET(ehdr->e_phnum); i++) { \
			if (EGET(phdr[i].p_type) != PT_DYNAMIC) continue; \
			offset = EGET(phdr[i].p_offset); \
			if (offset >= elf->len - sizeof(Elf ## B ## _Dyn)) continue; \
			dyn = DYN ## B (elf->data + offset); \
			while (EGET(dyn->d_tag) != DT_NULL) { \
				if (EGET(dyn->d_tag) == DT_SONAME) { \
					offset = EGET(strtbl->sh_offset) + EGET(dyn->d_un.d_ptr); \
					if (offset >= (Elf ## B ## _Off)elf->len) { \
						++dyn; \
						continue; \
					} \
					soname = (char*)(elf->data + offset); \
					*found_soname = 1; \
					return (be_wewy_wewy_quiet ? NULL : soname); \
				} \
				++dyn; \
			} \
		} }
		SHOW_SONAME(32)
		SHOW_SONAME(64)
	}

	return NULL;
}
static char *scanelf_file_sym(elfobj *elf, char *found_sym)
{
	unsigned long i;
	char *ret;
	void *symtab_void, *strtab_void;

	if (!find_sym) return NULL;
	ret = find_sym;

	scanelf_file_get_symtabs(elf, &symtab_void, &strtab_void);

	if (symtab_void && strtab_void) {
#define FIND_SYM(B) \
		if (elf->elf_class == ELFCLASS ## B) { \
		Elf ## B ## _Shdr *symtab = SHDR ## B (symtab_void); \
		Elf ## B ## _Shdr *strtab = SHDR ## B (strtab_void); \
		Elf ## B ## _Sym *sym = SYM ## B (elf->data + EGET(symtab->sh_offset)); \
		unsigned long cnt = EGET(symtab->sh_size) / EGET(symtab->sh_entsize); \
		char *symname; \
		for (i = 0; i < cnt; ++i) { \
			if (sym->st_name) { \
				symname = (char *)(elf->data + EGET(strtab->sh_offset) + EGET(sym->st_name)); \
				if (*find_sym == '*') { \
					printf("%s(%s) %5lX %15s %s\n", \
					       ((*found_sym == 0) ? "\n\t" : "\t"), \
					       elf->base_filename, \
					       (unsigned long)sym->st_size, \
					       get_elfstttype(sym->st_info), \
					       symname); \
					*found_sym = 1; \
				} else { \
					char *this_sym, *next_sym; \
					this_sym = find_sym; \
					do { \
						next_sym = strchr(this_sym, ','); \
						if (next_sym == NULL) \
							next_sym = this_sym + strlen(this_sym); \
						if ((strncmp(this_sym, symname, (next_sym-this_sym)) == 0 && symname[next_sym-this_sym] == '\0') || \
						    (strcmp(symname, versioned_symname) == 0)) { \
							ret = this_sym; \
							(*found_sym)++; \
							goto break_out; \
						} \
						this_sym = next_sym + 1; \
					} while (*next_sym != '\0'); \
				} \
			} \
			++sym; \
		} }
		FIND_SYM(32)
		FIND_SYM(64)
	}

break_out:
	if (be_wewy_wewy_quiet) return NULL;

	if (*find_sym != '*' && *found_sym)
		return ret;
	if (be_quiet)
		return NULL;
	else
		return (char *)" - ";
}
/* scan an elf file and show all the fun stuff */
#define prints(str) write(fileno(stdout), str, strlen(str))
static void scanelf_file(const char *filename)
{
	unsigned long i;
	char found_pax, found_phdr, found_relro, found_load, found_textrel, 
	     found_rpath, found_needed, found_interp, found_bind, found_soname, 
	     found_sym, found_lib, found_file, found_textrels;
	elfobj *elf;
	struct stat st;
	static char *out_buffer = NULL;
	static size_t out_len;

	/* make sure 'filename' exists */
	if (lstat(filename, &st) == -1) {
		if (be_verbose > 2) printf("%s: does not exist\n", filename);
		return;
	}
	/* always handle regular files and handle symlinked files if no -y */
	if (S_ISLNK(st.st_mode)) {
		if (!scan_symlink) return;
		stat(filename, &st);
	}
	if (!S_ISREG(st.st_mode)) {
		if (be_verbose > 2) printf("%s: skipping non-file\n", filename);
		return;
	}

	found_pax = found_phdr = found_relro = found_load = found_textrel = \
	found_rpath = found_needed = found_interp = found_bind = found_soname = \
	found_sym = found_lib = found_file = found_textrels = 0;

	/* verify this is real ELF */
	if ((elf = readelf(filename)) == NULL) {
		if (be_verbose > 2) printf("%s: not an ELF\n", filename);
		return;
	}

	if (be_verbose > 1)
		printf("%s: scanning file {%s,%s}\n", filename,
		       get_elfeitype(EI_CLASS, elf->elf_class),
		       get_elfeitype(EI_DATA, elf->data[EI_DATA]));
	else if (be_verbose)
		printf("%s: scanning file\n", filename);

	/* init output buffer */
	if (!out_buffer) {
		out_len = sizeof(char) * 80;
		out_buffer = (char*)xmalloc(out_len);
	}
	*out_buffer = '\0';

	/* show the header */
	if (!be_quiet && show_banner) {
		for (i = 0; out_format[i]; ++i) {
			if (!IS_MODIFIER(out_format[i])) continue;

			switch (out_format[++i]) {
			case '%': break;
			case '#': break;
			case 'F':
			case 'p':
			case 'f': prints("FILE "); found_file = 1; break;
			case 'o': prints(" TYPE   "); break;
			case 'x': prints(" PAX   "); break;
			case 'e': prints("STK/REL/PTL "); break;
			case 't': prints("TEXTREL "); break;
			case 'r': prints("RPATH "); break;
			case 'n': prints("NEEDED "); break;
			case 'i': prints("INTERP "); break;
			case 'b': prints("BIND "); break;
			case 'S': prints("SONAME "); break;
			case 's': prints("SYM "); break;
			case 'N': prints("LIB "); break;
			case 'T': prints("TEXTRELS "); break;
			default: warnf("'%c' has no title ?", out_format[i]);
			}
		}
		if (!found_file) prints("FILE ");
		prints("\n");
		found_file = 0;
		show_banner = 0;
	}

	/* dump all the good stuff */
	for (i = 0; out_format[i]; ++i) {
		const char *out;
		const char *tmp;

		/* make sure we trim leading spaces in quiet mode */
		if (be_quiet && *out_buffer == ' ' && !out_buffer[1])
			*out_buffer = '\0';

		if (!IS_MODIFIER(out_format[i])) {
			xchrcat(&out_buffer, out_format[i], &out_len);
			continue;
		}

		out = NULL;
		be_wewy_wewy_quiet = (out_format[i] == '#');
		switch (out_format[++i]) {
		case '%':
		case '#':
			xchrcat(&out_buffer, out_format[i], &out_len); break;
		case 'F':
			found_file = 1;
			if (be_wewy_wewy_quiet) break;
			xstrcat(&out_buffer, filename, &out_len);
			break;
		case 'p':
			found_file = 1;
			if (be_wewy_wewy_quiet) break;
			tmp = filename;
			if (search_path) {
				ssize_t len_search = strlen(search_path);
				ssize_t len_file = strlen(filename);
				if (!strncmp(filename, search_path, len_search) && \
				    len_file > len_search)
					tmp += len_search;
				if (*tmp == '/' && search_path[len_search-1] == '/') tmp++;
			}
			xstrcat(&out_buffer, tmp, &out_len);
			break;
		case 'f':
			found_file = 1;
			if (be_wewy_wewy_quiet) break;
			tmp = strrchr(filename, '/');
			tmp = (tmp == NULL ? filename : tmp+1);
			xstrcat(&out_buffer, tmp, &out_len);
			break;
		case 'o': out = get_elfetype(elf); break;
		case 'x': out = scanelf_file_pax(elf, &found_pax); break;
		case 'e': out = scanelf_file_phdr(elf, &found_phdr, &found_relro, &found_load); break;
		case 't': out = scanelf_file_textrel(elf, &found_textrel); break;
		case 'T': out = scanelf_file_textrels(elf, &found_textrels, &found_textrel); break;
		case 'r': scanelf_file_rpath(elf, &found_rpath, &out_buffer, &out_len); break;
		case 'n':
		case 'N': out = scanelf_file_needed_lib(elf, &found_needed, &found_lib, (out_format[i]=='N'), &out_buffer, &out_len); break;
		case 'i': out = scanelf_file_interp(elf, &found_interp); break;
		case 'b': out = scanelf_file_bind(elf, &found_bind); break;
		case 'S': out = scanelf_file_soname(elf, &found_soname); break;
		case 's': out = scanelf_file_sym(elf, &found_sym); break;
		default: warnf("'%c' has no scan code?", out_format[i]);
		}
		if (out) {
			/* hack for comma delimited output like `scanelf -s sym1,sym2,sym3` */
			if (out_format[i] == 's' && (tmp=strchr(out,',')) != NULL)
				xstrncat(&out_buffer, out, &out_len, (tmp-out));
			else
				xstrcat(&out_buffer, out, &out_len);
		}
	}

#define FOUND_SOMETHING() \
	(found_pax || found_phdr || found_relro || found_load || found_textrel || \
	 found_rpath || found_needed || found_interp || found_bind || \
	 found_soname || found_sym || found_lib || found_textrels)

	if (!found_file && (!be_quiet || (be_quiet && FOUND_SOMETHING()))) {
		xchrcat(&out_buffer, ' ', &out_len);
		xstrcat(&out_buffer, filename, &out_len);
	}
	if (!be_quiet || (be_quiet && FOUND_SOMETHING())) {
		puts(out_buffer);
		fflush(stdout);
	}

	unreadelf(elf);
}

/* scan a directory for ET_EXEC files and print when we find one */
static void scanelf_dir(const char *path)
{
	register DIR *dir;
	register struct dirent *dentry;
	struct stat st_top, st;
	char buf[_POSIX_PATH_MAX];
	size_t pathlen = 0, len = 0;

	/* make sure path exists */
	if (lstat(path, &st_top) == -1) {
		if (be_verbose > 2) printf("%s: does not exist\n", path);
		return;
	}

	/* ok, if it isn't a directory, assume we can open it */
	if (!S_ISDIR(st_top.st_mode)) {
		scanelf_file(path);
		return;
	}

	/* now scan the dir looking for fun stuff */
	if ((dir = opendir(path)) == NULL) {
		warnf("could not opendir %s: %s", path, strerror(errno));
		return;
	}
	if (be_verbose) printf("%s: scanning dir\n", path);

	pathlen = strlen(path);
	while ((dentry = readdir(dir))) {
		if (!strcmp(dentry->d_name, ".") || !strcmp(dentry->d_name, ".."))
			continue;
		len = (pathlen + 1 + strlen(dentry->d_name) + 1);
		if (len >= sizeof(buf)) {
			warnf("Skipping '%s': len > sizeof(buf); %lu > %lu\n", path,
			      (unsigned long)len, (unsigned long)sizeof(buf));
			continue;
		}
		sprintf(buf, "%s/%s", path, dentry->d_name);
		if (lstat(buf, &st) != -1) {
			if (S_ISREG(st.st_mode))
				scanelf_file(buf);
			else if (dir_recurse && S_ISDIR(st.st_mode)) {
				if (dir_crossmount || (st_top.st_dev == st.st_dev))
					scanelf_dir(buf);
			}
		}
	}
	closedir(dir);
}

static int scanelf_from_file(char *filename)
{
	FILE *fp = NULL;
	char *p;
	char path[_POSIX_PATH_MAX];

	if (((strcmp(filename, "-")) == 0) && (ttyname(0) == NULL))
		fp = stdin;
	else if ((fp = fopen(filename, "r")) == NULL)
		return 1;

	while ((fgets(path, _POSIX_PATH_MAX, fp)) != NULL) {
		if ((p = strchr(path, '\n')) != NULL)
			*p = 0;
		search_path = path;
		scanelf_dir(path);
	}
	if (fp != stdin)
		fclose(fp);
	return 0;
}

static void load_ld_so_conf()
{
	FILE *fp = NULL;
	char *p;
	char path[_POSIX_PATH_MAX];
	int i = 0;

	if ((fp = fopen("/etc/ld.so.conf", "r")) == NULL)
		return;

	while ((fgets(path, _POSIX_PATH_MAX, fp)) != NULL) {
		if (*path != '/')
			continue;

		if ((p = strrchr(path, '\r')) != NULL)
			*p = 0;
		if ((p = strchr(path, '\n')) != NULL)
			*p = 0;

		ldpaths[i++] = xstrdup(path);

		if (i + 1 == sizeof(ldpaths) / sizeof(*ldpaths))
			break;
	}
	ldpaths[i] = NULL;

	fclose(fp);
}

/* scan /etc/ld.so.conf for paths */
static void scanelf_ldpath()
{
	char scan_l, scan_ul, scan_ull;
	int i = 0;

	if (!ldpaths[0])
		err("Unable to load any paths from ld.so.conf");

	scan_l = scan_ul = scan_ull = 0;

	while (ldpaths[i]) {
		if (!scan_l   && !strcmp(ldpaths[i], "/lib")) scan_l = 1;
		if (!scan_ul  && !strcmp(ldpaths[i], "/usr/lib")) scan_ul = 1;
		if (!scan_ull && !strcmp(ldpaths[i], "/usr/local/lib")) scan_ull = 1;
		scanelf_dir(ldpaths[i]);
		++i;
	}

	if (!scan_l)   scanelf_dir("/lib");
	if (!scan_ul)  scanelf_dir("/usr/lib");
	if (!scan_ull) scanelf_dir("/usr/local/lib");
}

/* scan env PATH for paths */
static void scanelf_envpath()
{
	char *path, *p;

	path = getenv("PATH");
	if (!path)
		err("PATH is not set in your env !");
	path = xstrdup(path);

	while ((p = strrchr(path, ':')) != NULL) {
		scanelf_dir(p + 1);
		*p = 0;
	}

	free(path);
}


/* usage / invocation handling functions */
#define PARSE_FLAGS "plRmyxetrnLibSs:gN:TaqvF:f:o:BhV"
#define a_argument required_argument
static struct option const long_opts[] = {
	{"path",      no_argument, NULL, 'p'},
	{"ldpath",    no_argument, NULL, 'l'},
	{"recursive", no_argument, NULL, 'R'},
	{"mount",     no_argument, NULL, 'm'},
	{"symlink",   no_argument, NULL, 'y'},
	{"pax",       no_argument, NULL, 'x'},
	{"header",    no_argument, NULL, 'e'},
	{"textrel",   no_argument, NULL, 't'},
	{"rpath",     no_argument, NULL, 'r'},
	{"needed",    no_argument, NULL, 'n'},
	{"ldcache",   no_argument, NULL, 'L'},
	{"interp",    no_argument, NULL, 'i'},
	{"bind",      no_argument, NULL, 'b'},
	{"soname",    no_argument, NULL, 'S'},
	{"symbol",     a_argument, NULL, 's'},
	{"lib",        a_argument, NULL, 'N'},
	{"gmatch",    no_argument, NULL, 'g'},
	{"textrels",  no_argument, NULL, 'T'},
	{"all",       no_argument, NULL, 'a'},
	{"quiet",     no_argument, NULL, 'q'},
	{"verbose",   no_argument, NULL, 'v'},
	{"format",     a_argument, NULL, 'F'},
	{"from",       a_argument, NULL, 'f'},
	{"file",       a_argument, NULL, 'o'},
	{"nobanner",  no_argument, NULL, 'B'},
	{"help",      no_argument, NULL, 'h'},
	{"version",   no_argument, NULL, 'V'},
	{NULL,        no_argument, NULL, 0x0}
};

static const char *opts_help[] = {
	"Scan all directories in PATH environment",
	"Scan all directories in /etc/ld.so.conf",
	"Scan directories recursively",
	"Don't recursively cross mount points",
	"Don't scan symlinks\n",
	"Print PaX markings",
	"Print GNU_STACK/PT_LOAD markings",
	"Print TEXTREL information",
	"Print RPATH information",
	"Print NEEDED information",
	"Resolve NEEDED information (use with -n)",
	"Print INTERP information",
	"Print BIND information",
	"Print SONAME information",
	"Find a specified symbol",
	"Find a specified library",
	"Use strncmp to match libraries. (use with -N)",
	"Locate cause of TEXTREL",
	"Print all scanned info (-x -e -t -r -b)\n",
	"Only output 'bad' things",
	"Be verbose (can be specified more than once)",
	"Use specified format for output",
	"Read input stream from a filename",
	"Write output stream to a filename",
	"Don't display the header",
	"Print this help and exit",
	"Print version and exit",
	NULL
};

/* display usage and exit */
static void usage(int status)
{
	unsigned long i;
	printf("* Scan ELF binaries for stuff\n\n"
	       "Usage: %s [options] <dir1/file1> [dir2 dirN fileN ...]\n\n", argv0);
	printf("Options: -[%s]\n", PARSE_FLAGS);
	for (i = 0; long_opts[i].name; ++i)
		if (long_opts[i].has_arg == no_argument)
			printf("  -%c, --%-13s* %s\n", long_opts[i].val, 
			       long_opts[i].name, opts_help[i]);
		else
			printf("  -%c, --%-6s <arg> * %s\n", long_opts[i].val,
			       long_opts[i].name, opts_help[i]);

	if (status != EXIT_SUCCESS)
		exit(status);

	puts("\nThe format modifiers for the -F option are:");
	puts(" F Filename \tx PaX Flags \te STACK/RELRO");
	puts(" t TEXTREL  \tr RPATH     \tn NEEDED");
	puts(" i INTERP   \tb BIND      \ts symbol");
	puts(" N library  \to Type      \tT TEXTRELs");
	puts(" S SONAME");
	puts(" p filename (with search path removed)");
	puts(" f filename (short name/basename)");
	puts("Prefix each modifier with '%' (verbose) or '#' (silent)");

	exit(status);
}

/* parse command line arguments and preform needed actions */
static void parseargs(int argc, char *argv[])
{
	int i;
	char *from_file = NULL;

	opterr = 0;
	while ((i=getopt_long(argc, argv, PARSE_FLAGS, long_opts, NULL)) != -1) {
		switch (i) {

		case 'V':
			printf("pax-utils-%s: %s compiled %s\n%s\n"
			       "%s written for Gentoo by <solar and vapier @ gentoo.org>\n",
			       VERSION, __FILE__, __DATE__, rcsid, argv0);
			exit(EXIT_SUCCESS);
			break;
		case 'h': usage(EXIT_SUCCESS); break;
		case 'f':
			if (from_file) err("Don't specify -f twice");
			from_file = xstrdup(optarg);
			break;
		case 'o': {
			FILE *fp = NULL;
			if ((fp = freopen(optarg, "w", stdout)) == NULL)
				err("Could not open output stream '%s': %s", optarg, strerror(errno));
			SET_STDOUT(fp);
			break;
		}

		case 's': {
			if (find_sym) warn("You prob don't want to specify -s twice");
			find_sym = optarg;
			versioned_symname = (char*)xmalloc(sizeof(char) * (strlen(find_sym)+1+1));
			sprintf(versioned_symname, "%s@", find_sym);
			break;
		}
		case 'N': {
			if (find_lib) warn("You prob don't want to specify -N twice");
			find_lib = optarg;
			break;
		}

		case 'F': {
			if (out_format) warn("You prob don't want to specify -F twice");
			out_format = optarg;
			break;
		}

		case 'g': gmatch = 1; /* break; any reason we dont breal; here ? */
		case 'L': printcache = 1; break;
		case 'y': scan_symlink = 0; break;
		case 'B': show_banner = 0; break;
		case 'l': scan_ldpath = 1; break;
		case 'p': scan_envpath = 1; break;
		case 'R': dir_recurse = 1; break;
		case 'm': dir_crossmount = 0; break;
		case 'x': show_pax = 1; break;
		case 'e': show_phdr = 1; break;
		case 't': show_textrel = 1; break;
		case 'r': show_rpath = 1; break;
		case 'n': show_needed = 1; break;
		case 'i': show_interp = 1; break;
		case 'b': show_bind = 1; break;
		case 'S': show_soname = 1; break;
		case 'T': show_textrels = 1; break;
		case 'q': be_quiet = 1; break;
		case 'v': be_verbose = (be_verbose % 20) + 1; break;
		case 'a': show_pax = show_phdr = show_textrel = show_rpath = show_bind = 1; break;

		case ':':
			err("Option missing parameter\n");
		case '?':
			err("Unknown option\n");
		default:
			err("Unhandled option '%c'", i);
		}
	}

	/* let the format option override all other options */
	if (out_format) {
		show_pax = show_phdr = show_textrel = show_rpath = \
		show_needed = show_interp = show_bind = show_soname = \
		show_textrels = 0;
		for (i = 0; out_format[i]; ++i) {
			if (!IS_MODIFIER(out_format[i])) continue;

			switch (out_format[++i]) {
			case '%': break;
			case '#': break;
			case 'F': break;
			case 'p': break;
			case 'f': break;
			case 's': break;
			case 'N': break;
			case 'o': break;
			case 'x': show_pax = 1; break;
			case 'e': show_phdr = 1; break;
			case 't': show_textrel = 1; break;
			case 'r': show_rpath = 1; break;
			case 'n': show_needed = 1; break;
			case 'i': show_interp = 1; break;
			case 'b': show_bind = 1; break;
			case 'S': show_soname = 1; break;
			case 'T': show_textrels = 1; break;
			default:
				err("Invalid format specifier '%c' (byte %i)", 
				    out_format[i], i+1);
			}
		}

	/* construct our default format */
	} else {
		size_t fmt_len = 30;
		out_format = (char*)xmalloc(sizeof(char) * fmt_len);
		if (!be_quiet)     xstrcat(&out_format, "%o ", &fmt_len);
		if (show_pax)      xstrcat(&out_format, "%x ", &fmt_len);
		if (show_phdr)     xstrcat(&out_format, "%e ", &fmt_len);
		if (show_textrel)  xstrcat(&out_format, "%t ", &fmt_len);
		if (show_rpath)    xstrcat(&out_format, "%r ", &fmt_len);
		if (show_needed)   xstrcat(&out_format, "%n ", &fmt_len);
		if (show_interp)   xstrcat(&out_format, "%i ", &fmt_len);
		if (show_bind)     xstrcat(&out_format, "%b ", &fmt_len);
		if (show_soname)   xstrcat(&out_format, "%S ", &fmt_len);
		if (show_textrels) xstrcat(&out_format, "%T ", &fmt_len);
		if (find_sym)      xstrcat(&out_format, "%s ", &fmt_len);
		if (find_lib)      xstrcat(&out_format, "%N ", &fmt_len);
		if (!be_quiet)     xstrcat(&out_format, "%F ", &fmt_len);
	}
	if (be_verbose > 2) printf("Format: %s\n", out_format);

	/* now lets actually do the scanning */
	if (scan_ldpath || (show_rpath && be_quiet))
		load_ld_so_conf();
	if (scan_ldpath) scanelf_ldpath();
	if (scan_envpath) scanelf_envpath();
	if (from_file) {
		scanelf_from_file(from_file);
		free(from_file);
		from_file = *argv;
	}
	if (optind == argc && !scan_ldpath && !scan_envpath && !from_file)
		err("Nothing to scan !?");
	while (optind < argc) {
		search_path = argv[optind++];
		scanelf_dir(search_path);
	}

	/* clean up */
	if (versioned_symname) free(versioned_symname);
	for (i = 0; ldpaths[i]; ++i)
		free(ldpaths[i]);

	if (ldcache != 0)
		munmap(ldcache, ldcache_size);
}



/* utility funcs */
static char *xstrdup(const char *s)
{
	char *ret = strdup(s);
	if (!ret) err("Could not strdup(): %s", strerror(errno));
	return ret;
}
static void *xmalloc(size_t size)
{
	void *ret = malloc(size);
	if (!ret) err("Could not malloc() %li bytes", (unsigned long)size);
	return ret;
}
static void xstrncat(char **dst, const char *src, size_t *curr_len, size_t n)
{
	size_t new_len;

	new_len = strlen(*dst) + strlen(src);
	if (*curr_len <= new_len) {
		*curr_len = new_len + (*curr_len / 2);
		*dst = realloc(*dst, *curr_len);
		if (!*dst)
			err("could not realloc() %li bytes", (unsigned long)*curr_len);
	}

	if (n)
		strncat(*dst, src, n);
	else
		strcat(*dst, src);
}
static inline void xchrcat(char **dst, const char append, size_t *curr_len)
{
	static char my_app[2];
	my_app[0] = append;
	my_app[1] = '\0';
	xstrcat(dst, my_app, curr_len);
}



int main(int argc, char *argv[])
{
	if (argc < 2)
		usage(EXIT_FAILURE);
	parseargs(argc, argv);
	fclose(stdout);
#ifdef __BOUNDS_CHECKING_ON
	warn("The calls to add/delete heap should be off by 1 due to the out_buffer not being freed in scanelf_file()");
#endif
	return EXIT_SUCCESS;
}
