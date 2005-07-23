/*
 * $Header: /var/cvsroot/gentoo-projects/pax-utils/paxelf.h,v 1.34 2005/07/23 04:57:57 vapier Exp $
 * Make sure all of the common elf stuff is setup as we expect
 */

#ifndef _PAX_ELF_H
#define _PAX_ELF_H

#include "porting.h"

#ifndef VERSION
# define VERSION "cvs"
#endif

extern char do_reverse_endian;
/* Get a value 'X' in the elf header, compensating for endianness. */
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

typedef struct {
	void *ehdr;
	void *phdr;
	void *shdr;
	char *data;
	char elf_class;
	off_t len;
	int fd;
	const char *filename;
	const char *base_filename;
} elfobj;
#define EHDR32(ptr) ((Elf32_Ehdr *)(ptr))
#define EHDR64(ptr) ((Elf64_Ehdr *)(ptr))
#define PHDR32(ptr) ((Elf32_Phdr *)(ptr))
#define PHDR64(ptr) ((Elf64_Phdr *)(ptr))
#define SHDR32(ptr) ((Elf32_Shdr *)(ptr))
#define SHDR64(ptr) ((Elf64_Shdr *)(ptr))
#define RELA32(ptr) ((Elf32_Rela *)(ptr))
#define RELA64(ptr) ((Elf64_Rela *)(ptr))
#define REL32(ptr) ((Elf32_Rel *)(ptr))
#define REL64(ptr) ((Elf64_Rel *)(ptr))
#define DYN32(ptr) ((Elf32_Dyn *)(ptr))
#define DYN64(ptr) ((Elf64_Dyn *)(ptr))
#define SYM32(ptr) ((Elf32_Sym *)(ptr))
#define SYM64(ptr) ((Elf64_Sym *)(ptr))

/* prototypes */
extern char *pax_short_hf_flags(unsigned long flags);
extern char *pax_short_pf_flags(unsigned long flags);
extern char *gnu_short_stack_flags(unsigned long flags);
extern elfobj *readelf(const char *filename);
extern void unreadelf(elfobj *elf);
extern const char *get_elfeitype(int ei_type, int type);
extern const char *get_elfetype(elfobj *elf);
extern const char *get_elfemtype(int type);
extern const char *get_elfptype(int type);
extern const char *get_elfdtype(int type);
extern const char *get_elfshttype(int type);
extern const char *get_elfstttype(int type);
extern void *elf_findsecbyname(elfobj *elf, const char *name);

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

/* PaX flags (to be read in elfhdr.e_flags) */
#define HF_PAX_PAGEEXEC      1   /* 0: Paging based non-exec pages */
#define HF_PAX_EMUTRAMP      2   /* 0: Emulate trampolines */
#define HF_PAX_MPROTECT      4   /* 0: Restrict mprotect() */
#define HF_PAX_RANDMMAP      8   /* 0: Randomize mmap() base */
#define HF_PAX_RANDEXEC      16  /* 1: Randomize ET_EXEC base */
#define HF_PAX_SEGMEXEC      32  /* 0: Segmentation based non-exec pages */

#define EI_PAX               14  /* Index in e_ident[] where to read flags */
#define __EI_PAX_FLAGS(B, elf) \
	((EHDR ## B (elf->ehdr)->e_ident[EI_PAX + 1] << 8) + \
	 EHDR ## B (elf->ehdr)->e_ident[EI_PAX])
#define EI_PAX_FLAGS(elf) \
	(__extension__ ({ \
		unsigned long __res; \
		if (elf->elf_class == ELFCLASS32) \
			__res = __EI_PAX_FLAGS(32, elf); \
		else \
			__res = __EI_PAX_FLAGS(64, elf); \
		__res; \
	}))

#endif /* _PAX_ELF_H */
