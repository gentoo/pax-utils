/*
 * Copyright 2005-2007 Gentoo Foundation
 * Distributed under the terms of the GNU General Public License v2
 * $Header: /var/cvsroot/gentoo-projects/pax-utils/paxelf.h,v 1.49 2007/06/29 17:09:12 solar Exp $
 *
 * Copyright 2005-2007 Ned Ludd        - <solar@gentoo.org>
 * Copyright 2005-2007 Mike Frysinger  - <vapier@gentoo.org>
 *
 * Make sure all of the common elf stuff is setup as we expect
 */

#ifndef _PAX_ELF_H
#define _PAX_ELF_H

typedef struct {
	void *ehdr;
	void *phdr;
	void *shdr;
	char *data, *data_end;
	char elf_class;
	off_t len;
	int fd;
	int is_mmap;
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
extern elfobj *readelf_buffer(const char *filename, char *buffer, size_t buffer_len);
extern elfobj *_readelf_fd(const char *filename, int fd, size_t len, int read_only);
#define readelf_fd(filename, fd, len) _readelf_fd(filename, fd, len, 1)
extern elfobj *_readelf(const char *filename, int read_only);
#define readelf(filename) _readelf(filename, 1)
extern void unreadelf(elfobj *elf);
extern const char *get_elfeitype(int ei_type, int type);
extern const char *get_elfetype(elfobj *elf);
extern const char *get_endian(elfobj *elf);
extern const char *get_elfemtype(elfobj *elf);
extern const char *get_elfptype(int type);
extern const char *get_elfdtype(int type);
extern const char *get_elfshttype(int type);
extern const char *get_elfstttype(int type);
extern void *elf_findsecbyname(elfobj *elf, const char *name);
extern int elf_max_pt_load(elfobj *elf);
extern int get_etype(elfobj *elf);
extern int get_emtype(elfobj *elf);
extern void print_etypes(FILE *);
extern unsigned long pax_pf2hf_flags(unsigned long);
extern int etype_lookup(const char *);

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
