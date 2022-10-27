/*
 * Copyright 2005-2012 Gentoo Foundation
 * Distributed under the terms of the GNU General Public License v2
 *
 * Copyright 2005-2012 Ned Ludd        - <solar@gentoo.org>
 * Copyright 2005-2012 Mike Frysinger  - <vapier@gentoo.org>
 *
 * Make sure all of the common elf stuff is setup as we expect
 */

#ifndef _PAX_ELF_H
#define _PAX_ELF_H

typedef struct {
	const void *phdr;
	const void *shdr;
	/* When we need to duplicate the ELF buffer for alignment. */
	void *_data;
	union {
		const void *ehdr, *vdata;
		const char *data;
		uintptr_t udata;
	};
	const void *data_end;
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
#define VERDEF32(ptr) ((Elf32_Verdef *)(ptr))
#define VERDEF64(ptr) ((Elf64_Verdef *)(ptr))
#define VERDAUX32(ptr) ((Elf32_Verdaux *)(ptr))
#define VERDAUX64(ptr) ((Elf64_Verdaux *)(ptr))
#define VERNEED32(ptr) ((Elf32_Verneed *)(ptr))
#define VERNEED64(ptr) ((Elf64_Verneed *)(ptr))
#define VERNAUX32(ptr) ((Elf32_Vernaux *)(ptr))
#define VERNAUX64(ptr) ((Elf64_Vernaux *)(ptr))

#define VALID_RANGE(elf, offset, size) \
	((uint64_t)(size) <= (uint64_t)elf->len && \
	 (uint64_t)(offset) <= (uint64_t)elf->len - (uint64_t)(size))
#define VALID_SHDR(elf, shdr) \
	(shdr && \
	 EGET(shdr->sh_type) != SHT_NOBITS && \
	 VALID_RANGE(elf, EGET(shdr->sh_offset), EGET(shdr->sh_size)))
#define VALID_PHDR(elf, phdr) \
	(phdr && VALID_RANGE(elf, EGET(phdr->p_offset), EGET(phdr->p_filesz)))

/* prototypes */
extern const char *pax_short_hf_flags(unsigned long flags);
extern const char *pax_short_pf_flags(unsigned long flags);
extern const char *gnu_short_stack_flags(unsigned long flags);
extern elfobj *readelf_buffer(const char *filename, const void *buffer, size_t buffer_len);
extern elfobj *_readelf_fd(const char *filename, int fd, size_t len, int read_only);
#define readelf_fd(filename, fd, len) _readelf_fd(filename, fd, len, 1)
extern elfobj *_readelf(const char *filename, int read_only);
#define readelf(filename) _readelf(filename, 1)
extern void unreadelf(elfobj *elf);
extern const char *get_elfeitype(int ei_type, int type);
extern const char *get_elfetype(const elfobj *elf);
extern const char *get_endian(const elfobj *elf);
extern const char *get_elfosabi(const elfobj *elf);
extern const char *get_elf_eabi(const elfobj *elf);
extern const char *get_elfemtype(const elfobj *elf);
extern const char *get_elfptype(int type);
extern const char *get_elfdtype(int type);
extern const char *get_elfshntype(int type);
extern const char *get_elfshttype(int type);
extern const char *get_elfstbtype(int type);
extern const char *get_elfstvtype(int type);
extern const char *get_elfstttype(int type);
extern const char *get_elfnttype(uint16_t e_type, const char *name, int type);
extern const void *elf_findsecbyname(const elfobj *elf, const char *name);
extern unsigned int get_etype(const elfobj *elf);
extern unsigned int get_emtype(const elfobj *elf);
extern void print_etypes(FILE *);
extern unsigned int etype_lookup(const char *);

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
