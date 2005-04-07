/*
 * Make sure all of the common elf stuff is setup as we expect
 */

#ifndef _PAX_ELF_H
#define _PAX_ELF_H

#include <sys/mman.h>
#ifdef __linux__
# include <elf.h>
# include <asm/elf.h>
# include <byteswap.h>
#else
# include <sys/elf_common.h>
#endif

#ifndef ELF_CLASS
# error "UNABLE TO DETECT ELF_CLASS"
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
/* Set a value 'Y' in the elf header to 'X', compensating for endianness. */
#define ESET(Y,X) \
	do if (!do_reverse_endian) { Y = (X); \
	} else if (sizeof(Y) == 1) { Y = (X); \
	} else if (sizeof(Y) == 2) { Y = bswap_16((uint16_t)(X)); \
	} else if (sizeof(Y) == 4) { Y = bswap_32((uint32_t)(X)); \
	} else if (sizeof(Y) == 8) { Y = bswap_64((uint64_t)(X)); \
	} else { \
		fprintf(stderr, "ESET failed ;(\n")); \
		exit(EXIT_FAILURE); \
	} while (0)

typedef struct {
	void *ehdr;
	void *phdr;
	void *shdr;
	char *data;
	char elf_class;
	int len;
	int fd;
} elfobj;
#define EHDR32(ptr) ((Elf32_Ehdr *)(ptr))
#define EHDR64(ptr) ((Elf64_Ehdr *)(ptr))
#define PHDR32(ptr) ((Elf32_Phdr *)(ptr))
#define PHDR64(ptr) ((Elf64_Phdr *)(ptr))
#define SHDR32(ptr) ((Elf32_Shdr *)(ptr))
#define SHDR64(ptr) ((Elf64_Shdr *)(ptr))
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
extern const char *get_elfeitype(elfobj *elf, int ei_type, int type);
extern const char *get_elfetype(elfobj *elf);
extern const char *get_elfemtype(int type);
extern const char *get_elfptype(int type);
extern const char *get_elfdtype(int type);
extern const char *get_elfstttype(int type);
extern void *elf_findsecbyname(elfobj *elf, const char *name);

/* PaX flags (to be read in elfhdr.e_flags) */
#define HF_PAX_PAGEEXEC		1	/* 0: Paging based non-exec pages */
#define HF_PAX_EMUTRAMP		2	/* 0: Emulate trampolines */
#define HF_PAX_MPROTECT		4	/* 0: Restrict mprotect() */
#define HF_PAX_RANDMMAP		8	/* 0: Randomize mmap() base */
#define HF_PAX_RANDEXEC		16	/* 1: Randomize ET_EXEC base */
#define HF_PAX_SEGMEXEC		32	/* 0: Segmentation based non-exec pages */

#define EI_PAX			14	/* Index in e_ident[] where to read flags */
#define __PAX_FLAGS(B, elf) \
	((EHDR ## B (elf->ehdr)->e_ident[EI_PAX + 1] << 8) + EHDR ## B (elf->ehdr)->e_ident[EI_PAX])
#define PAX_FLAGS(elf) \
	(__extension__ ({ \
		unsigned long __res; \
		if (elf->elf_class == ELFCLASS32) \
			__res = __PAX_FLAGS(32, elf); \
		else \
			__res = __PAX_FLAGS(64, elf); \
		__res; \
	}))

/*
 * in case we are not defined by proper/up-to-date system headers, 
 * we check for a bunch of PT_GNU defines and custom PAX ones
 */

#ifndef PT_GNU_STACK
# define PT_GNU_STACK	0x6474e551
#endif

/* not in <=binutils-2.14.90.0.8 (should come in by way of .9) */
#ifndef PT_GNU_RELRO
# define PT_GNU_RELRO	0x6474e552
#endif

/* 
 * propably will never be official added to the toolchain.
 * But none the less we should try to get 0x65041580 reserved 
 */
#ifndef PT_PAX_FLAGS
# define PT_PAX_FLAGS	0x65041580

# define PF_PAGEEXEC     (1 << 4)	/* Enable  PAGEEXEC */
# define PF_NOPAGEEXEC   (1 << 5)	/* Disable PAGEEXEC */
# define PF_SEGMEXEC     (1 << 6)	/* Enable  SEGMEXEC */
# define PF_NOSEGMEXEC   (1 << 7)	/* Disable SEGMEXEC */
# define PF_MPROTECT     (1 << 8)	/* Enable  MPROTECT */
# define PF_NOMPROTECT   (1 << 9)	/* Disable MPROTECT */
# define PF_RANDEXEC     (1 << 10)	/* Enable  RANDEXEC */
# define PF_NORANDEXEC   (1 << 11)	/* Disable RANDEXEC */
# define PF_EMUTRAMP     (1 << 12)	/* Enable  EMUTRAMP */
# define PF_NOEMUTRAMP   (1 << 13)	/* Disable EMUTRAMP */
# define PF_RANDMMAP     (1 << 14)	/* Enable  RANDMMAP */
# define PF_NORANDMMAP   (1 << 15)	/* Disable RANDMMAP */
#endif				/* PT_PAX_ */

#endif /* _PAX_ELF_H */
