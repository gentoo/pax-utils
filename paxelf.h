/*
 * Make sure all of the common elf stuff is setup as we expect
 */

#ifndef _PAX_ELF_H
#define _PAX_ELF_H

#include <sys/mman.h>
#ifdef __linux__
# include <elf.h>
# include <asm/elf.h>
#else
# include <sys/elf_common.h>
#endif

#ifndef ELF_CLASS
# error "UNABLE TO DETECT ELF_CLASS"
#endif

/* I need a way to deal with 32/64 bit files at the same time using the same struct */

#if (ELF_CLASS == ELFCLASS32)
# define Elf_Ehdr Elf32_Ehdr
# define Elf_Phdr Elf32_Phdr
# define Elf_Shdr Elf32_Shdr
# define Elf_Dyn  Elf32_Dyn
#endif

#if (ELF_CLASS == ELFCLASS64)
# define Elf_Ehdr Elf64_Ehdr
# define Elf_Phdr Elf64_Phdr
# define Elf_Shdr Elf64_Shdr
# define Elf_Dyn  Elf64_Dyn
#endif

typedef struct {
	Elf_Ehdr *ehdr;
	Elf_Phdr *phdr;
	Elf_Shdr *shdr;
	char *data;
	int len;
	int fd;
} elfobj;

/* prototypes */
extern char *pax_short_hf_flags(unsigned long flags);
extern char *pax_short_pf_flags(unsigned long flags);
extern char *gnu_short_stack_flags(unsigned long flags);
extern int check_elf_header(Elf_Ehdr const *const ehdr);
extern elfobj *readelf(const char *filename);
extern void unreadelf(elfobj *elf);
extern const char *get_elfetype(int type);
extern const char *get_elfptype(int type);
extern const char *get_elfdtype(int type);
extern const char *elf_getsecname(elfobj *elf, Elf_Shdr *shdr);
extern Elf_Shdr *elf_findsecbyname(elfobj *elf, const char *name);

//#define IS_ELF(elf) ((elf->ehdr->e_ident[EI_CLASS] == ELFCLASS32 || elf->ehdr->e_ident[EI_CLASS] == ELFCLASS64))
#define IS_ELF(elf) (elf->ehdr->e_ident[EI_CLASS] == ELF_CLASS)
#define IS_ELF_TYPE(elf, type) ((elf->ehdr->e_type == type) && IS_ELF(elf))
#define IS_ELF_ET_EXEC(elf) IS_ELF_TYPE(elf, ET_EXEC)
#define IS_ELF_ET_DYN(elf)  IS_ELF_TYPE(elf, ET_DYN)

/* PaX flags (to be read in elfhdr.e_flags) */
#define HF_PAX_PAGEEXEC		1	/* 0: Paging based non-exec pages */
#define HF_PAX_EMUTRAMP		2	/* 0: Emulate trampolines */
#define HF_PAX_MPROTECT		4	/* 0: Restrict mprotect() */
#define HF_PAX_RANDMMAP		8	/* 0: Randomize mmap() base */
#define HF_PAX_RANDEXEC		16	/* 1: Randomize ET_EXEC base */
#define HF_PAX_SEGMEXEC		32	/* 0: Segmentation based non-exec pages */

#define EI_PAX			14	/* Index in e_ident[] where to read flags */
#define PAX_FLAGS(elf) ((elf->ehdr->e_ident[EI_PAX + 1] << 8) + (elf->ehdr->e_ident[EI_PAX]))

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

/* not in <glibc-2.3.3_pre20031222 */
#ifndef PT_GNU_HEAP
# define PT_GNU_HEAP	0x6474e552
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
