#ifndef _PAX_ELF_H
#define _PAX_ELF_H


#include <sys/mman.h>
#ifdef __linux__
#include <elf.h>
#include <asm/elf.h>
#else
#include <sys/elf_common.h>
#endif

#ifndef ELF_CLASS
#error "UNABLE TO DETECT ELF_CLASS"
#endif

#if (ELF_CLASS == ELFCLASS32)
#define Elf_Ehdr        Elf32_Ehdr
#define Elf_Phdr        Elf32_Phdr
#define Elf_Shdr        Elf32_Shdr
#define Elf_Dyn         Elf32_Dyn
#endif

#if (ELF_CLASS == ELFCLASS64)
#define Elf_Ehdr        Elf64_Ehdr
#define Elf_Phdr        Elf64_Phdr
#define Elf_Shdr        Elf64_Shdr
#define Elf_Dyn         Elf64_Dyn
#endif

struct Elf_File {
   Elf_Ehdr *ehdr;
   Elf_Phdr *phdr;
   Elf_Shdr *shdr;
   Elf_Dyn *dyn;
   char *data;
   int len;
};

typedef struct Elf_File elfobj;

/* prototypes */
char *pax_short_flags(unsigned long flags);
int check_elf_header(Elf_Ehdr const *const ehdr);
elfobj *readelf(char *filename);


#define IS_ELF_TYPE(elf, type) ( \
        (elf->ehdr->e_type == type) && \
                (elf->ehdr->e_ident[EI_CLASS] == ELFCLASS32 || \
                        elf->ehdr->e_ident[EI_CLASS] == ELFCLASS64) \
        )

#define IS_ELF_ET_EXEC(elf) IS_ELF_TYPE(elf, ET_EXEC)
#define IS_ELF_ET_DYN(elf)  IS_ELF_TYPE(elf, ET_DYN)

/* PaX flags (to be read in elfhdr.e_flags) */
#define HF_PAX_PAGEEXEC         1	/* 0: Paging based non-exec pages */
#define HF_PAX_EMUTRAMP         2	/* 0: Emulate trampolines */
#define HF_PAX_MPROTECT         4	/* 0: Restrict mprotect() */
#define HF_PAX_RANDMMAP         8	/* 0: Randomize mmap() base */
#define HF_PAX_RANDEXEC         16	/* 1: Randomize ET_EXEC base */
#define HF_PAX_SEGMEXEC         32	/* 0: Segmentation based non-exec pages */

#define EI_PAX                  14	/* Index in e_ident[] where to read flags */

#define PAX_FLAGS(elf) ((elf->ehdr->e_ident[EI_PAX + 1] << 8) + (elf->ehdr->e_ident[EI_PAX]))

#endif				/* _PAX_ELF_H */
