/*
 *	Jan 14 2004	- solar@gentoo
 *
 *	find RWX STACK segments.
 * ./pttool /{usr/{local/,},}{s,}bin/globstar > /dev/null
 */


#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "paxelf.h"

/* Read an ELF into memory */
elfobj *readelf(char *filename)
{
   int fd;
   struct stat st;
   elfobj *elf;

   if (stat(filename, &st) == -1)
      return NULL;

   if ((fd = open(filename, O_RDONLY)) == -1)
      return NULL;

   if (st.st_size <= 0)
      goto close_fd_and_return;

   elf = NULL;

   (elf = (void *) malloc(sizeof(elfobj)));
   if (elf == NULL)
      goto close_fd_and_return;

   elf->len = st.st_size;
#ifdef PTTOOL_MMAP_READONLY
   elf->data = (char *) mmap(0, elf->len, PROT_READ, MAP_PRIVATE, fd, 0);
#else
   elf->data =
       (char *) mmap(0, elf->len, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd,
		     0);
#endif
   if (elf->data == (char *) MAP_FAILED) {
      perror("mmap: ");
      free(elf);
      goto close_fd_and_return;
   }

   elf->ehdr = (void *) elf->data;
   elf->phdr = (void *) (elf->data + elf->ehdr->e_phoff);
   elf->shdr = (void *) (elf->data + elf->ehdr->e_shoff);

   /* argh!@#$% code not using bfd is a PITA to find on google. */
   /* where are you Dyn */
//   elf->dyn = (void *) (elf->data + elf->ehdr->et_dyn);

   /* keep the fd open */
   elf->fd = fd;
   return elf;

 close_fd_and_return:
   close(fd);
   return NULL;
}

/* check the elf header */
int check_elf_header(Elf_Ehdr const *const ehdr)
{
   if (!ehdr || strncmp((void *) ehdr, ELFMAG, SELFMAG) != 0 ||
       (ehdr->e_ident[EI_CLASS] != ELFCLASS32
	&& ehdr->e_ident[EI_CLASS] != ELFCLASS64)
       || ehdr->e_ident[EI_VERSION] != EV_CURRENT) {
      return 1;
   }
   return 0;
}

char *pax_short_pt_flags(unsigned long flags)
{
   static char buffer[13];
   // the logic is: lower case: explicitly disabled, upper case: explicitly enabled, - : default
   buffer[0] = (flags & PF_PAGEEXEC ? 'P' : '-');
   buffer[1] = (flags & PF_NOPAGEEXEC ? 'p' : '-');
   buffer[2] = (flags & PF_SEGMEXEC ? 'S' : '-');
   buffer[3] = (flags & PF_NOSEGMEXEC ? 's' : '-');
   buffer[4] = (flags & PF_MPROTECT ? 'M' : '-');
   buffer[5] = (flags & PF_NOMPROTECT ? 'm' : '-');
   buffer[6] = (flags & PF_RANDEXEC ? 'X' : '-');
   buffer[7] = (flags & PF_NORANDEXEC ? 'x' : '-');
   buffer[8] = (flags & PF_EMUTRAMP ? 'E' : '-');
   buffer[9] = (flags & PF_NOEMUTRAMP ? 'e' : '-');
   buffer[10] = (flags & PF_RANDMMAP ? 'R' : '-');
   buffer[11] = (flags & PF_NORANDMMAP ? 'r' : '-');
   buffer[12] = 0;

   return buffer;
}

char *pax_short_ei_flags(unsigned long flags)
{
   static char buffer[7];

   buffer[0] = (flags & HF_PAX_PAGEEXEC ? 'p' : 'P');
   buffer[1] = (flags & HF_PAX_EMUTRAMP ? 'E' : 'e');
   buffer[2] = (flags & HF_PAX_MPROTECT ? 'm' : 'M');
   buffer[3] = (flags & HF_PAX_RANDMMAP ? 'r' : 'R');
   buffer[4] = (flags & HF_PAX_RANDEXEC ? 'X' : 'x');
   buffer[5] = (flags & HF_PAX_SEGMEXEC ? 's' : 'S');
   buffer[6] = 0;

   return buffer;
}


int has_textrel(elfobj * elf)
{
   Elf_Dyn *dyn;

   return 0;

   for (dyn = elf->dyn; dyn->d_tag != DT_NULL; dyn++) {
      switch (dyn->d_tag) {
	 case DT_TEXTREL:
	 case DT_FLAGS:
	    if (dyn->d_un.d_val & DF_TEXTREL) {
	       printf("TEXTREL 0x%X\n", 0);
	       elf->textrel = 1;
	    }
	    break;
	 default:
	    break;
      }
   }
   return 0;
}

void scan_program_header(const char *filename)
{
   int i;
   elfobj *elf = NULL;

   if ((elf = readelf((char *) filename)) != NULL) {
      if (!check_elf_header(elf->ehdr)) {
	 if (IS_ELF(elf) && (IS_ELF_ET_DYN(elf) || IS_ELF_ET_EXEC(elf))) {
	    // printf("Entry point 0x%08X '%c' %s\n",
		//   elf->ehdr->e_entry,
		//   IS_ELF_ET_DYN(elf) ? '*' : '&', filename);
	    for (i = 0; i < elf->ehdr->e_phnum; i++) {
	       switch (elf->phdr[i].p_type) {
		  case PT_LOAD:
			// printf("LOAD it's only one 0x%X\n", elf->phdr[i].p_flags);
			break;
		  case PT_DYNAMIC:
		     has_textrel(elf);
		     break;
		  case PT_PAX_FLAGS:
		     printf("--- %s %s %s\n",
			    "PAX_FLAGS",
			    pax_short_pt_flags(elf->phdr[i].p_flags),
			    filename);
		     break;
		  case PT_GNU_STACK:
		  case PT_GNU_RELRO:
		     if (elf->phdr[i].p_flags & PF_R
			 || elf->phdr[i].p_flags & PF_W
			 || elf->phdr[i].p_flags & PF_X) {
			printf("%c%c%c %s %-12s %s\n",
			       (elf->phdr[i].p_flags & PF_R ? 'R' : '-'),
			       (elf->phdr[i].p_flags & PF_W ? 'W' : '-'),
			       (elf->phdr[i].p_flags & PF_X ? 'X' : '-'),
			       (elf->phdr[i].p_type ==
				PT_GNU_STACK ? "GNU_STACK" : "GNU_RELRO"),
			       pax_short_ei_flags(PAX_FLAGS(elf)),
			       filename);
			if (elf->phdr[i].p_flags == (PF_W | PF_X))
			   fprintf(stderr,
				   "WARN: %s has %s writable and executable memory segment\n",
				   filename,
				   elf->phdr[i].p_type ==
				   PT_GNU_STACK ? "GNU_STACK" :
				   "GNU_RELRO");
		     }
		  default:
		     break;
	       }
	    }
	 }
      }
      close(elf->fd);
      munmap(elf->data, elf->len);
      memset(elf, 0, sizeof(elfobj));
      free(elf);
      elf = NULL;
   }

}

int main(int argc, char **argv)
{
   int i;
   if (argc > 1) {
      for (i = 1; i != argc; i++)
	 scan_program_header(argv[i]);
   }
   return 0;
}
