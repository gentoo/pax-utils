/*
 * Copyright 2003 Ned Ludd <solar@gentoo.org>
 * Copyright 1999-2005 Gentoo Foundation
 * Distributed under the terms of the GNU General Public License v2
 * $Header: /var/cvsroot/gentoo-projects/pax-utils/paxelf.c,v 1.5 2005/03/25 21:50:20 vapier Exp $
 *
 ********************************************************************
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston,
 * MA 02111-1307, USA.
 ********************************************************************
 *
 * This program was written for the hcc suite by (solar|pappy)@g.o.
 * visit http://www.gentoo.org/proj/en/hardened/etdyn-ssp.xml for more
 * information on the Gentoo Hardened gcc suite
 * Also of interest is the pax site http://pax.grsecurity.net/
 * but you should know about that already.
 */

#include <stdio.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include "paxelf.h"

#define QUERY(n) { #n, n }
static struct elf_etypes {
	const char *str;
	int value;
} elf_etypes[] = {
	QUERY(ET_NONE),
	QUERY(ET_REL),
	QUERY(ET_EXEC),
	QUERY(ET_DYN),
	QUERY(ET_CORE),
	QUERY(ET_NUM),
	QUERY(ET_LOOS),
	QUERY(ET_HIOS),
	QUERY(ET_LOPROC),
	QUERY(ET_HIPROC)
};

/* Read an ELF into memory */
elfobj *readelf(char *filename)
{
   struct stat st;
   elfobj *elf;
   int fd;

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
   elf->data = (char *) mmap(0, elf->len, PROT_READ, MAP_PRIVATE, fd, 0);

   if (elf->data == (char *) MAP_FAILED) {
      free(elf);
      goto close_fd_and_return;
   }

   elf->ehdr = (void *) elf->data;
   elf->phdr = (void *) (elf->data + elf->ehdr->e_phoff);
   elf->shdr = (void *) (elf->data + elf->ehdr->e_shoff);

   /* elf->fd = fd; */
   /* do we want to keep the fd open? */
   close(fd);
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

char *pax_short_flags(unsigned long flags)
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

const char *get_elfetype(int type)
{
   int i;
   for (i = 0; i < sizeof(elf_etypes) / sizeof(elf_etypes[0]); i++)
      if (type == elf_etypes[i].value)
	 return elf_etypes[i].str;
   return "UNKNOWN ELF TYPE";
}
