/*
 * Copyright 2003 Ned Ludd <solar@gentoo.org>
 * Copyright 1999-2005 Gentoo Foundation
 * Distributed under the terms of the GNU General Public License v2
 * $Header: /var/cvsroot/gentoo-projects/pax-utils/paxelf.c,v 1.9 2005/04/01 17:00:24 solar Exp $
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

/* Setup a bunch of helper functions to translate
 * binary defines into readable strings.
 */
#define QUERY(n) { #n, n }
typedef struct {
	const char *str;
	int value;
} pairtype;
static inline const char *find_pairtype(pairtype *pt, int type)
{
	int i;
	for (i = 0; pt[i].str; ++i)
		if (type == pt[i].value)
			return pt[i].str;
	return "UNKNOWN TYPE";
}

/* translate elf ET_ defines */
static pairtype elf_etypes[] = {
	QUERY(ET_NONE),
	QUERY(ET_REL),
	QUERY(ET_EXEC),
	QUERY(ET_DYN),
	QUERY(ET_CORE),
	QUERY(ET_NUM),
	QUERY(ET_LOOS),
	QUERY(ET_HIOS),
	QUERY(ET_LOPROC),
	QUERY(ET_HIPROC),
	{ 0, 0 }
};
const char *get_elfetype(int type)
{
	return find_pairtype(elf_etypes, type);
}

/* translate elf PT_ defines */
static pairtype elf_ptypes[] = {
	QUERY(PT_DYNAMIC),
	QUERY(PT_GNU_HEAP),
	QUERY(PT_GNU_RELRO),
	QUERY(PT_GNU_STACK),
	QUERY(PT_INTERP),
	QUERY(PT_LOAD),
	QUERY(PT_NOTE),
	QUERY(PT_PAX_FLAGS),
	{ 0, 0 }
};
const char *get_elfptype(int type)
{
	return find_pairtype(elf_ptypes, type);
}

/* translate elf PT_ defines */
static pairtype elf_dtypes[] = {
	QUERY(DT_NULL),
	QUERY(DT_NEEDED),
	QUERY(DT_PLTRELSZ),
	QUERY(DT_PLTGOT),
	QUERY(DT_HASH),
	QUERY(DT_STRTAB),
	QUERY(DT_SYMTAB),
	QUERY(DT_RELA),
	QUERY(DT_RELASZ),
	QUERY(DT_RELAENT),
	QUERY(DT_STRSZ),
	QUERY(DT_SYMENT),
	QUERY(DT_INIT),
	QUERY(DT_FINI),
	QUERY(DT_SONAME),
	QUERY(DT_RPATH),
	QUERY(DT_SYMBOLIC),
	QUERY(DT_REL),
	QUERY(DT_RELSZ),
	QUERY(DT_RELENT),
	QUERY(DT_PLTREL),
	QUERY(DT_DEBUG),
	QUERY(DT_TEXTREL),
	QUERY(DT_JMPREL),
	QUERY(DT_BIND_NOW),
	QUERY(DT_INIT_ARRAY),
	QUERY(DT_FINI_ARRAY),
	QUERY(DT_INIT_ARRAYSZ),
	QUERY(DT_FINI_ARRAYSZ),
	QUERY(DT_RUNPATH),
	QUERY(DT_FLAGS),
	QUERY(DT_ENCODING),
	QUERY(DT_PREINIT_ARRAY),
	QUERY(DT_PREINIT_ARRAYSZ),
	QUERY(DT_NUM),
	{ 0, 0 }
};
const char *get_elfdtype(int type)
{
	return find_pairtype(elf_dtypes, type);
}

/* Read an ELF into memory */
#define IS_ELF_BUFFER(buff) \
	(buff[EI_MAG0] == ELFMAG0 && \
	 buff[EI_MAG1] == ELFMAG1 && \
	 buff[EI_MAG2] == ELFMAG2 && \
	 buff[EI_MAG3] == ELFMAG3)	
#define ABI_OK(buff) \
	(buff[EI_OSABI] == ELFOSABI_NONE || \
	 buff[EI_OSABI] == ELFOSABI_LINUX)
elfobj *readelf(const char *filename)
{
	struct stat st;
	int fd;
	elfobj *elf;

	if (stat(filename, &st) == -1)
		return NULL;

	if ((fd = open(filename, O_RDONLY)) == -1)
		return NULL;

	/* make sure we have enough bytes to scan e_ident */
	if (st.st_size <= EI_NIDENT)
		goto close_fd_and_return;

	elf = (elfobj*)malloc(sizeof(elfobj));
	if (elf == NULL)
		goto close_fd_and_return;
	memset(elf, 0x00, sizeof(elfobj));

	elf->fd = fd;
	elf->len = st.st_size;
	elf->data = (char *) mmap(0, elf->len, PROT_READ, MAP_PRIVATE, fd, 0);
	if (elf->data == (char *) MAP_FAILED)
		goto free_elf_and_return;

	elf->ehdr = (Elf_Ehdr *) elf->data;
	if (!IS_ELF_BUFFER(elf->ehdr->e_ident)) { /* make sure we have an elf */
		munmap(elf->data, elf->len);
		goto free_elf_and_return;
	}
	if (!ABI_OK(elf->ehdr->e_ident)) { /* only work with certain ABI's for now */
		munmap(elf->data, elf->len);
		goto free_elf_and_return;
	}
	if (elf->ehdr->e_phoff)
		elf->phdr = (Elf_Phdr *) (elf->data + elf->ehdr->e_phoff);
	if (elf->ehdr->e_shoff)
		elf->shdr = (Elf_Shdr *) (elf->data + elf->ehdr->e_shoff);

	return elf;

free_elf_and_return:
	free(elf);
close_fd_and_return:
	close(fd);
	return NULL;
}

/* undo the readelf() stuff */
void unreadelf(elfobj *elf)
{
	munmap(elf->data, elf->len);
	close(elf->fd);
	memset(elf, 0, sizeof(elfobj));
	free(elf);
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

/* the display logic is:
 * lower case: explicitly disabled
 * upper case: explicitly enabled
 * - : default */
char *pax_short_hf_flags(unsigned long flags)
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
char *pax_short_pf_flags(unsigned long flags)
{
	static char buffer[13];

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

char *gnu_short_stack_flags(unsigned long flags)
{
	static char buffer[4];

	buffer[0] = (flags & PF_R ? 'R' : '-');
	buffer[1] = (flags & PF_W ? 'W' : '-');
	buffer[2] = (flags & PF_X ? 'X' : '-');
	buffer[3] = 0;

	return buffer;
}

const char *elf_getsecname(elfobj *elf, Elf_Shdr *shdr)
{
	Elf_Shdr *strtbl = &elf->shdr[elf->ehdr->e_shstrndx];
	return (char *) (elf->data + strtbl->sh_offset + shdr->sh_name);
}

Elf_Shdr *elf_findsecbyname(elfobj *elf, const char *name)
{
	Elf_Shdr *strtbl = &elf->shdr[elf->ehdr->e_shstrndx];
	int i;
	char *shdr_name;
	for (i = 0; i < elf->ehdr->e_shnum; ++i) {
		shdr_name = (char *) (elf->data + strtbl->sh_offset + elf->shdr[i].sh_name);
		if (!strcmp(shdr_name, name))
			return &elf->shdr[i];
	}
	return NULL;
}

#if 0
/* Helper func to locate a program header */
static Elf_Phdr *loc_phdr(elfobj *elf, int type)
{
	Elf_Phdr *ret;

	//for (i = 0; i < elf->ehdr->e_phnum; ++i) {
	//	ret = elf->phdr[i];
	for (ret = elf->phdr; ret->p_type != PT_NULL; ++ret)
		if (ret->p_type == type)
			return elf->data + ret->p_offset;

	return NULL;
}
#endif
