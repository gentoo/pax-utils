/*
 * Copyright 2003 Ned Ludd <solar@gentoo.org>
 * Distributed under the terms of the GNU General Public License v2
 * $Header: /var/cvsroot/gentoo-projects/pax-utils/isetdyn.c,v 1.1 2003/10/20 02:45:58 solar Exp $
 *
 * On Gentoo Linux we need a simple way to detect if an ELF ehdr is of
 * type ET_DYN, we have a PT_INTERP phdr and also contains a symbol for main()
 * When these three conditions are true as we should be strip safe.
 *
 * Date:
 *	20030908
 *	20031007
 * Compile:
 *	gcc -o isetdyn isetdyn.c -ldl
 * Note:
 *	This program has visible output only when the file is a et_dyn.
 *	It's intended use is from shell scripts via return values 
 *
 */

/* 
 * <pappy-> # readelf -a filename | grep "program interpreter"
 * <pappy-> # readelf -a filename | grep "__libc_start_main"
 * <pappy-> # readelf -a filename | grep "Type:
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <dlfcn.h>

#include "paxelf.h"

int main(int argc, char **argv)
{
   int i = 0;
   elfobj *elf = NULL;
   void *handle = NULL;
   int exit_val = 1;

   if (argc < 2)
      return exit_val;

   if ((elf = readelf(argv[1])) == NULL)
      return exit_val;

   if (!check_elf_header(elf->ehdr))
      if (IS_ELF_ET_DYN(elf))
	 for (i = 0; i < elf->ehdr->e_phnum; i++)
	    if (elf->phdr[i].p_type == PT_INTERP)
	       if ((handle = dlopen(argv[1], RTLD_NOW)) != NULL)
		  if ((dlsym(handle, "main")) != 0x0) {
		     puts(argv[1]);
		     exit_val = 0;
		  }

   if (handle != NULL)
      dlclose(handle);

   munmap(elf->data, elf->len);
   free(elf);
   return exit_val;
}
