/*
 * Copyright 2003 Ned Ludd <solar@gentoo.org>
 * Copyright 1999-2003 Gentoo Technologies, Inc.
 * Distributed under the terms of the GNU General Public License v2
 * $Header: /var/cvsroot/gentoo-projects/pax-utils/scansym.c,v 1.1 2004/02/10 07:40:45 solar Exp $
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
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <dirent.h>
#include <getopt.h>
#include <fcntl.h>
#include <dlfcn.h>


#include "paxelf.h"

static const char *rcsid = "$Id: scansym.c,v 1.1 2004/02/10 07:40:45 solar Exp $";

#define PARSE_FLAGS "hvlps:"
static struct option const long_options[] = {
   {"help", no_argument, 0, 'h'},
   {"version", no_argument, 0, 'v'},
   {"file", required_argument, 0, 'f'},
   {"path", no_argument, 0, 'p'},
   {"ldpath", no_argument, 0, 'l'},
   {"sym", required_argument, 0, 's'},
   {NULL, no_argument, NULL, 0}
};

static char const *getstring(unsigned long offset, unsigned long size,
			     int skip, FILE * fp)
{
   static char *buf = NULL;
   static size_t buflen = 0;
   char *str;
   int n;

   if (!size)
      return "";

   if (size > buflen) {
      if (!(buf = realloc(buf, size + 1)))
	 return NULL;
      buflen = size;
   }

   if (fseek(fp, offset, SEEK_SET))
      return "";

   if (skip) {
      if ((n = fread(buf, 1, size, fp)) <= 0)
	 return "";
      for (str = buf; !*str && n; ++str, --n);
   } else {
      if (!fgets(buf, size, fp))
	 return "";
      n = size;
      str = buf;
   }
   if (!n)
      return "";

   str[n] = '\0';

   for (n = 0; str[n]; ++n)
      if (str[n] < ' ' || str[n] > '~')
	 str[n] = '.';

   return str;
}

static char const *getstring_fd(unsigned long offset, unsigned long size,
				int fd)
{
   static char *buf = NULL;
   static size_t buflen = 0;
   char *str;
   int n;

   if (!size)
      return NULL;

   if (size > buflen) {
      if (!(buf = realloc(buf, size + 1)))
	 return NULL;
      buflen = size;
   }

   if (lseek(fd, offset, SEEK_SET))
      return NULL;

   if (!(n = read(fd, buf, size)))
      return NULL;

   if (!(n = size))
      return NULL;
   str = buf;

   str[n] = '\0';

   for (n = 0; str[n]; ++n)
      if (str[n] < ' ' || str[n] > '~')
	 str[n] = '.';

   return str;
}

void scanelf_file_symbol(char *filename, char *symbol_name)
{
   elfobj *elf = NULL;
   void *handle = NULL;
   void *sym;
   int i, valid;
   const char *str;
   FILE *fp = NULL;

   /* verify this is real ELF */
   if ((elf = readelf(filename)) != NULL) {
      if (!check_elf_header(elf->ehdr))
	 if (IS_ELF(elf)) {
/*
	Strange behavior.
	--------------------------------------------------------------------------
	/usr/X11R6/lib/libMesaGL.so: symbolic link to `/usr/lib/opengl/nvidia/lib/libGL.so.1.0.4496'
	/usr/lib/opengl/nvidia/lib/libGL.so.1.0.4496: ELF 32-bit LSB shared object, Intel 80386, version 1 (SYSV), stripped
	---------------------------------------------------------------------------
	# this will make us segfault (invalid interp).
	-rwxr-xr-x    1 root     root       882854 Nov 20 03:22 /sbin/insmod.static
	/sbin/insmod.static: ELF 32-bit LSB shared object, Intel 80386, version 1 (SYSV), not stripped
	---------------------------------------------------------------------------

*/
	    // printf("%s %s", get_elfetype(elf->ehdr->e_type), filename);

	    valid = 1;
	    if (IS_ELF_ET_DYN(elf)) {
	       fp = NULL;

	       for (i = 0; i < elf->ehdr->e_phnum; i++) {

		  switch (elf->phdr[i].p_type) {
/*		printf("%c%c%c",
                 (phdr->p_flags & PF_R ? 'r' : '-'),
                 (phdr->p_flags & PF_W ? 'w' : '-'),
                 (phdr->p_flags & PF_X ? phdr == phentry ? 's' : 'x' : '-'));
*/

/*
		     case PT_NOTE:
			if (fp == NULL)
			   fp = fopen(filename, "rb");
			str = getstring(elf->phdr[i].p_offset + 12,
					elf->phdr[i].p_filesz - 12, 0, fp);
			printf("%d] .note %s\n", i, (str != NULL) ? str : "(null)");
			break;
*/
		     case PT_INTERP:
			if (fp == NULL)
			   fp = fopen(filename, "rb");
			str =
			    getstring(elf->phdr[i].p_offset,
				      elf->phdr[i].p_filesz, 0, fp);
			if (access(str, R_OK) != 0) {
			   valid = 0;
			   fprintf(stderr,
				   "invalid: invoke_dynamic_linker %s in %s\n",
				   str, filename);

			}
			break;
		     default:
			break;
		  }


	       }
	    }
	    if (valid) {
	       if ((handle =
		    dlopen(filename, RTLD_NOW | RTLD_GLOBAL)) != NULL) {
		  if ((sym = (void *) dlsym(handle, symbol_name)) != 0x0) {
		     printf("%s found in %s at %p\n", symbol_name,
			    filename, (void *) sym);
		  }
		  dlclose(handle);
	       } else {

	       }
	    }
	    if (elf != NULL) {
	       if (fp != NULL)
		  fclose(fp);
	       munmap(elf->data, elf->len);
	       free(elf);
	       elf = NULL;
	    }
	 }
   }
}


/* scan a directory for ELF files and print when we find one with matching symbol names */
void scanelf_symbol(const char *path, char *symbol_name)
{
   register DIR *dir;
   register struct dirent *dentry;
   char *p;
   int len = 0;
   if (symbol_name == NULL) {
      fprintf(stderr, "No symbol name provided\n");
      exit(EXIT_FAILURE);
   }
   if ((chdir(path) == 0) && ((dir = opendir(path)))) {
      while ((dentry = readdir(dir))) {
	 len = (strlen(path) + 2 + strlen(dentry->d_name));
	 p = malloc(len);
	 strncpy(p, path, len);
	 strncat(p, "/", len);
	 strncat(p, dentry->d_name, len);
	 scanelf_file_symbol(p, symbol_name);
	 free(p);
      }
      closedir(dir);
   }
}


/* display usage and exit */
void usage(char **argv)
{
   fprintf(stderr,
	   "Usage: %s [options] dir1 dir2 dirN...\n",
	   (*argv != NULL) ? argv[0] : __FILE__ "\b\b");
}


void showopt(int c, char *data)
{
   int i;
   for (i = 0; long_options[i].name; i++)
      if (long_options[i].val == c)
	 fprintf(stderr, "  -%c, --%s\t: %s\n", c,
		 long_options[i].name, data);
}

/* parse command line arguments and preform needed actions */
void parseargs(int argc, char **argv)
{
   int flag;
   char *p, *path;
   FILE *fp;
   char *symbol_name = "__guard";

   opterr = 0;
   while ((flag =
	   (int) getopt_long(argc, argv, PARSE_FLAGS, long_options,
			     NULL)) != EOF)
      if (flag == 's') {
	 symbol_name = optarg;
	 printf("symbol set to %s\n", symbol_name);
      }
   optind = 0;
   while ((flag =
	   (int) getopt_long(argc, argv,
			     PARSE_FLAGS, long_options, NULL)) != EOF) {
      switch (flag) {
	 case 'h':
	    usage(argv);
	    showopt('s', "Symbol name default");
	    showopt('f', "Scan filename");
	    showopt('p', "Scan all directories in PATH environment.");
	    showopt('l', "Scan all directories in /etc/ld.so.conf");
	    showopt('h', "Print this help and exit.");
	    showopt('v', "Print version and exit.");
	    exit(EXIT_SUCCESS);
	 case 'f':
	    scanelf_file_symbol(argv[optind], symbol_name);
	    break;
	 case 'v':
	    fprintf(stderr, "%s compiled %s\n", __FILE__, __DATE__);
	    fprintf(stderr,
		    "%s written for Gentoo Linux <solar@gentoo.org>\n\t%s\n",
		    (*argv != NULL) ? argv[0] : __FILE__ "\b\b", rcsid);
	    exit(EXIT_SUCCESS);
	 case 'l':
	    /* scan ld.so.conf for ldpath */
	    if ((fp = fopen("/etc/ld.so.conf", "r")) != NULL) {
	       path = malloc(_POSIX_PATH_MAX);
	       while ((fgets(path, _POSIX_PATH_MAX, fp)) != NULL) {
		  if (*path == '/') {
		     if ((p = strrchr(path, '\r')) != NULL)
			*p = 0;
		     if ((p = strrchr(path, '\n')) != NULL)
			*p = 0;
		     scanelf_symbol(path, symbol_name);
		  }
	       }
	       free(path);
	    }
	    break;
	 case 'p':
	    if ((path = strdup(getenv("PATH"))) == NULL) {
	       perror("strdup");
	       exit(EXIT_FAILURE);
	    }
	    /* split string into dirs */
	    while ((p = strrchr(path, ':')) != NULL) {
	       scanelf_symbol(p + 1, symbol_name);
	       *p = 0;
	    }
	    if (path != NULL)
	       free(path);
	    break;
	 case '?':
	 default:
	    break;
      }
   }
   while (optind < argc) {
      optind++;
      scanelf_symbol(argv[optind], symbol_name);
   }

}

int main(int argc, char **argv)
{
   if (argc < 2) {
      usage(argv);
      exit(EXIT_FAILURE);
   }
   parseargs(argc, argv);
   return 0;
}
