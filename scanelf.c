/*
 * Copyright 2003 Ned Ludd <solar@gentoo.org>
 * Copyright 1999-2003 Gentoo Technologies, Inc.
 * Distributed under the terms of the GNU General Public License v2
 * $Header: /var/cvsroot/gentoo-projects/pax-utils/scanelf.c,v 1.1 2003/10/24 22:19:20 solar Exp $
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
 * Also of interest is the pax site http://pageexec.virtualave.net/
 * but you should know about that already.
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <dirent.h>
#include <getopt.h>

#include "paxelf.h"

static const char *rcsid = "$Id: scanelf.c,v 1.1 2003/10/24 22:19:20 solar Exp $";

int display_pax_flags = 1;

#define PARSE_FLAGS "hvlp"
static struct option const long_options[] = {
   {"help", no_argument, 0, 'h'},
   {"version", no_argument, 0, 'v'},
   {"path", no_argument, 0, 'p'},
   {"ldpath", no_argument, 0, 'l'},
   {NULL, no_argument, NULL, 0}
};

/* scan a directory for ET_EXEC files and print when we find one */
void scanelf(const char *path)
{
   elfobj *elf = NULL;
   register DIR *dir;
   register struct dirent *dentry;

   if (chdir(path) == 0) {
      if ((dir = opendir(path))) {
	 while ((dentry = readdir(dir))) {
	    /* verify this is real ELF */
	    if ((elf = readelf(dentry->d_name)) != NULL) {
	       if (!check_elf_header(elf->ehdr))
		  if (IS_ELF(elf))
		     printf("%s %s %s/%s\n",
			    pax_short_flags(PAX_FLAGS(elf)),
			    get_elfetype(elf->ehdr->e_type), path,
			    dentry->d_name);
	       if (elf != NULL) {
		  munmap(elf->data, elf->len);
		  free(elf);
		  elf = NULL;
	       }
	    }
	 }
	 closedir(dir);
      }
   }
}


/* display usage and exit */
int usage(char **argv)
{
   printf
       ("Usage: %s [options] dir1 dir2 dirN...\n",
	(*argv != NULL) ? argv[0] : __FILE__ "\b\b");
   exit(EXIT_FAILURE);
}


void showopt(int c, char *data)
{
   int i;
   for (i = 0; long_options[i].name; i++)
      if (long_options[i].val == c)
	 printf("  -%c, --%s\t: %s\n", c, long_options[i].name, data);
}

/* parse command line arguments and preform needed actions */
void parseargs(int argc, char **argv)
{
   int flag;
   char *p, *path;
   FILE *fp;

   opterr = 0;
   while ((flag =
	   (int) getopt_long(argc, argv,
			     PARSE_FLAGS, long_options, NULL)) != EOF) {
      switch (flag) {
	 case 'h':
	    showopt('p', "Scan all directories in PATH environment.");
	    showopt('l', "Scan all directories in /etc/ld.so.conf");
	    showopt('h', "Print this help and exit.");
	    showopt('v', "Print version and exit.");
	    exit(EXIT_SUCCESS);
	 case 'v':
	    printf("%s compiled %s\n", __FILE__, __DATE__);
	    printf
		("%s written for Gentoo Linux <solar@gentoo.org>\n\t%s\n",
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
		     puts(path);
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
	       scanelf(p + 1);
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
   while (optind < argc)
      scanelf(argv[optind++]);
}

int main(int argc, char **argv)
{
   if (argc < 2)
      usage(argv);
   parseargs(argc, argv);
   return 0;
}
