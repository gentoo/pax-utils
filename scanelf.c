/*
 * Copyright 2003 Ned Ludd <solar@gentoo.org>
 * Copyright 1999-2005 Gentoo Foundation
 * Distributed under the terms of the GNU General Public License v2
 * $Header: /var/cvsroot/gentoo-projects/pax-utils/scanelf.c,v 1.11 2005/03/31 00:03:25 solar Exp $
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
#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>
#include <dirent.h>
#include <getopt.h>

#include "paxelf.h"

static const char *rcsid = "$Id: scanelf.c,v 1.11 2005/03/31 00:03:25 solar Exp $";


/* helper functions for showing errors */
#define argv0 "scanelf\0" /*((*argv != NULL) ? argv[0] : __FILE__ "\b\b")*/
#define warn(fmt, args...) \
	fprintf(stderr, "%s: " fmt "\n", argv0, ## args)
#define warnf(fmt, args...) warn("%s(): " fmt, __FUNCTION__, ## args)
#define err(fmt, args...) \
	do { \
	warn(fmt, ## args); \
	exit(EXIT_FAILURE); \
	} while (0)



/* prototypes */
static void scanelf_file(const char *filename);
static void scanelf_dir(const char *path);
static void scanelf_ldpath();
static void scanelf_envpath();
static void usage(int status);
static void parseargs(int argc, char *argv[]);

/* variables to control behavior */
static char scan_ldpath = 0;
static char scan_envpath = 0;
static char dir_recurse = 0;
static char show_pax = 0;
static char show_stack = 0;
static char show_textrel = 0;
static char show_rpath = 0;
static char show_header = 1;
static char be_quiet = 0;



/* scan an elf file and show all the fun stuff */
static void scanelf_file(const char *filename)
{
	int i;
	char found_stack = 0, found_textrel = 0, found_rpath = 0;
	Elf_Dyn *dyn;
	elfobj *elf = NULL;

	/* verify this is real ELF */
	if ((elf = readelf(filename)) == NULL)
		return;
	if (check_elf_header(elf->ehdr) || !IS_ELF(elf))
		goto bail;

	/* show the header */
	if (!be_quiet && show_header) {
		printf("TYPE ");
		if (show_pax) printf("PAX ");
		if (show_stack) printf("STACK ");
		if (show_textrel) printf("TEXTREL ");
		if (show_rpath) printf("RPATH ");
		printf("FILE\n");
		show_header = 0;
	}

	/* dump all the good stuff */
	if (!be_quiet)
		printf("%-7s ", get_elfetype(elf->ehdr->e_type));

	if (show_pax)
		printf("%s ", pax_short_hf_flags(PAX_FLAGS(elf)));

	/* stack fun */
	if (show_stack) {
		for (i = 0; i < elf->ehdr->e_phnum; i++) {
			if (elf->phdr[i].p_type != PT_GNU_STACK && \
			    elf->phdr[i].p_type != PT_GNU_RELRO) continue;

			if (be_quiet && !(elf->phdr[i].p_flags & PF_X))
				continue;

			found_stack = 1;
			printf("%s ", gnu_short_stack_flags(elf->phdr[i].p_flags));
		}
		if (!be_quiet && !found_stack) printf("- ");
	}

	/* textrel fun */
	if (show_textrel) {
		for (i = 0; i < elf->ehdr->e_phnum; i++) {
			if (elf->phdr[i].p_type != PT_DYNAMIC) continue;

			dyn = (Elf_Dyn *)(elf->data + elf->phdr[i].p_offset);
			while (dyn->d_tag != DT_NULL) {
				if (dyn->d_tag == DT_TEXTREL) { //dyn->d_tag != DT_FLAGS)
					found_textrel = 1;
//					if (dyn->d_un.d_val & DF_TEXTREL)
					printf("TEXTREL ");
				}
				++dyn;
			}
		}
		if (!be_quiet && !found_textrel) printf("- ");
	}

	/* rpath fun */
	/* TODO: if be_quiet, only output RPATH's which aren't in /etc/ld.so.conf */
	if (show_rpath) {
		Elf_Shdr *strtbl = elf_findsecbyname(elf, ".dynstr");

		if (strtbl)
		for (i = 0; i < elf->ehdr->e_phnum; i++) {
			if (elf->phdr[i].p_type != PT_DYNAMIC) continue;

			dyn = (Elf_Dyn *)(elf->data + elf->phdr[i].p_offset);
			while (dyn->d_tag != DT_NULL) {
				if (dyn->d_tag == DT_RPATH) { //|| dyn->d_tag != DT_RUNPATH)
					char *rpath = elf->data + strtbl->sh_offset + dyn->d_un.d_ptr;
					found_rpath = 1;
					printf("%s ", rpath);
				}
				++dyn;
			}
		}
		if (!be_quiet && !found_rpath) printf("- ");
	}

	if (!be_quiet || show_pax || found_stack || found_textrel || found_rpath)
		printf("%s\n", filename);

bail:
	unreadelf(elf);
}

/* scan a directory for ET_EXEC files and print when we find one */
static void scanelf_dir(const char *path)
{
	register DIR *dir;
	register struct dirent *dentry;
	struct stat st;
	char *p;
	int len = 0;

	/* make sure path exists */
	if (lstat(path, &st) == -1)
		return;

	/* ok, if it isn't a directory, assume we can open it */
	if (!S_ISDIR(st.st_mode)) {
		scanelf_file(path);
		return;
	}

	/* now scan the dir looking for fun stuff */
	if ((dir = opendir(path)) == NULL) {
		warnf("could not opendir %s: %s", path, strerror(errno));
		return;
	}

	while ((dentry = readdir(dir))) {
		if (!strcmp(dentry->d_name, ".") || !strcmp(dentry->d_name, ".."))
			continue;
		len = (strlen(path) + 2 + strlen(dentry->d_name));
		p = malloc(len);
		if (!p)
			err("scanelf_dir(): Could not malloc: %s", strerror(errno));
		strncpy(p, path, len);
		strncat(p, "/", len);
		strncat(p, dentry->d_name, len);
		if (lstat(p, &st) != -1) {
			if (S_ISREG(st.st_mode))
				scanelf_file(p);
			else if (dir_recurse && S_ISDIR(st.st_mode)) {
				scanelf_dir(p);
			}
		}
		free(p);
	}
	closedir(dir);
}

/* scan /etc/ld.so.conf for paths */
static void scanelf_ldpath()
{
	char *path, *p;
	FILE *fp;

	if ((fp = fopen("/etc/ld.so.conf", "r")) == NULL)
		err("Unable to open ld.so.conf: %s", strerror(errno));

	path = malloc(_POSIX_PATH_MAX);
	while ((fgets(path, _POSIX_PATH_MAX, fp)) != NULL)
		if (*path == '/') {
			if ((p = strrchr(path, '\r')) != NULL)
				*p = 0;
			if ((p = strrchr(path, '\n')) != NULL)
				*p = 0;
			scanelf_dir(path);
		}
	free(path);

	fclose(fp);
}

/* scan env PATH for paths */
static void scanelf_envpath()
{
	char *path, *p;

	path = getenv("PATH");
	if (!path)
		err("PATH is not set in your env !");

	if ((path = strdup(path)) == NULL)
		err("stdup failed: %s", strerror(errno));

	while ((p = strrchr(path, ':')) != NULL) {
		scanelf_dir(p + 1);
		*p = 0;
	}
	free(path);
}



/* usage / invocation handling functions */
#define PARSE_FLAGS "plRxstraqhV"
static struct option const long_opts[] = {
	{"path",      no_argument, NULL, 'p'},
	{"ldpath",    no_argument, NULL, 'l'},
	{"recursive", no_argument, NULL, 'R'},
	{"pax",       no_argument, NULL, 'x'},
	{"stack",     no_argument, NULL, 's'},
	{"textrel",   no_argument, NULL, 't'},
	{"rpath",     no_argument, NULL, 'r'},
	{"all",       no_argument, NULL, 'a'},
	{"quiet",     no_argument, NULL, 'q'},
/*	{"vebose",    no_argument, NULL, 'v'},*/
	{"help",      no_argument, NULL, 'h'},
	{"version",   no_argument, NULL, 'V'},
	{NULL,        no_argument, NULL, 0x0}
};
static char *opts_help[] = {
	"Scan all directories in PATH environment",
	"Scan all directories in /etc/ld.so.conf",
	"Scan directories recursively\n",
	"Print PaX markings",
	"Print GNU_STACK markings",
	"Print TEXTREL information",
	"Print RPATH information",
	"Print all scanned info",
	"Only output 'bad' things\n",
/*	"Be verbose !",*/
	"Print this help and exit",
	"Print version and exit",
	NULL
};

/* display usage and exit */
static void usage(int status)
{
	int i;
	printf("¤ Scan ELF binaries for stuff\n\n"
	       "Usage: %s [options] <dir1> [dir2 dirN ...]\n\n", argv0);
	printf("Options:\n");
	for (i = 0; long_opts[i].name; ++i)
		printf("  -%c, --%-12s× %s\n", long_opts[i].val, 
		       long_opts[i].name, opts_help[i]);
	exit(status);
}

/* parse command line arguments and preform needed actions */
static void parseargs(int argc, char *argv[])
{
	int flag;

	opterr = 0;
	while ((flag=getopt_long(argc, argv, PARSE_FLAGS, long_opts, NULL)) != -1) {
		switch (flag) {

		case 'V':                        /* version info */
			printf("%s compiled %s\n"
			       "%s written for Gentoo Linux by <solar and vapier @ gentoo.org>\n"
			       "%s\n",
			       __FILE__, __DATE__, argv0, rcsid);
			exit(EXIT_SUCCESS);
			break;
		case 'h': usage(EXIT_SUCCESS); break;

		case 'l': scan_ldpath = 1; break;
		case 'p': scan_envpath = 1; break;
		case 'R': dir_recurse = 1; break;
		case 'x': show_pax = 1; break;
		case 's': show_stack = 1; break;
		case 't': show_textrel = 1; break;
		case 'r': show_rpath = 1; break;
		case 'q': be_quiet = 1; break;
		case 'a': show_pax = show_stack = show_textrel = show_rpath = 1; break;

		case ':':
			warn("Option missing parameter");
			usage(EXIT_FAILURE);
			break;
		case '?':
			warn("Unknown option");
			usage(EXIT_FAILURE);
			break;
		default:
			err("Unhandled option '%c'", flag);
			break;
		}
	}

	if (scan_ldpath) scanelf_ldpath();
	if (scan_envpath) scanelf_envpath();
	while (optind < argc)
		scanelf_dir(argv[optind++]);
}



int main(int argc, char *argv[])
{
	if (argc < 2)
		usage(EXIT_FAILURE);
	parseargs(argc, argv);
	return EXIT_SUCCESS;
}
