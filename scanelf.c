/*
 * Copyright 2003 Ned Ludd <solar@gentoo.org>
 * Copyright 1999-2005 Gentoo Foundation
 * Distributed under the terms of the GNU General Public License v2
 * $Header: /var/cvsroot/gentoo-projects/pax-utils/scanelf.c,v 1.17 2005/04/02 00:11:01 vapier Exp $
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

static const char *rcsid = "$Id: scanelf.c,v 1.17 2005/04/02 00:11:01 vapier Exp $";


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
static char dir_crossmount = 1;
static char show_pax = 0;
static char show_stack = 0;
static char show_textrel = 0;
static char show_rpath = 0;
static char show_banner = 1;
static char be_quiet = 0;
static char be_verbose = 0;



/* scan an elf file and show all the fun stuff */
static void scanelf_file(const char *filename)
{
	int i;
	char found_pax, found_stack, found_relro, found_textrel, found_rpath;
	Elf_Dyn *dyn;
	elfobj *elf = NULL;

	found_pax = found_stack = found_relro = found_textrel = found_rpath = 0;

	/* verify this is real ELF */
	if ((elf = readelf(filename)) == NULL) {
		if (be_verbose > 1) printf("%s: not an ELF\n", filename);
		return;
	}
	if (check_elf_header(elf->ehdr) || !IS_ELF(elf)) {
		if (be_verbose > 1) printf("%s: cannot handle ELF :(\n", filename);
		goto bail;
	}

	if (be_verbose) printf("%s: scanning file\n", filename);

	/* show the header */
	if (!be_quiet && show_banner) {
		fputs(" TYPE  ", stdout);
		if (show_pax) fputs("  PAX  ", stdout);
		if (show_stack) fputs(" STK/REL ", stdout);
		if (show_textrel) fputs("TEXTREL ", stdout);
		if (show_rpath) fputs("RPATH ", stdout);
		fputs(" FILE\n", stdout);
		show_banner = 0;
	}

	/* dump all the good stuff */
	if (!be_quiet)
		printf("%-7s ", get_elfetype(elf->ehdr->e_type));

	if (show_pax) {
		char *paxflags = pax_short_hf_flags(PAX_FLAGS(elf));
		if (!be_quiet || (be_quiet && strncmp(paxflags, "PeMRxS", 6))) {
			found_pax = 1;
			printf("%s ", pax_short_hf_flags(PAX_FLAGS(elf)));
		}
	}

	/* stack fun */
	if (show_stack) {
		for (i = 0; i < elf->ehdr->e_phnum; i++) {
			if (elf->phdr[i].p_type != PT_GNU_STACK && \
			    elf->phdr[i].p_type != PT_GNU_RELRO) continue;

			if (be_quiet && !(elf->phdr[i].p_flags & PF_X))
				continue;

			if (elf->phdr[i].p_type == PT_GNU_STACK)
				found_stack = 1;
			if (elf->phdr[i].p_type == PT_GNU_RELRO)
				found_relro = 1;

			printf("%s ", gnu_short_stack_flags(elf->phdr[i].p_flags));
		}
		if (!be_quiet && !found_stack) fputs("--- ", stdout);
		if (!be_quiet && !found_relro) fputs("--- ", stdout);
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
					fputs("TEXTREL ", stdout);
				}
				++dyn;
			}
		}
		if (!be_quiet && !found_textrel) fputs("------- ", stdout);
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
		if (!be_quiet && !found_rpath) fputs("  -   ", stdout);
	}

	if (!be_quiet || found_pax || found_stack || found_textrel || found_rpath)
		puts(filename);

bail:
	unreadelf(elf);
}

/* scan a directory for ET_EXEC files and print when we find one */
static void scanelf_dir(const char *path)
{
	register DIR *dir;
	register struct dirent *dentry;
	struct stat st_top, st;
	char *p;
	int len = 0;

	/* make sure path exists */
	if (lstat(path, &st_top) == -1)
		return;

	/* ok, if it isn't a directory, assume we can open it */
	if (!S_ISDIR(st_top.st_mode)) {
		scanelf_file(path);
		return;
	}

	/* now scan the dir looking for fun stuff */
	if ((dir = opendir(path)) == NULL) {
		warnf("could not opendir %s: %s", path, strerror(errno));
		return;
	}
	if (be_verbose) printf("%s: scanning dir\n", path);

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
				if (dir_crossmount || (st_top.st_dev == st.st_dev))
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
	char scan_l, scan_ul, scan_ull;
	char *path, *p;
	FILE *fp;

	if ((fp = fopen("/etc/ld.so.conf", "r")) == NULL)
		err("Unable to open ld.so.conf: %s", strerror(errno));

	scan_l = scan_ul = scan_ull = 0;

	path = malloc(_POSIX_PATH_MAX);
	while ((fgets(path, _POSIX_PATH_MAX, fp)) != NULL)
		if (*path == '/') {
			if ((p = strrchr(path, '\r')) != NULL)
				*p = 0;
			if ((p = strrchr(path, '\n')) != NULL)
				*p = 0;
			if (!scan_l   && !strcmp(path, "/lib")) scan_l = 1;
			if (!scan_ul  && !strcmp(path, "/usr/lib")) scan_ul = 1;
			if (!scan_ull && !strcmp(path, "/usr/local/lib")) scan_ull = 1;
			scanelf_dir(path);
		}
	free(path);

	if (!scan_l)   scanelf_dir("/lib");
	if (!scan_ul)  scanelf_dir("/usr/lib");
	if (!scan_ull) scanelf_dir("/usr/local/lib");

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
#define PARSE_FLAGS "plRmxetraqvBhV"
static struct option const long_opts[] = {
	{"path",      no_argument, NULL, 'p'},
	{"ldpath",    no_argument, NULL, 'l'},
	{"recursive", no_argument, NULL, 'R'},
	{"mount",     no_argument, NULL, 'm'},
	{"pax",       no_argument, NULL, 'x'},
	{"header",    no_argument, NULL, 'e'},
	{"textrel",   no_argument, NULL, 't'},
	{"rpath",     no_argument, NULL, 'r'},
	{"all",       no_argument, NULL, 'a'},
	{"quiet",     no_argument, NULL, 'q'},
	{"verbose",   no_argument, NULL, 'v'},
	{"nobanner",  no_argument, NULL, 'B'},
	{"help",      no_argument, NULL, 'h'},
	{"version",   no_argument, NULL, 'V'},
	{NULL,        no_argument, NULL, 0x0}
};
static char *opts_help[] = {
	"Scan all directories in PATH environment",
	"Scan all directories in /etc/ld.so.conf",
	"Scan directories recursively",
	"Don't recursively cross mount points\n",
	"Print PaX markings",
	"Print GNU_STACK markings",
	"Print TEXTREL information",
	"Print RPATH information",
	"Print all scanned info (-x -e -t -r)\n",
	"Only output 'bad' things",
	"Be verbose (can be specified more than once)",
	"Don't display the header",
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
	fputs("Options:\n", stdout);
	for (i = 0; long_opts[i].name; ++i)
		printf("  -%c, --%-12s× %s\n", long_opts[i].val, 
		       long_opts[i].name, opts_help[i]);
#ifdef MANLYPAGE
	for (i = 0; long_opts[i].name; ++i)
		printf(".TP\n\\fB\\-%c, \\-\\-%s\\fR\n%s\n", long_opts[i].val, 
		       long_opts[i].name, opts_help[i]);
#endif
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
		case 's': /* reserved for -s, --symbol= */
		case 'h': usage(EXIT_SUCCESS); break;

		case 'B': show_banner = 0; break;
		case 'l': scan_ldpath = 1; break;
		case 'p': scan_envpath = 1; break;
		case 'R': dir_recurse = 1; break;
		case 'm': dir_crossmount = 0; break;
		case 'x': show_pax = 1; break;
		case 'e': show_stack = 1; break;
		case 't': show_textrel = 1; break;
		case 'r': show_rpath = 1; break;
		case 'q': be_quiet = 1; break;
		case 'v': be_verbose = (be_verbose % 20) + 1; break;
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

	if (be_quiet && be_verbose)
		err("You can be quiet or you can be verbose, not both, stupid");

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
