/*
 * Copyright 2003 Ned Ludd <solar@gentoo.org>
 * Copyright 1999-2005 Gentoo Foundation
 * Distributed under the terms of the GNU General Public License v2
 * $Header: /var/cvsroot/gentoo-projects/pax-utils/scanelf.c,v 1.31 2005/04/06 02:01:52 solar Exp $
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
#define __USE_GNU
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>
#include <dirent.h>
#include <getopt.h>
#include <assert.h>

#include "paxelf.h"

static const char *rcsid = "$Id: scanelf.c,v 1.31 2005/04/06 02:01:52 solar Exp $";


/* helper functions for showing errors */
#define argv0 "scanelf" /*((*argv != NULL) ? argv[0] : __FILE__ "\b\b")*/
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
static char *find_sym = NULL;



/* scan an elf file and show all the fun stuff */
static void scanelf_file(const char *filename)
{
	int i;
	char found_pax, found_stack, found_relro, found_textrel, found_rpath, found_sym;
	elfobj *elf;

	found_pax = found_stack = found_relro = found_textrel = found_rpath = found_sym = 0;

	/* verify this is real ELF */
	if ((elf = readelf(filename)) == NULL) {
		if (be_verbose > 2) printf("%s: not an ELF\n", filename);
		return;
	}

	if (be_verbose > 1)
		printf("%s: {%s,%s} scanning file\n", filename,
		       get_elfeitype(elf, EI_CLASS, elf->elf_class),
		       get_elfeitype(elf, EI_DATA, elf->data[EI_DATA]));
	else if (be_verbose)
		printf("%s: scanning file\n", filename);

	/* show the header */
	if (!be_quiet && show_banner) {
		printf(" TYPE  ");
		if (show_pax) printf("  PAX  ");
		if (show_stack) printf(" STK/REL ");
		if (show_textrel) printf("TEXTREL ");
		if (show_rpath) printf("RPATH ");
		printf(" FILE\n");
		show_banner = 0;
	}

	/* dump all the good stuff */
	if (!be_quiet)
		printf("%-7s ", get_elfetype(elf));

	if (show_pax) {
		char *paxflags = pax_short_hf_flags(PAX_FLAGS(elf));
		if (!be_quiet || (be_quiet && strncmp(paxflags, "PeMRxS", 6))) {
			found_pax = 1;
			printf("%s ", pax_short_hf_flags(PAX_FLAGS(elf)));
		}
	}

	/* stack fun */
	if (show_stack) {
#define SHOW_STACK(B) \
		if (elf->elf_class == ELFCLASS ## B) { \
		Elf ## B ## _Ehdr *ehdr = EHDR ## B (elf->ehdr); \
		Elf ## B ## _Phdr *phdr = PHDR ## B (elf->phdr); \
		for (i = 0; i < EGET(ehdr->e_phnum); i++) { \
			if (EGET(phdr[i].p_type) != PT_GNU_STACK && \
			    EGET(phdr[i].p_type) != PT_GNU_RELRO) continue; \
			if (be_quiet && !(EGET(phdr[i].p_flags) & PF_X)) \
				continue; \
			if (EGET(phdr[i].p_type) == PT_GNU_STACK) \
				found_stack = 1; \
			if (EGET(phdr[i].p_type) == PT_GNU_RELRO) \
				found_relro = 1; \
			printf("%s ", gnu_short_stack_flags(EGET(phdr[i].p_flags))); \
		} \
		}
		SHOW_STACK(32)
		SHOW_STACK(64)
		if (!be_quiet && !found_stack) printf("--- ");
		if (!be_quiet && !found_relro) printf("--- ");
	}

	/* textrel fun */
	if (show_textrel) {
#define SHOW_TEXTREL(B) \
		if (elf->elf_class == ELFCLASS ## B) { \
		Elf ## B ## _Dyn *dyn; \
		Elf ## B ## _Ehdr *ehdr = EHDR ## B (elf->ehdr); \
		Elf ## B ## _Phdr *phdr = PHDR ## B (elf->phdr); \
		for (i = 0; i < EGET(ehdr->e_phnum); i++) { \
			if (phdr[i].p_type != PT_DYNAMIC) continue; \
			dyn = DYN ## B (elf->data + EGET(phdr[i].p_offset)); \
			while (EGET(dyn->d_tag) != DT_NULL) { \
				if (EGET(dyn->d_tag) == DT_TEXTREL) { /*dyn->d_tag != DT_FLAGS)*/ \
					found_textrel = 1; \
					/*if (dyn->d_un.d_val & DF_TEXTREL)*/ \
					printf("TEXTREL "); \
				} \
				++dyn; \
			} \
		} }
		SHOW_TEXTREL(32)
		SHOW_TEXTREL(64)
		if (!be_quiet && !found_textrel) printf("------- ");
	}

	/* rpath fun */
	/* TODO: if be_quiet, only output RPATH's which aren't in /etc/ld.so.conf */
	if (show_rpath) {
		char *rpath, *runpath;
		void *strtbl_void = elf_findsecbyname(elf, ".dynstr");
		rpath = runpath = NULL;

		if (strtbl_void) {
#define SHOW_RPATH(B) \
		if (elf->elf_class == ELFCLASS ## B) { \
		Elf ## B ## _Dyn *dyn; \
		Elf ## B ## _Ehdr *ehdr = EHDR ## B (elf->ehdr); \
		Elf ## B ## _Phdr *phdr = PHDR ## B (elf->phdr); \
		Elf ## B ## _Shdr *strtbl = SHDR ## B (strtbl_void); \
		for (i = 0; i < EGET(ehdr->e_phnum); i++) { \
			if (EGET(phdr[i].p_type) != PT_DYNAMIC) continue; \
			dyn = DYN ## B (elf->data + EGET(phdr[i].p_offset)); \
			while (EGET(dyn->d_tag) != DT_NULL) { \
				if (EGET(dyn->d_tag) == DT_RPATH) { \
					rpath = elf->data + EGET(strtbl->sh_offset) + EGET(dyn->d_un.d_ptr); \
					found_rpath = 1; \
				} else if (EGET(dyn->d_tag) == DT_RUNPATH) { \
					runpath = elf->data + EGET(strtbl->sh_offset) + EGET(dyn->d_un.d_ptr); \
					found_rpath = 1; \
				} \
				++dyn; \
			} \
		} }
		SHOW_RPATH(32)
		SHOW_RPATH(64)
		}
		if (rpath && runpath) {
			if (!strcmp(rpath, runpath))
				printf("%-5s ", runpath);
			else {
				fprintf(stderr, "%s's RPATH [%s] != RUNPATH [%s]\n", filename, rpath, runpath);
				printf("{%s,%s} ", rpath, runpath);
			}
		} else if (rpath || runpath)
			printf("%-5s ", (runpath ? runpath : rpath));
		else if (!be_quiet && !found_rpath)
			printf("  -   ");
	}

	if (find_sym) {
		void *symtab_void, *strtab_void;
		char *versioned_symname = malloc(strlen(find_sym)+2);

		sprintf(versioned_symname, "%s@", find_sym);
		symtab_void = elf_findsecbyname(elf, ".symtab");
		strtab_void = elf_findsecbyname(elf, ".strtab");

		if (symtab_void && strtab_void) {
#define FIND_SYM(B) \
		if (elf->elf_class == ELFCLASS ## B) { \
		Elf ## B ## _Shdr *symtab = SHDR ## B (symtab_void); \
		Elf ## B ## _Shdr *strtab = SHDR ## B (strtab_void); \
		Elf ## B ## _Sym *sym = SYM ## B (elf->data + EGET(symtab->sh_offset)); \
		int cnt = EGET(symtab->sh_size) / EGET(symtab->sh_entsize); \
		char *symname; \
		for (i = 0; i < cnt; ++i) { \
			if (sym->st_name) { \
				symname = (char *)(elf->data + EGET(strtab->sh_offset) + EGET(sym->st_name)); \
				if (*find_sym == '*') { \
					printf("%s(%s) %5lX %15s %s\n", ((found_sym == 0) ? "\n\t" : "\t"), \
						(char *) basename(filename), \
						(long)sym->st_size, (char *) get_elfstttype(sym->st_info & 0xF), \
                                      		symname); \
						found_sym = 1; \
				} \
				if ((strcmp(find_sym, symname) == 0) || \
					(strncmp(symname, versioned_symname, strlen(versioned_symname)) == 0)) \
					found_sym++; \
			} \
			++sym; \
		} }
		FIND_SYM(32)
		FIND_SYM(64)
		}
		free(versioned_symname);
		if (*find_sym != '*') {
			if (found_sym)
				printf(" %s ", find_sym);
			else if (!be_quiet)
				printf(" - ");
		}
	}

	if (!be_quiet || found_pax || found_stack || found_textrel || found_rpath || found_sym)
		printf("%s\n", filename);

	unreadelf(elf);
}

/* scan a directory for ET_EXEC files and print when we find one */
static void scanelf_dir(const char *path)
{
	register DIR *dir;
	register struct dirent *dentry;
	struct stat st_top, st;
	char buf[_POSIX_PATH_MAX];
	size_t len = 0;

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
		if (len >= sizeof(buf)) warn("len > sizeof(buf); %d %d = %s\n", len, sizeof(buf), path);
		assert(len < sizeof(buf));
		sprintf(buf, "%s/%s", path, dentry->d_name);
		if (lstat(buf, &st) != -1) {
			if (S_ISREG(st.st_mode))
				scanelf_file(buf);
			else if (dir_recurse && S_ISDIR(st.st_mode)) {
				if (dir_crossmount || (st_top.st_dev == st.st_dev))
					scanelf_dir(buf);
			}
		}
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

	if ((path = malloc(_POSIX_PATH_MAX)) == NULL) {
		warn("Can not malloc() memory for ldpath scanning");
		return;
	}
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
#define PARSE_FLAGS "plRmxetrs:aqvo:BhV"
#define a_argument required_argument
static struct option const long_opts[] = {
	{"path",      no_argument, NULL, 'p'},
	{"ldpath",    no_argument, NULL, 'l'},
	{"recursive", no_argument, NULL, 'R'},
	{"mount",     no_argument, NULL, 'm'},
	{"pax",       no_argument, NULL, 'x'},
	{"header",    no_argument, NULL, 'e'},
	{"textrel",   no_argument, NULL, 't'},
	{"rpath",     no_argument, NULL, 'r'},
	{"symbol",    a_argument,  NULL, 's'},
	{"all",       no_argument, NULL, 'a'},
	{"quiet",     no_argument, NULL, 'q'},
	{"verbose",   no_argument, NULL, 'v'},
	{"file",      a_argument,  NULL, 'o'},
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
	"Find a specified symbol",
	"Print all scanned info (-x -e -t -r)\n",
	"Only output 'bad' things",
	"Be verbose (can be specified more than once)",
	"Write output stream to a filename",
	"Don't display the header",
	"Print this help and exit",
	"Print version and exit",
	NULL
};

/* display usage and exit */
static void usage(int status)
{
	int i;
	printf("¤ Scan ELF binaries for stuff\n"
	       "Usage: %s [options] <dir1> [dir2 dirN ...]\n\n", argv0);
	printf("Options:\n");
	for (i = 0; long_opts[i].name; ++i)
		if (long_opts[i].has_arg == no_argument)
			printf("  -%c, --%-13s× %s\n", long_opts[i].val, 
			       long_opts[i].name, opts_help[i]);
		else
			printf("  -%c, --%-6s <arg> × %s\n", long_opts[i].val,
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
			printf("%s compiled %s\n%s\n"
			       "%s written for Gentoo Linux by <solar and vapier @ gentoo.org>\n",
			       __FILE__, __DATE__, rcsid, argv0);
			exit(EXIT_SUCCESS);
			break;
		case 'h': usage(EXIT_SUCCESS); break;

		case 'o': {
			FILE *fp = NULL;
			fp = freopen(optarg, "w", stdout);
			if (fp == NULL)
				err("Could not open output stream '%s': %s", optarg, strerror(errno));
			stdout = fp;
			break;
		}

		case 's': find_sym = strdup(optarg); break;

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
	if (optind == argc && !scan_ldpath && !scan_envpath)
		err("Nothing to scan !?");
	while (optind < argc)
		scanelf_dir(argv[optind++]);

	if (find_sym) free(find_sym);
}



int main(int argc, char *argv[])
{
	if (argc < 2)
		usage(EXIT_FAILURE);
	parseargs(argc, argv);
	fclose(stdout);
	return EXIT_SUCCESS;
}
