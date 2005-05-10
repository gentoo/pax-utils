/*
 * Copyright 2003 Ned Ludd <solar@gentoo.org>
 * Copyright 1999-2005 Gentoo Foundation
 * Distributed under the terms of the GNU General Public License v2
 * $Header: /var/cvsroot/gentoo-projects/pax-utils/scanelf.c,v 1.44 2005/05/10 22:54:25 vapier Exp $
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

static const char *rcsid = "$Id: scanelf.c,v 1.44 2005/05/10 22:54:25 vapier Exp $";
#define argv0 "scanelf"



/* prototypes */
static void scanelf_file(const char *filename);
static void scanelf_dir(const char *path);
static void scanelf_ldpath();
static void scanelf_envpath();
static void usage(int status);
static void parseargs(int argc, char *argv[]);
static char *xstrdup(char *s);
static void *xmalloc(size_t size);
static void xstrcat(char **dst, const char *src, size_t *curr_len);
static inline void xchrcat(char **dst, const char append, size_t *curr_len);
static int xemptybuffer(const char *buff);

/* variables to control behavior */
static char scan_ldpath = 0;
static char scan_envpath = 0;
static char scan_symlink = 1;
static char dir_recurse = 0;
static char dir_crossmount = 1;
static char show_pax = 0;
static char show_stack = 0;
static char show_textrel = 0;
static char show_rpath = 0;
static char show_needed = 0;
static char show_interp = 0;
static char show_banner = 1;
static char be_quiet = 0;
static char be_verbose = 0;
static char *find_sym = NULL, *versioned_symname = NULL;
static char *out_format = NULL;



/* sub-funcs for scanelf_file() */
static char *scanelf_file_pax(elfobj *elf, char *found_pax)
{
	static char *paxflags;

	if (!show_pax) return NULL;

	paxflags = pax_short_hf_flags(PAX_FLAGS(elf));
	if (!be_quiet || (be_quiet && strncmp(paxflags, "PeMRxS", 6))) {
		*found_pax = 1;
		return paxflags;
	}

	return NULL;
}
static char *scanelf_file_stack(elfobj *elf, char *found_stack, char *found_relro)
{
	static char ret[8];
	char *found;
	unsigned long i, off, shown;

	if (!show_stack) return NULL;

	shown = 0;
	strcpy(ret, "--- ---");

	if (elf->phdr) {
#define SHOW_STACK(B) \
	if (elf->elf_class == ELFCLASS ## B) { \
	Elf ## B ## _Ehdr *ehdr = EHDR ## B (elf->ehdr); \
	Elf ## B ## _Phdr *phdr = PHDR ## B (elf->phdr); \
	for (i = 0; i < EGET(ehdr->e_phnum); i++) { \
		if (EGET(phdr[i].p_type) == PT_GNU_STACK) { \
			found = found_stack; \
			off = 0; \
		} else if (EGET(phdr[i].p_type) == PT_GNU_RELRO) { \
			found = found_relro; \
			off = 3; \
		} else \
			continue; \
		if (be_quiet && !(EGET(phdr[i].p_flags) & PF_X)) \
			continue; \
		memcpy(ret+off, gnu_short_stack_flags(EGET(phdr[i].p_flags)), 3); \
		*found = 1; \
		++shown; \
	} \
	}
	SHOW_STACK(32)
	SHOW_STACK(64)
	}

	if (be_quiet && !shown)
		return NULL;
	else
		return ret;
}
static char *scanelf_file_textrel(elfobj *elf, char *found_textrel)
{
	static char *ret = "TEXTREL";
	unsigned long i;

	if (!show_textrel) return NULL;

	if (elf->phdr) {
#define SHOW_TEXTREL(B) \
	if (elf->elf_class == ELFCLASS ## B) { \
	Elf ## B ## _Dyn *dyn; \
	Elf ## B ## _Ehdr *ehdr = EHDR ## B (elf->ehdr); \
	Elf ## B ## _Phdr *phdr = PHDR ## B (elf->phdr); \
	Elf ## B ## _Off offset; \
	for (i = 0; i < EGET(ehdr->e_phnum); i++) { \
		if (phdr[i].p_type != PT_DYNAMIC) continue; \
		offset = EGET(phdr[i].p_offset); \
		if (offset >= elf->len - sizeof(Elf ## B ## _Dyn)) continue; \
		dyn = DYN ## B (elf->data + offset); \
		while (EGET(dyn->d_tag) != DT_NULL) { \
			if (EGET(dyn->d_tag) == DT_TEXTREL) { /*dyn->d_tag != DT_FLAGS)*/ \
				*found_textrel = 1; \
				/*if (dyn->d_un.d_val & DF_TEXTREL)*/ \
				return ret; \
			} \
			++dyn; \
		} \
	} }
	SHOW_TEXTREL(32)
	SHOW_TEXTREL(64)
	}

	if (be_quiet)
		return NULL;
	else
		return "   -   ";
}
static void scanelf_file_rpath(elfobj *elf, char *found_rpath, char **ret, size_t *ret_len)
{
	/* TODO: if be_quiet, only output RPATH's which aren't in /etc/ld.so.conf */
	unsigned long i;
	char *rpath, *runpath;
	void *strtbl_void;

	if (!show_rpath) return;

	strtbl_void = elf_findsecbyname(elf, ".dynstr");
	rpath = runpath = NULL;

	if (elf->phdr && strtbl_void) {
#define SHOW_RPATH(B) \
		if (elf->elf_class == ELFCLASS ## B) { \
		Elf ## B ## _Dyn *dyn; \
		Elf ## B ## _Ehdr *ehdr = EHDR ## B (elf->ehdr); \
		Elf ## B ## _Phdr *phdr = PHDR ## B (elf->phdr); \
		Elf ## B ## _Shdr *strtbl = SHDR ## B (strtbl_void); \
		Elf ## B ## _Off offset; \
		for (i = 0; i < EGET(ehdr->e_phnum); i++) { \
			if (EGET(phdr[i].p_type) != PT_DYNAMIC) continue; \
			offset = EGET(phdr[i].p_offset); \
			if (offset >= elf->len - sizeof(Elf ## B ## _Dyn)) continue; \
			dyn = DYN ## B (elf->data + offset); \
			while (EGET(dyn->d_tag) != DT_NULL) { \
				if (EGET(dyn->d_tag) == DT_RPATH) { \
					if (rpath) warn("ELF has multiple DT_RPATH's !?"); \
					offset = EGET(strtbl->sh_offset) + EGET(dyn->d_un.d_ptr); \
					if (offset >= elf->len) continue; \
					rpath = (char*)(elf->data + offset); \
					*found_rpath = 1; \
				} else if (EGET(dyn->d_tag) == DT_RUNPATH) { \
					if (runpath) warn("ELF has multiple DT_RUNPATH's !?"); \
					offset = EGET(strtbl->sh_offset) + EGET(dyn->d_un.d_ptr); \
					if (offset >= elf->len) continue; \
					runpath = (char*)(elf->data + offset); \
					*found_rpath = 1; \
				} \
				++dyn; \
			} \
		} }
		SHOW_RPATH(32)
		SHOW_RPATH(64)
	}

	if (rpath && runpath) {
		if (!strcmp(rpath, runpath)) {
			xstrcat(ret, runpath, ret_len);
		} else {
			fprintf(stderr, "RPATH [%s] != RUNPATH [%s]\n", rpath, runpath);
			xchrcat(ret, '{', ret_len);
			xstrcat(ret, rpath, ret_len);
			xchrcat(ret, ',', ret_len);
			xstrcat(ret, runpath, ret_len);
			xchrcat(ret, '}', ret_len);
		}
	} else if (rpath || runpath)
		xstrcat(ret, (runpath ? runpath : rpath), ret_len);
	else if (!be_quiet)
		xstrcat(ret, "  -  ", ret_len);
}
static void scanelf_file_needed(elfobj *elf, char *found_needed, char **ret, size_t *ret_len)
{
	unsigned long i;
	char *needed;
	void *strtbl_void;

	if (!show_needed) return;

	strtbl_void = elf_findsecbyname(elf, ".dynstr");

	if (elf->phdr && strtbl_void) {
#define SHOW_NEEDED(B) \
		if (elf->elf_class == ELFCLASS ## B) { \
		Elf ## B ## _Dyn *dyn; \
		Elf ## B ## _Ehdr *ehdr = EHDR ## B (elf->ehdr); \
		Elf ## B ## _Phdr *phdr = PHDR ## B (elf->phdr); \
		Elf ## B ## _Shdr *strtbl = SHDR ## B (strtbl_void); \
		Elf ## B ## _Off offset; \
		for (i = 0; i < EGET(ehdr->e_phnum); i++) { \
			if (EGET(phdr[i].p_type) != PT_DYNAMIC) continue; \
			offset = EGET(phdr[i].p_offset); \
			if (offset >= elf->len - sizeof(Elf ## B ## _Dyn)) continue; \
			dyn = DYN ## B (elf->data + offset); \
			while (EGET(dyn->d_tag) != DT_NULL) { \
				if (EGET(dyn->d_tag) == DT_NEEDED) { \
					offset = EGET(strtbl->sh_offset) + EGET(dyn->d_un.d_ptr); \
					if (offset >= elf->len) continue; \
					needed = (char*)(elf->data + offset); \
					if (*found_needed) xchrcat(ret, ',', ret_len); \
					xstrcat(ret, needed, ret_len); \
					*found_needed = 1; \
				} \
				++dyn; \
			} \
		} }
		SHOW_NEEDED(32)
		SHOW_NEEDED(64)
	}
}
static char *scanelf_file_interp(elfobj *elf, char *found_interp)
{
	void *strtbl_void;

	if (!show_interp) return NULL;

	strtbl_void = elf_findsecbyname(elf, ".interp");

	if (strtbl_void) {
#define SHOW_INTERP(B) \
		if (elf->elf_class == ELFCLASS ## B) { \
			Elf ## B ## _Shdr *strtbl = SHDR ## B (strtbl_void); \
			*found_interp = 1; \
			return elf->data + EGET(strtbl->sh_offset); \
		}
		SHOW_INTERP(32)
		SHOW_INTERP(64)
	}
	return NULL;
}
static char *scanelf_file_sym(elfobj *elf, char *found_sym, const char *filename)
{
	unsigned long i;
	void *symtab_void, *strtab_void;

	if (!find_sym) return NULL;

	symtab_void = elf_findsecbyname(elf, ".symtab");
	strtab_void = elf_findsecbyname(elf, ".strtab");

	if (symtab_void && strtab_void) {
#define FIND_SYM(B) \
		if (elf->elf_class == ELFCLASS ## B) { \
		Elf ## B ## _Shdr *symtab = SHDR ## B (symtab_void); \
		Elf ## B ## _Shdr *strtab = SHDR ## B (strtab_void); \
		Elf ## B ## _Sym *sym = SYM ## B (elf->data + EGET(symtab->sh_offset)); \
		unsigned long cnt = EGET(symtab->sh_size) / EGET(symtab->sh_entsize); \
		char *symname; \
		for (i = 0; i < cnt; ++i) { \
			if (sym->st_name) { \
				symname = (char *)(elf->data + EGET(strtab->sh_offset) + EGET(sym->st_name)); \
				if (*find_sym == '*') { \
					printf("%s(%s) %5lX %15s %s\n", \
					       ((*found_sym == 0) ? "\n\t" : "\t"), \
					       (char *)basename(filename), \
					       (long)sym->st_size, \
					       (char *)get_elfstttype(sym->st_info), \
					       symname); \
					*found_sym = 1; \
				} else if ((strcmp(find_sym, symname) == 0) || \
				           (strcmp(symname, versioned_symname) == 0)) \
					(*found_sym)++; \
			} \
			++sym; \
		} }
		FIND_SYM(32)
		FIND_SYM(64)
	}
	if (*find_sym != '*' && *found_sym)
		return find_sym;
	if (be_quiet)
		return NULL;
	else
		return " - ";
}
/* scan an elf file and show all the fun stuff */
#define prints(str) fputs(str, stdout)
static void scanelf_file(const char *filename)
{
	unsigned long i;
	char found_pax, found_stack, found_relro, found_textrel, 
	     found_rpath, found_needed, found_interp, found_sym,
	     found_file;
	elfobj *elf;
	struct stat st;
	static char *out_buffer = NULL;
	static size_t out_len;

	/* make sure 'filename' exists */
	if (lstat(filename, &st) == -1) {
		if (be_verbose > 2) printf("%s: does not exist\n", filename);
		return;
	}
	/* always handle regular files and handle symlinked files if no -y */
	if (!(S_ISREG(st.st_mode) || (S_ISLNK(st.st_mode) && scan_symlink))) {
		if (be_verbose > 2) printf("%s: skipping non-file\n", filename);
		return;
	}

	found_pax = found_stack = found_relro = found_textrel = \
	found_rpath = found_needed = found_interp = found_sym = \
	found_file = 0;

	/* verify this is real ELF */
	if ((elf = readelf(filename)) == NULL) {
		if (be_verbose > 2) printf("%s: not an ELF\n", filename);
		return;
	}

	if (be_verbose > 1)
		printf("%s: scanning file {%s,%s}\n", filename,
		       get_elfeitype(elf, EI_CLASS, elf->elf_class),
		       get_elfeitype(elf, EI_DATA, elf->data[EI_DATA]));
	else if (be_verbose)
		printf("%s: scanning file\n", filename);

	/* init output buffer */
	if (!out_buffer) {
		out_len = sizeof(char) * 80;
		out_buffer = (char*)xmalloc(out_len);
	}
	*out_buffer = '\0';

	/* show the header */
	if (!be_quiet && show_banner) {
		for (i=0; out_format[i]; ++i) {
			if (out_format[i] != '%') continue;

			switch (out_format[++i]) {
			case '%': break;
			case 'F': prints("FILE "); break;
			case 'o': prints(" TYPE   "); break;
			case 'x': prints(" PAX   "); break;
			case 'e': prints("STK/REL "); break;
			case 't': prints("TEXTREL "); break;
			case 'r': prints("RPATH "); break;
			case 'n': prints("NEEDED "); break;
			case 'i': prints("INTERP "); break;
			case 's': prints("SYM "); break;
			}
		}
		prints("\n");
		show_banner = 0;
	}

	/* dump all the good stuff */
	for (i=0; out_format[i]; ++i) {
		const char *out;

		/* make sure we trim leading spaces in quiet mode */
		if (be_quiet && *out_buffer == ' ' && !out_buffer[1])
			*out_buffer = '\0';

		if (out_format[i] != '%') {
			xchrcat(&out_buffer, out_format[i], &out_len);
			continue;
		}

		out = NULL;
		switch (out_format[++i]) {
		case '%': xchrcat(&out_buffer, '%', &out_len); break;
		case 'F': found_file = 1; xstrcat(&out_buffer, filename, &out_len); break;
		case 'o': out = get_elfetype(elf); break;
		case 'x': out = scanelf_file_pax(elf, &found_pax); break;
		case 'e': out = scanelf_file_stack(elf, &found_stack, &found_relro); break;
		case 't': out = scanelf_file_textrel(elf, &found_textrel); break;
		case 'r': scanelf_file_rpath(elf, &found_rpath, &out_buffer, &out_len); break;
		case 'n': scanelf_file_needed(elf, &found_needed, &out_buffer, &out_len); break;
		case 'i': out = scanelf_file_interp(elf, &found_interp); break;
		case 's': out = scanelf_file_sym(elf, &found_sym, filename); break;
		}
		if (out) xstrcat(&out_buffer, out, &out_len);
	}

	if (!found_file) {
		if (!be_quiet || found_pax || found_stack || found_textrel || \
		    found_rpath || found_needed || found_interp || found_sym)
			xstrcat(&out_buffer, filename, &out_len);
	}
	if (!(be_quiet && xemptybuffer(out_buffer)))
		puts(out_buffer);

	unreadelf(elf);
}

/* scan a directory for ET_EXEC files and print when we find one */
static void scanelf_dir(const char *path)
{
	register DIR *dir;
	register struct dirent *dentry;
	struct stat st_top, st;
	char buf[_POSIX_PATH_MAX];
	size_t pathlen = 0, len = 0;

	/* make sure path exists */
	if (lstat(path, &st_top) == -1) {
		if (be_verbose > 2) printf("%s: does not exist\n", path);
		return;
	}

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

	pathlen = strlen(path);
	while ((dentry = readdir(dir))) {
		if (!strcmp(dentry->d_name, ".") || !strcmp(dentry->d_name, ".."))
			continue;
		len = (pathlen + 1 + strlen(dentry->d_name) + 1);
		if (len >= sizeof(buf)) {
			warnf("Skipping '%s': len > sizeof(buf); %d > %d\n", path, (int)len, (int)sizeof(buf));
			continue;
		}
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

	path = (char*)xmalloc(_POSIX_PATH_MAX);
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
	fclose(fp);

	if (!scan_l)   scanelf_dir("/lib");
	if (!scan_ul)  scanelf_dir("/usr/lib");
	if (!scan_ull) scanelf_dir("/usr/local/lib");
}

/* scan env PATH for paths */
static void scanelf_envpath()
{
	char *path, *p;

	path = getenv("PATH");
	if (!path)
		err("PATH is not set in your env !");
	path = xstrdup(path);

	while ((p = strrchr(path, ':')) != NULL) {
		scanelf_dir(p + 1);
		*p = 0;
	}

	free(path);
}



/* usage / invocation handling functions */
#define PARSE_FLAGS "plRmyxetrnis:aqvF:o:BhV"
#define a_argument required_argument
static struct option const long_opts[] = {
	{"path",      no_argument, NULL, 'p'},
	{"ldpath",    no_argument, NULL, 'l'},
	{"recursive", no_argument, NULL, 'R'},
	{"mount",     no_argument, NULL, 'm'},
	{"symlink",   no_argument, NULL, 'y'},
	{"pax",       no_argument, NULL, 'x'},
	{"header",    no_argument, NULL, 'e'},
	{"textrel",   no_argument, NULL, 't'},
	{"rpath",     no_argument, NULL, 'r'},
	{"needed",    no_argument, NULL, 'n'},
	{"interp",    no_argument, NULL, 'i'},
	{"symbol",    a_argument,  NULL, 's'},
	{"all",       no_argument, NULL, 'a'},
	{"quiet",     no_argument, NULL, 'q'},
	{"verbose",   no_argument, NULL, 'v'},
	{"format",    a_argument,  NULL, 'F'},
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
	"Don't recursively cross mount points",
	"Don't scan symlinks\n",
	"Print PaX markings",
	"Print GNU_STACK markings",
	"Print TEXTREL information",
	"Print RPATH information",
	"Print NEEDED information",
	"Print INTERP information",
	"Find a specified symbol",
	"Print all scanned info (-x -e -t -r)\n",
	"Only output 'bad' things",
	"Be verbose (can be specified more than once)",
	"Use specified format for output",
	"Write output stream to a filename",
	"Don't display the header",
	"Print this help and exit",
	"Print version and exit",
	NULL
};

/* display usage and exit */
static void usage(int status)
{
	unsigned long i;
	printf("¤ Scan ELF binaries for stuff\n\n"
	       "Usage: %s [options] <dir1/file1> [dir2 dirN fileN ...]\n\n", argv0);
	printf("Options: -[%s]\n", PARSE_FLAGS);
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

		case 'V':
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

		case 's': {
			size_t len;
			find_sym = xstrdup(optarg);
			len = strlen(find_sym) + 1;
			versioned_symname = (char*)xmalloc(sizeof(char) * (len+1));
			sprintf(versioned_symname, "%s@", find_sym);
			break;
		}

		case 'F': {
			out_format = strdup(optarg);
			break;
		}

		case 'y': scan_symlink = 0; break;
		case 'B': show_banner = 0; break;
		case 'l': scan_ldpath = 1; break;
		case 'p': scan_envpath = 1; break;
		case 'R': dir_recurse = 1; break;
		case 'm': dir_crossmount = 0; break;
		case 'x': show_pax = 1; break;
		case 'e': show_stack = 1; break;
		case 't': show_textrel = 1; break;
		case 'r': show_rpath = 1; break;
		case 'n': show_needed = 1; break;
		case 'i': show_interp = 1; break;
		case 'q': be_quiet = 1; break;
		case 'v': be_verbose = (be_verbose % 20) + 1; break;
		case 'a': show_pax = show_stack = show_textrel = show_rpath = show_needed = show_interp = 1; break;

		case ':':
			warn("Option missing parameter\n");
			usage(EXIT_FAILURE);
			break;
		case '?':
			warn("Unknown option\n");
			usage(EXIT_FAILURE);
			break;
		default:
			err("Unhandled option '%c'", flag);
			break;
		}
	}

	if (be_quiet && be_verbose)
		err("You can be quiet or you can be verbose, not both, stupid");

	/* let the format option override all other options */
	if (out_format) {
		show_pax = show_stack = show_textrel = show_rpath = show_needed = show_interp = 0;
		for (flag=0; out_format[flag]; ++flag) {
			if (out_format[flag] != '%') continue;

			switch (out_format[++flag]) {
			case '%': break;
			case 'F': break;
			case 's': break;
			case 'o': break;
			case 'x': show_pax = 1; break;
			case 'e': show_stack = 1; break;
			case 't': show_textrel = 1; break;
			case 'r': show_rpath = 1; break;
			case 'n': show_needed = 1; break;
			case 'i': show_interp = 1; break;
			default:
				err("Invalid format specifier '%c' (byte %i)", 
				    out_format[flag], flag+1);
			}
		}

	/* construct our default format */
	} else {
		size_t fmt_len = 30;
		out_format = (char*)xmalloc(sizeof(char) * fmt_len);
		if (!be_quiet)    xstrcat(&out_format, "%o ", &fmt_len);
		if (show_pax)     xstrcat(&out_format, "%x ", &fmt_len);
		if (show_stack)   xstrcat(&out_format, "%e ", &fmt_len);
		if (show_textrel) xstrcat(&out_format, "%t ", &fmt_len);
		if (show_rpath)   xstrcat(&out_format, "%r ", &fmt_len);
		if (show_needed)  xstrcat(&out_format, "%n ", &fmt_len);
		if (show_interp)  xstrcat(&out_format, "%i ", &fmt_len);
		if (find_sym)     xstrcat(&out_format, "%s ", &fmt_len);
		if (!be_quiet)    xstrcat(&out_format, "%F ", &fmt_len);
	}
	if (be_verbose > 2) printf("Format: %s\n", out_format);

	/* now lets actually do the scanning */
	if (scan_ldpath) scanelf_ldpath();
	if (scan_envpath) scanelf_envpath();
	if (optind == argc && !scan_ldpath && !scan_envpath)
		err("Nothing to scan !?");
	while (optind < argc)
		scanelf_dir(argv[optind++]);

	/* clean up */
	if (find_sym) {
		free(find_sym);
		free(versioned_symname);
	}
	if (out_format) free(out_format);
}



/* utility funcs */
static char *xstrdup(char *s)
{
	char *ret = strdup(s);
	if (!ret) err("Could not strdup(): %s", strerror(errno));
	return ret;
}
static void *xmalloc(size_t size)
{
	void *ret = malloc(size);
	if (!ret) err("Could not malloc() %li bytes", (unsigned long)size);
	return ret;
}
static void xstrcat(char **dst, const char *src, size_t *curr_len)
{
	long new_len;

	new_len = strlen(*dst) + strlen(src);
	if (*curr_len <= new_len) {
		*curr_len = new_len + (*curr_len / 2);
		*dst = realloc(*dst, *curr_len);
		if (!*dst)
			err("could not realloc %li bytes", (unsigned long)*curr_len);
	}

	strcat(*dst, src);
}
static inline void xchrcat(char **dst, const char append, size_t *curr_len)
{
	static char my_app[2];
	my_app[0] = append;
	my_app[1] = '\0';
	xstrcat(dst, my_app, curr_len);
}
static int xemptybuffer(const char *buff)
{
	long i;
	for (i=0; buff[i]; ++i)
		if (buff[i] != ' ')
			return 0;
	return 1;
}



int main(int argc, char *argv[])
{
	if (argc < 2)
		usage(EXIT_FAILURE);
	parseargs(argc, argv);
	fclose(stdout);
	return EXIT_SUCCESS;
}
