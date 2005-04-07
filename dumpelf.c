/*
 * Copyright 1999-2005 Gentoo Foundation
 * Distributed under the terms of the GNU General Public License v2
 * $Header: /var/cvsroot/gentoo-projects/pax-utils/dumpelf.c,v 1.1 2005/04/07 00:18:33 vapier Exp $
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

static const char *rcsid = "$Id: dumpelf.c,v 1.1 2005/04/07 00:18:33 vapier Exp $";


/* helper functions for showing errors */
#define argv0 "dumpelf" /*((*argv != NULL) ? argv[0] : __FILE__ "\b\b")*/
#define warn(fmt, args...) \
	fprintf(stderr, "%s: " fmt "\n", argv0, ## args)
#define warnf(fmt, args...) warn("%s(): " fmt, __FUNCTION__, ## args)
#define err(fmt, args...) \
	do { \
	warn(fmt, ## args); \
	exit(EXIT_FAILURE); \
	} while (0)



/* prototypes */
static void dumpelf(const char *filename);
static void dump_ehdr(elfobj *elf, void *ehdr);
static void dump_phdr(elfobj *elf, void *phdr);
static void dump_shdr(elfobj *elf, void *shdr);
static void dump_dyn(elfobj *elf, void *dyn);
static void dump_sym(elfobj *elf, void *sym);
static void dump_rel(elfobj *elf, void *rel);
static void dump_rela(elfobj *elf, void *rela);
static void usage(int status);
static void parseargs(int argc, char *argv[]);



/* dump all internal elf info */
static void dumpelf(const char *filename)
{
	elfobj *elf;
	int i;
	Elf64_Ehdr *ehdr;
	Elf64_Phdr *phdr;
	Elf64_Shdr *shdr;

	/* verify this is real ELF */
	if ((elf = readelf(filename)) == NULL) {
		return;
	}

	printf("ELF dump of %s:\n", filename);

	ehdr = EHDR64(elf->ehdr);
	printf("----- ELF Header -----\n");
	dump_ehdr(elf, elf->ehdr);

	if (elf->phdr) {
		phdr = PHDR64(elf->phdr);
		for (i = 0; i < ehdr->e_phnum; ++i) {
			printf("----- Program Header #%i -----\n", i);
			dump_phdr(elf, phdr);
			++phdr;
		}
	}

	if (elf->shdr) {
		shdr = SHDR64(elf->shdr);
		for (i = 0; i < ehdr->e_shnum; ++i) {
			printf("----- Section Header #%i -----\n", i);
			dump_shdr(elf, shdr);
			++shdr;
		}
	}

	unreadelf(elf);
}
static void dump_ehdr(elfobj *elf, void *ehdr_void)
{
	Elf64_Ehdr *ehdr = EHDR64(ehdr_void);

	printf("e_ident[EI_NIDENT] = {\n"
	       "\t[%i] EI_MAG:        {0x%X,%c,%c,%c}\n"
	       "\t[%i] EI_CLASS:      %i (%s)\n"
	       "\t[%i] EI_DATA:       %i (%s)\n"
	       "\t[%i] EI_VERSION:    %i (%s)\n"
	       "\t[%i] EI_OSABI:      %i (%s)\n"
	       "\t[%i] EI_ABIVERSION: %i\n"
	       "\t[%i] EI_PAD:        0x%02X * %i\n"
	       "}\n",
	       EI_MAG0, ehdr->e_ident[EI_MAG0], ehdr->e_ident[EI_MAG1], ehdr->e_ident[EI_MAG2], ehdr->e_ident[EI_MAG3],
	       EI_CLASS, ehdr->e_ident[EI_CLASS], get_elfeitype(elf, EI_CLASS, ehdr->e_ident[EI_CLASS]),
	       EI_DATA, ehdr->e_ident[EI_DATA], get_elfeitype(elf, EI_DATA, ehdr->e_ident[EI_DATA]),
	       EI_VERSION, ehdr->e_ident[EI_VERSION], get_elfeitype(elf, EI_VERSION, ehdr->e_ident[EI_VERSION]),
	       EI_OSABI, ehdr->e_ident[EI_OSABI], get_elfeitype(elf, EI_OSABI, ehdr->e_ident[EI_OSABI]),
	       EI_ABIVERSION, ehdr->e_ident[EI_ABIVERSION],
	       EI_PAD, ehdr->e_ident[EI_PAD], EI_NIDENT - EI_PAD
	);
	printf("e_type      = %i (%s)\n", ehdr->e_type, get_elfetype(elf));
	printf("e_machine   = %i (%s)\n", ehdr->e_machine, get_elfemtype(ehdr->e_machine));
	printf("e_version   = %i\n", ehdr->e_version);
	printf("e_entry     = 0x%X\n", ehdr->e_entry);
	printf("e_phoff     = %i (bytes into file)\n", ehdr->e_phoff);
	printf("e_shoff     = %i (bytes into file)\n", ehdr->e_shoff);
	printf("e_flags     = 0x%X\n", ehdr->e_flags);
	printf("e_ehsize    = %i (bytes)\n", ehdr->e_ehsize);
	printf("e_phentsize = %i (bytes)\n", ehdr->e_phentsize);
	printf("e_phnum     = %i (program headers)\n", ehdr->e_phnum);
	printf("e_shentsize = %i (bytes)\n", ehdr->e_shentsize);
	printf("e_shnum     = %i (section headers)\n", ehdr->e_shnum);
	printf("e_shstrndx  = %i\n", ehdr->e_shstrndx);
	printf("\n");
}
static void dump_phdr(elfobj *elf, void *phdr_void)
{
	Elf64_Phdr *phdr = PHDR64(phdr_void);

	printf("p_type   = %i [%s]\n", phdr->p_type, get_elfptype(phdr->p_type));
	printf("p_offset = %i\n", phdr->p_offset);
	printf("p_vaddr  = %i\n", phdr->p_vaddr);
	printf("p_paddr  = %i\n", phdr->p_paddr);
	printf("p_filesz = %i\n", phdr->p_filesz);
	printf("p_memsz  = %i\n", phdr->p_memsz);
	printf("p_flags  = %i\n", phdr->p_flags);
	printf("p_align  = %i\n", phdr->p_align);
}
static void dump_shdr(elfobj *elf, void *shdr_void)
{
	Elf64_Shdr *shdr = SHDR64(shdr_void);

	printf("sh_name      = %i\n", shdr->sh_name);
	printf("sh_type      = %i\n", shdr->sh_type);
	printf("sh_flags     = %i\n", shdr->sh_flags);
	printf("sh_addr      = %i\n", shdr->sh_addr);
	printf("sh_offset    = %i\n", shdr->sh_offset);
	printf("sh_size      = %i\n", shdr->sh_size);
	printf("sh_link      = %i\n", shdr->sh_link);
	printf("sh_info      = %i\n", shdr->sh_info);
	printf("sh_addralign = %i\n", shdr->sh_addralign);
	printf("sh_entsize   = %i\n", shdr->sh_entsize);
}



/* usage / invocation handling functions */
#define PARSE_FLAGS "hV"
#define a_argument required_argument
static struct option const long_opts[] = {
	{"help",      no_argument, NULL, 'h'},
	{"version",   no_argument, NULL, 'V'},
	{NULL,        no_argument, NULL, 0x0}
};
static char *opts_help[] = {
	"Print this help and exit",
	"Print version and exit",
	NULL
};

/* display usage and exit */
static void usage(int status)
{
	int i;
	printf("¤ Dump internal ELF structure\n\n"
	       "Usage: %s <file1> [file2 fileN ...]\n\n", argv0);
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

	if (optind == argc)
		err("Nothing to dump !?");
	while (optind < argc)
		dumpelf(argv[optind++]);
}



int main(int argc, char *argv[])
{
	if (argc < 2)
		usage(EXIT_FAILURE);
	parseargs(argc, argv);
	return EXIT_SUCCESS;
}
