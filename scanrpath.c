/*
 *	Mar 29 2005	- {solar,vapier}@gentoo
 *
 *	find binaries with RPATH in them
 * ./scanrpath /{usr/{local/,},}{s,}bin/globstar > /dev/null
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "paxelf.h"

void scan_program_header(const char *filename)
{
	int i;
	elfobj *elf;
	Elf_Shdr *strtbl;

	if ((elf = readelf((char *) filename)) == NULL)
		return;
	if (check_elf_header(elf->ehdr))
		goto bail;
	if (!(IS_ELF(elf) && (IS_ELF_ET_DYN(elf) || IS_ELF_ET_EXEC(elf))))
		goto bail;

	strtbl = elf_findsecbyname(elf, ".dynstr");
	if (!strtbl) {
		/* only static binaries should be lacking .dynstr ... */
		goto bail;
	}
	for (i = 0; i < elf->ehdr->e_phnum; i++)
		if (elf->phdr[i].p_type == PT_DYNAMIC) {
			Elf_Dyn *dyn = (Elf_Dyn *)(elf->data + elf->phdr[i].p_offset);
			while (dyn->d_tag != DT_NULL) {
				if (dyn->d_tag == DT_RPATH || dyn->d_tag == DT_RUNPATH)
					printf("%s %s %s\n", filename, get_elfdtype(dyn->d_tag),
					       elf->data + strtbl->sh_offset + dyn->d_un.d_ptr);
				++dyn;
			}
		}

bail:
	unreadelf(elf);
}

void usage(int status)
{
	printf("Usage: pttool <file1> [file2 file3 ...]\n");
	exit(status);
}

int main(int argc, char *argv[])
{
	int i;

	if (argc <= 1)
		usage(EXIT_FAILURE);

	for (i=1; argv[i]; ++i)
		scan_program_header(argv[i]);

	return 0;
}
